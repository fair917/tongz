package proxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/fair917/tongz/internal/config"
)

const (
	// idleTimeout bounds how long an intercepted connection may sit between
	// requests. It is cleared once a request arrives so that long-running
	// responses, such as token streaming, are never cut short.
	idleTimeout = 90 * time.Second
	// maxDrain bounds how much of a refused request's body is read. Reading
	// some of it is what lets the client see the refusal instead of a reset.
	maxDrain = 1 << 20
)

// intercept terminates TLS with a certificate the client trusts, then serves
// the requests inside.
func (p *Proxy) intercept(w http.ResponseWriter, r *http.Request, target, host string) {
	client, err := hijack(w)
	if err != nil {
		p.log.Error("hijack failed", slog.Any("error", err))
		return
	}
	defer client.Close()

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	conn := tls.Server(client, p.ca.ServerTLSConfig())
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err == nil {
		defer conn.SetDeadline(time.Time{})
	}
	if err := conn.Handshake(); err != nil {
		// Almost always a client that does not trust the CA. Say so plainly:
		// a bare TLS error sends people looking in the wrong place.
		p.log.Warn("TLS handshake with client failed; the container may not trust the tongz CA",
			slog.String("host", host), slog.Any("error", err))
		return
	}
	_ = conn.SetDeadline(time.Time{})

	p.serveIntercepted(conn, target, host)
}

// serveIntercepted reads HTTP/1.1 requests off the decrypted connection until
// the client goes away.
func (p *Proxy) serveIntercepted(conn net.Conn, target, host string) {
	br := bufio.NewReader(conn)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Time{})

		if !p.serveOne(conn, req, "https", target, host) {
			return
		}
	}
}

// serveOne handles one intercepted request and reports whether the connection
// can carry another.
func (p *Proxy) serveOne(conn net.Conn, req *http.Request, scheme, target, host string) bool {
	start := time.Now()
	path := req.URL.EscapedPath()

	out, rule, deny := p.prepare(req, scheme, target, host)
	if deny != nil {
		p.audit(host, req.Method, path, "deny", "", deny.status, start)
		drain(req.Body)
		writeDenial(conn, req, deny)
		return false
	}

	resp, err := p.upstrm.RoundTrip(out)
	if err != nil {
		p.audit(host, req.Method, path, "upstream-error", rule.Token, http.StatusBadGateway, start)
		p.log.Warn("upstream request failed",
			slog.String("host", host), slog.String("token", rule.Token), slog.Any("error", err))
		drain(req.Body)
		writeDenial(conn, req, &denial{
			status: http.StatusBadGateway,
			reason: "tongz: upstream request failed: " + err.Error(),
		})
		return false
	}
	defer resp.Body.Close()

	p.audit(host, req.Method, path, "inject", rule.Token, resp.StatusCode, start)
	if err := resp.Write(conn); err != nil {
		return false
	}
	return !req.Close && !resp.Close
}

// handleAbsolute serves a plain-HTTP request made in absolute form. Configured
// hosts stay fail-closed; anything else is forwarded without a credential.
func (p *Proxy) handleAbsolute(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host := config.NormalizeHost(r.URL.Host)
	target := r.URL.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "80")
	}
	path := r.URL.EscapedPath()

	var (
		out     *http.Request
		tokenID string
	)
	if p.cfg.Intercepts(host) {
		prepared, rule, deny := p.prepare(r, "http", target, host)
		if deny != nil {
			p.audit(host, r.Method, path, "deny", "", deny.status, start)
			http.Error(w, deny.reason, deny.status)
			return
		}
		out, tokenID = prepared, rule.Token
	} else {
		out = r.Clone(r.Context())
		out.RequestURI = ""
		out.URL.Host = target
		sanitize(out.Header)
	}

	resp, err := p.upstrm.RoundTrip(out)
	if err != nil {
		p.audit(host, r.Method, path, "upstream-error", tokenID, http.StatusBadGateway, start)
		http.Error(w, "tongz: upstream request failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	decision := "forward"
	if tokenID != "" {
		decision = "inject"
	}
	p.audit(host, r.Method, path, decision, tokenID, resp.StatusCode, start)

	for name, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// audit records what was decided. The token identifier is logged; its value
// never is.
func (p *Proxy) audit(host, method, path, decision, tokenID string, status int, start time.Time) {
	p.log.Info("request",
		slog.String("host", host),
		slog.String("method", method),
		slog.String("path", path),
		slog.String("decision", decision),
		slog.String("token", tokenID),
		slog.Int("status", status),
		slog.Duration("took", time.Since(start)))
}

func writeDenial(w io.Writer, req *http.Request, d *denial) {
	body := d.reason + "\n"
	resp := &http.Response{
		Status:        http.StatusText(d.status),
		StatusCode:    d.status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
		Close:         true,
	}
	_ = resp.Write(w)
}

func drain(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxDrain))
	_ = body.Close()
}
