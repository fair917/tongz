// Package proxy implements the explicit HTTP proxy that fronts every request
// an agent makes.
//
// Only hosts named by a rule are decrypted; everything else is tunnelled
// untouched. The isolation guarantee comes from where the credentials live, not
// from forcing traffic through this path, so a client that bypasses the proxy
// merely loses its authentication.
package proxy

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/fair917/tongz/internal/ca"
	"github.com/fair917/tongz/internal/config"
	"github.com/fair917/tongz/internal/secrets"
)

// Proxy serves the explicit proxy protocol on a single listener.
type Proxy struct {
	cfg    *config.Config
	ca     *ca.Authority
	store  *secrets.Store
	auth   string // shared secret for Proxy-Authorization; empty disables the check
	local  http.Handler
	log    *slog.Logger
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)
	upstrm *http.Transport
}

// Options configures a Proxy.
type Options struct {
	Config  *config.Config
	CA      *ca.Authority
	Secrets *secrets.Store
	// Auth is the resolved Proxy-Authorization secret. It grants use of the
	// proxy, not access to any upstream service, so keeping it inside the
	// container does not weaken the guarantee.
	Auth string
	// Local serves origin-form requests: CA distribution and setup.
	Local http.Handler
	Log   *slog.Logger
}

// New builds a Proxy. The upstream transport verifies certificates and never
// chains to another proxy.
func New(opts Options) *Proxy {
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	p := &Proxy{
		cfg:   opts.Config,
		ca:    opts.CA,
		store: opts.Secrets,
		auth:  opts.Auth,
		local: opts.Local,
		log:   log,
		dial:  dialer.DialContext,
	}
	p.upstrm = &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return p.dial(ctx, network, addr)
		},
		// Verification is deliberately left at the default: the container may
		// be careless about TLS, the host must not be.
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     false,
		DisableCompression:    true,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		if !p.authorized(r) {
			p.denyUnauthorized(w, r)
			return
		}
		p.handleConnect(w, r)
		return
	}
	if r.URL.IsAbs() {
		if !p.authorized(r) {
			p.denyUnauthorized(w, r)
			return
		}
		p.handleAbsolute(w, r)
		return
	}
	// Origin-form: a direct request to the proxy itself. Serving the CA here
	// is what removes the chicken-and-egg problem of trusting the interceptor.
	if p.local != nil {
		p.local.ServeHTTP(w, r)
		return
	}
	http.Error(w, "tongz: not a proxy request", http.StatusBadRequest)
}

// authorized reports whether the client presented the proxy secret.
func (p *Proxy) authorized(r *http.Request) bool {
	if p.auth == "" {
		return true
	}
	const prefix = "Bearer "
	got := r.Header.Get("Proxy-Authorization")
	if len(got) <= len(prefix) || got[:len(prefix)] != prefix {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got[len(prefix):]), []byte(p.auth)) == 1
}

func (p *Proxy) denyUnauthorized(w http.ResponseWriter, r *http.Request) {
	p.log.Warn("proxy authorization rejected",
		slog.String("host", hostOf(r)),
		slog.String("client", r.RemoteAddr))
	w.Header().Set("Proxy-Authenticate", `Bearer realm="tongz"`)
	http.Error(w, "tongz: proxy authorization required", http.StatusProxyAuthRequired)
}

// handleConnect either intercepts the connection or splices it through.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}
	host := config.NormalizeHost(target)

	if !p.cfg.Intercepts(host) {
		p.tunnel(w, r, target, host)
		return
	}
	p.intercept(w, r, target, host)
}

// tunnel splices the connection without decrypting it. Nothing is injected, so
// the request reaches the upstream unauthenticated.
func (p *Proxy) tunnel(w http.ResponseWriter, r *http.Request, target, host string) {
	upstream, err := p.dial(r.Context(), "tcp", target)
	if err != nil {
		p.log.Warn("tunnel dial failed", slog.String("host", host), slog.Any("error", err))
		http.Error(w, "tongz: cannot reach "+host, http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	client, err := hijack(w)
	if err != nil {
		p.log.Error("hijack failed", slog.Any("error", err))
		return
	}
	defer client.Close()

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	p.log.Info("tunnel",
		slog.String("host", host),
		slog.String("decision", "passthrough"),
		slog.Bool("credentialed", false))

	splice(client, upstream)
}

// splice copies in both directions until either side closes.
func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(a, b)
		closeWrite(a)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(b, a)
		closeWrite(b)
		done <- struct{}{}
	}()
	<-done
	<-done
}

type closeWriter interface{ CloseWrite() error }

func closeWrite(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

func hijack(w http.ResponseWriter) (net.Conn, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("connection cannot be hijacked")
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	// A client that pipelined data after CONNECT would have it sitting in the
	// buffer; refusing is safer than silently dropping bytes.
	if buf.Reader.Buffered() > 0 {
		conn.Close()
		return nil, fmt.Errorf("client sent data before the tunnel was established")
	}
	return conn, nil
}

func hostOf(r *http.Request) string {
	if r.URL != nil && r.URL.Host != "" {
		return config.NormalizeHost(r.URL.Host)
	}
	return config.NormalizeHost(r.Host)
}
