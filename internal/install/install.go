// Package install serves the CA certificate and the container-side setup
// script.
//
// The proxy distributes its own CA over plain HTTP on the same listener. There
// is no chicken-and-egg problem: the container has no trust to establish before
// it can ask the proxy for the thing it needs to trust it.
package install

import (
	"bytes"
	_ "embed"
	"fmt"
	"net/http"
	"strings"
	"text/template"
)

//go:embed setup.sh.tmpl
var setupTemplate string

var setup = template.Must(template.New("setup.sh").Parse(setupTemplate))

// Handler serves the install endpoints.
type Handler struct {
	caPEM []byte
	mux   *http.ServeMux
}

// NewHandler builds the handler around the CA certificate to distribute.
func NewHandler(caPEM []byte) *Handler {
	h := &Handler{caPEM: bytes.TrimRight(caPEM, "\n"), mux: http.NewServeMux()}
	h.mux.HandleFunc("GET /install", h.serveSetup)
	h.mux.HandleFunc("GET /ca.pem", h.serveCA)
	h.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	h.mux.HandleFunc("GET /{$}", h.serveIndex)
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) serveCA(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(append(h.caPEM, '\n'))
}

func (h *Handler) serveSetup(w http.ResponseWriter, r *http.Request) {
	proxyURL, err := proxyURLFor(r.Host)
	if err != nil {
		http.Error(w, "tongz: "+err.Error(), http.StatusBadRequest)
		return
	}
	var buf bytes.Buffer
	if err := setup.Execute(&buf, struct{ CAPEM, ProxyURL string }{
		CAPEM:    string(h.caPEM),
		ProxyURL: proxyURL,
	}); err != nil {
		http.Error(w, "tongz: cannot render setup script", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

func (h *Handler) serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "tongz\n\n"+
		"  curl -fsSL http://%s/install | sh   install the CA and proxy environment\n"+
		"  curl -fsSL http://%s/ca.pem         the CA certificate alone\n",
		r.Host, r.Host)
}

// proxyURLFor turns the Host the container reached us on into the proxy URL to
// write into its environment. The value lands inside a shell script, so it is
// validated rather than trusted.
func proxyURLFor(host string) (string, error) {
	if host == "" {
		return "", fmt.Errorf("request has no Host header")
	}
	if strings.ContainsFunc(host, func(r rune) bool {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return false
		case r == '.' || r == '-' || r == ':' || r == '[' || r == ']':
			return false
		default:
			return true
		}
	}) {
		return "", fmt.Errorf("Host %q contains characters that are not valid in an authority", host)
	}
	return "http://" + host, nil
}
