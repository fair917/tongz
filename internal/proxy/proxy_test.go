package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/fair917/tongz/internal/ca"
	"github.com/fair917/tongz/internal/config"
	"github.com/fair917/tongz/internal/secrets"
)

// upstream is a TLS server presenting a certificate for host, signed by a CA
// that has nothing to do with the tongz CA. Requests it receives are recorded.
type upstream struct {
	server *httptest.Server
	pool   *x509.CertPool
	last   atomic.Pointer[http.Request]
}

func newUpstream(t *testing.T, host string) *upstream {
	t.Helper()
	authority, err := ca.Load(t.TempDir())
	if err != nil {
		t.Fatalf("upstream CA: %v", err)
	}
	leaf, err := authority.Leaf(host)
	if err != nil {
		t.Fatalf("upstream leaf: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(authority.CertPEM()) {
		t.Fatal("upstream CA did not parse")
	}

	u := &upstream{pool: pool}
	u.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.last.Store(r.Clone(context.Background()))
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "upstream ok")
	}))
	u.server.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}}
	u.server.StartTLS()
	t.Cleanup(u.server.Close)
	return u
}

func (u *upstream) header(name string) string {
	r := u.last.Load()
	if r == nil {
		return ""
	}
	return r.Header.Get(name)
}

// harness wires a proxy in front of an upstream, with every dial redirected to
// it so that tests can use realistic hostnames.
type harness struct {
	proxy    *Proxy
	server   *httptest.Server
	tongzCA  *x509.CertPool
	upstream *upstream
}

func newHarness(t *testing.T, cfgYAML, upstreamHost string, auth string) *harness {
	t.Helper()
	cfg, err := config.Parse([]byte(cfgYAML))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	store, err := secrets.Resolve(cfg.Secrets)
	if err != nil {
		t.Fatalf("secrets: %v", err)
	}
	authority, err := ca.Load(t.TempDir())
	if err != nil {
		t.Fatalf("tongz CA: %v", err)
	}
	up := newUpstream(t, upstreamHost)

	p := New(Options{
		Config:  cfg,
		CA:      authority,
		Secrets: store,
		Auth:    auth,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	addr := up.server.Listener.Addr().String()
	p.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	p.upstrm.TLSClientConfig.RootCAs = up.pool

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(authority.CertPEM()) {
		t.Fatal("tongz CA did not parse")
	}

	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	return &harness{proxy: p, server: srv, tongzCA: pool, upstream: up}
}

// client returns an HTTP client that goes through the proxy and trusts roots.
func (h *harness) client(t *testing.T, roots *x509.CertPool, auth string) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse(h.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		TLSClientConfig:   &tls.Config{RootCAs: roots},
		ForceAttemptHTTP2: false,
	}
	if auth != "" {
		tr.ProxyConnectHeader = http.Header{"Proxy-Authorization": []string{"Bearer " + auth}}
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr}
}

const githubConfig = `
secrets:
  github/issues: env:TONGZ_TEST_GH
rules:
  - match: {host: api.example.test, path: /repos/*/issues, method: [GET, POST]}
    inject: {header: Authorization, format: "Bearer {token}"}
    token: github/issues
`

func TestInjectsCredentialOnMatch(t *testing.T) {
	t.Setenv("TONGZ_TEST_GH", "s3cret-token")
	h := newHarness(t, githubConfig, "api.example.test", "")

	resp, err := h.client(t, h.tongzCA, "").Get("https://api.example.test/repos/fair917/issues")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if got := h.upstream.header("Authorization"); got != "Bearer s3cret-token" {
		t.Errorf("upstream saw Authorization = %q, want the injected credential", got)
	}
}

// The agent must not be able to smuggle its own credential past the broker.
func TestReplacesClientSuppliedCredential(t *testing.T) {
	t.Setenv("TONGZ_TEST_GH", "s3cret-token")
	h := newHarness(t, githubConfig, "api.example.test", "")

	req, err := http.NewRequest(http.MethodGet, "https://api.example.test/repos/fair917/issues", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer agent-supplied")
	resp, err := h.client(t, h.tongzCA, "").Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if got := h.upstream.header("Authorization"); got != "Bearer s3cret-token" {
		t.Errorf("upstream saw Authorization = %q, want it replaced", got)
	}
}

func TestDeniesRequestMatchingNoRule(t *testing.T) {
	t.Setenv("TONGZ_TEST_GH", "s3cret-token")
	h := newHarness(t, githubConfig, "api.example.test", "")
	client := h.client(t, h.tongzCA, "")

	for _, target := range []string{
		"https://api.example.test/user/keys",               // path outside the rule
		"https://api.example.test/repos/fair917/issues/1",  // deeper than the rule
		"https://api.example.test/repos/a%2F..%2Fb/issues", // encoded separator
	} {
		resp, err := client.Get(target)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", target, resp.StatusCode)
		}
		if !strings.Contains(string(body), "no rule matches") {
			t.Errorf("%s: body = %q, want an explanation", target, body)
		}
	}
	if h.upstream.last.Load() != nil {
		t.Error("a denied request reached the upstream")
	}
}

func TestDeniesMethodOutsideRule(t *testing.T) {
	t.Setenv("TONGZ_TEST_GH", "s3cret-token")
	h := newHarness(t, githubConfig, "api.example.test", "")

	req, err := http.NewRequest(http.MethodDelete, "https://api.example.test/repos/fair917/issues", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := h.client(t, h.tongzCA, "").Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

// An unconfigured host is tunnelled: the client sees the real certificate and
// no credential is added.
func TestTunnelsUnconfiguredHost(t *testing.T) {
	t.Setenv("TONGZ_TEST_GH", "s3cret-token")
	h := newHarness(t, githubConfig, "other.example.test", "")

	resp, err := h.client(t, h.upstream.pool, "").Get("https://other.example.test/anything")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := h.upstream.header("Authorization"); got != "" {
		t.Errorf("tunnelled request carried Authorization = %q, want none", got)
	}
}

func TestProxyAuthorizationRequired(t *testing.T) {
	t.Setenv("TONGZ_TEST_GH", "s3cret-token")
	h := newHarness(t, githubConfig, "api.example.test", "proxy-secret")

	if _, err := h.client(t, h.tongzCA, "").Get("https://api.example.test/repos/fair917/issues"); err == nil {
		t.Error("request without the proxy secret succeeded, want it refused")
	}

	resp, err := h.client(t, h.tongzCA, "proxy-secret").Get("https://api.example.test/repos/fair917/issues")
	if err != nil {
		t.Fatalf("request with the proxy secret: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// The proxy secret authorizes use of the proxy and must not reach the upstream.
func TestProxyAuthorizationNotForwarded(t *testing.T) {
	t.Setenv("TONGZ_TEST_GH", "s3cret-token")
	h := newHarness(t, githubConfig, "api.example.test", "proxy-secret")

	resp, err := h.client(t, h.tongzCA, "proxy-secret").Get("https://api.example.test/repos/fair917/issues")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if got := h.upstream.header("Proxy-Authorization"); got != "" {
		t.Errorf("upstream saw Proxy-Authorization = %q, want none", got)
	}
}

func TestKeepAliveServesSecondRequest(t *testing.T) {
	t.Setenv("TONGZ_TEST_GH", "s3cret-token")
	h := newHarness(t, githubConfig, "api.example.test", "")
	client := h.client(t, h.tongzCA, "")

	for i := 0; i < 2; i++ {
		resp, err := client.Get("https://api.example.test/repos/fair917/issues")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d", i, resp.StatusCode)
		}
	}
}

func TestInstallEndpointServedOnProxyPort(t *testing.T) {
	t.Setenv("TONGZ_TEST_GH", "s3cret-token")
	h := newHarness(t, githubConfig, "api.example.test", "")
	h.proxy.local = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "local handler")
	})

	resp, err := http.Get(h.server.URL + "/ca.pem")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "local handler" {
		t.Errorf("body = %q, want the local handler to serve origin-form requests", body)
	}
}
