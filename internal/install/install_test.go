package install

import (
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

const testCA = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

func get(t *testing.T, h http.Handler, path, host string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = host
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestServeCA(t *testing.T) {
	rec := get(t, NewHandler([]byte(testCA), Options{}), "/ca.pem", "10.0.0.1:8080")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != testCA {
		t.Errorf("body = %q, want the CA verbatim", got)
	}
}

func TestSetupScriptEmbedsCAAndProxy(t *testing.T) {
	rec := get(t, NewHandler([]byte(testCA), Options{}), "/install", "10.0.0.1:8080")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, strings.TrimRight(testCA, "\n")) {
		t.Error("setup script does not contain the CA certificate")
	}
	if !strings.Contains(body, "http://10.0.0.1:8080") {
		t.Error("setup script does not point at the proxy the request arrived on")
	}
	for _, want := range []string{"NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "keytool"} {
		if !strings.Contains(body, want) {
			t.Errorf("setup script does not cover %s", want)
		}
	}
}

// The Host header ends up inside the generated shell script.
func TestSetupScriptRejectsUnsafeHost(t *testing.T) {
	rec := get(t, NewHandler([]byte(testCA), Options{}), "/install", `10.0.0.1:8080"; rm -rf /; echo "`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestSetupScriptIsValidShell(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh available")
	}
	rec := get(t, NewHandler([]byte(testCA), Options{}), "/install", "10.0.0.1:8080")
	cmd := exec.Command(sh, "-n")
	cmd.Stdin = strings.NewReader(rec.Body.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("setup script is not valid shell: %v\n%s", err, out)
	}
}

func TestSetupScriptExportsMetadataHostWhenEnabled(t *testing.T) {
	off := get(t, NewHandler([]byte(testCA), Options{}), "/install", "10.0.0.1:8080")
	if strings.Contains(off.Body.String(), "GCE_METADATA_HOST") {
		t.Error("setup script exports GCE_METADATA_HOST without a metadata rule")
	}

	on := get(t, NewHandler([]byte(testCA), Options{GCPMetadata: true}), "/install", "10.0.0.1:8080")
	if !strings.Contains(on.Body.String(), `export GCE_METADATA_HOST="10.0.0.1:8080"`) {
		t.Error("setup script does not point Google metadata clients at the proxy")
	}
}

func TestHealthz(t *testing.T) {
	rec := get(t, NewHandler([]byte(testCA), Options{}), "/healthz", "10.0.0.1:8080")
	if rec.Code != http.StatusOK || rec.Body.String() != "ok\n" {
		t.Errorf("healthz = %d %q", rec.Code, rec.Body.String())
	}
}
