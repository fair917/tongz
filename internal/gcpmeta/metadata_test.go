package gcpmeta

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fair917/tongz/internal/config"
)

var cfg = &config.Respond{
	Method:           config.RespondGCPMeta,
	ProjectID:        "agent-sandbox",
	NumericProjectID: "123456789",
	ServiceAccount:   "agent@agent-sandbox.iam.gserviceaccount.com",
}

func ask(t *testing.T, path string, flavor bool) (*http.Response, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://metadata.google.internal"+path, nil)
	if flavor {
		req.Header.Set("Metadata-Flavor", "Google")
	}
	resp := Respond(req, cfg)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body)
}

func TestRootProbeAnswersWithoutHeader(t *testing.T) {
	resp, body := ask(t, "/", false)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if resp.Header.Get("Metadata-Flavor") != "Google" {
		t.Error("response does not identify itself as a metadata server")
	}
	if !strings.Contains(body, "computeMetadata") {
		t.Errorf("body = %q", body)
	}
}

// The real server refuses requests without the header, and libraries rely on
// that to tell a metadata server from an unrelated HTTP server.
func TestMetadataFlavorRequired(t *testing.T) {
	resp, _ := ask(t, "/computeMetadata/v1/project/project-id", false)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestTokenIsAPlaceholder(t *testing.T) {
	resp, body := ask(t, "/computeMetadata/v1/instance/service-accounts/default/token", true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var payload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, body)
	}
	if payload.AccessToken != PlaceholderToken {
		t.Errorf("access_token = %q, want the placeholder", payload.AccessToken)
	}
	if payload.TokenType != "Bearer" || payload.ExpiresIn <= 0 {
		t.Errorf("token_type = %q, expires_in = %d", payload.TokenType, payload.ExpiresIn)
	}
}

func TestProjectAndAccountFields(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/computeMetadata/v1/project/project-id", "agent-sandbox"},
		{"/computeMetadata/v1/project/numeric-project-id", "123456789"},
		{"/computeMetadata/v1/instance/service-accounts/default/email", cfg.ServiceAccount},
		{"/computeMetadata/v1/instance/service-accounts/default/scopes", DefaultScope},
		{"/computeMetadata/v1/instance/zone", "projects/123456789/zones/us-central1-a"},
	}
	for _, tc := range tests {
		resp, body := ask(t, tc.path, true)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", tc.path, resp.StatusCode)
			continue
		}
		if strings.TrimSpace(body) != tc.want {
			t.Errorf("%s = %q, want %q", tc.path, strings.TrimSpace(body), tc.want)
		}
	}
}

// The email alias and the "default" alias name the same account.
func TestServiceAccountByEmail(t *testing.T) {
	resp, body := ask(t, "/computeMetadata/v1/instance/service-accounts/"+cfg.ServiceAccount+"/token", true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, PlaceholderToken) {
		t.Errorf("body = %q, want the placeholder token", body)
	}
}

func TestUnknownAccountAndPath(t *testing.T) {
	for _, path := range []string{
		"/computeMetadata/v1/instance/service-accounts/someone-else/token",
		"/computeMetadata/v1/instance/disks",
		"/latest/meta-data/",
	} {
		resp, _ := ask(t, path, true)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", path, resp.StatusCode)
		}
	}
}

// An ID token is a signed assertion with nothing to substitute later, so the
// responder says so instead of handing back something that cannot work.
func TestIdentityIsRefusedWithAReason(t *testing.T) {
	resp, body := ask(t, "/computeMetadata/v1/instance/service-accounts/default/identity", true)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	if !strings.Contains(body, "not brokered") {
		t.Errorf("body = %q, want an explanation", body)
	}
}

func TestServiceAccountDefaultsFromProject(t *testing.T) {
	bare := &config.Respond{Method: config.RespondGCPMeta, ProjectID: "p"}
	req := httptest.NewRequest(http.MethodGet, "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email", nil)
	req.Header.Set("Metadata-Flavor", "Google")
	resp := Respond(req, bare)
	body, _ := io.ReadAll(resp.Body)
	if want := "tongz-agent@p.iam.gserviceaccount.com"; string(body) != want {
		t.Errorf("email = %q, want %q", body, want)
	}
}
