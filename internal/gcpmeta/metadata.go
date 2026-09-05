// Package gcpmeta answers GCP metadata-server requests from the proxy itself.
//
// Google client libraries refuse to build a request when they cannot find
// ambient credentials, so they are given some: a placeholder token that is
// worthless everywhere. The real token is attached later, when the request to
// googleapis.com passes back through the proxy. Handing the container a working
// token here would be the one thing Tongz exists to avoid.
package gcpmeta

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/fair917/tongz/internal/config"
)

// PlaceholderToken is what the metadata server hands out. It is deliberately
// recognizable: seeing it in an upstream error means a request reached a
// service without passing through an injection rule.
const PlaceholderToken = "tongz-placeholder-token-not-a-credential"

// DefaultScope is what a metadata-issued token normally carries.
const DefaultScope = "https://www.googleapis.com/auth/cloud-platform"

// Hosts are the names client libraries use to reach the metadata server.
var Hosts = []string{"metadata.google.internal", "metadata", "169.254.169.254"}

// Respond answers req without contacting anything.
func Respond(req *http.Request, cfg *config.Respond) *http.Response {
	path := strings.TrimSuffix(req.URL.Path, "/")

	// The root probe is how libraries detect that a metadata server exists.
	if path == "" {
		return text(req, http.StatusOK, "computeMetadata/\n")
	}

	// Every real metadata request carries this header, and the real server
	// rejects requests without it. Matching that keeps a library's own
	// detection logic honest.
	if req.Header.Get("Metadata-Flavor") != "Google" {
		return text(req, http.StatusForbidden,
			"tongz: metadata requests must carry Metadata-Flavor: Google\n")
	}

	rest, ok := strings.CutPrefix(path, "/computeMetadata/v1")
	if !ok {
		return text(req, http.StatusNotFound, "tongz: unknown metadata path\n")
	}

	switch rest {
	case "":
		return text(req, http.StatusOK, "instance/\nproject/\n")

	case "/project/project-id":
		return text(req, http.StatusOK, cfg.ProjectID)
	case "/project/numeric-project-id":
		return text(req, http.StatusOK, numericProjectID(cfg))

	case "/instance/zone":
		return text(req, http.StatusOK, fmt.Sprintf("projects/%s/zones/%s", numericProjectID(cfg), zone(cfg)))

	case "/instance/service-accounts":
		return text(req, http.StatusOK, "default/\n"+serviceAccount(cfg)+"/\n")
	}

	account, field, ok := accountField(rest)
	if !ok {
		return text(req, http.StatusNotFound, "tongz: unknown metadata path\n")
	}
	if account != "default" && account != serviceAccount(cfg) {
		return text(req, http.StatusNotFound, "tongz: unknown service account\n")
	}

	switch field {
	case "":
		return text(req, http.StatusOK, "aliases\nemail\nscopes\ntoken\n")
	case "aliases":
		return text(req, http.StatusOK, "default\n")
	case "email":
		return text(req, http.StatusOK, serviceAccount(cfg))
	case "scopes":
		return text(req, http.StatusOK, DefaultScope+"\n")
	case "token":
		return jsonResponse(req, http.StatusOK, map[string]any{
			"access_token": PlaceholderToken,
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	case "identity":
		// An ID token is a signed assertion. There is nothing to substitute it
		// with later, so saying so beats handing back something malformed.
		return text(req, http.StatusNotFound,
			"tongz: identity tokens are not brokered; the proxy replaces access tokens, not signed assertions\n")
	default:
		return text(req, http.StatusNotFound, "tongz: unknown metadata path\n")
	}
}

// accountField splits "/instance/service-accounts/<account>/<field>".
func accountField(rest string) (account, field string, ok bool) {
	tail, ok := strings.CutPrefix(rest, "/instance/service-accounts/")
	if !ok {
		return "", "", false
	}
	account, field, _ = strings.Cut(tail, "/")
	return account, field, account != ""
}

func serviceAccount(cfg *config.Respond) string {
	if cfg.ServiceAccount != "" {
		return cfg.ServiceAccount
	}
	return "tongz-agent@" + cfg.ProjectID + ".iam.gserviceaccount.com"
}

func numericProjectID(cfg *config.Respond) string {
	if cfg.NumericProjectID != "" {
		return cfg.NumericProjectID
	}
	return "0"
}

func zone(cfg *config.Respond) string {
	if cfg.Zone != "" {
		return cfg.Zone
	}
	return "us-central1-a"
}

func text(req *http.Request, status int, body string) *http.Response {
	return response(req, status, "text/plain; charset=utf-8", body)
}

func jsonResponse(req *http.Request, status int, payload map[string]any) *http.Response {
	body, err := json.Marshal(payload)
	if err != nil {
		return text(req, http.StatusInternalServerError, "tongz: cannot encode metadata response\n")
	}
	return response(req, status, "application/json", string(body))
}

func response(req *http.Request, status int, contentType, body string) *http.Response {
	return &http.Response{
		Status:     http.StatusText(status),
		StatusCode: status,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Content-Type":    []string{contentType},
			"Metadata-Flavor": []string{"Google"},
			"Server":          []string{"tongz"},
		},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}
