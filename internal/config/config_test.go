package config

import (
	"strings"
	"testing"
	"time"
)

const minimalConfig = `
secrets:
  github/repo-scoped: env:GITHUB_TOKEN
rules:
  - match: {host: api.github.com, path: /repos/*/issues, method: [GET, POST]}
    inject: {header: Authorization, format: "Bearer {token}"}
    token: github/repo-scoped
`

func TestParseAppliesDefaults(t *testing.T) {
	cfg, err := Parse([]byte(minimalConfig))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Listen != DefaultListen {
		t.Errorf("Listen = %q, want %q", cfg.Listen, DefaultListen)
	}
	if cfg.StateDir != DefaultStateDir {
		t.Errorf("StateDir = %q, want %q", cfg.StateDir, DefaultStateDir)
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "no rules",
			yaml: "secrets: {a: env:A}\n",
			want: "no rules",
		},
		{
			name: "unknown token",
			yaml: `
secrets: {a: env:A}
rules:
  - match: {host: api.github.com}
    inject: {header: Authorization, format: "Bearer {token}"}
    token: missing
`,
			want: "not defined under secrets",
		},
		{
			name: "format without placeholder",
			yaml: `
secrets: {a: env:A}
rules:
  - match: {host: api.github.com}
    inject: {header: Authorization, format: "Bearer static"}
    token: a
`,
			want: "must contain {token}",
		},
		{
			name: "missing host",
			yaml: `
secrets: {a: env:A}
rules:
  - match: {path: /x}
    inject: {header: Authorization, format: "{token}"}
    token: a
`,
			want: "match.host is required",
		},
		{
			name: "host with port",
			yaml: `
secrets: {a: env:A}
rules:
  - match: {host: "api.github.com:443"}
    inject: {header: Authorization, format: "{token}"}
    token: a
`,
			want: "must not contain a scheme, port or path",
		},
		{
			name: "mid-label wildcard",
			yaml: `
secrets: {a: env:A}
rules:
  - match: {host: "api.*.com"}
    inject: {header: Authorization, format: "{token}"}
    token: a
`,
			want: "only a leading",
		},
		{
			name: "rule host also passed through",
			yaml: `
secrets: {a: env:A}
passthrough: [api.github.com]
rules:
  - match: {host: api.github.com}
    inject: {header: Authorization, format: "{token}"}
    token: a
`,
			want: "cannot receive an injected credential",
		},
		{
			name: "unknown field",
			yaml: `
secrets: {a: env:A}
rules:
  - match: {host: api.github.com}
    inject: {header: Authorization, format: "{token}"}
    token: a
    inject_body: true
`,
			want: "field inject_body not found",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if err == nil {
				t.Fatal("Parse succeeded, want error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestParseRejectsBadActions(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "no action",
			yaml: `
secrets: {a: env:A}
rules:
  - match: {host: api.github.com}
    token: a
`,
			want: "exactly one of inject, sign or respond",
		},
		{
			name: "two actions",
			yaml: `
secrets:
  a:
    fields: {access_key_id: env:A, secret_access_key: env:B}
rules:
  - match: {host: s3.amazonaws.com}
    inject: {header: Authorization, format: "{token}"}
    sign: {method: aws-sigv4}
    token: a
`,
			want: "exactly one of inject, sign or respond",
		},
		{
			name: "sign without the required fields",
			yaml: `
secrets: {a: env:A}
rules:
  - match: {host: s3.amazonaws.com}
    sign: {method: aws-sigv4}
    token: a
`,
			want: `needs token "a" to define the field "access_key_id"`,
		},
		{
			name: "unknown signing method",
			yaml: `
secrets:
  a:
    fields: {access_key_id: env:A, secret_access_key: env:B}
rules:
  - match: {host: s3.amazonaws.com}
    sign: {method: hmac-v1}
    token: a
`,
			want: "is not supported",
		},
		{
			name: "inject with a multi-field secret",
			yaml: `
secrets:
  a:
    fields: {access_key_id: env:A, secret_access_key: env:B}
rules:
  - match: {host: s3.amazonaws.com}
    inject: {header: Authorization, format: "{token}"}
    token: a
`,
			want: "needs a single-valued token",
		},
		{
			name: "respond naming a token",
			yaml: `
secrets: {a: env:A}
rules:
  - match: {host: metadata.google.internal}
    respond: {method: gcp-metadata, project_id: p}
    token: a
`,
			want: "must not name a token",
		},
		{
			name: "respond without a project",
			yaml: `
secrets: {a: env:A}
rules:
  - match: {host: metadata.google.internal}
    respond: {method: gcp-metadata}
`,
			want: "respond.project_id is required",
		},
		{
			name: "secret with both a value and fields",
			yaml: `
secrets:
  a:
    value: env:A
    fields: {access_key_id: env:B}
rules:
  - match: {host: api.github.com}
    inject: {header: Authorization, format: "{token}"}
    token: a
`,
			want: "not both",
		},
		{
			name: "refresh that is not a duration",
			yaml: `
secrets:
  a:
    value: env:A
    refresh: soon
rules:
  - match: {host: api.github.com}
    inject: {header: Authorization, format: "{token}"}
    token: a
`,
			want: "is not a duration",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if err == nil {
				t.Fatal("Parse succeeded, want error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestParseSecretForms(t *testing.T) {
	cfg, err := Parse([]byte(`
secrets:
  github/repo: env:GITHUB_TOKEN
  gcp/default:
    value: exec:gcloud auth print-access-token
    refresh: 30m
  aws/default:
    fields:
      access_key_id: env:AWS_ACCESS_KEY_ID
      secret_access_key: env:AWS_SECRET_ACCESS_KEY
rules:
  - match: {host: api.github.com}
    inject: {header: Authorization, format: "Bearer {token}"}
    token: github/repo
  - match: {host: "*.amazonaws.com"}
    sign: {method: aws-sigv4}
    token: aws/default
  - match: {host: metadata.google.internal}
    respond: {method: gcp-metadata, project_id: agent-sandbox}
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if got := cfg.Secrets["github/repo"].Value; got != "env:GITHUB_TOKEN" {
		t.Errorf("scalar secret = %q, want the shorthand expanded to a value", got)
	}
	if got := cfg.Secrets["gcp/default"].Refresh.Duration(); got != 30*time.Minute {
		t.Errorf("refresh = %v, want 30m", got)
	}
	if got := cfg.Secrets["aws/default"].Fields["access_key_id"]; got != "env:AWS_ACCESS_KEY_ID" {
		t.Errorf("field = %q", got)
	}

	wantActions := []string{"inject", "sign:aws-sigv4", "respond:gcp-metadata"}
	for i, want := range wantActions {
		if got := cfg.Rules[i].Describe(); got != want {
			t.Errorf("rules[%d].Describe() = %q, want %q", i, got, want)
		}
	}
}

func TestParseUppercasesMethods(t *testing.T) {
	cfg, err := Parse([]byte(`
secrets: {a: env:A}
rules:
  - match: {host: api.github.com, method: [get, Post]}
    inject: {header: Authorization, format: "{token}"}
    token: a
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := cfg.Rules[0].Match.Method
	if len(got) != 2 || got[0] != "GET" || got[1] != "POST" {
		t.Errorf("Method = %v, want [GET POST]", got)
	}
}
