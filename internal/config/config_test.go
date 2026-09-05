package config

import (
	"strings"
	"testing"
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
