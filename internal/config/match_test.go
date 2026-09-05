package config

import "testing"

func TestHostPatternMatches(t *testing.T) {
	tests := []struct {
		pattern HostPattern
		host    string
		want    bool
	}{
		{"api.github.com", "api.github.com", true},
		{"api.github.com", "API.GitHub.com", true},
		{"api.github.com", "api.github.com:443", true},
		{"api.github.com", "api.github.com.", true},
		{"api.github.com", "evil-api.github.com", false},
		{"api.github.com", "api.github.com.evil.test", false},
		{"*.googleapis.com", "storage.googleapis.com", true},
		{"*.googleapis.com", "a.b.googleapis.com", true},
		{"*.googleapis.com", "googleapis.com", false},
		{"*.googleapis.com", "evilgoogleapis.com", false},
	}
	for _, tc := range tests {
		if got := tc.pattern.Matches(tc.host); got != tc.want {
			t.Errorf("%q.Matches(%q) = %v, want %v", tc.pattern, tc.host, got, tc.want)
		}
	}
}

func TestMatchPath(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"", "/anything/at/all", true},
		{"/repos/*/issues", "/repos/fair917/issues", true},
		{"/repos/*/issues", "/repos/fair917/tongz/issues", false},
		{"/repos/*/issues", "/repos/fair917/issues/1", false},
		{"/repos/**", "/repos/fair917/tongz/issues", true},
		{"/repos/**", "/repos", true},
		{"/repos/**", "/orgs/fair917", false},
		{"/v1/chat*", "/v1/chatgpt", true},
		{"/v1/chat*", "/v1/chat/completions", false},
		{"/", "/", true},
		{"/**", "/", true},
		// An encoded separator would be one path here and another upstream.
		{"/repos/*/issues", "/repos/a%2F..%2Fadmin/issues", false},
		{"/repos/*/issues", "/repos/../admin/issues", false},
		// Percent-encoding that is not a separator still matches.
		{"/repos/*/issues", "/repos/my%20repo/issues", true},
	}
	for _, tc := range tests {
		if got := matchPath(tc.pattern, tc.path); got != tc.want {
			t.Errorf("matchPath(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

func TestFindFirstRuleWins(t *testing.T) {
	cfg, err := Parse([]byte(`
secrets:
  narrow: env:NARROW
  broad: env:BROAD
rules:
  - match: {host: api.github.com, path: /repos/*/issues, method: [GET]}
    inject: {header: Authorization, format: "Bearer {token}"}
    token: narrow
  - match: {host: api.github.com}
    inject: {header: Authorization, format: "Bearer {token}"}
    token: broad
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	r, ok := cfg.Find("api.github.com", "GET", "/repos/fair917/issues")
	if !ok || r.Token != "narrow" {
		t.Errorf("Find(issues) = %v, %v; want the narrow rule", r, ok)
	}
	r, ok = cfg.Find("api.github.com", "DELETE", "/user")
	if !ok || r.Token != "broad" {
		t.Errorf("Find(/user) = %v, %v; want the broad rule", r, ok)
	}
	if _, ok := cfg.Find("api.example.com", "GET", "/"); ok {
		t.Error("Find on an unconfigured host returned a rule")
	}
}

func TestInterceptsAndPassthrough(t *testing.T) {
	cfg, err := Parse([]byte(`
secrets: {a: env:A}
passthrough: ["*.google.com"]
rules:
  - match: {host: "*.googleapis.com"}
    inject: {header: Authorization, format: "Bearer {token}"}
    token: a
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !cfg.Intercepts("storage.googleapis.com") {
		t.Error("Intercepts(storage.googleapis.com) = false, want true")
	}
	if cfg.Intercepts("example.com") {
		t.Error("Intercepts(example.com) = true, want false")
	}
	if cfg.Intercepts("accounts.google.com") {
		t.Error("Intercepts on a passthrough host = true, want false")
	}
}

// A passthrough host must never receive a credential even if a wildcard rule
// covers it, since validation only rejects exact overlaps.
func TestFindSkipsPassthroughHost(t *testing.T) {
	cfg, err := Parse([]byte(`
secrets: {a: env:A}
passthrough: [pinned.example.com]
rules:
  - match: {host: "*.example.com"}
    inject: {header: Authorization, format: "Bearer {token}"}
    token: a
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, ok := cfg.Find("pinned.example.com", "GET", "/"); ok {
		t.Error("Find matched a passthrough host")
	}
	if _, ok := cfg.Find("api.example.com", "GET", "/"); !ok {
		t.Error("Find did not match the wildcard rule")
	}
}
