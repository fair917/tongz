package config

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"strings"
)

// HostPattern is an exact hostname or a wildcard of the form "*.example.com".
// The wildcard covers any number of leading labels, so "*.googleapis.com"
// matches both "storage.googleapis.com" and "a.b.googleapis.com" but not the
// bare "googleapis.com".
type HostPattern string

func (h HostPattern) normalized() HostPattern {
	s := strings.ToLower(strings.TrimSpace(string(h)))
	return HostPattern(strings.TrimSuffix(s, "."))
}

func (h HostPattern) validate() error {
	s := string(h)
	if rest, ok := strings.CutPrefix(s, "*."); ok {
		s = rest
	}
	if s == "" || strings.Contains(s, "*") {
		return fmt.Errorf("host %q: only a leading %q wildcard is supported", string(h), "*.")
	}
	if strings.ContainsAny(s, "/:") {
		return fmt.Errorf("host %q: must not contain a scheme, port or path", string(h))
	}
	return nil
}

// Matches reports whether host, which may carry a port, is covered by h.
func (h HostPattern) Matches(host string) bool {
	host = NormalizeHost(host)
	pattern := string(h.normalized())
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		return strings.HasSuffix(host, "."+suffix)
	}
	return host == pattern
}

// NormalizeHost strips any port and trailing dot and lowercases the result, so
// that "API.GitHub.com:443" and "api.github.com" compare equal.
func NormalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(host, ".")
}

// Matches reports whether the request is selected by m. rawPath is the escaped
// path as it appeared on the wire.
func (m Match) Matches(host, method, rawPath string) bool {
	if !m.Host.Matches(host) {
		return false
	}
	if !m.matchesMethod(method) {
		return false
	}
	return matchPath(m.Path, rawPath)
}

func (m Match) matchesMethod(method string) bool {
	if len(m.Method) == 0 {
		return true
	}
	method = strings.ToUpper(method)
	for _, allowed := range m.Method {
		if allowed == method {
			return true
		}
	}
	return false
}

// matchPath applies a segment-aware glob: "*" matches within a single path
// segment and "**" matches any number of segments. An empty pattern matches
// every path.
func matchPath(pattern, rawPath string) bool {
	if pattern == "" {
		return true
	}
	clean, ok := normalizePath(rawPath)
	if !ok {
		return false
	}
	return matchSegments(splitPath(pattern), splitPath(clean))
}

// normalizePath decodes rawPath for matching. It refuses paths that could be
// read one way here and another way upstream: an encoded separator or a dot
// segment would let "/repos/x%2F..%2Fadmin" satisfy a rule written for
// "/repos/*/issues" while the server resolves it elsewhere. Such a path simply
// matches nothing, so the request is denied rather than credentialed.
func normalizePath(rawPath string) (string, bool) {
	lower := strings.ToLower(rawPath)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return "", false
	}
	decoded, err := url.PathUnescape(rawPath)
	if err != nil {
		return "", false
	}
	for _, seg := range splitPath(decoded) {
		if seg == "." || seg == ".." {
			return "", false
		}
	}
	return decoded, true
}

func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func matchSegments(pattern, segs []string) bool {
	if len(pattern) == 0 {
		return len(segs) == 0
	}
	if pattern[0] == "**" {
		for i := 0; i <= len(segs); i++ {
			if matchSegments(pattern[1:], segs[i:]) {
				return true
			}
		}
		return false
	}
	if len(segs) == 0 {
		return false
	}
	if ok, err := path.Match(pattern[0], segs[0]); err != nil || !ok {
		return false
	}
	return matchSegments(pattern[1:], segs[1:])
}

// Find returns the first rule matching the request. Rules are evaluated in the
// order they appear in the file.
func (c *Config) Find(host, method, rawPath string) (*Rule, bool) {
	if c.IsPassthrough(host) {
		return nil, false
	}
	for i := range c.Rules {
		if c.Rules[i].Match.Matches(host, method, rawPath) {
			return &c.Rules[i], true
		}
	}
	return nil, false
}

// Intercepts reports whether connections to host should be decrypted. Only
// hosts named by a rule are, which keeps TLS breakage confined to what the
// operator explicitly configured.
func (c *Config) Intercepts(host string) bool {
	if c.IsPassthrough(host) {
		return false
	}
	for _, r := range c.Rules {
		if r.Match.Host.Matches(host) {
			return true
		}
	}
	return false
}

// IsPassthrough reports whether host is tunnelled without decryption.
func (c *Config) IsPassthrough(host string) bool {
	for _, p := range c.Passthrough {
		if p.Matches(host) {
			return true
		}
	}
	return false
}
