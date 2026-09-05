// Package secrets resolves credential references into an in-memory store.
//
// Resolution happens once at startup so that no lookup sits on the request
// path: a proxy slow enough to notice is a proxy people work around by writing
// a .env file, which is exactly what Tongz exists to prevent.
package secrets

import (
	"fmt"
	"os"
	"strings"
)

// Store holds resolved credentials keyed by their configured identifier. Only
// the identifier is ever logged; the value stays here.
type Store struct {
	values map[string]string
}

// Resolve reads every reference in refs. A reference that cannot be resolved is
// an error rather than an empty credential, so a misconfigured deployment fails
// at startup instead of sending unauthenticated requests upstream.
func Resolve(refs map[string]string) (*Store, error) {
	s := &Store{values: make(map[string]string, len(refs))}
	for id, ref := range refs {
		v, err := ResolveRef(ref)
		if err != nil {
			return nil, fmt.Errorf("secret %q: %w", id, err)
		}
		s.values[id] = v
	}
	return s, nil
}

// Get returns the credential stored under id.
func (s *Store) Get(id string) (string, bool) {
	v, ok := s.values[id]
	return v, ok
}

// IDs returns the configured identifiers. Safe to log.
func (s *Store) IDs() []string {
	ids := make([]string, 0, len(s.values))
	for id := range s.values {
		ids = append(ids, id)
	}
	return ids
}

// ResolveRef reads a single reference of the form "scheme:value".
//
//	env:GITHUB_TOKEN      the host process environment
//	file:/run/secrets/gh  a file on the host, trailing newline trimmed
func ResolveRef(ref string) (string, error) {
	scheme, value, ok := strings.Cut(ref, ":")
	if !ok {
		return "", fmt.Errorf("reference %q: want scheme:value, for example env:GITHUB_TOKEN", ref)
	}
	switch scheme {
	case "env":
		v, ok := os.LookupEnv(value)
		if !ok {
			return "", fmt.Errorf("environment variable %s is not set", value)
		}
		if v == "" {
			return "", fmt.Errorf("environment variable %s is empty", value)
		}
		return v, nil
	case "file":
		b, err := os.ReadFile(value)
		if err != nil {
			return "", err
		}
		v := strings.TrimRight(string(b), "\r\n")
		if v == "" {
			return "", fmt.Errorf("file %s is empty", value)
		}
		return v, nil
	default:
		return "", fmt.Errorf("reference %q: unknown scheme %q", ref, scheme)
	}
}
