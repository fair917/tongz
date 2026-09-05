// Package secrets resolves credential references into an in-memory store.
//
// Resolution happens at startup, and refreshes happen in the background, so
// that no lookup sits on the request path: a proxy slow enough to notice is a
// proxy people work around by writing a .env file, which is exactly what Tongz
// exists to prevent.
package secrets

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fair917/tongz/internal/config"
)

// execTimeout bounds a credential helper such as `gcloud auth print-access-token`.
const execTimeout = 30 * time.Second

// Credential is one resolved credential: either a single value, or a set of
// named fields for schemes that need more than one, such as AWS SigV4.
type Credential struct {
	value  string
	fields map[string]string
}

// Value returns the single-valued form.
func (c Credential) Value() string { return c.value }

// Field returns one named field.
func (c Credential) Field(name string) string { return c.fields[name] }

// Store holds resolved credentials keyed by their configured identifier. Only
// the identifier is ever logged; the values stay here.
type Store struct {
	specs map[string]config.Secret

	mu    sync.RWMutex
	creds map[string]Credential
}

// Resolve reads every reference in specs. A reference that cannot be resolved
// is an error rather than an empty credential, so a misconfigured deployment
// fails at startup instead of sending unauthenticated requests upstream.
func Resolve(specs map[string]config.Secret) (*Store, error) {
	s := &Store{
		specs: maps.Clone(specs),
		creds: make(map[string]Credential, len(specs)),
	}
	for id := range specs {
		cred, err := resolveSecret(specs[id])
		if err != nil {
			return nil, fmt.Errorf("secret %q: %w", id, err)
		}
		s.creds[id] = cred
	}
	return s, nil
}

// Get returns the credential stored under id.
func (s *Store) Get(id string) (Credential, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cred, ok := s.creds[id]
	return cred, ok
}

// IDs returns the configured identifiers, sorted. Safe to log.
func (s *Store) IDs() []string {
	ids := make([]string, 0, len(s.specs))
	for id := range s.specs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// StartRefresh re-reads the secrets that declare an interval until ctx ends.
// A refresh that fails keeps the previous value: a transient failure in a
// credential helper should not take the proxy down with it.
func (s *Store) StartRefresh(ctx context.Context, log *slog.Logger) {
	for id, spec := range s.specs {
		interval := spec.Refresh.Duration()
		if interval <= 0 {
			continue
		}
		go func(id string, spec config.Secret, interval time.Duration) {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					cred, err := resolveSecret(spec)
					if err != nil {
						log.Warn("credential refresh failed; keeping the previous value",
							slog.String("token", id), slog.Any("error", err))
						continue
					}
					s.mu.Lock()
					s.creds[id] = cred
					s.mu.Unlock()
					log.Info("credential refreshed", slog.String("token", id))
				}
			}
		}(id, spec, interval)
	}
}

func resolveSecret(spec config.Secret) (Credential, error) {
	if spec.Value != "" {
		v, err := ResolveRef(spec.Value)
		return Credential{value: v}, err
	}
	fields := make(map[string]string, len(spec.Fields))
	for name, ref := range spec.Fields {
		v, err := ResolveRef(ref)
		if err != nil {
			return Credential{}, fmt.Errorf("field %q: %w", name, err)
		}
		fields[name] = v
	}
	return Credential{fields: fields}, nil
}

// ResolveRef reads a single reference of the form "scheme:value".
//
//	env:GITHUB_TOKEN                     the host process environment
//	file:/run/secrets/gh                 a file on the host
//	exec:gcloud auth print-access-token  standard output of a host command
//
// An exec reference runs through the shell on the host, with the operator's own
// privileges. It is configuration written by the person running the proxy, not
// anything the container can influence.
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
		return trimmed(string(b), fmt.Sprintf("file %s", value))
	case "exec":
		return runCommand(value)
	default:
		return "", fmt.Errorf("reference %q: unknown scheme %q", ref, scheme)
	}
}

func runCommand(command string) (string, error) {
	if strings.TrimSpace(command) == "" {
		return "", fmt.Errorf("exec reference has no command")
	}
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return "", fmt.Errorf("command %q failed: %w: %s", command, err, msg)
		}
		return "", fmt.Errorf("command %q failed: %w", command, err)
	}
	return trimmed(string(out), fmt.Sprintf("command %q", command))
}

func trimmed(s, what string) (string, error) {
	v := strings.TrimRight(s, "\r\n")
	if v == "" {
		return "", fmt.Errorf("%s produced nothing", what)
	}
	return v, nil
}
