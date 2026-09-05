package secrets

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fair917/tongz/internal/config"
)

func TestResolveRefEnv(t *testing.T) {
	t.Setenv("TONGZ_TEST_TOKEN", "ghp_example")
	got, err := ResolveRef("env:TONGZ_TEST_TOKEN")
	if err != nil {
		t.Fatalf("ResolveRef: %v", err)
	}
	if got != "ghp_example" {
		t.Errorf("got %q, want %q", got, "ghp_example")
	}
}

func TestResolveRefFileTrimsNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("ghp_example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveRef("file:" + path)
	if err != nil {
		t.Fatalf("ResolveRef: %v", err)
	}
	if got != "ghp_example" {
		t.Errorf("got %q, want %q", got, "ghp_example")
	}
}

func TestResolveRefErrors(t *testing.T) {
	t.Setenv("TONGZ_TEST_EMPTY", "")
	tests := []struct {
		ref  string
		want string
	}{
		{"GITHUB_TOKEN", "want scheme:value"},
		{"vault:secret/gh", "unknown scheme"},
		{"env:TONGZ_TEST_UNSET", "is not set"},
		{"env:TONGZ_TEST_EMPTY", "is empty"},
		{"file:/nonexistent/tongz/token", "no such file"},
	}
	for _, tc := range tests {
		_, err := ResolveRef(tc.ref)
		if err == nil {
			t.Errorf("ResolveRef(%q) succeeded, want error", tc.ref)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ResolveRef(%q) = %v, want it to contain %q", tc.ref, err, tc.want)
		}
	}
}

func TestResolveFailsOnAnyMissingSecret(t *testing.T) {
	t.Setenv("TONGZ_TEST_TOKEN", "ghp_example")
	_, err := Resolve(map[string]config.Secret{
		"github/repo": {Value: "env:TONGZ_TEST_TOKEN"},
		"openai/main": {Value: "env:TONGZ_TEST_UNSET"},
	})
	if err == nil {
		t.Fatal("Resolve succeeded, want error")
	}
	if !strings.Contains(err.Error(), `secret "openai/main"`) {
		t.Errorf("error = %v, want it to name the failing secret", err)
	}
}

func TestResolveFields(t *testing.T) {
	t.Setenv("TONGZ_TEST_AKID", "AKIDEXAMPLE")
	t.Setenv("TONGZ_TEST_SECRET", "wJalr")
	store, err := Resolve(map[string]config.Secret{
		"aws/default": {Fields: map[string]string{
			"access_key_id":     "env:TONGZ_TEST_AKID",
			"secret_access_key": "env:TONGZ_TEST_SECRET",
		}},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	cred, ok := store.Get("aws/default")
	if !ok {
		t.Fatal("credential not stored")
	}
	if got := cred.Field("access_key_id"); got != "AKIDEXAMPLE" {
		t.Errorf("access_key_id = %q", got)
	}
	if got := cred.Field("session_token"); got != "" {
		t.Errorf("absent field = %q, want empty", got)
	}
}

func TestResolveRefExec(t *testing.T) {
	got, err := ResolveRef("exec:printf 'gcp-access-token\\n'")
	if err != nil {
		t.Fatalf("ResolveRef: %v", err)
	}
	if got != "gcp-access-token" {
		t.Errorf("got %q, want the command output with the newline trimmed", got)
	}
}

func TestResolveRefExecFailureNamesCommand(t *testing.T) {
	_, err := ResolveRef("exec:echo 'no credentials' >&2; exit 1")
	if err == nil {
		t.Fatal("ResolveRef succeeded, want error")
	}
	if !strings.Contains(err.Error(), "no credentials") {
		t.Errorf("error = %v, want it to carry the command's stderr", err)
	}
}

// A credential helper that fails must not blank out a working credential.
func TestRefreshKeepsPreviousValueOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec := config.Secret{Value: "file:" + path, Refresh: config.Duration(10 * time.Millisecond)}
	store, err := Resolve(map[string]config.Secret{"rotating": spec})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store.StartRefresh(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)

	cred, _ := store.Get("rotating")
	if cred.Value() != "first" {
		t.Errorf("value = %q, want the previous value kept after a failed refresh", cred.Value())
	}
}

func TestRefreshPicksUpNewValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec := config.Secret{Value: "file:" + path, Refresh: config.Duration(10 * time.Millisecond)}
	store, err := Resolve(map[string]config.Secret{"rotating": spec})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store.StartRefresh(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if err := os.WriteFile(path, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cred, _ := store.Get("rotating"); cred.Value() == "second" {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Error("the refreshed value never appeared")
}
