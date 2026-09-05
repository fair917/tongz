package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	_, err := Resolve(map[string]string{
		"github/repo": "env:TONGZ_TEST_TOKEN",
		"openai/main": "env:TONGZ_TEST_UNSET",
	})
	if err == nil {
		t.Fatal("Resolve succeeded, want error")
	}
	if !strings.Contains(err.Error(), `secret "openai/main"`) {
		t.Errorf("error = %v, want it to name the failing secret", err)
	}
}
