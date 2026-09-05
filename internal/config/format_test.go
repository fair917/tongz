package config

import (
	"encoding/base64"
	"testing"
)

func TestRenderFormat(t *testing.T) {
	if got := RenderFormat("Bearer {token}", "ghp_x"); got != "Bearer ghp_x" {
		t.Errorf("got %q", got)
	}
	if got := RenderFormat("token {token} {token}", "x"); got != "token x x" {
		t.Errorf("got %q", got)
	}

	// git over HTTPS sends the token as the password of a Basic credential.
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:ghp_x"))
	if got := RenderFormat("Basic {basic:x-access-token}", "ghp_x"); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestValidateFormat(t *testing.T) {
	valid := []string{
		"Bearer {token}",
		"{token}",
		"token={token}",
		"Basic {basic:x-access-token}",
	}
	for _, f := range valid {
		if err := validateFormat(f); err != nil {
			t.Errorf("validateFormat(%q) = %v, want nil", f, err)
		}
	}

	invalid := []string{
		"",
		"Bearer static",
		"Bearer {secret}",
		"Basic {basic}",
		"Bearer {token:extra}",
	}
	for _, f := range invalid {
		if err := validateFormat(f); err == nil {
			t.Errorf("validateFormat(%q) = nil, want an error", f)
		}
	}
}
