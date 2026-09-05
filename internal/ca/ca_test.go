package ca

import (
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadPersistsCA(t *testing.T) {
	dir := t.TempDir()
	first, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	second, err := Load(dir)
	if err != nil {
		t.Fatalf("Load again: %v", err)
	}
	if string(first.CertPEM()) != string(second.CertPEM()) {
		t.Error("reloading produced a different CA; containers would have to re-trust it")
	}

	info, err := os.Stat(filepath.Join(dir, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("CA key mode = %o, want 600", perm)
	}
}

func TestLoadRejectsHalfWrittenState(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, keyFile)); err != nil {
		t.Fatal(err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load succeeded with a missing key, want error")
	}
	if !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("error = %v, want it to report incomplete state", err)
	}
}

func TestLeafChainsToCA(t *testing.T) {
	a, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	leaf, err := a.Leaf("api.github.com:443")
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(a.CertPEM()) {
		t.Fatal("CA certificate did not parse")
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{
		DNSName:     "api.github.com",
		Roots:       roots,
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("leaf does not verify against the CA: %v", err)
	}
}

func TestLeafCachesPerHost(t *testing.T) {
	a, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	first, err := a.Leaf("api.github.com")
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	// The port must not create a second cache entry.
	second, err := a.Leaf("API.github.com:443")
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	if first != second {
		t.Error("Leaf returned a fresh certificate for a cached host")
	}
	other, err := a.Leaf("api.openai.com")
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	if other == first {
		t.Error("Leaf returned the same certificate for a different host")
	}
}

func TestLeafForIPAddress(t *testing.T) {
	a, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	leaf, err := a.Leaf("10.1.2.3")
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	if len(leaf.Leaf.IPAddresses) != 1 || !leaf.Leaf.IPAddresses[0].Equal(net.ParseIP("10.1.2.3")) {
		t.Errorf("IPAddresses = %v, want [10.1.2.3]", leaf.Leaf.IPAddresses)
	}
	if len(leaf.Leaf.DNSNames) != 0 {
		t.Errorf("DNSNames = %v, want none", leaf.Leaf.DNSNames)
	}
}

func TestLeafWithoutServerName(t *testing.T) {
	a, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := a.Leaf(""); err == nil {
		t.Error("Leaf(\"\") succeeded, want error")
	}
}
