// Package ca issues the leaf certificates the proxy presents to clients.
//
// The CA key never leaves the host; the certificate is handed to containers by
// the /install endpoint so they can trust the interception.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	certFile = "ca.pem"
	keyFile  = "ca.key"

	caValidity   = 5 * 365 * 24 * time.Hour
	leafValidity = 30 * 24 * time.Hour
	// clockSkew backdates certificates so a container whose clock trails the
	// host does not reject a freshly minted leaf.
	clockSkew = time.Hour
)

// Authority signs leaf certificates on demand, one per SNI name.
type Authority struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte

	// leafKey is shared by every leaf. Generating a P-256 key per host would
	// add latency to the first connection of each host for no benefit: the
	// keys are equally ephemeral either way.
	leafKey *ecdsa.PrivateKey

	mu    sync.RWMutex
	cache map[string]*tls.Certificate
}

// Load reads the CA from dir, generating and persisting one if absent.
func Load(dir string) (*Authority, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}
	cert, key, certPEM, err := loadOrGenerate(dir)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	return &Authority{
		cert:    cert,
		key:     key,
		certPEM: certPEM,
		leafKey: leafKey,
		cache:   make(map[string]*tls.Certificate),
	}, nil
}

func loadOrGenerate(dir string) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	certPath := filepath.Join(dir, certFile)
	keyPath := filepath.Join(dir, keyFile)

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	switch {
	case certErr == nil && keyErr == nil:
		cert, key, err := parsePair(certPEM, keyPEM)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("read CA from %s: %w", dir, err)
		}
		return cert, key, certPEM, nil
	case os.IsNotExist(certErr) && os.IsNotExist(keyErr):
		return generate(certPath, keyPath)
	default:
		// One half present without the other means a partial write or a
		// half-deleted state dir. Regenerating silently would invalidate the CA
		// containers already trust.
		return nil, nil, nil, fmt.Errorf("CA state in %s is incomplete: %s and %s must both exist or both be absent",
			dir, certFile, keyFile)
	}
}

func parsePair(certPEM, keyPEM []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("certificate is not valid PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("key is not valid PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func generate(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Tongz Local CA",
			Organization: []string{"Tongz"},
		},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("sign CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, nil, nil, fmt.Errorf("write CA key: %w", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, nil, nil, fmt.Errorf("write CA certificate: %w", err)
	}
	return cert, key, certPEM, nil
}

// CertPEM returns the CA certificate for distribution to containers.
func (a *Authority) CertPEM() []byte {
	return a.certPEM
}

// Leaf returns the certificate for host, minting and caching it on first use.
func (a *Authority) Leaf(host string) (*tls.Certificate, error) {
	host = normalize(host)
	if host == "" {
		return nil, fmt.Errorf("no server name to issue a certificate for")
	}

	a.mu.RLock()
	cached, ok := a.cache[host]
	a.mu.RUnlock()
	if ok {
		return cached, nil
	}

	leaf, err := a.issue(host)
	if err != nil {
		return nil, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	// A concurrent caller may have won the race; either certificate is valid,
	// so keep the one already published to avoid handing out two.
	if cached, ok := a.cache[host]; ok {
		return cached, nil
	}
	a.cache[host] = leaf
	return leaf, nil
}

func (a *Authority) issue(host string) (*tls.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(leafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &a.leafKey.PublicKey, a.key)
	if err != nil {
		return nil, fmt.Errorf("sign certificate for %s: %w", host, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, a.cert.Raw},
		PrivateKey:  a.leafKey,
		Leaf:        leaf,
	}, nil
}

// Prewarm issues certificates ahead of the first request so that the initial
// connection to a configured host is not slower than the rest.
func (a *Authority) Prewarm(hosts []string) {
	for _, h := range hosts {
		if strings.Contains(h, "*") {
			continue // the concrete name is only known at handshake time
		}
		_, _ = a.Leaf(h)
	}
}

// ServerTLSConfig returns the configuration used for the client-facing side of
// an intercepted connection.
func (a *Authority) ServerTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return a.Leaf(hello.ServerName)
		},
		// Only HTTP/1.1 is advertised: header rewriting for HTTP/2 needs
		// connection-scoped HPACK handling, which is not implemented yet.
		// Clients that would have negotiated h2 fall back cleanly.
		NextProtos: []string{"http/1.1"},
	}
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}
	return serial, nil
}

func normalize(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(host, ".")
}
