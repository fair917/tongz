// Package config loads and validates the Tongz proxy configuration.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the on-disk configuration of the proxy.
type Config struct {
	// Listen is the address the proxy binds to. Binding to loopback makes the
	// proxy unreachable from containers while exposing it to every process on
	// the host, so the default is the bridge-facing wildcard address.
	Listen string `yaml:"listen"`

	// StateDir holds generated state, currently the CA key pair.
	StateDir string `yaml:"state_dir"`

	// ProxyAuth is a secret reference. When set, clients must present the
	// resolved value in Proxy-Authorization. It grants use of the proxy, not
	// access to any upstream service.
	ProxyAuth string `yaml:"proxy_auth"`

	// Secrets maps a token identifier to a secret reference such as
	// "env:GITHUB_TOKEN". Only the identifier ever reaches the audit log.
	Secrets map[string]string `yaml:"secrets"`

	// Rules are evaluated in order; the first match wins.
	Rules []Rule `yaml:"rules"`

	// Passthrough hosts are tunnelled without decryption, for clients that
	// cannot be made to trust the Tongz CA. No credential can be injected.
	Passthrough []HostPattern `yaml:"passthrough"`
}

// Rule injects one credential into the requests it matches.
type Rule struct {
	Match  Match  `yaml:"match"`
	Inject Inject `yaml:"inject"`
	Token  string `yaml:"token"`
}

// Match selects requests by host, path and method. Host alone is too coarse:
// a token scoped to issues should not reach the admin API on the same host.
type Match struct {
	Host   HostPattern `yaml:"host"`
	Path   string      `yaml:"path"`
	Method []string    `yaml:"method"`
}

// Inject describes the header to write. The existing value is always replaced,
// never appended to, so a credential the agent supplied itself cannot survive.
type Inject struct {
	Header string `yaml:"header"`
	Format string `yaml:"format"`
}

// TokenPlaceholder is substituted with the resolved secret in Inject.Format.
const TokenPlaceholder = "{token}"

// Default values applied when the field is absent from the file.
const (
	DefaultListen   = "0.0.0.0:8080"
	DefaultStateDir = "~/.tongz"
)

// Load reads and validates the configuration at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse validates configuration already read into memory.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.StateDir == "" {
		c.StateDir = DefaultStateDir
	}
	for i := range c.Rules {
		r := &c.Rules[i]
		r.Match.Host = r.Match.Host.normalized()
		for j, m := range r.Match.Method {
			r.Match.Method[j] = strings.ToUpper(strings.TrimSpace(m))
		}
	}
	for i, p := range c.Passthrough {
		c.Passthrough[i] = p.normalized()
	}
}

func (c *Config) validate() error {
	if len(c.Rules) == 0 {
		return fmt.Errorf("config: no rules defined; the proxy would inject nothing")
	}
	for ref := range c.Secrets {
		if ref == "" {
			return fmt.Errorf("config: secret identifier must not be empty")
		}
	}
	for i, r := range c.Rules {
		if err := r.validate(c.Secrets); err != nil {
			return fmt.Errorf("config: rules[%d]: %w", i, err)
		}
		for _, p := range c.Passthrough {
			if p == r.Match.Host {
				return fmt.Errorf("config: rules[%d]: host %q is also listed in passthrough; "+
					"a tunnelled host cannot receive an injected credential", i, r.Match.Host)
			}
		}
	}
	return nil
}

func (r Rule) validate(secrets map[string]string) error {
	if r.Match.Host == "" {
		return fmt.Errorf("match.host is required")
	}
	if err := r.Match.Host.validate(); err != nil {
		return err
	}
	if r.Inject.Header == "" {
		return fmt.Errorf("inject.header is required")
	}
	if !strings.Contains(r.Inject.Format, TokenPlaceholder) {
		return fmt.Errorf("inject.format must contain %s", TokenPlaceholder)
	}
	if r.Token == "" {
		return fmt.Errorf("token is required")
	}
	if _, ok := secrets[r.Token]; !ok {
		return fmt.Errorf("token %q is not defined under secrets", r.Token)
	}
	return nil
}
