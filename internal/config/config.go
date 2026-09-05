// Package config loads and validates the Tongz proxy configuration.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

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

	// Secrets maps a credential identifier to where the value comes from. Only
	// the identifier ever reaches the audit log.
	Secrets map[string]Secret `yaml:"secrets"`

	// Rules are evaluated in order; the first match wins.
	Rules []Rule `yaml:"rules"`

	// Passthrough hosts are tunnelled without decryption, for clients that
	// cannot be made to trust the Tongz CA. No credential can be injected.
	Passthrough []HostPattern `yaml:"passthrough"`
}

// Rule decides what happens to the requests it matches. Exactly one action is
// set: Inject writes a header, Sign computes a signature, Respond answers
// locally without contacting any upstream.
type Rule struct {
	Match   Match    `yaml:"match"`
	Inject  *Inject  `yaml:"inject"`
	Sign    *Sign    `yaml:"sign"`
	Respond *Respond `yaml:"respond"`
	Token   string   `yaml:"token"`
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

// Sign names a signature scheme that cannot be expressed declaratively.
type Sign struct {
	Method string `yaml:"method"`
	// Region and Service are derived from the host when left empty.
	Region  string `yaml:"region"`
	Service string `yaml:"service"`
}

// Respond answers the request from the proxy itself. It exists so that a
// client library looking for ambient credentials finds something, while the
// credential it finds is worthless: the real one is attached later, upstream.
type Respond struct {
	Method string `yaml:"method"`

	// GCP metadata server fields.
	ProjectID        string `yaml:"project_id"`
	NumericProjectID string `yaml:"numeric_project_id"`
	ServiceAccount   string `yaml:"service_account"`
	Zone             string `yaml:"zone"`
}

// Signing and responder methods.
const (
	SignAWSSigV4    = "aws-sigv4"
	RespondGCPMeta  = "gcp-metadata"
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
	for id, s := range c.Secrets {
		if id == "" {
			return fmt.Errorf("config: secret identifier must not be empty")
		}
		if err := s.validate(); err != nil {
			return fmt.Errorf("config: secret %q: %w", id, err)
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

func (r Rule) validate(secrets map[string]Secret) error {
	if r.Match.Host == "" {
		return fmt.Errorf("match.host is required")
	}
	if err := r.Match.Host.validate(); err != nil {
		return err
	}

	actions := 0
	for _, set := range []bool{r.Inject != nil, r.Sign != nil, r.Respond != nil} {
		if set {
			actions++
		}
	}
	if actions != 1 {
		return fmt.Errorf("exactly one of inject, sign or respond is required")
	}

	if r.Respond != nil {
		if r.Respond.Method != RespondGCPMeta {
			return fmt.Errorf("respond.method %q is not supported (want %q)", r.Respond.Method, RespondGCPMeta)
		}
		if r.Token != "" {
			return fmt.Errorf("respond serves a placeholder credential and must not name a token")
		}
		if r.Respond.ProjectID == "" {
			return fmt.Errorf("respond.project_id is required; client libraries read it to address requests")
		}
		return nil
	}

	if r.Token == "" {
		return fmt.Errorf("token is required")
	}
	secret, ok := secrets[r.Token]
	if !ok {
		return fmt.Errorf("token %q is not defined under secrets", r.Token)
	}

	if r.Inject != nil {
		if r.Inject.Header == "" {
			return fmt.Errorf("inject.header is required")
		}
		if err := validateFormat(r.Inject.Format); err != nil {
			return err
		}
		if secret.Value == "" {
			return fmt.Errorf("inject needs a single-valued token, but %q defines fields", r.Token)
		}
		return nil
	}

	if r.Sign.Method != SignAWSSigV4 {
		return fmt.Errorf("sign.method %q is not supported (want %q)", r.Sign.Method, SignAWSSigV4)
	}
	for _, field := range []string{"access_key_id", "secret_access_key"} {
		if _, ok := secret.Fields[field]; !ok {
			return fmt.Errorf("sign method %s needs token %q to define the field %q",
				SignAWSSigV4, r.Token, field)
		}
	}
	return nil
}

// Secret says where one credential comes from. It accepts either a bare
// reference or a mapping, so the common single-token case stays a one-liner:
//
//	github/repo: env:GITHUB_TOKEN
//	aws/default:
//	  fields:
//	    access_key_id: env:AWS_ACCESS_KEY_ID
//	    secret_access_key: env:AWS_SECRET_ACCESS_KEY
//	gcp/default:
//	  value: exec:gcloud auth print-access-token
//	  refresh: 30m
type Secret struct {
	Value  string            `yaml:"value"`
	Fields map[string]string `yaml:"fields"`
	// Refresh re-reads the reference on an interval, for credentials that
	// expire. Resolution stays off the request path either way.
	Refresh Duration `yaml:"refresh"`
}

func (s *Secret) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		return node.Decode(&s.Value)
	}
	type raw Secret
	return node.Decode((*raw)(s))
}

func (s Secret) validate() error {
	switch {
	case s.Value == "" && len(s.Fields) == 0:
		return fmt.Errorf("needs either a reference or fields")
	case s.Value != "" && len(s.Fields) > 0:
		return fmt.Errorf("set either a reference or fields, not both")
	case s.Refresh < 0:
		return fmt.Errorf("refresh must not be negative")
	}
	return nil
}

// Duration accepts Go duration strings such as "30m".
type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("%q is not a duration such as 30m: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// Duration returns the interval as a time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }
