package config

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

// placeholderRE matches "{name}" and "{name:argument}" in an Inject.Format.
var placeholderRE = regexp.MustCompile(`\{([a-z_]+)(?::([^}]*))?\}`)

// Placeholder names usable in Inject.Format.
const (
	// PlaceholderToken substitutes the credential as-is.
	PlaceholderToken = "token"
	// PlaceholderBasic substitutes base64(argument + ":" + credential), which
	// is what git over HTTPS wants: the token travels as the password.
	PlaceholderBasic = "basic"
)

func validateFormat(format string) error {
	if format == "" {
		return fmt.Errorf("inject.format is required")
	}
	matches := placeholderRE.FindAllStringSubmatch(format, -1)
	if len(matches) == 0 {
		return fmt.Errorf("inject.format must contain {%s} or {%s:username}", PlaceholderToken, PlaceholderBasic)
	}
	for _, m := range matches {
		name, arg := m[1], m[2]
		switch name {
		case PlaceholderToken:
			if arg != "" {
				return fmt.Errorf("{%s} takes no argument", PlaceholderToken)
			}
		case PlaceholderBasic:
			if arg == "" {
				return fmt.Errorf("{%s} needs a username, as in {%s:x-access-token}",
					PlaceholderBasic, PlaceholderBasic)
			}
		default:
			return fmt.Errorf("unknown placeholder {%s} in inject.format", name)
		}
	}
	return nil
}

// RenderFormat substitutes the credential into an Inject.Format that
// validateFormat has already accepted.
func RenderFormat(format, token string) string {
	return placeholderRE.ReplaceAllStringFunc(format, func(match string) string {
		m := placeholderRE.FindStringSubmatch(match)
		switch m[1] {
		case PlaceholderToken:
			return token
		case PlaceholderBasic:
			return base64.StdEncoding.EncodeToString([]byte(m[2] + ":" + token))
		default:
			return match
		}
	})
}

// SignsWith reports whether the rule uses the named signature scheme.
func (r *Rule) SignsWith(method string) bool {
	return r.Sign != nil && r.Sign.Method == method
}

// Describe names the rule's action for the audit log.
func (r *Rule) Describe() string {
	switch {
	case r.Inject != nil:
		return "inject"
	case r.Sign != nil:
		return "sign:" + r.Sign.Method
	case r.Respond != nil:
		return "respond:" + r.Respond.Method
	default:
		return "none"
	}
}

// MetadataRule returns the GCP metadata responder rule, if one is configured.
func (c *Config) MetadataRule() *Rule {
	for i := range c.Rules {
		if r := &c.Rules[i]; r.Respond != nil && r.Respond.Method == RespondGCPMeta {
			return r
		}
	}
	return nil
}

// Hosts returns the distinct hosts named by the rules, for startup output and
// certificate prewarming.
func (c *Config) Hosts() []string {
	seen := make(map[string]bool)
	var hosts []string
	for _, r := range c.Rules {
		h := strings.TrimSpace(string(r.Match.Host))
		if !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	return hosts
}
