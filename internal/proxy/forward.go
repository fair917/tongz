package proxy

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/fair917/tongz/internal/config"
)

// denial is a request the proxy refuses to forward. Every refusal carries a
// reason the agent can read, since a silent failure here looks like a network
// fault and costs an hour of debugging.
type denial struct {
	status int
	reason string
}

func (d *denial) Error() string { return d.reason }

// hopByHop headers are consumed by this proxy and must not reach the upstream.
var hopByHop = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// prepare builds the upstream request for req, or explains why it is refused.
//
// scheme and target describe the connection the client asked for; host is the
// normalized name that rules are matched against.
func (p *Proxy) prepare(req *http.Request, scheme, target, host string) (*http.Request, *config.Rule, *denial) {
	// The client dialed one authority and may claim another in the Host
	// header. Matching rules against the dialed host while sending the other
	// one upstream would let a rule for a permitted host carry a credential to
	// a different service on the same address.
	if reqHost := config.NormalizeHost(req.Host); reqHost != "" && reqHost != host {
		return nil, nil, &denial{
			status: http.StatusForbidden,
			reason: fmt.Sprintf("tongz: Host %q does not match the connection to %q", req.Host, host),
		}
	}

	if isUpgrade(req) {
		return nil, nil, &denial{
			status: http.StatusNotImplemented,
			reason: "tongz: protocol upgrades are not supported on an intercepted host; " +
				"add the host to passthrough to tunnel it without a credential",
		}
	}

	rule, ok := p.cfg.Find(host, req.Method, req.URL.EscapedPath())
	if !ok {
		return nil, nil, &denial{
			status: http.StatusForbidden,
			reason: fmt.Sprintf("tongz: no rule matches %s %s%s", req.Method, host, req.URL.EscapedPath()),
		}
	}

	token, ok := p.store.Get(rule.Token)
	if !ok {
		return nil, nil, &denial{
			status: http.StatusInternalServerError,
			reason: fmt.Sprintf("tongz: token %q is not loaded", rule.Token),
		}
	}

	out := req.Clone(req.Context())
	out.RequestURI = ""
	out.URL.Scheme = scheme
	out.URL.Host = target
	sanitize(out.Header)
	// Replace, never append: a credential the agent supplied itself must not
	// survive this point.
	out.Header.Set(rule.Inject.Header, strings.ReplaceAll(rule.Inject.Format, config.TokenPlaceholder, token))
	return out, rule, nil
}

// sanitize removes hop-by-hop headers, including the ones named by Connection.
func sanitize(h http.Header) {
	for _, name := range strings.Split(h.Get("Connection"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			h.Del(name)
		}
	}
	for _, name := range hopByHop {
		h.Del(name)
	}
}

func isUpgrade(req *http.Request) bool {
	if req.Header.Get("Upgrade") == "" {
		return false
	}
	for _, name := range strings.Split(req.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(name), "upgrade") {
			return true
		}
	}
	return false
}
