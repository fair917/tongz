package proxy

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/fair917/tongz/internal/awssig"
	"github.com/fair917/tongz/internal/config"
	"github.com/fair917/tongz/internal/gcpmeta"
)

// denial is a request the proxy refuses to forward. Every refusal carries a
// reason the agent can read, since a silent failure here looks like a network
// fault and costs an hour of debugging.
type denial struct {
	status int
	reason string
}

func (d *denial) Error() string { return d.reason }

// plan is what the proxy decided to do with one request: forward it upstream
// with a credential attached, or answer it here without contacting anything.
type plan struct {
	request *http.Request
	local   *http.Response
	rule    *config.Rule
}

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

// makePlan decides what happens to req, or explains why it is refused.
//
// scheme and target describe the connection the client asked for; host is the
// normalized name that rules are matched against.
func (p *Proxy) makePlan(req *http.Request, scheme, target, host string) (*plan, *denial) {
	// The client dialed one authority and may claim another in the Host
	// header. Matching rules against the dialed host while sending the other
	// one upstream would let a rule for a permitted host carry a credential to
	// a different service on the same address.
	if reqHost := config.NormalizeHost(req.Host); reqHost != "" && reqHost != host {
		return nil, &denial{
			status: http.StatusForbidden,
			reason: fmt.Sprintf("tongz: Host %q does not match the connection to %q", req.Host, host),
		}
	}

	if isUpgrade(req) {
		return nil, &denial{
			status: http.StatusNotImplemented,
			reason: "tongz: protocol upgrades are not supported on an intercepted host; " +
				"add the host to passthrough to tunnel it without a credential",
		}
	}

	rule, ok := p.cfg.Find(host, req.Method, req.URL.EscapedPath())
	if !ok {
		return nil, &denial{
			status: http.StatusForbidden,
			reason: fmt.Sprintf("tongz: no rule matches %s %s%s", req.Method, host, req.URL.EscapedPath()),
		}
	}

	if rule.Respond != nil {
		return &plan{local: gcpmeta.Respond(req, rule.Respond), rule: rule}, nil
	}

	cred, ok := p.store.Get(rule.Token)
	if !ok {
		return nil, &denial{
			status: http.StatusInternalServerError,
			reason: fmt.Sprintf("tongz: token %q is not loaded", rule.Token),
		}
	}

	out := req.Clone(req.Context())
	out.RequestURI = ""
	out.URL.Scheme = scheme
	out.URL.Host = target
	sanitize(out.Header)

	if rule.Inject != nil {
		// Replace, never append: a credential the agent supplied itself must
		// not survive this point.
		out.Header.Set(rule.Inject.Header, config.RenderFormat(rule.Inject.Format, cred.Value()))
		return &plan{request: out, rule: rule}, nil
	}

	if deny := signAWS(out, rule, cred.Field, host); deny != nil {
		return nil, deny
	}
	return &plan{request: out, rule: rule}, nil
}

// signAWS replaces the placeholder signature the SDK produced with a real one.
func signAWS(out *http.Request, rule *config.Rule, field func(string) string, host string) *denial {
	region, service := rule.Sign.Region, rule.Sign.Service
	if region == "" || service == "" {
		derivedService, derivedRegion, ok := awssig.Endpoint(host)
		if !ok {
			return &denial{
				status: http.StatusBadRequest,
				reason: fmt.Sprintf("tongz: cannot derive the signing service and region from %q; "+
					"name them on the rule", host),
			}
		}
		if region == "" {
			region = derivedRegion
		}
		if service == "" {
			service = derivedService
		}
	}

	creds := awssig.Credentials{
		AccessKeyID:     field("access_key_id"),
		SecretAccessKey: field("secret_access_key"),
		SessionToken:    field("session_token"),
	}
	if err := awssig.Sign(out, creds, region, service, time.Now()); err != nil {
		return &denial{status: http.StatusBadRequest, reason: "tongz: " + err.Error()}
	}
	return nil
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
