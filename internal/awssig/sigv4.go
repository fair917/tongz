// Package awssig re-signs requests with AWS Signature Version 4.
//
// An AWS SDK refuses to build a request without credentials, so the container
// is given obviously fake ones and signs with those. That signature is
// discarded here and replaced with one made from the real credentials, which
// never leave the host.
package awssig

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	algorithm   = "AWS4-HMAC-SHA256"
	terminator  = "aws4_request"
	timeFormat  = "20060102T150405Z"
	dateFormat  = "20060102"
	emptyDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// MaxBodyToHash bounds how much of a request body is buffered to compute
	// its digest. Clients that send more are expected to state the digest
	// themselves in x-amz-content-sha256, as the S3 SDKs do.
	MaxBodyToHash = 8 << 20
)

// Credentials are the host-held AWS credentials used for signing.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// Sign replaces any signature already on req with one computed from creds. The
// request must carry the exact path, query and body that will be sent.
func Sign(req *http.Request, creds Credentials, region, service string, now time.Time) error {
	// Whatever the SDK signed with its placeholder credentials is worthless.
	req.Header.Del("Authorization")
	req.Header.Del("X-Amz-Security-Token")
	req.Header.Del("X-Amz-Date")

	digest, err := payloadDigest(req, service)
	if err != nil {
		return err
	}

	now = now.UTC()
	amzDate := now.Format(timeFormat)
	req.Header.Set("X-Amz-Date", amzDate)
	if creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	}
	if service == "s3" {
		req.Header.Set("X-Amz-Content-Sha256", digest)
	}

	signed, canonicalHeaders := canonicalizeHeaders(req)
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL, service),
		canonicalQuery(req.URL),
		canonicalHeaders,
		strings.Join(signed, ";"),
		digest,
	}, "\n")

	scope := strings.Join([]string{now.Format(dateFormat), region, service, terminator}, "/")
	stringToSign := strings.Join([]string{
		algorithm,
		amzDate,
		scope,
		hashHex([]byte(canonicalRequest)),
	}, "\n")

	signature := hex.EncodeToString(hmacSHA256(signingKey(creds.SecretAccessKey, now, region, service), []byte(stringToSign)))
	req.Header.Set("Authorization", fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		algorithm, creds.AccessKeyID, scope, strings.Join(signed, ";"), signature))
	return nil
}

// payloadDigest returns the hash the signature covers.
//
// When the client states the digest, that value is used without reading the
// body: the client already controls the body, and a digest that does not match
// what AWS receives simply fails there.
func payloadDigest(req *http.Request, service string) (string, error) {
	if stated := req.Header.Get("X-Amz-Content-Sha256"); stated != "" {
		if strings.HasPrefix(stated, "STREAMING-") {
			// The body itself is signed chunk by chunk with the placeholder
			// credentials, so re-signing would mean rewriting every chunk.
			return "", fmt.Errorf("chunked payload signing (%s) is not supported; "+
				"configure the client to send an unsigned or whole-body-hashed payload", stated)
		}
		return stated, nil
	}
	if req.Body == nil || req.Body == http.NoBody {
		return emptyDigest, nil
	}

	body, err := io.ReadAll(io.LimitReader(req.Body, MaxBodyToHash+1))
	req.Body.Close()
	if err != nil {
		return "", fmt.Errorf("read request body: %w", err)
	}
	if len(body) > MaxBodyToHash {
		return "", fmt.Errorf("request body exceeds %d bytes and states no x-amz-content-sha256 digest", MaxBodyToHash)
	}

	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.TransferEncoding = nil
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	return hashHex(body), nil
}

// canonicalizeHeaders returns the sorted signed-header names and the canonical
// header block. Only Host, Content-Type and the x-amz-* headers are signed:
// they are the ones AWS requires and the ones this proxy controls end to end.
func canonicalizeHeaders(req *http.Request) ([]string, string) {
	values := map[string]string{"host": req.Host}
	if values["host"] == "" {
		values["host"] = req.URL.Host
	}
	if ct := req.Header.Get("Content-Type"); ct != "" {
		values["content-type"] = ct
	}
	for name, vs := range req.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-amz-") {
			values[lower] = strings.Join(vs, ",")
		}
	}

	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(collapseSpaces(values[name]))
		b.WriteByte('\n')
	}
	return names, b.String()
}

// canonicalURI encodes the path as AWS expects. S3 keys are taken verbatim
// because their names may contain characters that a second round of encoding
// would change.
func canonicalURI(u *url.URL, service string) string {
	path := u.EscapedPath()
	if path == "" {
		return "/"
	}
	if service == "s3" {
		return path
	}
	return uriEncode(path, false)
}

func canonicalQuery(u *url.URL) string {
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return ""
	}
	pairs := make([]string, 0, len(values))
	for key, vs := range values {
		sorted := append([]string(nil), vs...)
		sort.Strings(sorted)
		for _, v := range sorted {
			pairs = append(pairs, uriEncode(key, true)+"="+uriEncode(v, true))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// uriEncode percent-encodes everything outside the RFC 3986 unreserved set.
func uriEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte('/')
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func collapseSpaces(v string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(v)), " ")
}

func signingKey(secret string, t time.Time, region, service string) []byte {
	key := hmacSHA256([]byte("AWS4"+secret), []byte(t.Format(dateFormat)))
	key = hmacSHA256(key, []byte(region))
	key = hmacSHA256(key, []byte(service))
	return hmacSHA256(key, []byte(terminator))
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func hashHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
