package awssig

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The example published with the Signature Version 4 specification. Matching
// it end to end is what shows the canonicalization is right.
func TestSignMatchesPublishedExample(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	creds := Credentials{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
	}
	when := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	if err := Sign(req, creds, "us-east-1", "iam", when); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	want := "AWS4-HMAC-SHA256 " +
		"Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, " +
		"SignedHeaders=content-type;host;x-amz-date, " +
		"Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if got := req.Header.Get("Authorization"); got != want {
		t.Errorf("Authorization =\n%s\nwant\n%s", got, want)
	}
	if got := req.Header.Get("X-Amz-Date"); got != "20150830T123600Z" {
		t.Errorf("X-Amz-Date = %q", got)
	}
}

// Whatever the agent signed with its placeholder credentials must not survive.
func TestSignDiscardsClientSignature(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://iam.amazonaws.com/?Action=ListUsers", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAAGENTFAKE/20150830/us-east-1/iam/aws4_request, SignedHeaders=host, Signature=deadbeef")
	req.Header.Set("X-Amz-Security-Token", "agent-supplied-session")
	req.Header.Set("X-Amz-Date", "19700101T000000Z")

	creds := Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "secret"}
	if err := Sign(req, creds, "us-east-1", "iam", time.Now()); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	auth := req.Header.Get("Authorization")
	if strings.Contains(auth, "AKIAAGENTFAKE") || strings.Contains(auth, "deadbeef") {
		t.Errorf("Authorization still carries the agent's signature: %s", auth)
	}
	if got := req.Header.Get("X-Amz-Security-Token"); got != "" {
		t.Errorf("X-Amz-Security-Token = %q, want it dropped when the host has no session token", got)
	}
	if got := req.Header.Get("X-Amz-Date"); got == "19700101T000000Z" {
		t.Error("X-Amz-Date was not refreshed")
	}
}

func TestSignSetsSessionToken(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://iam.amazonaws.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	creds := Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret", SessionToken: "host-session"}
	if err := Sign(req, creds, "us-east-1", "iam", time.Now()); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got := req.Header.Get("X-Amz-Security-Token"); got != "host-session" {
		t.Errorf("X-Amz-Security-Token = %q, want the host session token", got)
	}
	if !strings.Contains(req.Header.Get("Authorization"), "x-amz-security-token") {
		t.Error("the session token is not covered by the signature")
	}
}

func TestSignHashesAndRestoresBody(t *testing.T) {
	body := "{\"TableName\":\"agents\"}"
	req, err := http.NewRequest(http.MethodPost, "https://dynamodb.us-west-2.amazonaws.com/", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	creds := Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}
	if err := Sign(req, creds, "us-west-2", "dynamodb", time.Now()); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Errorf("body = %q, want it readable after signing", got)
	}
	if req.ContentLength != int64(len(body)) {
		t.Errorf("ContentLength = %d, want %d", req.ContentLength, len(body))
	}
}

// S3 clients state the digest themselves, so the body is never buffered.
func TestSignUsesStatedDigest(t *testing.T) {
	req, err := http.NewRequest(http.MethodPut, "https://bucket.s3.us-west-2.amazonaws.com/key", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")

	creds := Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}
	if err := Sign(req, creds, "us-west-2", "s3", time.Now()); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got := req.Header.Get("X-Amz-Content-Sha256"); got != "UNSIGNED-PAYLOAD" {
		t.Errorf("X-Amz-Content-Sha256 = %q, want the stated digest kept", got)
	}
	got, _ := io.ReadAll(req.Body)
	if string(got) != "payload" {
		t.Errorf("body = %q, want it untouched", got)
	}
}

func TestSignRefusesChunkedSigning(t *testing.T) {
	req, err := http.NewRequest(http.MethodPut, "https://bucket.s3.us-west-2.amazonaws.com/key", strings.NewReader("chunk"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")

	creds := Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}
	err = Sign(req, creds, "us-west-2", "s3", time.Now())
	if err == nil {
		t.Fatal("Sign accepted a chunk-signed payload, want it refused")
	}
	if !strings.Contains(err.Error(), "chunked payload signing") {
		t.Errorf("error = %v, want it to name the limitation", err)
	}
}

func TestSignSetsContentDigestForS3(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://bucket.s3.us-west-2.amazonaws.com/key", nil)
	if err != nil {
		t.Fatal(err)
	}
	creds := Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}
	if err := Sign(req, creds, "us-west-2", "s3", time.Now()); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got := req.Header.Get("X-Amz-Content-Sha256"); got != emptyDigest {
		t.Errorf("X-Amz-Content-Sha256 = %q, want the empty-body digest", got)
	}
}

func TestEndpoint(t *testing.T) {
	tests := []struct {
		host    string
		service string
		region  string
		ok      bool
	}{
		{"iam.amazonaws.com", "iam", "us-east-1", true},
		{"sts.amazonaws.com", "sts", "us-east-1", true},
		{"dynamodb.eu-central-1.amazonaws.com", "dynamodb", "eu-central-1", true},
		{"bucket.s3.us-west-2.amazonaws.com", "s3", "us-west-2", true},
		{"s3.ap-northeast-1.amazonaws.com:443", "s3", "ap-northeast-1", true},
		{"execute-api.us-gov-west-1.amazonaws.com", "execute-api", "us-gov-west-1", true},
		{"s3.cn-north-1.amazonaws.com.cn", "s3", "cn-north-1", true},
		{"api.github.com", "", "", false},
		{"amazonaws.com", "", "", false},
	}
	for _, tc := range tests {
		service, region, ok := Endpoint(tc.host)
		if ok != tc.ok || service != tc.service || region != tc.region {
			t.Errorf("Endpoint(%q) = %q, %q, %v; want %q, %q, %v",
				tc.host, service, region, ok, tc.service, tc.region, tc.ok)
		}
	}
}

func TestCanonicalQuerySortsAndEncodes(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://iam.amazonaws.com/?b=2&a=1&a=0&c=hello%20world", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "a=0&a=1&b=2&c=hello%20world"
	if got := canonicalQuery(req.URL); got != want {
		t.Errorf("canonicalQuery = %q, want %q", got, want)
	}
}
