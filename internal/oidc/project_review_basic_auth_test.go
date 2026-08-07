package oidc

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func TestProjectReviewStrictBasicRejectsBoundedAndControlInputs(t *testing.T) {
	t.Parallel()

	tooLong := "Basic " + strings.Repeat("A", maxBasicAuthorizationBytes)
	tests := []struct {
		name  string
		value string
	}{
		{name: "encoded header exceeds limit before decode", value: tooLong},
		{name: "raw NUL", value: "Basic client:secret\x00"},
		{name: "raw unit separator", value: "Basic client:secret\x1f"},
		{name: "raw DEL", value: "Basic client:secret\x7f"},
		{name: "decoded NUL", value: projectReviewBasicHeader("client", "secret\x00value")},
		{name: "decoded unit separator", value: projectReviewBasicHeader("client\x1fvalue", "secret")},
		{name: "decoded DEL", value: projectReviewBasicHeader("client", "secret\x7fvalue")},
		{name: "unescaped NUL", value: projectReviewBasicHeaderRaw("client%00", "secret")},
		{name: "unescaped unit separator", value: projectReviewBasicHeaderRaw("client", "secret%1f")},
		{name: "unescaped DEL", value: projectReviewBasicHeaderRaw("client%7f", "secret")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clientID, secret, err := parseStrictBasic(test.value)
			if err == nil || clientID != "" || secret != "" {
				t.Fatalf("parseStrictBasic() = (%q, %q, %v), want value-free rejection", clientID, secret, err)
			}
			for _, canary := range []string{"client", "secret", "%00", "%1f", "%7f"} {
				if strings.Contains(err.Error(), canary) {
					t.Fatalf("Basic error leaked %q: %v", canary, err)
				}
			}
		})
	}
}

func TestProjectReviewStrictBasicAcceptsCredentialNearMaximum(t *testing.T) {
	t.Parallel()

	clientID := "ois_cli_project_review"
	secret := "s"
	for {
		candidate := projectReviewBasicHeader(clientID, secret+"s")
		if len(candidate) > maxBasicAuthorizationBytes {
			break
		}
		secret += "s"
	}
	header := projectReviewBasicHeader(clientID, secret)
	if len(header) > maxBasicAuthorizationBytes || len(header) < maxBasicAuthorizationBytes-16 {
		t.Fatalf("near-limit header length = %d, max = %d", len(header), maxBasicAuthorizationBytes)
	}
	gotClient, gotSecret, err := parseStrictBasic(header)
	if err != nil || gotClient != clientID || gotSecret != secret {
		t.Fatalf("parseStrictBasic() = (%q, %q, %v), want original credentials", gotClient, gotSecret, err)
	}
}

func projectReviewBasicHeader(clientID, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(clientID)+":"+url.QueryEscape(secret)))
}

func projectReviewBasicHeaderRaw(clientID, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret))
}
