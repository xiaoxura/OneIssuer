package httpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/oneissuer/oneissuer/internal/oidc"
)

func TestParseRPLogoutHTTPRequestChannelAndWireMatrix(t *testing.T) {
	t.Parallel()
	valid := "id_token_hint=hint&client_id=client&post_logout_redirect_uri=https%3A%2F%2Frp.example.test%2Fout&state=s"
	tests := []struct {
		name   string
		method string
		target string
		body   string
		ctype  string
		want   bool
	}{
		{name: "GET query", method: http.MethodGet, target: "/oauth2/logout?" + valid, want: true},
		{name: "POST form", method: http.MethodPost, target: "/oauth2/logout", body: valid, ctype: "application/x-www-form-urlencoded", want: true},
		{name: "GET body", method: http.MethodGet, target: "/oauth2/logout", body: "state=x", want: false},
		{name: "POST query", method: http.MethodPost, target: "/oauth2/logout?state=x", body: valid, ctype: "application/x-www-form-urlencoded", want: false},
		{name: "POST wrong content type", method: http.MethodPost, target: "/oauth2/logout", body: valid, ctype: "text/plain", want: false},
		{name: "duplicate", method: http.MethodGet, target: "/oauth2/logout?state=x&state=y", want: false},
		{name: "unknown", method: http.MethodGet, target: "/oauth2/logout?unexpected=x", want: false},
		{name: "empty", method: http.MethodGet, target: "/oauth2/logout?state=", want: false},
		{name: "bad percent", method: http.MethodGet, target: "/oauth2/logout?state=%zz", want: false},
		{name: "NUL", method: http.MethodGet, target: "/oauth2/logout?state=%00", want: false},
		{name: "empty local request", method: http.MethodGet, target: "/oauth2/logout", want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.target, strings.NewReader(test.body))
			if test.ctype != "" {
				request.Header.Set("Content-Type", test.ctype)
			}
			_, err := parseRPLogoutHTTPRequest(httptest.NewRecorder(), request)
			if (err == nil) != test.want {
				t.Fatalf("error = %v, want accepted=%v", err, test.want)
			}
		})
	}
}

func TestParseRPLogoutHTTPRequestStrictBoundsAndUTF8(t *testing.T) {
	t.Parallel()
	for _, target := range []string{
		"/oauth2/logout?state=" + strings.Repeat("a", maxLogoutRequestBytes),
		"/oauth2/logout?state=%C0%AF",
		"/oauth2/logout?state=%E2%28%A1",
	} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		if _, err := parseRPLogoutHTTPRequest(httptest.NewRecorder(), request); err == nil {
			t.Errorf("oversized/malformed target accepted: %q", target[:shortPrefixLen(len(target), 80)])
		}
	}
	body := "state=" + strings.Repeat("a", maxLogoutRequestBytes)
	request := httptest.NewRequest(http.MethodPost, "/oauth2/logout", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, err := parseRPLogoutHTTPRequest(httptest.NewRecorder(), request); err == nil {
		t.Fatal("oversized POST accepted")
	}
}

func TestParseLogoutConfirmationFormExactSchema(t *testing.T) {
	t.Parallel()
	valid := "csrf_token=lc1_proof&decision=confirm"
	for _, test := range []struct {
		name  string
		body  string
		query string
		ctype string
		want  bool
	}{
		{name: "valid", body: valid, ctype: "application/x-www-form-urlencoded", want: true},
		{name: "cancel", body: "csrf_token=lc1_proof&decision=cancel", ctype: "application/x-www-form-urlencoded", want: true},
		{name: "duplicate", body: "csrf_token=lc1_proof&decision=confirm&decision=cancel", ctype: "application/x-www-form-urlencoded"},
		{name: "unknown", body: valid + "&transaction=x", ctype: "application/x-www-form-urlencoded"},
		{name: "empty", body: "csrf_token=&decision=confirm", ctype: "application/x-www-form-urlencoded"},
		{name: "bad decision", body: "csrf_token=lc1_proof&decision=yes", ctype: "application/x-www-form-urlencoded"},
		{name: "query", body: valid, query: "x=1", ctype: "application/x-www-form-urlencoded"},
		{name: "wrong type", body: valid, ctype: "application/json"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, oidc.LogoutConfirmPath+func() string {
				if test.query != "" {
					return "?" + test.query
				}
				return ""
			}(), strings.NewReader(test.body))
			if test.ctype != "" {
				request.Header.Set("Content-Type", test.ctype)
			}
			csrf, decision, err := parseLogoutConfirmationForm(httptest.NewRecorder(), request)
			if (err == nil) != test.want {
				t.Fatalf("csrf=%q decision=%q err=%v want=%v", csrf, decision, err, test.want)
			}
			if test.want && (csrf != "lc1_proof" || decision == "") {
				t.Fatalf("parsed form = %q/%q", csrf, decision)
			}
		})
	}
}

func shortPrefixLen(a, b int) int {
	if a < b {
		return a
	}
	return b
}
