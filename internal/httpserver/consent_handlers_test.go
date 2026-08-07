package httpserver

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/authflow"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/consent"
)

func TestParseConsentFormStrictBoundary(t *testing.T) {
	t.Parallel()
	valid := url.Values{"transaction": {"t1_opaque"}, "csrf_token": {"csrf_opaque"}, "decision": {"approve"}}
	tests := []struct {
		name        string
		target      string
		contentType string
		body        string
		duplicateCT bool
		valid       bool
	}{
		{name: "valid approve", target: "/consent", contentType: "application/x-www-form-urlencoded", body: valid.Encode(), valid: true},
		{name: "valid deny", target: "/consent", contentType: "application/x-www-form-urlencoded", body: strings.Replace(valid.Encode(), "approve", "deny", 1), valid: true},
		{name: "query rejected", target: "/consent?transaction=other", contentType: "application/x-www-form-urlencoded", body: valid.Encode()},
		{name: "wrong media type", target: "/consent", contentType: "application/json", body: valid.Encode()},
		{name: "media parameters rejected", target: "/consent", contentType: "application/x-www-form-urlencoded; charset=utf-8", body: valid.Encode()},
		{name: "duplicate content type", target: "/consent", contentType: "application/x-www-form-urlencoded", body: valid.Encode(), duplicateCT: true},
		{name: "extra field", target: "/consent", contentType: "application/x-www-form-urlencoded", body: valid.Encode() + "&scope=openid"},
		{name: "duplicate transaction", target: "/consent", contentType: "application/x-www-form-urlencoded", body: valid.Encode() + "&transaction=second"},
		{name: "unknown decision", target: "/consent", contentType: "application/x-www-form-urlencoded", body: strings.Replace(valid.Encode(), "approve", "maybe", 1)},
		{name: "whitespace token", target: "/consent", contentType: "application/x-www-form-urlencoded", body: strings.Replace(valid.Encode(), "t1_opaque", "+t1_opaque", 1)},
		{name: "oversized", target: "/consent", contentType: "application/x-www-form-urlencoded", body: valid.Encode() + "&padding=" + strings.Repeat("x", maxConsentBodyBytes)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest(http.MethodPost, test.target, strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			if test.duplicateCT {
				request.Header.Add("Content-Type", test.contentType)
			}
			_, err := parseConsentForm(httptest.NewRecorder(), request)
			if (err == nil) != test.valid {
				t.Fatalf("parseConsentForm() error = %v, valid=%v", err, test.valid)
			}
		})
	}
}

func TestConsentTemplateEscapesClientAndUsesFixedScopeCopy(t *testing.T) {
	t.Parallel()
	templates, err := template.ParseFS(templateFiles, "templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	handler := &applicationHandler{templates: templates}
	transaction := authflow.Transaction{RedirectURI: "https://client.example.test/callback", Scopes: []string{"email", "openid", "profile"}}
	clientValue := clientdomain.Client{Name: `<img src=x onerror="alert(1)">`}
	evaluation := consent.Evaluation{AlreadyGranted: []string{"openid"}, NewScopes: []string{"email", "profile"}}
	request := httptest.NewRequest(http.MethodGet, "/consent?lang=en", nil)
	response := httptest.NewRecorder()
	handler.renderConsent(response, request, clientValue, transaction, evaluation, "t1_canary", "csrf_canary")
	body := response.Body.String()
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d headers=%v", response.Code, response.Header())
	}
	if policy := response.Header().Get("Content-Security-Policy"); !strings.Contains(policy, "form-action 'self' https://client.example.test") {
		t.Fatalf("Consent CSP did not allow the verified callback origin: %q", policy)
	}
	if strings.Contains(body, `<img src=x`) || !strings.Contains(body, "&lt;img src=x") {
		t.Fatalf("Client name was not HTML escaped: %s", body)
	}
	for _, fixed := range []string{"Basic identity", "Profile", "Email", "Previously granted", "New request"} {
		if !strings.Contains(body, fixed) {
			t.Errorf("fixed Consent copy %q missing: %s", fixed, body)
		}
	}
	if !strings.Contains(body, `name="transaction" value="t1_canary"`) || !strings.Contains(body, `name="csrf_token" value="csrf_canary"`) {
		t.Fatal("Consent form lacks server-restored opaque values")
	}
}

func TestAuthorizationReauthenticationCompletesAfterFreshLogin(t *testing.T) {
	t.Parallel()
	created := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	zero := uint32(0)
	sixty := uint32(60)
	tests := []struct {
		name          string
		transaction   authflow.Transaction
		authenticated time.Time
		now           time.Time
		want          bool
	}{
		{name: "prompt login with old Session", transaction: authflow.Transaction{CreatedAt: created, Prompts: []string{"login"}}, authenticated: created.Add(-time.Second), now: created, want: true},
		{name: "prompt login after reauthentication", transaction: authflow.Transaction{CreatedAt: created, Prompts: []string{"login"}}, authenticated: created.Add(time.Second), now: created.Add(time.Second), want: false},
		{name: "max age zero with old Session", transaction: authflow.Transaction{CreatedAt: created, MaxAgeSeconds: &zero}, authenticated: created.Add(-time.Second), now: created, want: true},
		{name: "max age zero after reauthentication", transaction: authflow.Transaction{CreatedAt: created, MaxAgeSeconds: &zero}, authenticated: created.Add(time.Second), now: created.Add(time.Second), want: false},
		{name: "max age elapsed", transaction: authflow.Transaction{CreatedAt: created, MaxAgeSeconds: &sixty}, authenticated: created.Add(-2 * time.Minute), now: created, want: true},
		{name: "max age current", transaction: authflow.Transaction{CreatedAt: created, MaxAgeSeconds: &sixty}, authenticated: created.Add(-30 * time.Second), now: created, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := authorizationNeedsReauthentication(test.transaction, test.authenticated, test.now); got != test.want {
				t.Fatalf("authorizationNeedsReauthentication() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestValidConsentQueryRejectsClientControlledContext(t *testing.T) {
	t.Parallel()
	if !validConsentQuery(url.Values{"transaction": {"t1_value"}, "lang": {"zh-CN"}}) {
		t.Fatal("valid server transaction query rejected")
	}
	for _, values := range []url.Values{
		{}, {"transaction": {""}}, {"transaction": {"a", "b"}},
		{"transaction": {"t1_value"}, "client_id": {uuid.NewString()}},
		{"transaction": {"t1_value"}, "scope": {"openid"}},
	} {
		if validConsentQuery(values) {
			t.Errorf("unsafe Consent query accepted: %v", values)
		}
	}
}
