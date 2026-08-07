package httpserver

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/oidc"
)

func TestAuthenticationRateLimiterEnforcesPerClientBurstAndRefill(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 2, 10, 0, 0, 0, time.UTC)
	limiter := newAuthenticationRateLimiter(AuthenticationRateLimitConfig{
		PerMinute: 60, Burst: 2, GlobalPerSecond: 100, GlobalBurst: 100,
	}, now)
	address := netip.MustParseAddr("192.0.2.10")
	for request := 1; request <= 2; request++ {
		if !limiter.allow(address, now) {
			t.Fatalf("initial per-client burst request %d was not available", request)
		}
	}
	if limiter.allow(address, now) {
		t.Fatal("request beyond per-client burst was accepted")
	}
	if !limiter.allow(address, now.Add(time.Second)) {
		t.Fatal("per-client token did not refill at the configured rate")
	}
}

func TestAuthenticationRateLimiterEnforcesGlobalBudgetAcrossClients(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 2, 10, 0, 0, 0, time.UTC)
	limiter := newAuthenticationRateLimiter(AuthenticationRateLimitConfig{
		PerMinute: 600, Burst: 10, GlobalPerSecond: 1, GlobalBurst: 2,
	}, now)
	if !limiter.allow(netip.MustParseAddr("192.0.2.1"), now) ||
		!limiter.allow(netip.MustParseAddr("192.0.2.2"), now) {
		t.Fatal("initial global burst was not available")
	}
	if limiter.allow(netip.MustParseAddr("192.0.2.3"), now) {
		t.Fatal("request beyond global burst was accepted")
	}
	if !limiter.allow(netip.MustParseAddr("192.0.2.3"), now.Add(time.Second)) {
		t.Fatal("global token did not refill at the configured rate")
	}
}

func TestAuthenticationRateLimiterBoundsAndSweepsClientEntries(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 2, 10, 0, 0, 0, time.UTC)
	limiter := newAuthenticationRateLimiter(AuthenticationRateLimitConfig{
		PerMinute: 60, Burst: 1, GlobalPerSecond: 100_000, GlobalBurst: 100_000,
	}, now)
	for index := 0; index < maxAuthRateLimitEntries; index++ {
		address := netip.AddrFrom4([4]byte{198, 18, byte(index >> 8), byte(index)})
		if !limiter.allow(address, now) {
			t.Fatalf("client entry %d was unexpectedly rejected", index)
		}
	}
	if got := len(limiter.clients); got != maxAuthRateLimitEntries {
		t.Fatalf("client entry count = %d, want %d", got, maxAuthRateLimitEntries)
	}
	if limiter.allow(netip.MustParseAddr("203.0.113.1"), now) {
		t.Fatal("new client was accepted after the bounded map filled")
	}
	later := now.Add(authRateEntryTTL + time.Second)
	if !limiter.allow(netip.MustParseAddr("203.0.113.1"), later) {
		t.Fatal("expired client entries were not swept")
	}
	if got := len(limiter.clients); got != 1 {
		t.Fatalf("client entry count after sweep = %d, want 1", got)
	}
}

func TestAuthenticationRateLimiterDoesNotRescanFullTableBeforeScheduledSweep(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 2, 10, 0, 0, 0, time.UTC)
	limiter := newAuthenticationRateLimiter(AuthenticationRateLimitConfig{
		PerMinute: 60, Burst: 1, GlobalPerSecond: 100_000, GlobalBurst: 100_000,
	}, now)
	staleAddress := netip.MustParseAddr("198.18.0.1")
	for index := 0; index < maxAuthRateLimitEntries; index++ {
		address := netip.AddrFrom4([4]byte{198, 18, byte(index >> 8), byte(index)})
		limiter.clients[address] = tokenBucket{tokens: 1, last: now, lastSeen: now}
	}
	stale := limiter.clients[staleAddress]
	stale.lastSeen = now.Add(-authRateEntryTTL - time.Second)
	limiter.clients[staleAddress] = stale

	newAddress := netip.MustParseAddr("203.0.113.1")
	if limiter.allow(newAddress, now) {
		t.Fatal("new client was accepted while the bounded table was full")
	}
	if _, exists := limiter.clients[staleAddress]; !exists {
		t.Fatal("full table was swept before the scheduled bounded cadence")
	}
	if !limiter.allow(newAddress, now.Add(authRateSweepInterval)) {
		t.Fatal("scheduled sweep did not retire an idle entry for a new client")
	}
}

func TestAuthenticationRateLimiterEnforcesAuthenticatedClientBuckets(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 2, 10, 0, 0, 0, time.UTC)
	limiter := newAuthenticationRateLimiter(AuthenticationRateLimitConfig{
		PerMinute: 60, Burst: 1, GlobalPerSecond: 100, GlobalBurst: 100,
	}, now)
	first := uuid.New()
	second := uuid.New()
	if !limiter.allowClient(first, now) {
		t.Fatal("authenticated Client's initial bucket was not available")
	}
	if limiter.allowClient(first, now) {
		t.Fatal("authenticated Client exceeded its bucket")
	}
	if !limiter.allowClient(second, now) {
		t.Fatal("authenticated Client buckets were not isolated")
	}
	if !limiter.allowClient(first, now.Add(time.Second)) {
		t.Fatal("authenticated Client bucket did not refill")
	}
}

func TestAuthenticationRateLimitHTTPContract(t *testing.T) {
	t.Parallel()

	templates, err := template.ParseFS(templateFiles, "templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 2, 10, 0, 0, 0, time.UTC)
	limiter := newAuthenticationRateLimiter(AuthenticationRateLimitConfig{
		PerMinute: 1, Burst: 1, GlobalPerSecond: 10, GlobalBurst: 10,
	}, now)
	address := netip.MustParseAddr("192.0.2.10")
	if !limiter.allow(address, now) {
		t.Fatal("failed to consume setup token")
	}
	handler := &applicationHandler{authLimiter: limiter, now: func() time.Time { return now }, templates: templates}

	for _, path := range []string{"/login", "/register", oidc.AuthorizePath} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.RemoteAddr = address.String() + ":1234"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusTooManyRequests {
			t.Fatalf("%s status = %d, want 429: %s", path, response.Code, response.Body.String())
		}
		if response.Header().Get("Retry-After") != "60" || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s rate-limit headers = %v", path, response.Header())
		}
		if !strings.Contains(response.Body.String(), "temporarily_unavailable") {
			t.Fatalf("%s response lacks bounded error: %s", path, response.Body.String())
		}
	}

	request := httptest.NewRequest(http.MethodGet, oidc.TokenPath, nil)
	request.RemoteAddr = address.String() + ":1234"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code == http.StatusTooManyRequests {
		t.Fatal("non-browser token endpoint was unexpectedly subject to the authentication-form limiter")
	}
}

func TestOAuthLifecycleRateLimitHTTPContract(t *testing.T) {
	t.Parallel()

	templates, err := template.ParseFS(templateFiles, "templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 2, 10, 0, 0, 0, time.UTC)
	address := netip.MustParseAddr("192.0.2.20")
	cases := []struct {
		name        string
		method      string
		path        string
		wantContent string
		wantBearer  bool
		wantJSON    bool
	}{
		{name: "token", method: http.MethodPost, path: oidc.TokenPath, wantContent: "application/json", wantJSON: true},
		{name: "revocation", method: http.MethodPost, path: oidc.RevocationPath, wantContent: "application/json", wantJSON: true},
		{name: "introspection", method: http.MethodPost, path: oidc.IntrospectionPath, wantContent: "application/json", wantJSON: true},
		{name: "userinfo get", method: http.MethodGet, path: oidc.UserInfoPath, wantContent: "application/json", wantBearer: true, wantJSON: true},
		{name: "userinfo post", method: http.MethodPost, path: oidc.UserInfoPath, wantContent: "application/json", wantBearer: true, wantJSON: true},
		{name: "logout get", method: http.MethodGet, path: oidc.LogoutPath, wantContent: "text/html"},
		{name: "logout post", method: http.MethodPost, path: oidc.LogoutPath, wantContent: "text/html"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			limiter := newAuthenticationRateLimiter(AuthenticationRateLimitConfig{
				PerMinute: 60, Burst: 1, GlobalPerSecond: 100, GlobalBurst: 100,
			}, now)
			if !limiter.allow(address, now) {
				t.Fatal("failed to consume setup token")
			}
			handler := &applicationHandler{
				oauthLimiter: limiter,
				now:          func() time.Time { return now },
				templates:    templates,
			}
			request := httptest.NewRequest(testCase.method, testCase.path, nil)
			request.RemoteAddr = address.String() + ":1234"
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusTooManyRequests {
				t.Fatalf("status = %d, want 429: %s", response.Code, response.Body.String())
			}
			if response.Header().Get("Retry-After") != "1" ||
				response.Header().Get("Cache-Control") != "no-store" ||
				response.Header().Get("Pragma") != "no-cache" ||
				response.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Fatalf("rate-limit headers = %v", response.Header())
			}
			if !strings.HasPrefix(response.Header().Get("Content-Type"), testCase.wantContent) {
				t.Fatalf("Content-Type = %q, want %q", response.Header().Get("Content-Type"), testCase.wantContent)
			}
			if testCase.wantJSON {
				var body oauthErrorResponse
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatalf("JSON error response: %v; body=%s", err, response.Body.String())
				}
				if body.Error != "temporarily_unavailable" {
					t.Fatalf("error = %q, want temporarily_unavailable", body.Error)
				}
			}
			if testCase.wantBearer && response.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatalf("WWW-Authenticate = %q, want Bearer", response.Header().Get("WWW-Authenticate"))
			}
			if !testCase.wantBearer && response.Header().Get("WWW-Authenticate") != "" {
				t.Fatalf("unexpected WWW-Authenticate = %q", response.Header().Get("WWW-Authenticate"))
			}
			if testCase.wantContent == "text/html" && !strings.Contains(response.Body.String(), `data-error-code="temporarily_unavailable"`) {
				t.Fatalf("HTML response lacks bounded error code: %s", response.Body.String())
			}
		})
	}
}

func TestOAuthLifecycleRateLimiterIgnoresNonSensitiveMethods(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 2, 10, 0, 0, 0, time.UTC)
	address := netip.MustParseAddr("192.0.2.21")
	cases := []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: oidc.TokenPath},
		{method: http.MethodGet, path: oidc.RevocationPath},
		{method: http.MethodGet, path: oidc.IntrospectionPath},
		{method: http.MethodPut, path: oidc.UserInfoPath},
		{method: http.MethodPut, path: oidc.LogoutPath},
	}
	for _, testCase := range cases {
		t.Run(testCase.method+" "+testCase.path, func(t *testing.T) {
			limiter := newAuthenticationRateLimiter(AuthenticationRateLimitConfig{
				PerMinute: 60, Burst: 1, GlobalPerSecond: 100, GlobalBurst: 100,
			}, now)
			handler := &applicationHandler{oauthLimiter: limiter, now: func() time.Time { return now }}
			request := httptest.NewRequest(testCase.method, testCase.path, nil)
			request.RemoteAddr = address.String() + ":1234"
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code == http.StatusTooManyRequests {
				t.Fatalf("non-sensitive method was rate limited: %s", response.Body.String())
			}
			followup := httptest.NewRequest(http.MethodPost, oidc.TokenPath, nil)
			followup.RemoteAddr = address.String() + ":1234"
			followupResponse := httptest.NewRecorder()
			handler.ServeHTTP(followupResponse, followup)
			if followupResponse.Code == http.StatusTooManyRequests {
				t.Fatalf("non-sensitive method consumed the limiter token")
			}
		})
	}
}
