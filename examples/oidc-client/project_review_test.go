package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func TestProjectReviewRefreshMutationValidationAndProviderBoundary(t *testing.T) {
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/oauth2/token" {
			http.NotFound(writer, request)
			return
		}
		calls.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, projectReviewRefreshJSON(t, "project_review_access", "project_review_refresh", "offline_access openid"))
	}))
	defer provider.Close()

	now := time.Date(2026, time.August, 6, 12, 0, 0, 0, time.UTC)
	application, sessionValue, cfg := projectReviewApplication(t, provider, []string{"offline_access", "openid"}, now)
	validBody := url.Values{"csrf_token": {sessionValue.CSRFToken}}.Encode()

	invalid := []struct {
		name       string
		method     string
		body       string
		content    string
		origin     string
		referer    string
		wantStatus int
	}{
		{name: "GET", method: http.MethodGet, wantStatus: http.StatusMethodNotAllowed},
		{name: "missing CSRF", method: http.MethodPost, content: "application/x-www-form-urlencoded", origin: "http://127.0.0.1:8081", wantStatus: http.StatusBadRequest},
		{name: "wrong CSRF", method: http.MethodPost, body: url.Values{"csrf_token": {projectReviewOpaque(t, "csrf_")}}.Encode(), content: "application/x-www-form-urlencoded", origin: "http://127.0.0.1:8081", wantStatus: http.StatusConflict},
		{name: "wrong Origin", method: http.MethodPost, body: validBody, content: "application/x-www-form-urlencoded", origin: "https://evil.invalid", wantStatus: http.StatusBadRequest},
		{name: "wrong Referer", method: http.MethodPost, body: validBody, content: "application/x-www-form-urlencoded", referer: "https://evil.invalid/form", wantStatus: http.StatusBadRequest},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "/refresh", strings.NewReader(test.body))
			if test.content != "" {
				request.Header.Set("Content-Type", test.content)
			}
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			if test.referer != "" {
				request.Header.Set("Referer", test.referer)
			}
			request.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: sessionValue.ID})
			response := httptest.NewRecorder()
			application.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d want=%d", response.Code, test.wantStatus)
			}
			if got := calls.Load(); got != 0 {
				t.Fatalf("invalid refresh reached provider: calls=%d", got)
			}
		})
	}

	request := httptest.NewRequest(http.MethodPost, "/refresh", strings.NewReader(validBody))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://127.0.0.1:8081")
	request.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: sessionValue.ID})
	response := httptest.NewRecorder()
	application.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/" {
		t.Fatalf("valid refresh status=%d location=%s", response.Code, response.Header().Get("Location"))
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("valid refresh provider calls=%d want=1", got)
	}
	current, ok := application.sessions.get(sessionValue.ID, now)
	if !ok || current.AccessToken == sessionValue.AccessToken || current.RefreshToken == sessionValue.RefreshToken || current.RefreshInFlight != 0 {
		t.Fatal("valid refresh did not atomically replace the session credentials")
	}
}

func TestProjectReviewConcurrentRefreshClaimsOneProviderGeneration(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		call := calls.Add(1)
		if call == 1 {
			close(started)
			<-release
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, projectReviewRefreshJSON(t, "project_review_concurrent_access", "project_review_concurrent_refresh", "offline_access openid"))
	}))
	defer provider.Close()

	now := time.Date(2026, time.August, 6, 12, 1, 0, 0, time.UTC)
	application, sessionValue, cfg := projectReviewApplication(t, provider, []string{"offline_access", "openid"}, now)
	body := url.Values{"csrf_token": {sessionValue.CSRFToken}}.Encode()
	newRefreshRequest := func() *http.Request {
		request := httptest.NewRequest(http.MethodPost, "/refresh", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Origin", "http://127.0.0.1:8081")
		request.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: sessionValue.ID})
		return request
	}

	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		application.ServeHTTP(response, newRefreshRequest())
		firstDone <- response
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first refresh did not reach provider")
	}

	secondResponse := httptest.NewRecorder()
	application.ServeHTTP(secondResponse, newRefreshRequest())
	if secondResponse.Code != http.StatusConflict {
		t.Fatalf("second refresh status=%d want=%d", secondResponse.Code, http.StatusConflict)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("concurrent refresh provider calls=%d want=1", got)
	}

	close(release)
	var firstResponse *httptest.ResponseRecorder
	select {
	case firstResponse = <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first refresh did not complete")
	}
	if firstResponse.Code != http.StatusSeeOther || firstResponse.Header().Get("Location") != "/" {
		t.Fatalf("first refresh status=%d location=%s", firstResponse.Code, firstResponse.Header().Get("Location"))
	}
	current, ok := application.sessions.get(sessionValue.ID, now)
	if !ok || current.AccessToken == sessionValue.AccessToken || current.RefreshToken == sessionValue.RefreshToken || current.RefreshInFlight != 0 {
		t.Fatal("a failed concurrent claim overwrote the successful replacement")
	}
}

func TestProjectReviewRefreshHandlersPreserveLoginAndLogoutStateDuringProviderBlock(t *testing.T) {
	now := time.Date(2026, time.August, 6, 12, 1, 30, 0, time.UTC)
	providerStarted := make(chan struct{})
	releaseProvider := make(chan struct{})
	release := func() {
		select {
		case <-releaseProvider:
		default:
			close(releaseProvider)
		}
	}
	var refreshCalls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/oauth2/token" {
			http.NotFound(writer, request)
			return
		}
		refreshCalls.Add(1)
		_, _ = io.ReadAll(request.Body)
		close(providerStarted)
		select {
		case <-releaseProvider:
		case <-request.Context().Done():
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, projectReviewJSON(tokenResponse{
			AccessToken: "interleaving_replacement_access", RefreshToken: "interleaving_replacement_refresh",
			TokenType: "Bearer", ExpiresIn: 600, Scope: "offline_access openid",
		}))
	}))
	defer provider.Close()
	defer release()

	application, sessionValue, cfg := projectReviewApplication(t, provider, []string{"offline_access", "openid"}, now)
	body := url.Values{"csrf_token": {sessionValue.CSRFToken}}.Encode()
	newRefreshRequest := func() *http.Request {
		request := httptest.NewRequest(http.MethodPost, "/refresh", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Origin", "http://127.0.0.1:8081")
		request.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: sessionValue.ID})
		return request
	}
	refreshDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		application.ServeHTTP(response, newRefreshRequest())
		refreshDone <- response
	}()
	select {
	case <-providerStarted:
	case response := <-refreshDone:
		t.Fatalf("refresh returned before reaching Provider: status=%d", response.Code)
	case <-time.After(time.Second):
		t.Fatal("refresh did not reach the blocked Provider exchange")
	}
	claimed, ok := application.sessions.get(sessionValue.ID, now)
	if !ok || claimed.RefreshInFlight == 0 {
		t.Fatal("refresh generation was not claimed before Provider exchange")
	}

	loginRequest := httptest.NewRequest(http.MethodGet, "/login", nil)
	loginRequest.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: sessionValue.ID})
	loginResponse := httptest.NewRecorder()
	application.ServeHTTP(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusFound {
		t.Fatalf("login status=%d want=%d", loginResponse.Code, http.StatusFound)
	}
	loginLocation, err := url.Parse(loginResponse.Header().Get("Location"))
	if err != nil {
		t.Fatalf("login redirect parse failed: %v", err)
	}
	loginQuery := loginLocation.Query()
	loginState := loginQuery.Get("state")
	if loginLocation.String() == "" || loginQuery.Get("client_id") != cfg.ClientID || len(loginQuery["state"]) != 1 || !strings.HasPrefix(loginState, "state_") {
		t.Fatalf("login redirect did not carry a pending authorization state")
	}
	current, ok := application.sessions.get(sessionValue.ID, now)
	if !ok || current.Pending == nil || current.Pending.State != loginState || current.Pending.Nonce != loginQuery.Get("nonce") {
		t.Fatal("login handler did not bind its authorization state to the session")
	}

	logoutRequest := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(body))
	logoutRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	logoutRequest.Header.Set("Origin", "http://127.0.0.1:8081")
	logoutRequest.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: sessionValue.ID})
	logoutResponse := httptest.NewRecorder()
	application.ServeHTTP(logoutResponse, logoutRequest)
	if logoutResponse.Code != http.StatusOK || !strings.Contains(logoutResponse.Body.String(), `<form`) {
		t.Fatalf("logout status=%d want 200 form", logoutResponse.Code)
	}
	logoutStateMatch := regexp.MustCompile(`name="state" value="([^"]+)"`).FindStringSubmatch(logoutResponse.Body.String())
	if len(logoutStateMatch) != 2 || !strings.HasPrefix(logoutStateMatch[1], "logout_") {
		t.Fatal("logout handler did not render a bound return state")
	}
	logoutState := logoutStateMatch[1]
	current, ok = application.sessions.get(sessionValue.ID, now)
	if !ok || current.Pending == nil || current.Pending.State != loginState || current.PendingLogoutState != logoutState {
		t.Fatal("logout handler did not preserve and bind the session protocol states")
	}

	release()
	var refreshResponse *httptest.ResponseRecorder
	select {
	case refreshResponse = <-refreshDone:
	case <-time.After(time.Second):
		t.Fatal("refresh did not complete after releasing Provider")
	}
	if refreshResponse.Code != http.StatusSeeOther || refreshResponse.Header().Get("Location") != "/" {
		t.Fatalf("refresh status=%d location=%q", refreshResponse.Code, refreshResponse.Header().Get("Location"))
	}
	if refreshCalls.Load() != 1 {
		t.Fatalf("Provider refresh calls=%d want=1", refreshCalls.Load())
	}
	final, ok := application.sessions.get(sessionValue.ID, now)
	if !ok || final.AccessToken != "interleaving_replacement_access" || final.RefreshToken != "interleaving_replacement_refresh" || final.RefreshInFlight != 0 {
		t.Fatal("refresh replacement was not committed or left in flight")
	}
	if final.Pending == nil || final.Pending.State != loginState || final.PendingLogoutState != logoutState {
		t.Fatal("refresh replacement erased the login or logout state bound by concurrent handlers")
	}
}

func TestProjectReviewRefreshLoginLogoutInterleavingIsVersionBound(t *testing.T) {
	now := time.Date(2026, time.August, 6, 12, 2, 0, 0, time.UTC)
	store := newMemorySessions(rand.Reader)
	initial := projectReviewStoredSession(t, store, now, []string{"offline_access", "openid"})
	oldSnapshot := cloneBrowserSession(initial)

	attemptOne, err := store.claimRefresh(initial.ID, initial.CSRFToken, now)
	if err != nil {
		t.Fatal("initial refresh claim failed")
	}
	loginAttempt := authorizationAttempt{
		State: projectReviewOpaque(t, "state_"), Nonce: projectReviewOpaque(t, "nonce_"),
		Verifier: projectReviewOpaque(t, "verifier_"), CreatedAt: now,
	}
	if _, err := store.beginAuthorization(initial.ID, loginAttempt, now); err != nil {
		t.Fatal("login transition failed")
	}
	if _, err := store.completeWithTokens(oldSnapshot, jitIdentity{Key: projectReviewOpaque(t, "jit1_")}, tokenResponse{}, now); err == nil {
		t.Fatal("stale login snapshot was accepted")
	}

	firstReplacement := tokenResponse{
		AccessToken: projectReviewOpaque(t, "access_"), RefreshToken: projectReviewOpaque(t, "refresh_"),
		GrantedScopes: []string{"offline_access", "openid"},
	}
	if _, err := store.replaceRefresh(attemptOne, firstReplacement, now); err != nil {
		t.Fatal("refresh replacement failed")
	}
	current, ok := store.get(initial.ID, now)
	if !ok || current.Pending == nil || current.Pending.State != loginAttempt.State || current.AccessToken != firstReplacement.AccessToken || current.RefreshToken != firstReplacement.RefreshToken {
		t.Fatal("refresh replacement erased the newer login state")
	}
	if err := store.save(oldSnapshot, now); err == nil {
		t.Fatal("old snapshot was able to restore protocol state")
	}

	logoutState := projectReviewOpaque(t, "logout_")
	if _, err := store.beginLogout(current.ID, current.IDToken, current.CSRFToken, logoutState, now); err != nil {
		t.Fatal("logout transition failed")
	}
	attemptTwo, err := store.claimRefresh(current.ID, current.CSRFToken, now)
	if err != nil {
		t.Fatal("second refresh claim failed")
	}
	secondReplacement := tokenResponse{
		AccessToken: projectReviewOpaque(t, "access_"), RefreshToken: projectReviewOpaque(t, "refresh_"),
		GrantedScopes: []string{"offline_access", "openid"},
	}
	if _, err := store.replaceRefresh(attemptTwo, secondReplacement, now); err != nil {
		t.Fatal("second refresh replacement failed")
	}
	if _, err := store.replaceRefresh(attemptOne, tokenResponse{AccessToken: projectReviewOpaque(t, "stale_")}, now); err == nil {
		t.Fatal("stale refresh success overwrote a newer generation")
	}
	if err := store.failRefresh(attemptOne, now); err == nil {
		t.Fatal("stale refresh failure cleared a newer generation")
	}
	final, ok := store.get(current.ID, now)
	if !ok || final.AccessToken != secondReplacement.AccessToken || final.RefreshToken != secondReplacement.RefreshToken || final.Pending == nil || final.Pending.State != loginAttempt.State || final.PendingLogoutState != logoutState || final.RefreshInFlight != 0 {
		t.Fatal("stale refresh outcome changed the current login/logout state")
	}
}

func TestProjectReviewProviderInvalidGrantRequiresStrict400JSON(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
		wantInvalid bool
	}{
		{name: "strict invalid grant", status: http.StatusBadRequest, contentType: "application/json", body: `{"error":"invalid_grant"}`, wantInvalid: true},
		{name: "status five hundred", status: http.StatusInternalServerError, contentType: "application/json", body: `{"error":"invalid_grant"}`},
		{name: "missing content type", status: http.StatusBadRequest, body: `{"error":"invalid_grant"}`},
		{name: "unknown field", status: http.StatusBadRequest, contentType: "application/json", body: `{"error":"invalid_grant","unknown":"x"}`},
		{name: "multiple values", status: http.StatusBadRequest, contentType: "application/json", body: `{"error":"invalid_grant"}{"error":"invalid_grant"}`},
		{name: "different oauth error", status: http.StatusBadRequest, contentType: "application/json", body: `{"error":"temporarily_unavailable"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				if test.contentType != "" {
					writer.Header().Set("Content-Type", test.contentType)
				}
				writer.WriteHeader(test.status)
				_, _ = io.WriteString(writer, test.body)
			}))
			defer provider.Close()
			cfg := exampleTestConfig(t, provider.URL)
			var destination providerOAuthErrorResponse
			err := providerJSON(context.Background(), provider.Client(), cfg, http.MethodPost, provider.URL+"/oauth2/token", strings.NewReader("grant_type=refresh_token"), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, &destination)
			if test.wantInvalid {
				if !errors.Is(err, errProviderInvalidGrant) {
					t.Fatal("strict invalid_grant response was not classified as invalid_grant")
				}
			} else if err == nil || errors.Is(err, errProviderInvalidGrant) {
				t.Fatal("non-strict provider error was misclassified")
			}
		})
	}
}

func TestProjectReviewRefreshErrorsCleanupWithoutRetry(t *testing.T) {
	tests := []struct {
		name          string
		wantLogin     bool
		handler       func(*testing.T, http.ResponseWriter, *http.Request)
		clientTimeout time.Duration
	}{
		{name: "invalid grant", wantLogin: true, handler: func(_ *testing.T, writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(writer, `{"error":"invalid_grant"}`)
		}},
		{name: "provider five hundred", handler: func(_ *testing.T, writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(writer, `{"error":"invalid_grant"}`)
		}},
		{name: "malformed success", handler: func(_ *testing.T, writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"access_token":`)
		}},
		{name: "timeout", clientTimeout: 25 * time.Millisecond, handler: func(_ *testing.T, _ http.ResponseWriter, request *http.Request) {
			_, _ = io.Copy(io.Discard, request.Body)
			<-request.Context().Done()
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				calls.Add(1)
				test.handler(t, writer, request)
			}))
			defer provider.Close()
			now := time.Date(2026, time.August, 6, 12, 3, 0, 0, time.UTC)
			client := provider.Client()
			if test.clientTimeout != 0 {
				client = &http.Client{Transport: client.Transport, Timeout: test.clientTimeout}
			}
			application, sessionValue, cfg := projectReviewApplicationWithClient(t, provider, []string{"offline_access", "openid"}, now, client)
			body := url.Values{"csrf_token": {sessionValue.CSRFToken}}.Encode()
			request := httptest.NewRequest(http.MethodPost, "/refresh", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.Header.Set("Origin", "http://127.0.0.1:8081")
			request.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: sessionValue.ID})
			response := httptest.NewRecorder()
			application.ServeHTTP(response, request)
			if calls.Load() != 1 {
				t.Fatalf("provider calls=%d want=1", calls.Load())
			}
			location := response.Header().Get("Location")
			if response.Code != http.StatusSeeOther || (test.wantLogin && location != "/login?prompt=login") || (!test.wantLogin && location != "/?result=reauthorization_required") {
				t.Fatalf("refresh error status=%d location=%s", response.Code, location)
			}
			current, ok := application.sessions.get(sessionValue.ID, now)
			if !ok || current.AccessToken != "" || current.RefreshToken != "" || len(current.GrantedScopes) != 0 || current.RefreshInFlight != 0 {
				t.Fatal("ambiguous refresh outcome did not conditionally clear local authority")
			}
		})
	}
}

func TestProjectReviewAuthorizationAndRefreshUseActualGrantedScope(t *testing.T) {
	quadrants := []struct {
		name      string
		scope     string
		refresh   bool
		wantError bool
	}{
		{name: "offline with refresh", scope: "offline_access openid", refresh: true},
		{name: "offline without refresh", scope: "offline_access openid", wantError: true},
		{name: "online without refresh", scope: "openid"},
		{name: "online with refresh", scope: "openid", refresh: true, wantError: true},
	}
	for _, quadrant := range quadrants {
		for _, refreshExchange := range []bool{false, true} {
			name := "authorization/" + quadrant.name
			if refreshExchange {
				name = "refresh/" + quadrant.name
			}
			t.Run(name, func(t *testing.T) {
				provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					if request.URL.Path != "/oauth2/token" {
						http.NotFound(writer, request)
						return
					}
					writer.Header().Set("Content-Type", "application/json")
					response := tokenResponse{
						AccessToken: projectReviewOpaque(t, "access_"), TokenType: "Bearer", ExpiresIn: 600,
						Scope: quadrant.scope,
					}
					if !refreshExchange {
						response.IDToken = projectReviewOpaque(t, "id_")
					}
					if quadrant.refresh {
						response.RefreshToken = projectReviewOpaque(t, "refresh_")
					}
					_, _ = io.WriteString(writer, projectReviewJSON(response))
				}))
				defer provider.Close()
				cfg := exampleTestConfig(t, provider.URL)
				cfg.Scopes = []string{"offline_access", "openid"}
				metadata := exampleTestMetadata(provider.URL)
				var err error
				if refreshExchange {
					_, err = exchangeRefreshToken(context.Background(), provider.Client(), cfg, metadata, projectReviewOpaque(t, "refresh_"), []string{"offline_access", "openid"})
				} else {
					_, err = exchangeAuthorizationCode(context.Background(), provider.Client(), cfg, metadata, projectReviewOpaque(t, "code_"), projectReviewOpaque(t, "verifier_"))
				}
				if (err != nil) != quadrant.wantError {
					t.Fatalf("scope/refresh quadrant error=%t want=%t", err != nil, quadrant.wantError)
				}
			})
		}
	}

	// Refresh responses may narrow an existing authority, but may not expand it.
	provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, projectReviewRefreshJSON(t, "access_", "", "openid"))
	}))
	defer provider.Close()
	cfg := exampleTestConfig(t, provider.URL)
	cfg.Scopes = []string{"offline_access", "openid"}
	metadata := exampleTestMetadata(provider.URL)
	if _, err := exchangeRefreshToken(context.Background(), provider.Client(), cfg, metadata, projectReviewOpaque(t, "refresh_"), []string{"offline_access", "openid"}); err != nil {
		t.Fatal("scope reduction without offline_access was rejected")
	}

	expansion := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, projectReviewRefreshJSON(t, "access_", "", "email openid"))
	}))
	defer expansion.Close()
	cfg = exampleTestConfig(t, expansion.URL)
	cfg.Scopes = []string{"email", "offline_access", "openid"}
	metadata = exampleTestMetadata(expansion.URL)
	if _, err := exchangeRefreshToken(context.Background(), expansion.Client(), cfg, metadata, projectReviewOpaque(t, "refresh_"), []string{"offline_access", "openid"}); err == nil {
		t.Fatal("refresh scope expansion was accepted")
	}
}

func TestProjectReviewPostLogoutRedirectDefaultsAndRejectsUnsafeOverrides(t *testing.T) {
	setValidExampleEnvironment(t)
	t.Setenv("EXAMPLE_POST_LOGOUT_REDIRECT_URI", "")
	config, err := loadExampleConfig()
	if err != nil || config.PostLogoutRedirectURI != "http://127.0.0.1:8081/logged-out" {
		t.Fatal("default post-logout redirect was not derived from the callback origin")
	}

	for _, value := range []string{
		"http://localhost:8081/logged-out",
		"http://127.0.0.1:8081/callback",
		"http://127.0.0.1:8081/logged-out?next=unsafe",
	} {
		t.Run("reject override", func(t *testing.T) {
			setValidExampleEnvironment(t)
			t.Setenv("EXAMPLE_POST_LOGOUT_REDIRECT_URI", value)
			if _, err := loadExampleConfig(); err == nil {
				t.Fatal("unsafe post-logout redirect was accepted")
			}
		})
	}
}

func TestProjectReviewLogoutMutationRequiresCSRFAndSameOrigin(t *testing.T) {
	provider := httptest.NewServer(http.NotFoundHandler())
	defer provider.Close()
	now := time.Date(2026, time.August, 6, 12, 4, 0, 0, time.UTC)
	application, sessionValue, cfg := projectReviewApplication(t, provider, []string{"openid"}, now)
	body := url.Values{"csrf_token": {sessionValue.CSRFToken}}.Encode()

	invalid := []struct {
		name       string
		method     string
		body       string
		origin     string
		referer    string
		wantStatus int
	}{
		{name: "GET", method: http.MethodGet, wantStatus: http.StatusMethodNotAllowed},
		{name: "missing CSRF", method: http.MethodPost, origin: "http://127.0.0.1:8081", wantStatus: http.StatusBadRequest},
		{name: "wrong CSRF", method: http.MethodPost, body: url.Values{"csrf_token": {projectReviewOpaque(t, "csrf_")}}.Encode(), origin: "http://127.0.0.1:8081", wantStatus: http.StatusConflict},
		{name: "wrong Origin", method: http.MethodPost, body: body, origin: "https://evil.invalid", wantStatus: http.StatusBadRequest},
		{name: "wrong Referer", method: http.MethodPost, body: body, referer: "https://evil.invalid/form", wantStatus: http.StatusBadRequest},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "/logout", strings.NewReader(test.body))
			if test.method == http.MethodPost {
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			if test.referer != "" {
				request.Header.Set("Referer", test.referer)
			}
			request.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: sessionValue.ID})
			response := httptest.NewRecorder()
			application.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d want=%d", response.Code, test.wantStatus)
			}
			if _, ok := application.sessions.get(sessionValue.ID, now); !ok {
				t.Fatal("invalid logout mutation destroyed the local session")
			}
		})
	}

	valid := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(body))
	valid.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	valid.Header.Set("Origin", "http://127.0.0.1:8081")
	valid.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: sessionValue.ID})
	validResponse := httptest.NewRecorder()
	application.ServeHTTP(validResponse, valid)
	if validResponse.Code != http.StatusOK || !strings.Contains(validResponse.Body.String(), "<form") {
		t.Fatalf("valid logout status=%d", validResponse.Code)
	}
	current, ok := application.sessions.get(sessionValue.ID, now)
	if !ok || current.PendingLogoutState == "" {
		t.Fatal("valid logout did not bind server-side return state")
	}
}

func TestProjectReviewCallbackFailuresRevokeIssuedTokens(t *testing.T) {
	tests := []struct {
		name        string
		refresh     bool
		invalidID   bool
		invalidUser bool
		wantHint    string
		wantToken   string
		wantHTTP    int
	}{
		{name: "ID verify with refresh", refresh: true, invalidID: true, wantHint: "refresh_token", wantToken: "callback_refresh_token", wantHTTP: http.StatusBadGateway},
		{name: "UserInfo with refresh", refresh: true, invalidUser: true, wantHint: "refresh_token", wantToken: "callback_refresh_token", wantHTTP: http.StatusBadGateway},
		{name: "UserInfo without refresh", invalidUser: true, wantHint: "access_token", wantToken: "callback_access_token", wantHTTP: http.StatusBadGateway},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			timeNow := time.Date(2026, time.August, 6, 13, 0, 0, 0, time.UTC)
			private := exampleTestRSAKey(t)
			kid := exampleTestKID(private)
			const (
				state    = "state_callback_revoke"
				nonce    = "nonce_callback_revoke"
				verifier = "verifier_callback_revoke"
				code     = "code_callback_revoke"
				subject  = "subject_callback_revoke"
			)
			var issuer string
			var revocationCount atomic.Int32
			revocations := make(chan projectReviewRevocationCall, 2)
			provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				switch request.URL.Path {
				case "/oauth2/token":
					scope := "openid"
					if test.refresh {
						scope = "offline_access openid"
					}
					response := tokenResponse{
						AccessToken: "callback_access_token", TokenType: "Bearer", ExpiresIn: 600,
						Scope: scope,
					}
					if test.refresh {
						response.RefreshToken = "callback_refresh_token"
					}
					if test.invalidID {
						response.IDToken = "not-a-valid-id-token"
					} else {
						claims := idTokenClaims{
							Issuer: issuer, Subject: subject, Audience: "ois_cli_example", AuthorizedParty: "ois_cli_example",
							ExpiresAt: timeNow.Add(5 * time.Minute).Unix(), IssuedAt: timeNow.Unix(), AuthTime: timeNow.Unix(), Nonce: nonce,
						}
						response.IDToken = signExampleJWT(t, private, kid, "JWT", claims)
					}
					_, _ = io.WriteString(writer, projectReviewJSON(response))
				case "/oauth2/jwks":
					_, _ = io.WriteString(writer, projectReviewJSON(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
						Key: &private.PublicKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig",
					}}}))
				case "/oauth2/userinfo":
					if test.invalidUser {
						_, _ = io.WriteString(writer, projectReviewJSON(userInfoResponse{Subject: "different_subject"}))
						return
					}
					_, _ = io.WriteString(writer, projectReviewJSON(userInfoResponse{Subject: subject}))
				case "/oauth2/revoke":
					revocationCount.Add(1)
					call := projectReviewRecordRevocation(request)
					revocations <- call
					writer.WriteHeader(http.StatusOK)
				default:
					http.NotFound(writer, request)
				}
			}))
			defer provider.Close()
			issuer = provider.URL
			scopes := []string{"openid"}
			if test.refresh {
				scopes = []string{"offline_access", "openid"}
			}
			application, sessionValue, cfg := projectReviewPendingCallbackApplication(t, provider, scopes, timeNow, state, nonce, verifier)
			request := httptest.NewRequest(http.MethodGet, "/callback?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), nil)
			request.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: sessionValue.ID})
			response := httptest.NewRecorder()
			application.ServeHTTP(response, request)
			if response.Code != test.wantHTTP {
				t.Fatalf("callback status=%d want=%d", response.Code, test.wantHTTP)
			}
			if revocationCount.Load() != 1 {
				t.Fatalf("revocation calls=%d want=1", revocationCount.Load())
			}
			select {
			case call := <-revocations:
				if call.hint != test.wantHint || call.token != test.wantToken {
					t.Fatal("revocation did not use the expected issued token hint")
				}
			case <-time.After(time.Second):
				t.Fatal("revocation request was not recorded")
			}
		})
	}
}

func TestProjectReviewCallbackCASFailureRevokesTokensAfterProviderBlock(t *testing.T) {
	timeNow := time.Date(2026, time.August, 6, 13, 1, 0, 0, time.UTC)
	private := exampleTestRSAKey(t)
	kid := exampleTestKID(private)
	const (
		state    = "state_callback_cas"
		nonce    = "nonce_callback_cas"
		verifier = "verifier_callback_cas"
		code     = "code_callback_cas"
		subject  = "subject_callback_cas"
	)
	var issuer string
	userinfoStarted := make(chan struct{})
	releaseUserinfo := make(chan struct{})
	revocations := make(chan projectReviewRevocationCall, 1)
	provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/oauth2/token":
			claims := idTokenClaims{
				Issuer: issuer, Subject: subject, Audience: "ois_cli_example", AuthorizedParty: "ois_cli_example",
				ExpiresAt: timeNow.Add(5 * time.Minute).Unix(), IssuedAt: timeNow.Unix(), AuthTime: timeNow.Unix(), Nonce: nonce,
			}
			_, _ = io.WriteString(writer, projectReviewJSON(tokenResponse{
				AccessToken: "callback_cas_access", RefreshToken: "callback_cas_refresh", TokenType: "Bearer", ExpiresIn: 600,
				IDToken: signExampleJWT(t, private, kid, "JWT", claims), Scope: "offline_access openid",
			}))
		case "/oauth2/jwks":
			_, _ = io.WriteString(writer, projectReviewJSON(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
				Key: &private.PublicKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig",
			}}}))
		case "/oauth2/userinfo":
			close(userinfoStarted)
			<-releaseUserinfo
			_, _ = io.WriteString(writer, projectReviewJSON(userInfoResponse{Subject: subject}))
		case "/oauth2/revoke":
			revocations <- projectReviewRecordRevocation(request)
			writer.WriteHeader(http.StatusOK)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer provider.Close()
	issuer = provider.URL
	application, sessionValue, cfg := projectReviewPendingCallbackApplication(t, provider, []string{"offline_access", "openid"}, timeNow, state, nonce, verifier)
	request := httptest.NewRequest(http.MethodGet, "/callback?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), nil)
	request.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: sessionValue.ID})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		application.ServeHTTP(response, request)
		done <- response
	}()
	select {
	case <-userinfoStarted:
	case <-time.After(time.Second):
		t.Fatal("callback did not reach the blocked UserInfo request")
	}
	changed, err := application.sessions.beginAuthorization(sessionValue.ID, authorizationAttempt{
		State: "state_newer", Nonce: "nonce_newer", Verifier: "verifier_newer", CreatedAt: timeNow,
	}, timeNow)
	if err != nil || changed.Pending == nil || changed.Pending.State != "state_newer" {
		t.Fatal("local callback state did not change while Provider was blocked")
	}
	close(releaseUserinfo)
	var response *httptest.ResponseRecorder
	select {
	case response = <-done:
	case <-time.After(time.Second):
		t.Fatal("callback did not complete after releasing UserInfo")
	}
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("callback CAS failure status=%d want=%d", response.Code, http.StatusInternalServerError)
	}
	select {
	case call := <-revocations:
		if call.hint != "refresh_token" || call.token != "callback_cas_refresh" {
			t.Fatal("callback CAS failure did not revoke the replacement Refresh Token")
		}
	case <-time.After(time.Second):
		t.Fatal("callback CAS failure did not trigger revocation")
	}
}

func TestProjectReviewRefreshCASFailureRevokesReplacementAfterProviderBlock(t *testing.T) {
	timeNow := time.Date(2026, time.August, 6, 13, 2, 0, 0, time.UTC)
	tokenStarted := make(chan struct{})
	releaseToken := make(chan struct{})
	revocations := make(chan projectReviewRevocationCall, 1)
	provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/oauth2/token":
			close(tokenStarted)
			<-releaseToken
			_, _ = io.WriteString(writer, projectReviewJSON(tokenResponse{
				AccessToken: "replacement_access", RefreshToken: "replacement_refresh", TokenType: "Bearer", ExpiresIn: 600,
				Scope: "offline_access openid",
			}))
		case "/oauth2/revoke":
			revocations <- projectReviewRecordRevocation(request)
			writer.WriteHeader(http.StatusOK)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer provider.Close()
	application, sessionValue, cfg := projectReviewApplication(t, provider, []string{"offline_access", "openid"}, timeNow)
	body := url.Values{"csrf_token": {sessionValue.CSRFToken}}.Encode()
	request := httptest.NewRequest(http.MethodPost, "/refresh", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://127.0.0.1:8081")
	request.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: sessionValue.ID})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		application.ServeHTTP(response, request)
		done <- response
	}()
	select {
	case <-tokenStarted:
	case <-time.After(time.Second):
		t.Fatal("refresh did not reach the blocked Provider exchange")
	}
	current, ok := application.sessions.get(sessionValue.ID, timeNow)
	if !ok || current.RefreshInFlight == 0 {
		t.Fatal("refresh generation was not claimed before Provider exchange")
	}
	if err := application.sessions.failRefresh(refreshAttempt{SessionID: sessionValue.ID, Version: current.RefreshInFlight}, timeNow); err != nil {
		t.Fatal("local refresh state did not change while Provider was blocked")
	}
	close(releaseToken)
	var response *httptest.ResponseRecorder
	select {
	case response = <-done:
	case <-time.After(time.Second):
		t.Fatal("refresh did not complete after releasing Provider")
	}
	if response.Code != http.StatusConflict {
		t.Fatalf("refresh CAS failure status=%d want=%d", response.Code, http.StatusConflict)
	}
	select {
	case call := <-revocations:
		if call.hint != "refresh_token" || call.token != "replacement_refresh" {
			t.Fatal("refresh CAS failure did not revoke the replacement Refresh Token")
		}
	case <-time.After(time.Second):
		t.Fatal("refresh CAS failure did not trigger revocation")
	}
}

func TestProjectReviewRefreshExchangeFailureDoesNotRevokePresentedToken(t *testing.T) {
	var revocationCount atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/oauth2/token":
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(writer, `{"error":"temporarily_unavailable"}`)
		case "/oauth2/revoke":
			revocationCount.Add(1)
			writer.WriteHeader(http.StatusOK)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer provider.Close()
	timeNow := time.Date(2026, time.August, 6, 13, 3, 0, 0, time.UTC)
	application, sessionValue, cfg := projectReviewApplication(t, provider, []string{"offline_access", "openid"}, timeNow)
	body := url.Values{"csrf_token": {sessionValue.CSRFToken}}.Encode()
	request := httptest.NewRequest(http.MethodPost, "/refresh", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://127.0.0.1:8081")
	request.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: sessionValue.ID})
	response := httptest.NewRecorder()
	application.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/?result=reauthorization_required" {
		t.Fatalf("refresh exchange failure status=%d location=%s", response.Code, response.Header().Get("Location"))
	}
	if revocationCount.Load() != 0 {
		t.Fatalf("exchange failure issued %d revocation requests", revocationCount.Load())
	}
}

func TestProjectReviewProviderUsesExclusiveAuthenticationChannels(t *testing.T) {
	for _, test := range []struct {
		name   string
		secret string
		basic  bool
	}{
		{name: "public", basic: false},
		{name: "confidential", secret: "confidential-test-secret", basic: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var authFailures atomic.Int32
			provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				body, _ := io.ReadAll(request.Body)
				form, _ := url.ParseQuery(string(body))
				basicUser, basicPassword, hasBasic := request.BasicAuth()
				if test.basic {
					if !hasBasic || basicUser != "ois_cli_example" || basicPassword != test.secret || form.Get("client_id") != "" {
						authFailures.Add(1)
					}
				} else if hasBasic || request.Header.Get("Authorization") != "" || form.Get("client_id") != "ois_cli_example" {
					authFailures.Add(1)
				}
				switch request.URL.Path {
				case "/oauth2/token":
					if form.Get("grant_type") == "authorization_code" {
						_, _ = io.WriteString(writer, projectReviewJSON(tokenResponse{
							AccessToken: "auth_code_access", RefreshToken: "auth_code_refresh", TokenType: "Bearer", ExpiresIn: 600,
							IDToken: "auth_code_id", Scope: "offline_access openid",
						}))
					} else {
						_, _ = io.WriteString(writer, projectReviewJSON(tokenResponse{
							AccessToken: "auth_refresh_access", RefreshToken: "auth_refresh_refresh", TokenType: "Bearer", ExpiresIn: 600,
							Scope: "offline_access openid",
						}))
					}
				case "/oauth2/revoke":
					writer.WriteHeader(http.StatusOK)
				default:
					http.NotFound(writer, request)
				}
			}))
			defer provider.Close()
			cfg := exampleTestConfig(t, provider.URL)
			cfg.ClientSecret = test.secret
			cfg.Scopes = []string{"offline_access", "openid"}
			metadata := exampleTestMetadata(provider.URL)
			if _, err := exchangeAuthorizationCode(context.Background(), provider.Client(), cfg, metadata, "code", "verifier"); err != nil {
				t.Fatal("authorization code exchange failed")
			}
			if _, err := exchangeRefreshToken(context.Background(), provider.Client(), cfg, metadata, "presented_refresh", []string{"offline_access", "openid"}); err != nil {
				t.Fatal("refresh exchange failed")
			}
			if err := revokeProviderTokens(context.Background(), provider.Client(), cfg, metadata, tokenResponse{AccessToken: "access", RefreshToken: "refresh"}); err != nil {
				t.Fatal("revocation failed")
			}
			if authFailures.Load() != 0 {
				t.Fatalf("provider observed %d mixed or missing authentication channels", authFailures.Load())
			}
		})
	}
}

func TestProjectReviewRevocationRejectsProviderRedirect(t *testing.T) {
	var followed atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/oauth2/revoke" {
			writer.Header().Set("Location", "/oauth2/revoke-followed")
			writer.WriteHeader(http.StatusFound)
			return
		}
		if request.URL.Path == "/oauth2/revoke-followed" {
			followed.Add(1)
		}
		http.NotFound(writer, request)
	}))
	defer provider.Close()
	cfg := exampleTestConfig(t, provider.URL)
	metadata := exampleTestMetadata(provider.URL)
	if err := revokeProviderTokens(context.Background(), provider.Client(), cfg, metadata, tokenResponse{AccessToken: "access"}); err == nil {
		t.Fatal("provider redirect was accepted as a successful revocation")
	}
	if followed.Load() != 0 {
		t.Fatal("revocation client followed a provider redirect")
	}
}

func TestProjectReviewRevocationFailureAndTimeoutKeepCallbackHTTPFailure(t *testing.T) {
	for _, test := range []struct {
		name          string
		status        int
		block         bool
		clientTimeout time.Duration
	}{
		{name: "provider failure", status: http.StatusServiceUnavailable},
		{name: "timeout", block: true, clientTimeout: 100 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			timeNow := time.Date(2026, time.August, 6, 13, 4, 0, 0, time.UTC)
			var issuer string
			var revocationCount atomic.Int32
			private := exampleTestRSAKey(t)
			kid := exampleTestKID(private)
			const (
				state    = "state_callback_revoke_failure"
				nonce    = "nonce_callback_revoke_failure"
				verifier = "verifier_callback_revoke_failure"
				code     = "code_callback_revoke_failure"
			)
			provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				switch request.URL.Path {
				case "/oauth2/token":
					claims := idTokenClaims{
						Issuer: issuer, Subject: "subject_revoke_failure", Audience: "ois_cli_example", AuthorizedParty: "ois_cli_example",
						ExpiresAt: timeNow.Add(5 * time.Minute).Unix(), IssuedAt: timeNow.Unix(), AuthTime: timeNow.Unix(), Nonce: nonce,
					}
					_, _ = io.WriteString(writer, projectReviewJSON(tokenResponse{
						AccessToken: "revoke_failure_access", RefreshToken: "revoke_failure_refresh", TokenType: "Bearer", ExpiresIn: 600,
						IDToken: signExampleJWT(t, private, kid, "JWT", claims), Scope: "offline_access openid",
					}))
				case "/oauth2/jwks":
					_, _ = io.WriteString(writer, projectReviewJSON(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
						Key: &private.PublicKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig",
					}}}))
				case "/oauth2/userinfo":
					_, _ = io.WriteString(writer, projectReviewJSON(userInfoResponse{Subject: "unexpected_subject"}))
				case "/oauth2/revoke":
					revocationCount.Add(1)
					if test.block {
						_, _ = io.Copy(io.Discard, request.Body)
						<-request.Context().Done()
						return
					}
					writer.WriteHeader(test.status)
				default:
					http.NotFound(writer, request)
				}
			}))
			defer provider.Close()
			issuer = provider.URL
			client := provider.Client()
			if test.clientTimeout > 0 {
				client = &http.Client{Transport: client.Transport, Timeout: test.clientTimeout}
			}
			application, sessionValue, cfg := projectReviewPendingCallbackApplicationWithClient(t, provider, []string{"offline_access", "openid"}, timeNow, state, nonce, verifier, client)
			request := httptest.NewRequest(http.MethodGet, "/callback?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), nil)
			request.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: sessionValue.ID})
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				response := httptest.NewRecorder()
				application.ServeHTTP(response, request)
				done <- response
			}()
			select {
			case response := <-done:
				if response.Code != http.StatusBadGateway {
					t.Fatalf("callback status=%d want=%d", response.Code, http.StatusBadGateway)
				}
				if revocationCount.Load() != 1 {
					t.Fatalf("revocation calls=%d want=1", revocationCount.Load())
				}
			case <-time.After(time.Second):
				t.Fatal("callback did not complete after revocation failure")
			}
		})
	}
}

type projectReviewRevocationCall struct {
	token string
	hint  string
}

func projectReviewRecordRevocation(request *http.Request) projectReviewRevocationCall {
	body, _ := io.ReadAll(request.Body)
	form, _ := url.ParseQuery(string(body))
	return projectReviewRevocationCall{token: form.Get("token"), hint: form.Get("token_type_hint")}
}

func projectReviewPendingCallbackApplication(t *testing.T, provider *httptest.Server, scopes []string, now time.Time, state, nonce, verifier string) (*exampleApplication, browserSession, exampleConfig) {
	return projectReviewPendingCallbackApplicationWithClient(t, provider, scopes, now, state, nonce, verifier, provider.Client())
}

func projectReviewPendingCallbackApplicationWithClient(t *testing.T, provider *httptest.Server, scopes []string, now time.Time, state, nonce, verifier string, client *http.Client) (*exampleApplication, browserSession, exampleConfig) {
	t.Helper()
	cfg := exampleTestConfig(t, provider.URL)
	cfg.Scopes = append([]string(nil), scopes...)
	sessions := newMemorySessions(rand.Reader)
	sessionValue, err := sessions.create(now)
	if err != nil {
		t.Fatal("callback session setup failed")
	}
	sessionValue.Pending = &authorizationAttempt{State: state, Nonce: nonce, Verifier: verifier, CreatedAt: now}
	if err := sessions.save(sessionValue, now); err != nil {
		t.Fatal("callback pending state setup failed")
	}
	application, err := newExampleApplication(cfg, exampleTestMetadata(provider.URL), client, sessions)
	if err != nil {
		t.Fatal("example application setup failed")
	}
	application.now = func() time.Time { return now }
	return application, sessionValue, cfg
}

func projectReviewApplication(t *testing.T, provider *httptest.Server, scopes []string, now time.Time) (*exampleApplication, browserSession, exampleConfig) {
	return projectReviewApplicationWithClient(t, provider, scopes, now, provider.Client())
}

func projectReviewApplicationWithClient(t *testing.T, provider *httptest.Server, scopes []string, now time.Time, client *http.Client) (*exampleApplication, browserSession, exampleConfig) {
	t.Helper()
	cfg := exampleTestConfig(t, provider.URL)
	cfg.Scopes = append([]string(nil), scopes...)
	sessions := newMemorySessions(rand.Reader)
	sessionValue := projectReviewStoredSession(t, sessions, now, scopes)
	application, err := newExampleApplication(cfg, exampleTestMetadata(provider.URL), client, sessions)
	if err != nil {
		t.Fatal("example application setup failed")
	}
	application.now = func() time.Time { return now }
	return application, sessionValue, cfg
}

func projectReviewStoredSession(t *testing.T, store *memorySessions, now time.Time, scopes []string) browserSession {
	t.Helper()
	value, err := store.create(now)
	if err != nil {
		t.Fatal("session setup failed")
	}
	value.Identity = &jitIdentity{
		Key: projectReviewOpaque(t, "jit1_"), Issuer: "https://issuer.example", Subject: projectReviewOpaque(t, "sub_"), Name: "Project Review", SignedIn: now,
	}
	value.AccessToken = projectReviewOpaque(t, "access_")
	value.RefreshToken = projectReviewOpaque(t, "refresh_")
	value.IDToken = projectReviewOpaque(t, "id_")
	value.GrantedScopes = append([]string(nil), scopes...)
	if err := store.save(value, now); err != nil {
		t.Fatal("session credentials setup failed")
	}
	return value
}

func projectReviewOpaque(t *testing.T, prefix string) string {
	t.Helper()
	value, err := randomOpaque(rand.Reader, prefix, 24)
	if err != nil {
		t.Fatal("runtime token generation failed")
	}
	return value
}

func projectReviewRefreshJSON(t *testing.T, access, refresh, scope string) string {
	t.Helper()
	response := tokenResponse{AccessToken: projectReviewOpaque(t, access), TokenType: "Bearer", ExpiresIn: 600, Scope: scope}
	if refresh != "" {
		response.RefreshToken = projectReviewOpaque(t, refresh)
	}
	return projectReviewJSON(response)
}

func projectReviewJSON(value any) string {
	// Keep provider fixtures opaque; the handlers only need protocol-shaped JSON.
	encoded, err := json.Marshal(value)
	if err != nil {
		panic("provider fixture encoding failed")
	}
	return string(encoded)
}
