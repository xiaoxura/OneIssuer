package httpserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/admin"
	"github.com/oneissuer/oneissuer/internal/audit"
	"github.com/oneissuer/oneissuer/internal/authn"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/identity"
	logoutdomain "github.com/oneissuer/oneissuer/internal/logout"
	"github.com/oneissuer/oneissuer/internal/pagination"
	"github.com/oneissuer/oneissuer/internal/session"
)

var errProjectReviewLogoutInfrastructure = errors.New("project review logout dependency unavailable")

type projectReviewLogoutSessionRepository struct {
	principal      session.Principal
	err            error
	findCalls      int
	foundTokenHash []byte
}

func (r *projectReviewLogoutSessionRepository) FindLoginSession(_ context.Context, tokenHash []byte) (session.Principal, error) {
	r.findCalls++
	r.foundTokenHash = append([]byte(nil), tokenHash...)
	if r.err != nil {
		return session.Principal{}, r.err
	}
	return r.principal, nil
}

func (*projectReviewLogoutSessionRepository) TouchLoginSession(context.Context, uuid.UUID, time.Time, time.Time) error {
	return nil
}

func (*projectReviewLogoutSessionRepository) RotateSessionCSRF(context.Context, uuid.UUID, []byte, time.Time) error {
	return nil
}

func (*projectReviewLogoutSessionRepository) ListUserSessions(context.Context, uuid.UUID, pagination.Cursor, int) ([]session.Summary, error) {
	return nil, nil
}

func (*projectReviewLogoutSessionRepository) RevokeUserSession(context.Context, uuid.UUID, uuid.UUID, time.Time, audit.Event) error {
	return nil
}

func (*projectReviewLogoutSessionRepository) RevokeOtherUserSessions(context.Context, uuid.UUID, uuid.UUID, time.Time, audit.Event) (int64, error) {
	return 0, nil
}

func (*projectReviewLogoutSessionRepository) RevokeSessionByHash(context.Context, []byte, time.Time, string, audit.Event) error {
	return nil
}

func (*projectReviewLogoutSessionRepository) CleanupSessions(context.Context, time.Time, time.Time) (int64, error) {
	return 0, nil
}

type projectReviewLogoutRepository struct {
	bindErr       error
	completeErr   error
	complete      logoutdomain.CompletionCandidate
	bindCalls     int
	bindInput     logoutdomain.BindInput
	completeCalls int
	completeInput logoutdomain.CompleteInput
}

func (*projectReviewLogoutRepository) CreateLogoutTransaction(context.Context, logoutdomain.Transaction) error {
	return nil
}

func (r *projectReviewLogoutRepository) BindLogoutTransaction(_ context.Context, input logoutdomain.BindInput) (logoutdomain.Transaction, error) {
	r.bindCalls++
	r.bindInput = input
	r.bindInput.LookupHash = append([]byte(nil), input.LookupHash...)
	r.bindInput.CSRFHash = append([]byte(nil), input.CSRFHash...)
	if r.bindErr != nil {
		return logoutdomain.Transaction{}, r.bindErr
	}
	return logoutdomain.Transaction{
		Stage:                 logoutdomain.StageBoundConfirm,
		UserID:                uuidPtrProjectReviewLogout(projectReviewLogoutUserID),
		SessionID:             uuidPtrProjectReviewLogout(projectReviewLogoutSessionID),
		SessionBindingID:      uuidPtrProjectReviewLogout(projectReviewLogoutBindingID),
		ExpiresAt:             projectReviewLogoutNow.Add(time.Minute),
		PostLogoutRedirectURI: "",
	}, nil
}

func (r *projectReviewLogoutRepository) CompleteLogoutTransaction(_ context.Context, input logoutdomain.CompleteInput) (logoutdomain.CompletionCandidate, error) {
	r.completeCalls++
	r.completeInput = input
	r.completeInput.LookupHash = append([]byte(nil), input.LookupHash...)
	r.completeInput.CSRFHash = append([]byte(nil), input.CSRFHash...)
	if r.completeErr != nil {
		return logoutdomain.CompletionCandidate{}, r.completeErr
	}
	return r.complete, nil
}

type projectReviewLogoutClients struct{}

func (projectReviewLogoutClients) ResolveActive(context.Context, string) (clientdomain.Client, error) {
	return clientdomain.Client{}, clientdomain.ErrNotFound
}

func (projectReviewLogoutClients) GetActive(context.Context, uuid.UUID) (clientdomain.Client, error) {
	return clientdomain.Client{}, clientdomain.ErrNotFound
}

type projectReviewLogoutKeys struct{}

func (projectReviewLogoutKeys) PublicKeys() []jose.JSONWebKey { return nil }

var (
	projectReviewLogoutIssuer       = "http://issuer.example.test"
	projectReviewLogoutUserID       = uuid.UUID{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	projectReviewLogoutSessionID    = uuid.UUID{0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22}
	projectReviewLogoutBindingID    = uuid.UUID{0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33}
	projectReviewLogoutNow          = time.Unix(1_735_689_600, 0).UTC()
	projectReviewLogoutLookupToken  = "lt1_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	projectReviewLogoutCSRFProof    = "lc1_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	projectReviewLogoutSessionToken = "s1_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

func uuidPtrProjectReviewLogout(value uuid.UUID) *uuid.UUID { return &value }

func projectReviewLogoutPrincipal(now time.Time) session.Principal {
	return session.Principal{
		SessionID: projectReviewLogoutSessionID, SessionBindingID: projectReviewLogoutBindingID,
		User:      identity.User{ID: projectReviewLogoutUserID, Subject: "subject-project-review-logout", Status: identity.StatusActive},
		CreatedAt: now, LastSeenAt: now, AuthenticatedAt: now,
		ExpiresAt: now.Add(time.Hour), IdleExpiresAt: now.Add(time.Hour),
	}
}

func newProjectReviewLogoutHandler(t *testing.T, sessionErr, bindErr, completeErr error, completion logoutdomain.CompletionCandidate) (http.Handler, session.CookieManager, logoutdomain.CookieManager, *projectReviewLogoutSessionRepository, *projectReviewLogoutRepository) {
	t.Helper()
	principal := projectReviewLogoutPrincipal(projectReviewLogoutNow)
	sessionRepository := &projectReviewLogoutSessionRepository{principal: principal, err: sessionErr}
	tokens, err := session.NewTokenManager(rand.Reader, time.Hour, 30*time.Minute, 15*time.Minute)
	if err != nil {
		t.Fatalf("session token manager: %v", err)
	}
	sessions := session.NewService(sessionRepository, tokens)
	logoutRepository := &projectReviewLogoutRepository{bindErr: bindErr, completeErr: completeErr, complete: completion}
	logoutService, err := logoutdomain.NewService(
		logoutRepository, projectReviewLogoutClients{}, projectReviewLogoutKeys{}, projectReviewLogoutIssuer,
		5*time.Minute, 24*time.Hour, time.Minute, 1, rand.Reader,
	)
	if err != nil {
		t.Fatalf("logout service: %v", err)
	}
	issuer, err := url.Parse(projectReviewLogoutIssuer)
	if err != nil {
		t.Fatalf("issuer URL: %v", err)
	}
	cookies := session.NewCookieManager("oneissuer_session", false, time.Hour, 15*time.Minute)
	logoutCookies := logoutdomain.NewCookieManager(cookies.SessionName, false, 5*time.Minute)
	application, err := NewApplicationHandler(ApplicationOptions{
		Authn: &authn.Service{}, Sessions: sessions, Admin: &admin.Service{},
		Logout: logoutService, LogoutCookies: logoutCookies, Cookies: cookies,
		Issuer: issuer, Now: func() time.Time { return projectReviewLogoutNow },
		OAuthRateLimit: AuthenticationRateLimitConfig{PerMinute: 1000, Burst: 1000, GlobalPerSecond: 1000, GlobalBurst: 1000},
	})
	if err != nil {
		t.Fatalf("application handler: %v", err)
	}
	return application, cookies, logoutCookies, sessionRepository, logoutRepository
}

func projectReviewLogoutRequest(method, path string, cookies ...*http.Cookie) *http.Request {
	request := httptest.NewRequest(method, path, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	return request
}

func projectReviewLogoutCookie(name, value string) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: logoutdomain.ConfirmPath}
}

func projectReviewLogoutResponseCookies(response *httptest.ResponseRecorder) []*http.Cookie {
	return response.Result().Cookies()
}

func projectReviewLogoutHasCleared(cookies []*http.Cookie, name string) bool {
	for _, cookie := range cookies {
		if cookie.Name == name && cookie.MaxAge < 0 {
			return true
		}
	}
	return false
}

func TestProjectReviewRPLogoutCleanGETCookieMatrix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		sessionErr error
		bindErr    error
		wantStatus int
		wantResult string
		wantCode   string
		wantClear  bool
		wantRetry  bool
	}{
		{name: "unauthenticated clears as already signed out", sessionErr: session.ErrNotFound, wantStatus: http.StatusOK, wantResult: "no active OneIssuer session", wantCode: "already_signed_out", wantClear: true},
		{name: "authentication infrastructure failure preserves transient cookie", sessionErr: errProjectReviewLogoutInfrastructure, wantStatus: http.StatusInternalServerError, wantResult: "logout confirmation is no longer available", wantCode: "unavailable", wantClear: false},
		{name: "bind not found clears transient cookie", bindErr: logoutdomain.ErrNotFound, wantStatus: http.StatusBadRequest, wantResult: "logout confirmation is no longer available", wantCode: "unavailable", wantClear: true},
		{name: "bind capacity preserves transient cookie", bindErr: logoutdomain.ErrCapacity, wantStatus: http.StatusTooManyRequests, wantResult: "logout confirmation is no longer available", wantCode: "unavailable", wantClear: false, wantRetry: true},
		{name: "bind infrastructure failure preserves transient cookie", bindErr: errProjectReviewLogoutInfrastructure, wantStatus: http.StatusInternalServerError, wantResult: "logout confirmation is no longer available", wantCode: "unavailable", wantClear: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, cookies, logoutCookies, sessionRepository, logoutRepository := newProjectReviewLogoutHandler(t, test.sessionErr, test.bindErr, nil, logoutdomain.CompletionCandidate{})
			request := projectReviewLogoutRequest(http.MethodGet, logoutdomain.ConfirmPath,
				projectReviewLogoutCookie(logoutCookies.Name, projectReviewLogoutLookupToken),
				projectReviewLogoutCookie(cookies.SessionName, projectReviewLogoutSessionToken),
			)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.wantStatus, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), test.wantResult) {
				t.Fatalf("body does not contain %q: %s", test.wantResult, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), `data-logout-result="`+test.wantCode+`"`) {
				t.Fatalf("logout result code is not %q: %s", test.wantCode, response.Body.String())
			}
			setCookies := projectReviewLogoutResponseCookies(response)
			if got := projectReviewLogoutHasCleared(setCookies, logoutCookies.Name); got != test.wantClear {
				t.Fatalf("transient cookie cleared = %v, want %v; cookies=%v", got, test.wantClear, setCookies)
			}
			if test.wantRetry && response.Header().Get("Retry-After") != "1" {
				t.Fatalf("Retry-After = %q, want 1", response.Header().Get("Retry-After"))
			}
			if sessionRepository.findCalls != 1 {
				t.Fatalf("FindLoginSession calls = %d, want 1", sessionRepository.findCalls)
			}
			wantSessionHash := session.HashToken(projectReviewLogoutSessionToken)
			if !bytes.Equal(sessionRepository.foundTokenHash, wantSessionHash) {
				t.Fatalf("FindLoginSession token hash = %x, want %x", sessionRepository.foundTokenHash, wantSessionHash)
			}
			wantBindCalls := 0
			if test.sessionErr == nil {
				wantBindCalls = 1
			}
			if logoutRepository.bindCalls != wantBindCalls {
				t.Fatalf("BindLogoutTransaction calls = %d, want %d", logoutRepository.bindCalls, wantBindCalls)
			}
			if logoutRepository.completeCalls != 0 {
				t.Fatalf("CompleteLogoutTransaction calls = %d, want 0", logoutRepository.completeCalls)
			}
			if wantBindCalls == 1 {
				lookupHash, err := logoutdomain.DigestLookupToken(projectReviewLogoutLookupToken)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(logoutRepository.bindInput.LookupHash, lookupHash) || logoutRepository.bindInput.UserID != projectReviewLogoutUserID || logoutRepository.bindInput.SessionID != projectReviewLogoutSessionID || logoutRepository.bindInput.SessionBindingID != projectReviewLogoutBindingID {
					t.Fatalf("BindLogoutTransaction input = %+v, want current session authority", logoutRepository.bindInput)
				}
			}
		})
	}
}

func TestProjectReviewRPLogoutConfirmPOSTCookieMatrix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		completeErr   error
		confirmed     bool
		decision      logoutdomain.Decision
		wantStatus    int
		wantResult    string
		wantCode      string
		wantTransient bool
		wantMain      bool
	}{
		{name: "CSRF failure clears transient only", completeErr: logoutdomain.ErrCSRF, decision: logoutdomain.DecisionConfirm, wantStatus: http.StatusForbidden, wantResult: "logout confirmation is no longer available", wantCode: "unavailable", wantTransient: true},
		{name: "missing transaction clears transient only", completeErr: logoutdomain.ErrNotFound, decision: logoutdomain.DecisionConfirm, wantStatus: http.StatusBadRequest, wantResult: "logout confirmation is no longer available", wantCode: "unavailable", wantTransient: true},
		{name: "infrastructure failure preserves both cookies", completeErr: errProjectReviewLogoutInfrastructure, decision: logoutdomain.DecisionConfirm, wantStatus: http.StatusInternalServerError, wantResult: "logout confirmation is no longer available", wantCode: "unavailable"},
		{name: "cancel clears transient but keeps authenticated session", confirmed: false, decision: logoutdomain.DecisionCancel, wantStatus: http.StatusOK, wantResult: "You are still signed in", wantCode: "canceled", wantTransient: true},
		{name: "confirm clears transient and authenticated cookies after success", confirmed: true, decision: logoutdomain.DecisionConfirm, wantStatus: http.StatusOK, wantResult: "You have signed out", wantCode: "confirmed", wantTransient: true, wantMain: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			completion := logoutdomain.CompletionCandidate{Confirmed: test.confirmed}
			handler, cookies, logoutCookies, sessionRepository, logoutRepository := newProjectReviewLogoutHandler(t, nil, nil, test.completeErr, completion)
			request := projectReviewLogoutRequest(http.MethodPost, logoutdomain.ConfirmPath,
				projectReviewLogoutCookie(logoutCookies.Name, projectReviewLogoutLookupToken),
				projectReviewLogoutCookie(cookies.SessionName, projectReviewLogoutSessionToken),
			)
			request.Header.Set("Origin", projectReviewLogoutIssuer)
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			body := "csrf_token=" + projectReviewLogoutCSRFProof + "&decision=" + string(test.decision)
			request.Body = io.NopCloser(strings.NewReader(body))
			request.ContentLength = int64(len(body))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.wantStatus, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), test.wantResult) {
				t.Fatalf("body does not contain %q: %s", test.wantResult, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), `data-logout-result="`+test.wantCode+`"`) {
				t.Fatalf("logout result code is not %q: %s", test.wantCode, response.Body.String())
			}
			setCookies := projectReviewLogoutResponseCookies(response)
			if got := projectReviewLogoutHasCleared(setCookies, logoutCookies.Name); got != test.wantTransient {
				t.Fatalf("transient cookie cleared = %v, want %v; cookies=%v", got, test.wantTransient, setCookies)
			}
			if got := projectReviewLogoutHasCleared(setCookies, cookies.SessionName) || projectReviewLogoutHasCleared(setCookies, cookies.CSRFName); got != test.wantMain {
				t.Fatalf("authenticated cookies cleared = %v, want %v; cookies=%v", got, test.wantMain, setCookies)
			}
			if sessionRepository.findCalls != 1 {
				t.Fatalf("FindLoginSession calls = %d, want 1", sessionRepository.findCalls)
			}
			wantSessionHash := session.HashToken(projectReviewLogoutSessionToken)
			if !bytes.Equal(sessionRepository.foundTokenHash, wantSessionHash) {
				t.Fatalf("FindLoginSession token hash = %x, want %x", sessionRepository.foundTokenHash, wantSessionHash)
			}
			if logoutRepository.bindCalls != 0 {
				t.Fatalf("BindLogoutTransaction calls = %d, want 0", logoutRepository.bindCalls)
			}
			if logoutRepository.completeCalls != 1 {
				t.Fatalf("CompleteLogoutTransaction calls = %d, want 1", logoutRepository.completeCalls)
			}
			lookupHash, err := logoutdomain.DigestLookupToken(projectReviewLogoutLookupToken)
			if err != nil {
				t.Fatal(err)
			}
			csrfHash, err := logoutdomain.DigestCSRFProof(projectReviewLogoutCSRFProof)
			if err != nil {
				t.Fatal(err)
			}
			input := logoutRepository.completeInput
			if !bytes.Equal(input.LookupHash, lookupHash) || !bytes.Equal(input.CSRFHash, csrfHash) || input.Decision != test.decision || input.UserID != projectReviewLogoutUserID || input.SessionID != projectReviewLogoutSessionID || input.SessionBindingID != projectReviewLogoutBindingID {
				t.Fatalf("CompleteLogoutTransaction input = %+v, want decision=%q and current session authority", input, test.decision)
			}
		})
	}
}
