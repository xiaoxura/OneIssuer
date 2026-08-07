package httpserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/admin"
	"github.com/oneissuer/oneissuer/internal/audit"
	"github.com/oneissuer/oneissuer/internal/authn"
	"github.com/oneissuer/oneissuer/internal/authorization"
	logoutdomain "github.com/oneissuer/oneissuer/internal/logout"
	"github.com/oneissuer/oneissuer/internal/oidc"
	"github.com/oneissuer/oneissuer/internal/pagination"
	"github.com/oneissuer/oneissuer/internal/session"
	"github.com/oneissuer/oneissuer/internal/token"
)

var errProjectReviewLocalLogoutInfrastructure = errors.New("local logout dependency unavailable")

var projectReviewLocalLogoutCSRFToken = "c1_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))

type projectReviewLocalLogoutSessionRepository struct {
	principal      session.Principal
	findErr        error
	revokeErr      error
	findCalls      int
	revokeCalls    int
	callOrder      []string
	findHash       []byte
	revokeHash     []byte
	findDeadline   time.Time
	revokeDeadline time.Time
}

func (r *projectReviewLocalLogoutSessionRepository) FindLoginSession(ctx context.Context, tokenHash []byte) (session.Principal, error) {
	r.findCalls++
	r.callOrder = append(r.callOrder, "authenticate")
	r.findHash = append([]byte(nil), tokenHash...)
	r.findDeadline, _ = ctx.Deadline()
	if r.findErr != nil {
		return session.Principal{}, r.findErr
	}
	if !bytes.Equal(tokenHash, session.HashToken(projectReviewLogoutSessionToken)) {
		return session.Principal{}, session.ErrNotFound
	}
	return r.principal, nil
}

func (*projectReviewLocalLogoutSessionRepository) TouchLoginSession(context.Context, uuid.UUID, time.Time, time.Time) error {
	return nil
}

func (*projectReviewLocalLogoutSessionRepository) RotateSessionCSRF(context.Context, uuid.UUID, []byte, time.Time) error {
	return nil
}

func (*projectReviewLocalLogoutSessionRepository) ListUserSessions(context.Context, uuid.UUID, pagination.Cursor, int) ([]session.Summary, error) {
	return nil, nil
}

func (*projectReviewLocalLogoutSessionRepository) RevokeUserSession(context.Context, uuid.UUID, uuid.UUID, time.Time, audit.Event) error {
	return nil
}

func (*projectReviewLocalLogoutSessionRepository) RevokeOtherUserSessions(context.Context, uuid.UUID, uuid.UUID, time.Time, audit.Event) (int64, error) {
	return 0, nil
}

func (r *projectReviewLocalLogoutSessionRepository) RevokeSessionByHash(ctx context.Context, tokenHash []byte, _ time.Time, _ string, _ audit.Event) error {
	r.revokeCalls++
	r.callOrder = append(r.callOrder, "commit")
	r.revokeHash = append([]byte(nil), tokenHash...)
	r.revokeDeadline, _ = ctx.Deadline()
	return r.revokeErr
}

func (*projectReviewLocalLogoutSessionRepository) CleanupSessions(context.Context, time.Time, time.Time) (int64, error) {
	return 0, nil
}

func projectReviewLocalLogoutPrincipal(now time.Time) session.Principal {
	principal := projectReviewLogoutPrincipal(now)
	principal.CSRFHash = session.HashCSRF(projectReviewLocalLogoutCSRFToken)
	principal.CSRFExpiresAt = now.Add(time.Minute)
	return principal
}

func newProjectReviewLocalLogoutHTTPHandler(t *testing.T, repository *projectReviewLocalLogoutSessionRepository) (http.Handler, session.CookieManager) {
	t.Helper()
	tokens, err := session.NewTokenManager(rand.Reader, time.Hour, 30*time.Minute, 15*time.Minute)
	if err != nil {
		t.Fatalf("session token manager: %v", err)
	}
	sessions := session.NewService(repository, tokens)
	issuer, err := url.Parse(projectReviewLogoutIssuer)
	if err != nil {
		t.Fatalf("issuer URL: %v", err)
	}
	cookies := session.NewCookieManager("oneissuer_session", false, time.Hour, 15*time.Minute)
	handler, err := NewApplicationHandler(ApplicationOptions{
		Authn: &authn.Service{}, Sessions: sessions, Admin: &admin.Service{}, Cookies: cookies,
		Issuer: issuer, Now: func() time.Time { return projectReviewLogoutNow },
	})
	if err != nil {
		t.Fatalf("application handler: %v", err)
	}
	return handler, cookies
}

func projectReviewLocalLogoutRequest(method, target string, cookies session.CookieManager) *http.Request {
	request := httptest.NewRequest(method, target, nil)
	request.AddCookie(&http.Cookie{Name: cookies.SessionName, Value: projectReviewLogoutSessionToken})
	request.AddCookie(&http.Cookie{Name: cookies.CSRFName, Value: projectReviewLocalLogoutCSRFToken})
	return request
}

func TestProjectReviewLocalLogoutPOSTCookieAndCommitMatrix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		target        string
		forceQuery    bool
		findErr       error
		revokeErr     error
		form          bool
		wantStatus    int
		wantLocation  string
		wantMainClear bool
		wantFind      int
		wantRevoke    int
		wantOrder     string
	}{
		{name: "arbitrary query rejected before authentication", target: "/logout?unexpected=1", wantStatus: http.StatusBadRequest, wantOrder: ""},
		{name: "force query rejected before authentication", target: "/logout", forceQuery: true, wantStatus: http.StatusBadRequest, wantOrder: ""},
		{name: "Authenticate ErrUnauthenticated is the only stale-cookie redirect", target: "/logout", findErr: session.ErrUnauthenticated, form: false, wantStatus: http.StatusSeeOther, wantLocation: "/login", wantMainClear: true, wantFind: 1, wantOrder: "authenticate"},
		{name: "authentication infrastructure failure preserves cookies", target: "/logout", findErr: errProjectReviewLocalLogoutInfrastructure, form: false, wantStatus: http.StatusInternalServerError, wantFind: 1, wantOrder: "authenticate"},
		{name: "logout commit infrastructure failure preserves cookies", target: "/logout", revokeErr: errProjectReviewLocalLogoutInfrastructure, form: true, wantStatus: http.StatusInternalServerError, wantFind: 1, wantRevoke: 1, wantOrder: "authenticate,commit"},
		{name: "successful logout commits before clearing cookies", target: "/logout", form: true, wantStatus: http.StatusSeeOther, wantLocation: "/login", wantMainClear: true, wantFind: 1, wantRevoke: 1, wantOrder: "authenticate,commit"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &projectReviewLocalLogoutSessionRepository{
				principal: projectReviewLocalLogoutPrincipal(projectReviewLogoutNow),
				findErr:   test.findErr,
				revokeErr: test.revokeErr,
			}
			handler, cookies := newProjectReviewLocalLogoutHTTPHandler(t, repository)
			request := projectReviewLocalLogoutRequest(http.MethodPost, test.target, cookies)
			if test.forceQuery {
				request.URL.ForceQuery = true
			}
			if test.form {
				body := url.Values{"csrf_token": {projectReviewLocalLogoutCSRFToken}}.Encode()
				request.Body = io.NopCloser(strings.NewReader(body))
				request.ContentLength = int64(len(body))
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				request.Header.Set("Origin", projectReviewLogoutIssuer)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
			if got := response.Header().Get("Location"); got != test.wantLocation {
				t.Fatalf("Location = %q, want %q", got, test.wantLocation)
			}
			setCookies := response.Result().Cookies()
			sessionCleared := projectReviewLogoutHasCleared(setCookies, cookies.SessionName)
			csrfCleared := projectReviewLogoutHasCleared(setCookies, cookies.CSRFName)
			if sessionCleared != test.wantMainClear || csrfCleared != test.wantMainClear {
				t.Fatalf("authenticated cookie clears = session:%v csrf:%v, want %v/%v", sessionCleared, csrfCleared, test.wantMainClear, test.wantMainClear)
			}
			if repository.findCalls != test.wantFind || repository.revokeCalls != test.wantRevoke {
				t.Fatalf("authenticate calls = %d, commit calls = %d; want %d/%d", repository.findCalls, repository.revokeCalls, test.wantFind, test.wantRevoke)
			}
			if got := strings.Join(repository.callOrder, ","); got != test.wantOrder {
				t.Fatalf("call order = %q, want %q", got, test.wantOrder)
			}
			if test.wantFind == 1 && !bytes.Equal(repository.findHash, session.HashToken(projectReviewLogoutSessionToken)) {
				t.Fatal("authentication did not receive the session cookie digest")
			}
			if test.wantRevoke == 1 && !bytes.Equal(repository.revokeHash, session.HashToken(projectReviewLogoutSessionToken)) {
				t.Fatal("logout commit did not receive the session cookie digest")
			}
		})
	}
}

func TestProjectReviewLocalLogoutPOSTSharesBoundedOperationDeadline(t *testing.T) {
	t.Parallel()
	repository := &projectReviewLocalLogoutSessionRepository{
		principal: projectReviewLocalLogoutPrincipal(projectReviewLogoutNow),
	}
	handler, cookies := newProjectReviewLocalLogoutHTTPHandler(t, repository)
	request := projectReviewLocalLogoutRequest(http.MethodPost, "/logout", cookies)
	if _, ok := request.Context().Deadline(); ok {
		t.Fatal("test request unexpectedly has a parent deadline")
	}
	body := url.Values{"csrf_token": {projectReviewLocalLogoutCSRFToken}}.Encode()
	request.Body = io.NopCloser(strings.NewReader(body))
	request.ContentLength = int64(len(body))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", projectReviewLogoutIssuer)
	started := time.Now()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login" {
		t.Fatalf("successful logout status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
	if repository.findCalls != 1 || repository.revokeCalls != 1 || strings.Join(repository.callOrder, ",") != "authenticate,commit" {
		t.Fatalf("logout dependency calls=%d/%d order=%q, want 1/1 authenticate,commit", repository.findCalls, repository.revokeCalls, strings.Join(repository.callOrder, ","))
	}
	assertProjectReviewLocalOperationDeadline(t, repository.findDeadline, started)
	assertProjectReviewLocalOperationDeadline(t, repository.revokeDeadline, started)
	if !repository.findDeadline.Equal(repository.revokeDeadline) {
		t.Fatalf("authentication deadline=%v differs from logout commit deadline=%v", repository.findDeadline, repository.revokeDeadline)
	}
	setCookies := response.Result().Cookies()
	if !projectReviewLogoutHasCleared(setCookies, cookies.SessionName) || !projectReviewLogoutHasCleared(setCookies, cookies.CSRFName) {
		t.Fatal("successful logout did not clear authenticated cookies after commit")
	}
}

type projectReviewLocalDeadlineProtocolTokens struct {
	exchangeCalled   chan struct{}
	refreshCalled    chan struct{}
	exchangeInput    token.ExchangeInput
	refreshInput     token.RefreshInput
	exchangeDeadline time.Time
	refreshDeadline  time.Time
	exchangeCalls    int
	refreshCalls     int
	exchangeErr      error
	refreshErr       error
}

func (f *projectReviewLocalDeadlineProtocolTokens) Exchange(ctx context.Context, input token.ExchangeInput) (token.Response, error) {
	f.exchangeCalls++
	f.exchangeInput = input
	f.exchangeDeadline, _ = ctx.Deadline()
	close(f.exchangeCalled)
	<-ctx.Done()
	f.exchangeErr = ctx.Err()
	return token.Response{}, f.exchangeErr
}

func (f *projectReviewLocalDeadlineProtocolTokens) Refresh(ctx context.Context, input token.RefreshInput) (token.Response, error) {
	f.refreshCalls++
	f.refreshInput = input
	f.refreshDeadline, _ = ctx.Deadline()
	close(f.refreshCalled)
	<-ctx.Done()
	f.refreshErr = ctx.Err()
	return token.Response{}, f.refreshErr
}

func (*projectReviewLocalDeadlineProtocolTokens) Revoke(context.Context, token.RevocationInput) error {
	return nil
}

func (*projectReviewLocalDeadlineProtocolTokens) Introspect(context.Context, token.IntrospectionInput) (token.IntrospectionResponse, error) {
	return token.IntrospectionResponse{Active: false}, nil
}

func (*projectReviewLocalDeadlineProtocolTokens) UserInfoForAccessToken(context.Context, string, time.Time) (token.UserInfo, error) {
	return token.UserInfo{}, errors.New("unexpected UserInfo call")
}

var _ ProtocolTokenService = (*projectReviewLocalDeadlineProtocolTokens)(nil)

func assertProjectReviewLocalOperationDeadline(t *testing.T, deadline, started time.Time) {
	t.Helper()
	if deadline.IsZero() {
		t.Fatal("operation dependency did not receive a deadline")
	}
	delta := deadline.Sub(started)
	if delta < defaultOperationTimeout-time.Second || delta > defaultOperationTimeout+time.Second {
		t.Fatalf("operation deadline delta = %v, want approximately %v", delta, defaultOperationTimeout)
	}
}

func TestProjectReviewLocalTokenOperationsUseBoundedContexts(t *testing.T) {
	t.Parallel()
	resolver := newHTTPTokenResolver()
	for _, test := range []struct {
		name       string
		form       url.Values
		called     func(*projectReviewLocalDeadlineProtocolTokens) <-chan struct{}
		deadline   func(*projectReviewLocalDeadlineProtocolTokens) time.Time
		calls      func(*projectReviewLocalDeadlineProtocolTokens) int
		otherCalls func(*projectReviewLocalDeadlineProtocolTokens) int
	}{
		{
			name: "authorization code exchange", form: validHTTPTokenForm(),
			called:     func(fake *projectReviewLocalDeadlineProtocolTokens) <-chan struct{} { return fake.exchangeCalled },
			deadline:   func(fake *projectReviewLocalDeadlineProtocolTokens) time.Time { return fake.exchangeDeadline },
			calls:      func(fake *projectReviewLocalDeadlineProtocolTokens) int { return fake.exchangeCalls },
			otherCalls: func(fake *projectReviewLocalDeadlineProtocolTokens) int { return fake.refreshCalls },
		},
		{
			name: "refresh token exchange", form: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {"r1_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 32))},
				"client_id":     {resolver.public.ClientID},
			},
			called:     func(fake *projectReviewLocalDeadlineProtocolTokens) <-chan struct{} { return fake.refreshCalled },
			deadline:   func(fake *projectReviewLocalDeadlineProtocolTokens) time.Time { return fake.refreshDeadline },
			calls:      func(fake *projectReviewLocalDeadlineProtocolTokens) int { return fake.refreshCalls },
			otherCalls: func(fake *projectReviewLocalDeadlineProtocolTokens) int { return fake.exchangeCalls },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var wantHash []byte
			var digestErr error
			switch test.form.Get("grant_type") {
			case "authorization_code":
				wantHash, digestErr = authorization.DigestPresentedCode(test.form.Get("code"))
			case "refresh_token":
				wantHash, digestErr = token.DigestPresentedRefreshToken(test.form.Get("refresh_token"))
			default:
				t.Fatalf("unsupported fixture grant type %q", test.form.Get("grant_type"))
			}
			if digestErr != nil {
				t.Fatalf("fixture digest: %v", digestErr)
			}
			fake := &projectReviewLocalDeadlineProtocolTokens{
				exchangeCalled: make(chan struct{}), refreshCalled: make(chan struct{}),
			}
			handler := &applicationHandler{tokenClients: resolver, tokens: fake, now: func() time.Time { return httpTokenNow }}
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			request := httptest.NewRequest(http.MethodPost, oidc.TokenPath, strings.NewReader(test.form.Encode())).WithContext(parent)
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			started := time.Now()
			responses := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				responses <- response
			}()
			select {
			case <-test.called(fake):
			case early := <-responses:
				var body oauthErrorResponse
				decodeErr := json.Unmarshal(early.Body.Bytes(), &body)
				if decodeErr != nil {
					body.Error = "<invalid>"
				}
				t.Fatalf("token handler returned before dependency call: status=%d oauth_error=%q", early.Code, body.Error)
			case <-time.After(time.Second):
				cancel()
				select {
				case <-responses:
				case <-time.After(time.Second):
				}
				t.Fatal("blocking token dependency was not called")
			}
			assertProjectReviewLocalOperationDeadline(t, test.deadline(fake), started)
			cancel()
			var response *httptest.ResponseRecorder
			select {
			case response = <-responses:
			case <-time.After(time.Second):
				t.Fatal("token handler did not return after context cancellation")
			}
			if response.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500", response.Code)
			}
			var body map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body["error"] != "server_error" || len(body) != 1 {
				t.Fatalf("protocol error body = %v, decode error = %v", body, err)
			}
			if strings.Contains(response.Body.String(), "access_token") || strings.Contains(response.Body.String(), "refresh_token") {
				t.Fatal("canceled token operation returned a success profile")
			}
			if test.calls(fake) != 1 || test.otherCalls(fake) != 0 {
				t.Fatalf("token calls = %d, other grant calls = %d; want 1/0", test.calls(fake), test.otherCalls(fake))
			}
			if test.form.Get("grant_type") == "refresh_token" {
				if !bytes.Equal(fake.refreshInput.TokenHash, wantHash) {
					t.Fatalf("refresh input token hash = %x, want domain digest", fake.refreshInput.TokenHash)
				}
			} else if !bytes.Equal(fake.exchangeInput.CodeHash, wantHash) {
				t.Fatalf("exchange input code hash = %x, want domain digest", fake.exchangeInput.CodeHash)
			}
		})
	}
}

type projectReviewLocalDeadlineLogoutRepository struct {
	bindCalled       chan struct{}
	completeCalled   chan struct{}
	bindDeadline     time.Time
	completeDeadline time.Time
	bindCalls        int
	completeCalls    int
}

func (*projectReviewLocalDeadlineLogoutRepository) CreateLogoutTransaction(context.Context, logoutdomain.Transaction) error {
	return nil
}

func (r *projectReviewLocalDeadlineLogoutRepository) BindLogoutTransaction(ctx context.Context, _ logoutdomain.BindInput) (logoutdomain.Transaction, error) {
	r.bindCalls++
	r.bindDeadline, _ = ctx.Deadline()
	close(r.bindCalled)
	<-ctx.Done()
	return logoutdomain.Transaction{}, ctx.Err()
}

func (r *projectReviewLocalDeadlineLogoutRepository) CompleteLogoutTransaction(ctx context.Context, _ logoutdomain.CompleteInput) (logoutdomain.CompletionCandidate, error) {
	r.completeCalls++
	r.completeDeadline, _ = ctx.Deadline()
	close(r.completeCalled)
	<-ctx.Done()
	return logoutdomain.CompletionCandidate{}, ctx.Err()
}

func newProjectReviewLocalRPLogoutHandler(t *testing.T, repository logoutdomain.Repository) (http.Handler, session.CookieManager, logoutdomain.CookieManager, *projectReviewLocalLogoutSessionRepository) {
	t.Helper()
	sessionRepository := &projectReviewLocalLogoutSessionRepository{principal: projectReviewLocalLogoutPrincipal(projectReviewLogoutNow)}
	tokens, err := session.NewTokenManager(rand.Reader, time.Hour, 30*time.Minute, 15*time.Minute)
	if err != nil {
		t.Fatalf("session token manager: %v", err)
	}
	sessions := session.NewService(sessionRepository, tokens)
	logoutService, err := logoutdomain.NewService(
		repository, projectReviewLogoutClients{}, projectReviewLogoutKeys{}, projectReviewLogoutIssuer,
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
	handler, err := NewApplicationHandler(ApplicationOptions{
		Authn: &authn.Service{}, Sessions: sessions, Admin: &admin.Service{}, Logout: logoutService,
		LogoutCookies: logoutCookies, Cookies: cookies, Issuer: issuer,
		Now: func() time.Time { return projectReviewLogoutNow },
	})
	if err != nil {
		t.Fatalf("application handler: %v", err)
	}
	return handler, cookies, logoutCookies, sessionRepository
}

func projectReviewLocalRPLogoutCookies(request *http.Request, cookies session.CookieManager, logoutCookies logoutdomain.CookieManager) {
	request.AddCookie(&http.Cookie{Name: cookies.SessionName, Value: projectReviewLogoutSessionToken})
	request.AddCookie(&http.Cookie{Name: cookies.CSRFName, Value: projectReviewLocalLogoutCSRFToken})
	request.AddCookie(&http.Cookie{Name: logoutCookies.Name, Value: projectReviewLogoutLookupToken})
}

func TestProjectReviewLocalRPLogoutBindAndCompleteUseBoundedContexts(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		post     bool
		called   func(*projectReviewLocalDeadlineLogoutRepository) <-chan struct{}
		deadline func(*projectReviewLocalDeadlineLogoutRepository) time.Time
		calls    func(*projectReviewLocalDeadlineLogoutRepository) int
	}{
		{
			name: "bind", called: func(fake *projectReviewLocalDeadlineLogoutRepository) <-chan struct{} { return fake.bindCalled },
			deadline: func(fake *projectReviewLocalDeadlineLogoutRepository) time.Time { return fake.bindDeadline },
			calls:    func(fake *projectReviewLocalDeadlineLogoutRepository) int { return fake.bindCalls },
		},
		{
			name: "complete", post: true, called: func(fake *projectReviewLocalDeadlineLogoutRepository) <-chan struct{} { return fake.completeCalled },
			deadline: func(fake *projectReviewLocalDeadlineLogoutRepository) time.Time { return fake.completeDeadline },
			calls:    func(fake *projectReviewLocalDeadlineLogoutRepository) int { return fake.completeCalls },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := &projectReviewLocalDeadlineLogoutRepository{
				bindCalled: make(chan struct{}), completeCalled: make(chan struct{}),
			}
			handler, cookies, logoutCookies, sessionRepository := newProjectReviewLocalRPLogoutHandler(t, fake)
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			method := http.MethodGet
			target := logoutdomain.ConfirmPath
			var body string
			if test.post {
				method = http.MethodPost
				body = url.Values{"csrf_token": {projectReviewLogoutCSRFProof}, "decision": {string(logoutdomain.DecisionConfirm)}}.Encode()
			}
			request := httptest.NewRequest(method, target, strings.NewReader(body)).WithContext(parent)
			if test.post {
				request.Header.Set("Origin", projectReviewLogoutIssuer)
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				request.ContentLength = int64(len(body))
			}
			projectReviewLocalRPLogoutCookies(request, cookies, logoutCookies)
			started := time.Now()
			responses := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				responses <- response
			}()
			select {
			case <-test.called(fake):
			case <-time.After(time.Second):
				cancel()
				select {
				case <-responses:
				case <-time.After(time.Second):
				}
				t.Fatal("blocking RP logout dependency was not called")
			}
			assertProjectReviewLocalOperationDeadline(t, test.deadline(fake), started)
			cancel()
			var response *httptest.ResponseRecorder
			select {
			case response = <-responses:
			case <-time.After(time.Second):
				t.Fatal("RP logout handler did not return after context cancellation")
			}
			if response.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500", response.Code)
			}
			if test.calls(fake) != 1 || sessionRepository.findCalls != 1 {
				t.Fatalf("dependency calls = %d, authenticate calls = %d; want 1/1", test.calls(fake), sessionRepository.findCalls)
			}
			setCookies := response.Result().Cookies()
			if projectReviewLogoutHasCleared(setCookies, cookies.SessionName) || projectReviewLogoutHasCleared(setCookies, cookies.CSRFName) || projectReviewLogoutHasCleared(setCookies, logoutCookies.Name) {
				t.Fatal("canceled RP logout operation cleared a cookie")
			}
			if strings.Contains(response.Body.String(), projectReviewLogoutLookupToken) || strings.Contains(response.Body.String(), projectReviewLogoutCSRFProof) {
				t.Fatal("RP logout error leaked submitted credential material")
			}
		})
	}
}
