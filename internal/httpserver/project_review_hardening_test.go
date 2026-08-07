package httpserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oneissuer/oneissuer/internal/oidc"
	"github.com/oneissuer/oneissuer/internal/token"
)

func TestProjectReviewRecoveryLogsOnlyFixedPanicClassification(t *testing.T) {
	t.Parallel()

	const canary = "project-review-panic-canary"
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{}))
	handler := requestIDMiddleware(recoveryMiddleware(logger, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(canary)
	})))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/panic", nil))

	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), `"code":"internal_error"`) {
		t.Fatalf("panic response = %d %s", response.Code, response.Body)
	}
	if strings.Contains(logs.String(), canary) || strings.Contains(logs.String(), "stack") || strings.Contains(logs.String(), "runtime/debug") {
		t.Fatalf("panic log leaked value or stack: %s", logs.String())
	}
	if !strings.Contains(logs.String(), `"error_class":"panic"`) {
		t.Fatalf("panic classification missing: %s", logs.String())
	}
}

func TestProjectReviewLifecycleRoutesHaveStableMetricLabels(t *testing.T) {
	t.Parallel()
	for _, path := range []string{oidc.RevocationPath, oidc.IntrospectionPath} {
		if got := routeLabel(path); got != path {
			t.Errorf("routeLabel(%q) = %q, want stable route label", path, got)
		}
	}
}

func TestProjectReviewOperationContextHasDeadline(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(http.MethodPost, oidc.RevocationPath, nil)
	before := time.Now()
	ctx, cancel := operationContext(request)
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.After(before) || deadline.After(before.Add(defaultOperationTimeout+time.Second)) {
		t.Fatalf("operation context deadline = %v, ok=%v, now=%v", deadline, ok, before)
	}
}

func TestProjectReviewLifecycleHandlersPropagateDeadlineAndNeverReturnSuccess(t *testing.T) {
	t.Parallel()
	resolver := newHTTPTokenResolver()
	for _, test := range []struct {
		name       string
		path       string
		form       url.Values
		header     string
		called     func(*projectReviewBlockingProtocolTokens) *atomic.Bool
		serviceErr func(*projectReviewBlockingProtocolTokens) error
	}{
		{
			name: "revoke", path: oidc.RevocationPath,
			form:       url.Values{"token": {"opaque"}, "client_id": {resolver.public.ClientID}},
			called:     func(fake *projectReviewBlockingProtocolTokens) *atomic.Bool { return &fake.revokeCalled },
			serviceErr: func(fake *projectReviewBlockingProtocolTokens) error { return fake.revokeErr },
		},
		{
			name: "introspect", path: oidc.IntrospectionPath,
			form:       url.Values{"token": {"opaque"}},
			header:     "Basic " + base64.StdEncoding.EncodeToString([]byte(resolver.confidential.ClientID+":"+resolver.secret)),
			called:     func(fake *projectReviewBlockingProtocolTokens) *atomic.Bool { return &fake.introspectCalled },
			serviceErr: func(fake *projectReviewBlockingProtocolTokens) error { return fake.introspectErr },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := &projectReviewBlockingProtocolTokens{}
			handler := &applicationHandler{tokenClients: resolver, tokens: fake, now: func() time.Time { return httpTokenNow }}
			parent, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
			defer cancel()
			request := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(test.form.Encode())).WithContext(parent)
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if test.header != "" {
				request.Header.Set("Authorization", test.header)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if !test.called(fake).Load() {
				t.Fatal("blocking protocol fake was not called")
			}
			if test.serviceErr(fake) == nil {
				t.Fatal("blocking protocol fake did not observe context cancellation")
			}
			if response.Code != http.StatusInternalServerError {
				t.Fatalf("status=%d body=%s, want server_error rather than success/partial state", response.Code, response.Body)
			}
			var body map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body["error"] != "server_error" || len(body) != 1 {
				t.Fatalf("error response=%v decode=%v", body, err)
			}
		})
	}
}

type projectReviewBlockingProtocolTokens struct {
	revokeCalled     atomic.Bool
	introspectCalled atomic.Bool
	revokeErr        error
	introspectErr    error
}

func (f *projectReviewBlockingProtocolTokens) Exchange(context.Context, token.ExchangeInput) (token.Response, error) {
	return token.Response{}, errors.New("unexpected exchange")
}

func (f *projectReviewBlockingProtocolTokens) Refresh(context.Context, token.RefreshInput) (token.Response, error) {
	return token.Response{}, errors.New("unexpected refresh")
}

func (f *projectReviewBlockingProtocolTokens) Revoke(ctx context.Context, _ token.RevocationInput) error {
	f.revokeCalled.Store(true)
	<-ctx.Done()
	f.revokeErr = ctx.Err()
	return f.revokeErr
}

func (f *projectReviewBlockingProtocolTokens) Introspect(ctx context.Context, _ token.IntrospectionInput) (token.IntrospectionResponse, error) {
	f.introspectCalled.Store(true)
	<-ctx.Done()
	f.introspectErr = ctx.Err()
	return token.IntrospectionResponse{}, f.introspectErr
}

func (f *projectReviewBlockingProtocolTokens) UserInfoForAccessToken(context.Context, string, time.Time) (token.UserInfo, error) {
	return token.UserInfo{}, errors.New("unexpected userinfo")
}

var _ ProtocolTokenService = (*projectReviewBlockingProtocolTokens)(nil)

func TestProjectReviewUserInfoErrorsUseProtocolSafeResponses(t *testing.T) {
	t.Parallel()

	const compact = "header.payload.signature"
	const infrastructureCanary = "userinfo database password canary"
	tests := []struct {
		name          string
		serviceErr    error
		wantStatus    int
		wantCode      string
		wantChallenge string
	}{
		{
			name:          "invalid token",
			serviceErr:    token.ErrInvalidToken,
			wantStatus:    http.StatusUnauthorized,
			wantCode:      "invalid_token",
			wantChallenge: "Bearer",
		},
		{
			name:       "infrastructure failure",
			serviceErr: errors.New(infrastructureCanary),
			wantStatus: http.StatusInternalServerError,
			wantCode:   "server_error",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &fakeProtocolTokens{userinfoErr: test.serviceErr}
			handler := &applicationHandler{tokens: service, now: func() time.Time { return httpTokenNow }}
			request := httptest.NewRequest(http.MethodGet, oidc.UserInfoPath, nil)
			request.Header.Set("Authorization", "Bearer "+compact)
			response := httptest.NewRecorder()
			handler.handleUserInfo(response, request)

			if response.Code != test.wantStatus || response.Header().Get("WWW-Authenticate") != test.wantChallenge {
				t.Fatalf("status=%d challenge=%q body=%s", response.Code, response.Header().Get("WWW-Authenticate"), response.Body)
			}
			var body map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body["error"] != test.wantCode || len(body) != 1 {
				t.Fatalf("body=%v decode=%v", body, err)
			}
			if strings.Contains(response.Body.String(), compact) || strings.Contains(response.Body.String(), infrastructureCanary) {
				t.Fatalf("UserInfo error leaked credential or infrastructure detail: %s", response.Body)
			}
		})
	}
}

func TestProjectReviewUserInfoBlockingServiceHonorsParentDeadline(t *testing.T) {
	t.Parallel()

	const compact = "header.payload.signature"
	service := &projectReviewUserInfoBlockingProtocolTokens{}
	handler := &applicationHandler{tokens: service, now: func() time.Time { return httpTokenNow }}
	parent, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	parentDeadline, _ := parent.Deadline()
	request := httptest.NewRequest(http.MethodGet, oidc.UserInfoPath, nil).WithContext(parent)
	request.Header.Set("Authorization", "Bearer "+compact)
	response := httptest.NewRecorder()
	handler.handleUserInfo(response, request)

	if !service.called.Load() {
		t.Fatal("blocking UserInfo service was not called")
	}
	if !service.contextDeadlineSet || service.contextDeadline.After(parentDeadline) {
		t.Fatalf("derived operation deadline=%v, parent deadline=%v", service.contextDeadline, parentDeadline)
	}
	if !errors.Is(service.contextErr, context.DeadlineExceeded) {
		t.Fatalf("blocking UserInfo service error=%v, want context deadline", service.contextErr)
	}
	if response.Code != http.StatusInternalServerError || response.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("status=%d challenge=%q body=%s, want server_error without Bearer challenge", response.Code, response.Header().Get("WWW-Authenticate"), response.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body["error"] != "server_error" || len(body) != 1 {
		t.Fatalf("body=%v decode=%v", body, err)
	}
	if strings.Contains(response.Body.String(), compact) {
		t.Fatalf("server error leaked submitted token: %s", response.Body)
	}
}

type projectReviewUserInfoBlockingProtocolTokens struct {
	projectReviewBlockingProtocolTokens
	called             atomic.Bool
	contextDeadline    time.Time
	contextDeadlineSet bool
	contextErr         error
}

func (f *projectReviewUserInfoBlockingProtocolTokens) UserInfoForAccessToken(ctx context.Context, _ string, _ time.Time) (token.UserInfo, error) {
	f.called.Store(true)
	f.contextDeadline, f.contextDeadlineSet = ctx.Deadline()
	select {
	case <-ctx.Done():
		f.contextErr = ctx.Err()
	case <-time.After(time.Second):
		f.contextErr = errors.New("blocking UserInfo fake timed out")
	}
	return token.UserInfo{}, f.contextErr
}

var _ ProtocolTokenService = (*projectReviewUserInfoBlockingProtocolTokens)(nil)
