package httpserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/authorization"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/oidc"
	"github.com/oneissuer/oneissuer/internal/token"
)

func TestParseTokenFormEnforcesExactBoundedEncoding(t *testing.T) {
	t.Parallel()
	valid := validHTTPTokenForm().Encode()
	tests := []struct {
		name        string
		target      string
		contentType []string
		body        string
		length      int64
		wantOK      bool
	}{
		{name: "valid", target: oidc.TokenPath, contentType: []string{"application/x-www-form-urlencoded"}, body: valid, wantOK: true},
		{name: "media type case", target: oidc.TokenPath, contentType: []string{"Application/X-Www-Form-Urlencoded"}, body: valid, wantOK: true},
		{name: "missing content type", target: oidc.TokenPath, body: valid},
		{name: "duplicate content type", target: oidc.TokenPath, contentType: []string{"application/x-www-form-urlencoded", "application/x-www-form-urlencoded"}, body: valid},
		{name: "content type parameter", target: oidc.TokenPath, contentType: []string{"application/x-www-form-urlencoded; charset=utf-8"}, body: valid},
		{name: "json", target: oidc.TokenPath, contentType: []string{"application/json"}, body: valid},
		{name: "query", target: oidc.TokenPath + "?code=canary", contentType: []string{"application/x-www-form-urlencoded"}, body: valid},
		{name: "empty", target: oidc.TokenPath, contentType: []string{"application/x-www-form-urlencoded"}, body: ""},
		{name: "bad percent", target: oidc.TokenPath, contentType: []string{"application/x-www-form-urlencoded"}, body: "code=%GG"},
		{name: "semicolon", target: oidc.TokenPath, contentType: []string{"application/x-www-form-urlencoded"}, body: "code=a;b"},
		{name: "declared too large", target: oidc.TokenPath, contentType: []string{"application/x-www-form-urlencoded"}, body: valid, length: maxTokenBodyBytes + 1},
		{name: "actual too large", target: oidc.TokenPath, contentType: []string{"application/x-www-form-urlencoded"}, body: strings.Repeat("x", maxTokenBodyBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, test.target, strings.NewReader(test.body))
			request.Header.Del("Content-Type")
			for _, value := range test.contentType {
				request.Header.Add("Content-Type", value)
			}
			if test.length != 0 {
				request.ContentLength = test.length
			}
			values, err := parseTokenForm(httptest.NewRecorder(), request)
			if (err == nil) != test.wantOK {
				t.Fatalf("values=%v err=%v wantOK=%v", values, err, test.wantOK)
			}
		})
	}
}

func TestTokenHandlerSuccessReturnsOnlyCommittedProfile(t *testing.T) {
	t.Parallel()
	resolver := newHTTPTokenResolver()
	service := &fakeProtocolTokens{exchangeResponse: token.Response{
		AccessToken: "access.canary.token", TokenType: "Bearer", ExpiresIn: 600,
		IDToken: "identity.canary.token", Scope: "openid profile",
	}}
	handler := &applicationHandler{tokenClients: resolver, tokens: service, now: func() time.Time { return httpTokenNow }}
	form := validHTTPTokenForm()
	clearCode := form.Get("code")
	request := httptest.NewRequest(http.MethodPost, oidc.TokenPath, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()

	handler.handleToken(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("Pragma") != "no-cache" || response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["token_type"] != "Bearer" || body["expires_in"] != float64(600) || body["scope"] != "openid profile" ||
		body["access_token"] == "" || body["id_token"] == "" {
		t.Fatalf("unexpected response: %v", body)
	}
	if _, exists := body["refresh_token"]; exists {
		t.Fatal("refresh_token must never be emitted")
	}
	wantHash, err := authorization.DigestPresentedCode(clearCode)
	if err != nil {
		t.Fatal(err)
	}
	if service.exchangeCalls != 1 || string(service.exchangeInput.CodeHash) != string(wantHash) ||
		service.exchangeInput.CodeVerifier != form.Get("code_verifier") || service.exchangeInput.RedirectURI != form.Get("redirect_uri") ||
		service.exchangeInput.Client.ClientID != resolver.public.ClientID || !service.exchangeInput.Now.Equal(httpTokenNow) {
		t.Fatalf("exchange input=%+v calls=%d", service.exchangeInput, service.exchangeCalls)
	}
	if strings.Contains(response.Body.String(), clearCode) || strings.Contains(response.Body.String(), form.Get("code_verifier")) {
		t.Fatal("token response leaked request credentials")
	}
}

func TestTokenHandlerUsesStableOAuthErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		method        string
		form          url.Values
		header        string
		serviceErr    error
		wantStatus    int
		wantCode      string
		wantChallenge string
	}{
		{name: "method", method: http.MethodGet, form: validHTTPTokenForm(), wantStatus: http.StatusMethodNotAllowed},
		{name: "unsupported grant", method: http.MethodPost, form: mutateHTTPForm(func(values url.Values) { values.Set("grant_type", "client_credentials") }), wantStatus: http.StatusBadRequest, wantCode: "unsupported_grant_type"},
		{name: "duplicate code", method: http.MethodPost, form: mutateHTTPForm(func(values url.Values) { values.Add("code", values.Get("code")) }), wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "unknown public", method: http.MethodPost, form: mutateHTTPForm(func(values url.Values) { values.Set("client_id", httpClientID(9)) }), wantStatus: http.StatusUnauthorized, wantCode: "invalid_client"},
		{name: "bad Basic", method: http.MethodPost, form: mutateHTTPForm(func(values url.Values) { values.Del("client_id") }), header: "Basic !!!", wantStatus: http.StatusUnauthorized, wantCode: "invalid_client", wantChallenge: "Basic"},
		{name: "invalid grant", method: http.MethodPost, form: validHTTPTokenForm(), serviceErr: token.ErrInvalidGrant, wantStatus: http.StatusBadRequest, wantCode: "invalid_grant"},
		{name: "storage failure", method: http.MethodPost, form: validHTTPTokenForm(), serviceErr: errors.New("database canary secret"), wantStatus: http.StatusInternalServerError, wantCode: "server_error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := newHTTPTokenResolver()
			service := &fakeProtocolTokens{exchangeErr: test.serviceErr}
			handler := &applicationHandler{tokenClients: resolver, tokens: service, now: func() time.Time { return httpTokenNow }}
			request := httptest.NewRequest(test.method, oidc.TokenPath, strings.NewReader(test.form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if test.header != "" {
				request.Header.Set("Authorization", test.header)
			}
			response := httptest.NewRecorder()
			handler.handleToken(response, request)
			if response.Code != test.wantStatus || response.Header().Get("WWW-Authenticate") != test.wantChallenge ||
				response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Pragma") != "no-cache" {
				t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body)
			}
			if test.wantStatus == http.StatusMethodNotAllowed {
				if !headerContainsToken(response.Header(), "Allow", http.MethodPost) {
					t.Fatal("missing Allow: POST")
				}
				return
			}
			var body map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body["error"] != test.wantCode || len(body) != 1 {
				t.Fatalf("body=%v decodeErr=%v", body, err)
			}
			for _, canary := range []string{test.form.Get("code"), test.form.Get("code_verifier"), "database canary secret"} {
				if canary != "" && strings.Contains(response.Body.String(), canary) {
					t.Fatalf("OAuth error leaked canary %q", canary)
				}
			}
		})
	}
}

func TestUserInfoHandlerAcceptsOnlySingleHeaderBearer(t *testing.T) {
	t.Parallel()
	compact := "header.payload.signature"
	service := &fakeProtocolTokens{userinfo: token.UserInfo{Subject: "usr_subject", Email: stringTestPointer("current@example.test"), EmailVerified: boolTestPointer(false)}}
	handler := &applicationHandler{tokens: service, now: func() time.Time { return httpTokenNow }}

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		request := httptest.NewRequest(method, oidc.UserInfoPath, nil)
		request.Header.Set("Authorization", "Bearer "+compact)
		response := httptest.NewRecorder()
		handler.handleUserInfo(response, request)
		if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/json" ||
			response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Pragma") != "no-cache" {
			t.Fatalf("method=%s status=%d headers=%v body=%s", method, response.Code, response.Header(), response.Body)
		}
		var body map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body["sub"] != "usr_subject" ||
			body["email"] != "current@example.test" || body["email_verified"] != false || len(body) != 3 {
			t.Fatalf("method=%s body=%v err=%v", method, body, err)
		}
	}
	if service.userinfoCalls != 2 || service.bearer != compact || !service.userinfoNow.Equal(httpTokenNow) {
		t.Fatalf("calls=%d bearer=%q now=%v", service.userinfoCalls, service.bearer, service.userinfoNow)
	}
}

func TestUserInfoHandlerRejectsAlternateTokenChannelsAndMalformedBearer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		method     string
		target     string
		body       string
		headers    []string
		serviceErr error
		wantStatus int
	}{
		{name: "missing", method: http.MethodGet, target: oidc.UserInfoPath, wantStatus: http.StatusUnauthorized},
		{name: "query token", method: http.MethodGet, target: oidc.UserInfoPath + "?access_token=canary", headers: []string{"Bearer header.payload.signature"}, wantStatus: http.StatusUnauthorized},
		{name: "body token", method: http.MethodPost, target: oidc.UserInfoPath, body: "access_token=canary", headers: []string{"Bearer header.payload.signature"}, wantStatus: http.StatusUnauthorized},
		{name: "duplicate", method: http.MethodGet, target: oidc.UserInfoPath, headers: []string{"Bearer header.payload.signature", "Bearer second.payload.signature"}, wantStatus: http.StatusUnauthorized},
		{name: "Basic", method: http.MethodGet, target: oidc.UserInfoPath, headers: []string{"Basic abc"}, wantStatus: http.StatusUnauthorized},
		{name: "comma", method: http.MethodGet, target: oidc.UserInfoPath, headers: []string{"Bearer header.payload.signature,Bearer second.payload.signature"}, wantStatus: http.StatusUnauthorized},
		{name: "extra space", method: http.MethodGet, target: oidc.UserInfoPath, headers: []string{"Bearer  header.payload.signature"}, wantStatus: http.StatusUnauthorized},
		{name: "too large", method: http.MethodGet, target: oidc.UserInfoPath, headers: []string{"Bearer " + strings.Repeat("a", maxBearerTokenBytes+1) + ".b.c"}, wantStatus: http.StatusUnauthorized},
		{name: "bad compact", method: http.MethodGet, target: oidc.UserInfoPath, headers: []string{"Bearer opaque"}, wantStatus: http.StatusUnauthorized},
		{name: "verification failure", method: http.MethodGet, target: oidc.UserInfoPath, headers: []string{"Bearer header.payload.signature"}, serviceErr: token.ErrInvalidToken, wantStatus: http.StatusUnauthorized},
		{name: "method", method: http.MethodPut, target: oidc.UserInfoPath, headers: []string{"Bearer header.payload.signature"}, wantStatus: http.StatusMethodNotAllowed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &fakeProtocolTokens{userinfoErr: test.serviceErr}
			handler := &applicationHandler{tokens: service, now: func() time.Time { return httpTokenNow }}
			request := httptest.NewRequest(test.method, test.target, strings.NewReader(test.body))
			for _, header := range test.headers {
				request.Header.Add("Authorization", header)
			}
			response := httptest.NewRecorder()
			handler.handleUserInfo(response, request)
			if response.Code != test.wantStatus || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Pragma") != "no-cache" {
				t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body)
			}
			if test.wantStatus == http.StatusMethodNotAllowed {
				if !headerContainsToken(response.Header(), "Allow", http.MethodGet) || !headerContainsToken(response.Header(), "Allow", http.MethodPost) {
					t.Fatal("missing UserInfo Allow methods")
				}
				return
			}
			if response.Header().Get("WWW-Authenticate") != "Bearer" || service.userinfoCalls > 1 {
				t.Fatalf("challenge=%q calls=%d", response.Header().Get("WWW-Authenticate"), service.userinfoCalls)
			}
			var body map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body["error"] != "invalid_token" || len(body) != 1 {
				t.Fatalf("body=%v err=%v", body, err)
			}
			if strings.Contains(response.Body.String(), "canary") || strings.Contains(response.Body.String(), "header.payload.signature") {
				t.Fatal("Bearer failure leaked submitted token")
			}
		})
	}
}

var httpTokenNow = time.Date(2026, time.August, 1, 8, 0, 0, 0, time.UTC)

type httpTokenResolver struct {
	public       clientdomain.Client
	confidential clientdomain.Client
	secret       string
}

func newHTTPTokenResolver() *httpTokenResolver {
	return &httpTokenResolver{
		public: clientdomain.Client{
			ID: uuid.New(), ClientID: httpClientID(1), Type: clientdomain.TypePublic,
			TokenEndpointAuthMethod: clientdomain.AuthMethodNone, Status: clientdomain.StatusActive, Scopes: []string{"openid", "profile"},
		},
		confidential: clientdomain.Client{
			ID: uuid.New(), ClientID: httpClientID(2), Type: clientdomain.TypeConfidential,
			TokenEndpointAuthMethod: clientdomain.AuthMethodClientSecretBasic, Status: clientdomain.StatusActive, Scopes: []string{"openid"},
		},
		secret: "ois_sec_v1_" + base64.RawURLEncoding.EncodeToString(bytesOf(3, 32)),
	}
}

func (r *httpTokenResolver) ResolveActive(_ context.Context, id string) (clientdomain.Client, error) {
	if id == r.public.ClientID {
		return r.public, nil
	}
	if id == r.confidential.ClientID {
		return r.confidential, nil
	}
	return clientdomain.Client{}, clientdomain.ErrNotFound
}

func (r *httpTokenResolver) ValidateSecret(_ context.Context, id, secret string) (clientdomain.Client, error) {
	if id == r.confidential.ClientID && secret == r.secret {
		return r.confidential, nil
	}
	return clientdomain.Client{}, clientdomain.ErrNotFound
}

type fakeProtocolTokens struct {
	exchangeResponse token.Response
	exchangeErr      error
	exchangeInput    token.ExchangeInput
	exchangeCalls    int
	refreshResponse  token.Response
	refreshErr       error
	refreshInput     token.RefreshInput
	refreshCalls     int
	userinfo         token.UserInfo
	userinfoErr      error
	bearer           string
	userinfoNow      time.Time
	userinfoCalls    int
}

func (f *fakeProtocolTokens) Exchange(_ context.Context, input token.ExchangeInput) (token.Response, error) {
	f.exchangeCalls++
	f.exchangeInput = input
	return f.exchangeResponse, f.exchangeErr
}

func (f *fakeProtocolTokens) Refresh(_ context.Context, input token.RefreshInput) (token.Response, error) {
	f.refreshCalls++
	f.refreshInput = input
	return f.refreshResponse, f.refreshErr
}

func (f *fakeProtocolTokens) Revoke(context.Context, token.RevocationInput) error { return nil }

func (f *fakeProtocolTokens) Introspect(context.Context, token.IntrospectionInput) (token.IntrospectionResponse, error) {
	return token.IntrospectionResponse{Active: false}, nil
}

func (f *fakeProtocolTokens) UserInfoForAccessToken(_ context.Context, bearer string, now time.Time) (token.UserInfo, error) {
	f.userinfoCalls++
	f.bearer = bearer
	f.userinfoNow = now
	return f.userinfo, f.userinfoErr
}

func validHTTPTokenForm() url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"c1_" + base64.RawURLEncoding.EncodeToString(bytesOf(4, 32))},
		"redirect_uri":  {"https://rp.example/cb"},
		"code_verifier": {"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"},
		"client_id":     {httpClientID(1)},
	}
}

func mutateHTTPForm(mutate func(url.Values)) url.Values {
	values := validHTTPTokenForm()
	mutate(values)
	return values
}

func httpClientID(fill byte) string {
	return "ois_cli_" + base64.RawURLEncoding.EncodeToString(bytesOf(fill, 24))
}

func bytesOf(fill byte, size int) []byte {
	value := make([]byte, size)
	for index := range value {
		value[index] = fill
	}
	return value
}

func stringTestPointer(value string) *string { return &value }
func boolTestPointer(value bool) *bool       { return &value }

func TestHTTPTokenFixtureDigestIsNotClearValue(t *testing.T) {
	t.Parallel()
	code := validHTTPTokenForm().Get("code")
	digest, err := authorization.DigestPresentedCode(code)
	if err != nil || len(digest) != sha256.Size || strings.Contains(base64.RawURLEncoding.EncodeToString(digest), code) {
		t.Fatalf("digest=%x err=%v", digest, err)
	}
}
