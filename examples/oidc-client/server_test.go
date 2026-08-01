package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func TestBeginLoginKeepsStateNonceAndVerifierServerSide(t *testing.T) {
	t.Parallel()
	cfg := exampleTestConfig(t, "http://127.0.0.1:9000")
	metadata := exampleTestMetadata(cfg.Issuer.String())
	sessions := newMemorySessions(rand.Reader)
	application, err := newExampleApplication(cfg, metadata, &http.Client{Timeout: time.Second}, sessions)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 1, 12, 0, 0, 0, time.UTC)
	application.now = func() time.Time { return now }
	request := httptest.NewRequest(http.MethodGet, "/login?prompt=create", nil)
	response := httptest.NewRecorder()
	application.ServeHTTP(response, request)
	if response.Code != http.StatusFound || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body)
	}
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	query := location.Query()
	for key, want := range map[string]string{
		"client_id": cfg.ClientID, "redirect_uri": cfg.RedirectURI, "response_type": "code",
		"response_mode": "query", "scope": "email openid profile", "code_challenge_method": "S256", "prompt": "create",
	} {
		if len(query[key]) != 1 || query.Get(key) != want {
			t.Fatalf("authorize parameter %s=%q want=%q", key, query[key], want)
		}
	}
	if len(query.Get("state")) < 40 || len(query.Get("nonce")) < 40 || len(query.Get("code_challenge")) != 43 {
		t.Fatalf("bounded random parameters are missing: %v", query)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].Value == "" {
		t.Fatalf("session cookie=%+v", cookies)
	}
	sessionValue, ok := sessions.get(cookies[0].Value, now)
	if !ok || sessionValue.Pending == nil || sessionValue.Pending.State != query.Get("state") || sessionValue.Pending.Nonce != query.Get("nonce") {
		t.Fatalf("server-side pending state=%+v", sessionValue.Pending)
	}
	digest := sha256.Sum256([]byte(sessionValue.Pending.Verifier))
	if base64.RawURLEncoding.EncodeToString(digest[:]) != query.Get("code_challenge") || strings.Contains(location.String(), sessionValue.Pending.Verifier) {
		t.Fatal("PKCE verifier was not retained exclusively server-side")
	}
}

func TestCallbackValidatesTokensCallsUserInfoAndStoresOnlyJITIdentity(t *testing.T) {
	t.Parallel()
	private := exampleTestRSAKey(t)
	kid := exampleTestKID(private)
	now := time.Date(2026, time.August, 1, 12, 0, 0, 0, time.UTC)
	const (
		state       = "state_server_side_canary"
		nonce       = "nonce_server_side_canary"
		verifier    = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
		code        = "code_callback_canary"
		accessToken = "access.token.canary"
		subject     = "usr_subject_for_example"
	)
	var issuer string
	provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/oauth2/token":
			if request.Method != http.MethodPost || request.Header.Get("Authorization") != "" || request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				t.Errorf("unexpected Token request headers: %v", request.Header)
			}
			body, _ := io.ReadAll(request.Body)
			form, _ := url.ParseQuery(string(body))
			if form.Get("code") != code || form.Get("code_verifier") != verifier || form.Get("client_id") == "" {
				t.Errorf("unexpected Token form (values intentionally not printed)")
			}
			claims := idTokenClaims{
				Issuer: issuer, Subject: subject, Audience: form.Get("client_id"), AuthorizedParty: form.Get("client_id"),
				ExpiresAt: now.Add(5 * time.Minute).Unix(), IssuedAt: now.Unix(), AuthTime: now.Add(-time.Minute).Unix(), Nonce: nonce,
				Name: exampleStringPointer("Alice"), Email: exampleStringPointer("alice@example.test"), EmailVerified: exampleBoolPointer(false),
			}
			compact := signExampleJWT(t, private, kid, "JWT", claims)
			_ = json.NewEncoder(writer).Encode(tokenResponse{
				AccessToken: accessToken, TokenType: "Bearer", ExpiresIn: 600, IDToken: compact, Scope: "email openid profile",
			})
		case "/oauth2/jwks":
			_ = json.NewEncoder(writer).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
				Key: &private.PublicKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig",
			}}})
		case "/oauth2/userinfo":
			if request.Header.Get("Authorization") != "Bearer "+accessToken {
				t.Errorf("UserInfo did not receive the transient Access Token")
			}
			_ = json.NewEncoder(writer).Encode(userInfoResponse{
				Subject: subject, Name: exampleStringPointer("Alice Current"), Email: exampleStringPointer("alice@example.test"), EmailVerified: exampleBoolPointer(false),
			})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer provider.Close()
	issuer = provider.URL
	cfg := exampleTestConfig(t, issuer)
	metadata := exampleTestMetadata(issuer)
	sessions := newMemorySessions(rand.Reader)
	sessionValue, err := sessions.create(now)
	if err != nil {
		t.Fatal(err)
	}
	sessionValue.Pending = &authorizationAttempt{State: state, Nonce: nonce, Verifier: verifier, CreatedAt: now.Add(-time.Second)}
	sessions.save(sessionValue)
	application, err := newExampleApplication(cfg, metadata, provider.Client(), sessions)
	if err != nil {
		t.Fatal(err)
	}
	application.now = func() time.Time { return now }

	request := httptest.NewRequest(http.MethodGet, "/callback?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), nil)
	request.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: sessionValue.ID})
	response := httptest.NewRecorder()
	application.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/" ||
		strings.Contains(response.Body.String(), accessToken) || strings.Contains(response.Body.String(), code) || strings.Contains(response.Body.String(), verifier) {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value == sessionValue.ID {
		t.Fatalf("example session was not rotated: %+v", cookies)
	}
	rotated, ok := sessions.get(cookies[0].Value, now)
	if !ok || rotated.Pending != nil || rotated.Identity == nil || rotated.Identity.Issuer != issuer || rotated.Identity.Subject != subject ||
		rotated.Identity.Key != jitIdentityKey(issuer, subject) || rotated.Identity.Name != "Alice Current" {
		t.Fatalf("rotated identity=%+v", rotated.Identity)
	}
	serialized, _ := json.Marshal(rotated)
	for _, forbidden := range []string{accessToken, code, verifier, nonce, "IDToken", "AccessToken"} {
		if strings.Contains(string(serialized), forbidden) {
			t.Fatalf("server session retained protocol credential %q", forbidden)
		}
	}

	home := httptest.NewRequest(http.MethodGet, "/", nil)
	home.AddCookie(cookies[0])
	homeResponse := httptest.NewRecorder()
	application.ServeHTTP(homeResponse, home)
	if homeResponse.Code != http.StatusOK || !strings.Contains(homeResponse.Body.String(), "Alice Current") {
		t.Fatalf("home status=%d body=%s", homeResponse.Code, homeResponse.Body)
	}
	for _, forbidden := range []string{accessToken, code, verifier, nonce, "alice@example.test"} {
		if strings.Contains(homeResponse.Body.String(), forbidden) {
			t.Fatalf("example page exposed transient/private value %q", forbidden)
		}
	}
}

func TestVerifyIDTokenRejectsAlgorithmHeaderClaimAndKeyConfusion(t *testing.T) {
	t.Parallel()
	private := exampleTestRSAKey(t)
	other := exampleTestRSAKey(t)
	kid := exampleTestKID(private)
	now := time.Date(2026, time.August, 1, 12, 0, 0, 0, time.UTC)
	var jwks jose.JSONWebKeySet
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(jwks)
	}))
	defer server.Close()
	cfg := exampleTestConfig(t, server.URL)
	metadata := exampleTestMetadata(server.URL)
	jwks = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &private.PublicKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"}}}
	valid := idTokenClaims{
		Issuer: server.URL, Subject: "subject", Audience: cfg.ClientID, AuthorizedParty: cfg.ClientID,
		ExpiresAt: now.Add(5 * time.Minute).Unix(), IssuedAt: now.Unix(), AuthTime: now.Add(-time.Minute).Unix(), Nonce: "nonce",
	}
	tests := []struct {
		name   string
		build  func() string
		mutate func()
	}{
		{name: "typ", build: func() string { return signExampleJWT(t, private, kid, "at+jwt", valid) }},
		{name: "kid", build: func() string { return signExampleJWT(t, private, "unknown", "JWT", valid) }},
		{name: "signature", build: func() string { return signExampleJWT(t, other, kid, "JWT", valid) }},
		{name: "issuer", build: func() string {
			claims := valid
			claims.Issuer = "https://other.example"
			return signExampleJWT(t, private, kid, "JWT", claims)
		}},
		{name: "audience", build: func() string {
			claims := valid
			claims.Audience = "other-client"
			return signExampleJWT(t, private, kid, "JWT", claims)
		}},
		{name: "nonce", build: func() string {
			claims := valid
			claims.Nonce = "other"
			return signExampleJWT(t, private, kid, "JWT", claims)
		}},
		{name: "expired", build: func() string {
			claims := valid
			claims.ExpiresAt = now.Add(-time.Minute).Unix()
			claims.IssuedAt = now.Add(-10 * time.Minute).Unix()
			return signExampleJWT(t, private, kid, "JWT", claims)
		}},
		{name: "private JWKS", mutate: func() {
			jwks = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: private, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"}}}
		}, build: func() string { return signExampleJWT(t, private, kid, "JWT", valid) }},
		{name: "duplicate kid", mutate: func() {
			jwks = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &private.PublicKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"}, {Key: &other.PublicKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"}}}
		}, build: func() string { return signExampleJWT(t, private, kid, "JWT", valid) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			jwks = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &private.PublicKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"}}}
			if test.mutate != nil {
				test.mutate()
			}
			if _, err := verifyIDToken(context.Background(), server.Client(), cfg, metadata, test.build(), "nonce", now); err == nil {
				t.Fatal("invalid ID Token was accepted")
			}
		})
	}
}

func TestProviderResponseRejectsRefreshTokenAndUntrustedEndpoint(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"access_token":"a","token_type":"Bearer","expires_in":600,"id_token":"i","scope":"openid","refresh_token":"forbidden"}`)
	}))
	defer server.Close()
	cfg := exampleTestConfig(t, server.URL)
	metadata := exampleTestMetadata(server.URL)
	if _, err := exchangeAuthorizationCode(context.Background(), server.Client(), cfg, metadata, "code", "verifier"); err == nil {
		t.Fatal("example accepted a phase-four refresh_token field")
	}
	if _, err := cfg.backchannelURL("https://attacker.invalid/oauth2/token"); err == nil {
		t.Fatal("example accepted an endpoint outside the configured Issuer")
	}
}

func exampleTestConfig(t *testing.T, issuer string) exampleConfig {
	t.Helper()
	parsed, err := url.Parse(issuer)
	if err != nil {
		t.Fatal(err)
	}
	return exampleConfig{
		Name: "Example RP", Addr: ":0", Issuer: parsed, ClientID: "ois_cli_example",
		RedirectURI: "http://127.0.0.1:8081/callback", Scopes: []string{"email", "openid", "profile"},
		CookieName: "example_session", CookieSecure: false,
	}
}

func exampleTestMetadata(issuer string) providerMetadata {
	return providerMetadata{
		Issuer: issuer, AuthorizationEndpoint: issuer + "/oauth2/authorize", TokenEndpoint: issuer + "/oauth2/token",
		UserInfoEndpoint: issuer + "/oauth2/userinfo", JWKSURI: issuer + "/oauth2/jwks",
		ResponseTypesSupported: []string{"code"}, ResponseModesSupported: []string{"query"}, GrantTypesSupported: []string{"authorization_code"},
		SubjectTypesSupported: []string{"public"}, IDTokenSigningAlgorithmsSupported: []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"none", "client_secret_basic"}, ScopesSupported: []string{"openid", "profile", "email"},
		ClaimsSupported:               []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "azp", "name", "preferred_username", "email", "email_verified"},
		CodeChallengeMethodsSupported: []string{"S256"}, PromptValuesSupported: []string{"none", "login", "consent", "create"},
	}
}

func exampleTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func exampleTestKID(key *rsa.PrivateKey) string {
	digest := sha256.Sum256(key.N.Bytes())
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func signExampleJWT(t *testing.T, key *rsa.PrivateKey, kid, typ string, claims any) string {
	t.Helper()
	options := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{
		Key: key, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig",
	}}, options)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func exampleStringPointer(value string) *string { return &value }
func exampleBoolPointer(value bool) *bool       { return &value }

func TestJITIdentityKeyUsesIssuerAndSubjectTuple(t *testing.T) {
	t.Parallel()
	first := jitIdentityKey("https://issuer-a.example", "subject")
	if first == jitIdentityKey("https://issuer-b.example", "subject") || first == jitIdentityKey("https://issuer-a.example", "other") ||
		!strings.HasPrefix(first, "jit1_") {
		t.Fatal("JIT key did not bind both iss and sub")
	}
}

func TestMemorySessionDoesNotAliasSensitivePendingState(t *testing.T) {
	t.Parallel()
	store := newMemorySessions(bytes.NewReader(bytes.Repeat([]byte{1}, 256)))
	now := time.Now().UTC()
	value, err := store.create(now)
	if err != nil {
		t.Fatal(err)
	}
	value.Pending = &authorizationAttempt{State: "state", Nonce: "nonce", Verifier: "verifier", CreatedAt: now}
	store.save(value)
	loaded, ok := store.get(value.ID, now)
	if !ok {
		t.Fatal("saved session missing")
	}
	loaded.Pending.Verifier = "mutated"
	reloaded, _ := store.get(value.ID, now)
	if reloaded.Pending.Verifier != "verifier" {
		t.Fatal("session store returned an aliased pending authorization value")
	}
}

func TestDecodeStrictJSONRejectsMultipleValues(t *testing.T) {
	t.Parallel()
	var value map[string]any
	if err := decodeStrictJSON(strings.NewReader(`{} {}`), &value); err == nil {
		t.Fatal("multiple JSON documents accepted")
	}
}
