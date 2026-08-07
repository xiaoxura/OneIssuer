package token

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/consent"
	"github.com/oneissuer/oneissuer/internal/identity"
)

const testIssuer = "https://issuer.example"

var errTestCommit = errors.New("test commit failed")

func TestExchangeMintsFixedRS256Profiles(t *testing.T) {
	t.Parallel()
	fixture := newTokenFixture(t, []string{"email", "openid", "profile"})

	response, err := fixture.service.Exchange(context.Background(), fixture.exchangeInput())
	if err != nil {
		t.Fatal(err)
	}
	if response.AccessToken == "" || response.IDToken == "" || response.TokenType != "Bearer" ||
		response.ExpiresIn != int64((10*time.Minute)/time.Second) || response.Scope != "email openid profile" {
		t.Fatalf("unexpected token response: %+v", response)
	}
	if strings.Contains(mustJSON(t, response), "refresh_token") {
		t.Fatal("phase-three response unexpectedly contains refresh_token")
	}

	idHeader, idPayload := parseAndVerify(t, response.IDToken, fixture.keys, jose.RS256)
	assertHeader(t, idHeader, fixture.keys.kid, "JWT")
	var idClaims IDTokenClaims
	decodeExact(t, idPayload, &idClaims)
	if idClaims.Issuer != testIssuer || idClaims.Subject != fixture.authority.User.Subject ||
		idClaims.Audience != fixture.authority.Client.ClientID || idClaims.AuthorizedParty != fixture.authority.Client.ClientID ||
		idClaims.IssuedAt != fixture.now.Unix() || idClaims.ExpiresAt != fixture.now.Add(5*time.Minute).Unix() ||
		idClaims.AuthTime != fixture.authority.AuthenticatedAt.Unix() || idClaims.Nonce != fixture.authority.Nonce {
		t.Fatalf("unexpected ID Token claims: %+v", idClaims)
	}
	if idClaims.Name == nil || *idClaims.Name != fixture.authority.User.DisplayName ||
		idClaims.PreferredUsername == nil || *idClaims.PreferredUsername != fixture.authority.User.Username ||
		idClaims.Email == nil || *idClaims.Email != fixture.authority.User.Email ||
		idClaims.EmailVerified == nil || *idClaims.EmailVerified {
		t.Fatalf("scope claim projection is wrong: %+v", idClaims)
	}
	var idMap map[string]any
	decodeExact(t, idPayload, &idMap)
	if verified, present := idMap["email_verified"]; !present || verified != false {
		t.Fatalf("email_verified=false must be present, payload=%s", idPayload)
	}
	for _, forbidden := range []string{"id", "role", "status", "username_normalized", "email_normalized", "password", "session", "client_secret"} {
		if _, present := idMap[forbidden]; present {
			t.Fatalf("internal claim %q leaked in ID Token", forbidden)
		}
	}

	accessHeader, accessPayload := parseAndVerify(t, response.AccessToken, fixture.keys, jose.RS256)
	assertHeader(t, accessHeader, fixture.keys.kid, "at+jwt")
	var accessClaims AccessTokenClaims
	decodeExact(t, accessPayload, &accessClaims)
	if accessClaims.Issuer != testIssuer || accessClaims.Subject != fixture.authority.User.Subject ||
		accessClaims.Audience != testIssuer+"/oauth2/userinfo" || accessClaims.ClientID != fixture.authority.Client.ClientID ||
		accessClaims.Scope != "email openid profile" || accessClaims.IssuedAt != fixture.now.Unix() ||
		accessClaims.ExpiresAt != fixture.now.Add(10*time.Minute).Unix() || !validJTI(accessClaims.JWTID) {
		t.Fatalf("unexpected Access Token claims: %+v", accessClaims)
	}
	if !bytes.Equal(fixture.repository.minted.JTIHash, HashJTI(accessClaims.JWTID)) ||
		fixture.repository.minted.AccessTokenID == uuid.Nil {
		t.Fatal("persistable access metadata does not bind the minted jti")
	}
}

func TestExchangeMinimizesOptionalClaims(t *testing.T) {
	t.Parallel()
	fixture := newTokenFixture(t, []string{"openid"})
	fixture.authority.Nonce = ""
	fixture.repository.exchangeAuthority.Nonce = ""

	response, err := fixture.service.Exchange(context.Background(), fixture.exchangeInput())
	if err != nil {
		t.Fatal(err)
	}
	_, payload := parseAndVerify(t, response.IDToken, fixture.keys, jose.RS256)
	var claims map[string]any
	decodeExact(t, payload, &claims)
	for _, absent := range []string{"nonce", "name", "preferred_username", "email", "email_verified"} {
		if _, present := claims[absent]; present {
			t.Fatalf("claim %q must be absent for openid-only grant: %s", absent, payload)
		}
	}
}

func TestExchangeFailsClosedForSignerAndCommitFailures(t *testing.T) {
	t.Parallel()

	t.Run("signer", func(t *testing.T) {
		fixture := newTokenFixture(t, []string{"openid"})
		fixture.keys.failAt = 1
		response, err := fixture.service.Exchange(context.Background(), fixture.exchangeInput())
		if err == nil || response != (Response{}) || fixture.repository.committed {
			t.Fatalf("response=%+v err=%v committed=%v", response, err, fixture.repository.committed)
		}
	})

	t.Run("access signer after ID signer", func(t *testing.T) {
		fixture := newTokenFixture(t, []string{"openid"})
		fixture.keys.failAt = 2
		response, err := fixture.service.Exchange(context.Background(), fixture.exchangeInput())
		if err == nil || response != (Response{}) || fixture.repository.committed {
			t.Fatalf("response=%+v err=%v committed=%v", response, err, fixture.repository.committed)
		}
	})

	t.Run("repository commit", func(t *testing.T) {
		fixture := newTokenFixture(t, []string{"openid"})
		fixture.repository.commitErr = errTestCommit
		response, err := fixture.service.Exchange(context.Background(), fixture.exchangeInput())
		if !errors.Is(err, errTestCommit) || response != (Response{}) || fixture.repository.committed {
			t.Fatalf("response=%+v err=%v committed=%v", response, err, fixture.repository.committed)
		}
		if fixture.repository.minted.AccessToken == "" || fixture.repository.minted.IDToken == "" {
			t.Fatal("test did not reach the post-mint commit boundary")
		}
	})
}

func TestExchangeRejectsInvalidBoundaryInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*ExchangeInput)
	}{
		{name: "code digest", mutate: func(input *ExchangeInput) { input.CodeHash = input.CodeHash[:31] }},
		{name: "redirect", mutate: func(input *ExchangeInput) { input.RedirectURI = "" }},
		{name: "verifier", mutate: func(input *ExchangeInput) { input.CodeVerifier = "short" }},
		{name: "time", mutate: func(input *ExchangeInput) { input.Now = time.Time{} }},
		{name: "disabled client", mutate: func(input *ExchangeInput) { input.Client.Status = clientdomain.StatusDisabled }},
		{name: "auth downgrade", mutate: func(input *ExchangeInput) {
			input.Client.TokenEndpointAuthMethod = clientdomain.AuthMethodClientSecretBasic
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTokenFixture(t, []string{"openid"})
			input := fixture.exchangeInput()
			test.mutate(&input)
			response, err := fixture.service.Exchange(context.Background(), input)
			if !errors.Is(err, ErrInvalidGrant) || response != (Response{}) || fixture.repository.mintCalled {
				t.Fatalf("response=%+v err=%v mintCalled=%v", response, err, fixture.repository.mintCalled)
			}
		})
	}
}

func TestUserInfoRequiresJWTAndCommittedCurrentAuthority(t *testing.T) {
	t.Parallel()
	fixture := newTokenFixture(t, []string{"email", "openid", "profile"})
	response, err := fixture.service.Exchange(context.Background(), fixture.exchangeInput())
	if err != nil {
		t.Fatal(err)
	}
	fixture.repository.accessAuthority = fixture.accessAuthority()

	result, err := fixture.service.UserInfoForAccessToken(context.Background(), response.AccessToken, fixture.now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if result.Subject != fixture.authority.User.Subject || result.Name == nil || *result.Name != fixture.authority.User.DisplayName ||
		result.PreferredUsername == nil || *result.PreferredUsername != fixture.authority.User.Username ||
		result.Email == nil || *result.Email != fixture.authority.User.Email || result.EmailVerified == nil || *result.EmailVerified {
		t.Fatalf("unexpected UserInfo: %+v", result)
	}
	if !bytes.Equal(fixture.repository.lookupHash, fixture.repository.minted.JTIHash) {
		t.Fatal("UserInfo lookup did not use the domain-separated jti digest")
	}

	tests := []struct {
		name   string
		mutate func(*AccessAuthority, *fakeRepository)
	}{
		{name: "metadata missing", mutate: func(_ *AccessAuthority, repository *fakeRepository) { repository.accessErr = ErrInvalidToken }},
		{name: "disabled user", mutate: func(authority *AccessAuthority, _ *fakeRepository) { authority.User.Status = identity.StatusDisabled }},
		{name: "wrong subject", mutate: func(authority *AccessAuthority, _ *fakeRepository) { authority.User.Subject = "usr_different" }},
		{name: "disabled client", mutate: func(authority *AccessAuthority, _ *fakeRepository) {
			authority.Client.Status = clientdomain.StatusDisabled
		}},
		{name: "client scope shrink", mutate: func(authority *AccessAuthority, _ *fakeRepository) { authority.Client.Scopes = []string{"openid"} }},
		{name: "grant shrink", mutate: func(authority *AccessAuthority, _ *fakeRepository) { authority.Grant.Scopes = []string{"openid"} }},
		{name: "grant identity", mutate: func(authority *AccessAuthority, _ *fakeRepository) { authority.Grant.ID = uuid.New() }},
		{name: "metadata jti", mutate: func(authority *AccessAuthority, _ *fakeRepository) {
			authority.Metadata.JTIHash = make([]byte, sha256.Size)
		}},
		{name: "metadata scope", mutate: func(authority *AccessAuthority, _ *fakeRepository) { authority.Metadata.Scopes = []string{"openid"} }},
		{name: "metadata expired", mutate: func(authority *AccessAuthority, _ *fakeRepository) { authority.Metadata.ExpiresAt = fixture.now }},
		{name: "metadata client", mutate: func(authority *AccessAuthority, _ *fakeRepository) { authority.Client.ClientID = "ois_cli_different" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture.repository.accessErr = nil
			authority := fixture.accessAuthority()
			test.mutate(&authority, fixture.repository)
			fixture.repository.accessAuthority = authority
			userinfo, err := fixture.service.UserInfoForAccessToken(context.Background(), response.AccessToken, fixture.now.Add(time.Minute))
			if !errors.Is(err, ErrInvalidToken) || userinfo != (UserInfo{}) {
				t.Fatalf("userinfo=%+v err=%v", userinfo, err)
			}
		})
	}
}

func TestUserInfoRejectsUntrustedHeadersSignaturesAndClaims(t *testing.T) {
	t.Parallel()
	fixture := newTokenFixture(t, []string{"openid"})
	validClaims := AccessTokenClaims{
		Issuer: testIssuer, Subject: fixture.authority.User.Subject,
		Audience: testIssuer + "/oauth2/userinfo", ClientID: fixture.authority.Client.ClientID,
		Scope: "openid", IssuedAt: fixture.now.Unix(), ExpiresAt: fixture.now.Add(10 * time.Minute).Unix(),
		JWTID: "jti_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16)),
	}
	otherKey := newTestKeyStore(t)

	tests := []struct {
		name  string
		build func() string
	}{
		{name: "empty", build: func() string { return "" }},
		{name: "whitespace", build: func() string { return " " + signClaims(t, fixture.keys, validClaims, "at+jwt", fixture.keys.kid, nil) }},
		{name: "wrong algorithm", build: func() string { return signHMACClaims(t, validClaims) }},
		{name: "wrong typ", build: func() string { return signClaims(t, fixture.keys, validClaims, "JWT", fixture.keys.kid, nil) }},
		{name: "wrong kid", build: func() string { return signClaims(t, fixture.keys, validClaims, "at+jwt", "unknown-kid", nil) }},
		{name: "wrong signature", build: func() string { return signClaims(t, otherKey, validClaims, "at+jwt", fixture.keys.kid, nil) }},
		{name: "extra header", build: func() string {
			return signClaims(t, fixture.keys, validClaims, "at+jwt", fixture.keys.kid, map[jose.HeaderKey]any{"foo": "bar"})
		}},
		{name: "wrong issuer", build: func() string {
			claims := validClaims
			claims.Issuer = "https://other.example"
			return signClaims(t, fixture.keys, claims, "at+jwt", fixture.keys.kid, nil)
		}},
		{name: "wrong audience", build: func() string {
			claims := validClaims
			claims.Audience = testIssuer + "/api"
			return signClaims(t, fixture.keys, claims, "at+jwt", fixture.keys.kid, nil)
		}},
		{name: "expired", build: func() string {
			claims := validClaims
			claims.IssuedAt = fixture.now.Add(-10 * time.Minute).Unix()
			claims.ExpiresAt = fixture.now.Add(-31 * time.Second).Unix()
			return signClaims(t, fixture.keys, claims, "at+jwt", fixture.keys.kid, nil)
		}},
		{name: "future iat", build: func() string {
			claims := validClaims
			claims.IssuedAt = fixture.now.Add(31 * time.Second).Unix()
			claims.ExpiresAt = fixture.now.Add(10 * time.Minute).Unix()
			return signClaims(t, fixture.keys, claims, "at+jwt", fixture.keys.kid, nil)
		}},
		{name: "excess lifetime", build: func() string {
			claims := validClaims
			claims.ExpiresAt = fixture.now.Add(31 * time.Minute).Unix()
			return signClaims(t, fixture.keys, claims, "at+jwt", fixture.keys.kid, nil)
		}},
		{name: "malformed jti", build: func() string {
			claims := validClaims
			claims.JWTID = "jti_short"
			return signClaims(t, fixture.keys, claims, "at+jwt", fixture.keys.kid, nil)
		}},
		{name: "noncanonical scope", build: func() string {
			claims := validClaims
			claims.Scope = "openid openid"
			return signClaims(t, fixture.keys, claims, "at+jwt", fixture.keys.kid, nil)
		}},
		{name: "unsupported scope", build: func() string {
			claims := validClaims
			claims.Scope = "openid unknown"
			return signClaims(t, fixture.keys, claims, "at+jwt", fixture.keys.kid, nil)
		}},
		{name: "unknown claim", build: func() string {
			claims := map[string]any{"iss": validClaims.Issuer, "sub": validClaims.Subject, "aud": validClaims.Audience, "client_id": validClaims.ClientID,
				"scope": validClaims.Scope, "iat": validClaims.IssuedAt, "exp": validClaims.ExpiresAt, "jti": validClaims.JWTID, "role": "admin"}
			return signClaims(t, fixture.keys, claims, "at+jwt", fixture.keys.kid, nil)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture.repository.lookupCount = 0
			userinfo, err := fixture.service.UserInfoForAccessToken(context.Background(), test.build(), fixture.now)
			if !errors.Is(err, ErrInvalidToken) || userinfo != (UserInfo{}) || fixture.repository.lookupCount != 0 {
				t.Fatalf("userinfo=%+v err=%v metadata lookups=%d", userinfo, err, fixture.repository.lookupCount)
			}
		})
	}
}

func TestUserInfoRejectsAmbiguousOrWeakTrustedKeys(t *testing.T) {
	t.Parallel()
	fixture := newTokenFixture(t, []string{"openid"})
	claims := AccessTokenClaims{
		Issuer: testIssuer, Subject: fixture.authority.User.Subject, Audience: testIssuer + "/oauth2/userinfo",
		ClientID: fixture.authority.Client.ClientID, Scope: "openid", IssuedAt: fixture.now.Unix(),
		ExpiresAt: fixture.now.Add(10 * time.Minute).Unix(), JWTID: "jti_" + base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
	}
	tokenValue := signClaims(t, fixture.keys, claims, "at+jwt", fixture.keys.kid, nil)

	t.Run("duplicate kid", func(t *testing.T) {
		fixture.keys.public = append(fixture.keys.public, fixture.keys.public[0])
		if _, err := fixture.service.UserInfoForAccessToken(context.Background(), tokenValue, fixture.now); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("weak RSA", func(t *testing.T) {
		weak, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		weakKeys := &testKeyStore{private: weak, kid: "weak", public: []jose.JSONWebKey{{Key: &weak.PublicKey, KeyID: "weak", Algorithm: string(jose.RS256), Use: "sig"}}}
		weakToken := signClaims(t, weakKeys, claims, "at+jwt", weakKeys.kid, nil)
		service, err := NewService(fixture.repository, weakKeys, bytes.NewReader(make([]byte, 64)), testIssuer, 5*time.Minute, 10*time.Minute, 30*time.Second, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.UserInfoForAccessToken(context.Background(), weakToken, fixture.now); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestNewServiceValidatesFixedSecurityBounds(t *testing.T) {
	t.Parallel()
	repository := &fakeRepository{}
	keys := newTestKeyStore(t)
	valid := func() (*Service, error) {
		return NewService(repository, keys, nil, testIssuer, 5*time.Minute, 10*time.Minute, 30*time.Second, nil)
	}
	if _, err := valid(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		call func() (*Service, error)
	}{
		{name: "repository", call: func() (*Service, error) {
			return NewService(nil, keys, nil, testIssuer, 5*time.Minute, 10*time.Minute, 0, nil)
		}},
		{name: "keys", call: func() (*Service, error) {
			return NewService(repository, nil, nil, testIssuer, 5*time.Minute, 10*time.Minute, 0, nil)
		}},
		{name: "issuer path", call: func() (*Service, error) {
			return NewService(repository, keys, nil, testIssuer+"/oidc", 5*time.Minute, 10*time.Minute, 0, nil)
		}},
		{name: "issuer query", call: func() (*Service, error) {
			return NewService(repository, keys, nil, testIssuer+"?x=1", 5*time.Minute, 10*time.Minute, 0, nil)
		}},
		{name: "id ttl short", call: func() (*Service, error) {
			return NewService(repository, keys, nil, testIssuer, time.Second, 10*time.Minute, 0, nil)
		}},
		{name: "id ttl long", call: func() (*Service, error) {
			return NewService(repository, keys, nil, testIssuer, 16*time.Minute, 10*time.Minute, 0, nil)
		}},
		{name: "access ttl long", call: func() (*Service, error) {
			return NewService(repository, keys, nil, testIssuer, 5*time.Minute, 31*time.Minute, 0, nil)
		}},
		{name: "skew negative", call: func() (*Service, error) {
			return NewService(repository, keys, nil, testIssuer, 5*time.Minute, 10*time.Minute, -time.Second, nil)
		}},
		{name: "skew long", call: func() (*Service, error) {
			return NewService(repository, keys, nil, testIssuer, 5*time.Minute, 10*time.Minute, 3*time.Minute, nil)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.call(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

type tokenFixture struct {
	now        time.Time
	keys       *testKeyStore
	repository *fakeRepository
	service    *Service
	authority  Authority
}

func newTokenFixture(t *testing.T, scopes []string) *tokenFixture {
	t.Helper()
	canonical, err := consent.CanonicalScopes(scopes)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 1, 12, 0, 0, 0, time.UTC)
	user := identity.User{
		ID: uuid.New(), Subject: "usr_subject_0123456789", Username: "alice", UsernameNormalized: "alice",
		DisplayName: "Alice Example", Email: "alice@example.test", EmailNormalized: "alice@example.test",
		EmailVerified: false, Status: identity.StatusActive, Role: identity.RoleAdmin,
	}
	clientValue := clientdomain.Client{
		ID: uuid.New(), ClientID: "ois_cli_0123456789abcdefghijklmn", Name: "Example",
		Type: clientdomain.TypePublic, TokenEndpointAuthMethod: clientdomain.AuthMethodNone,
		Status: clientdomain.StatusActive, Scopes: append([]string(nil), canonical...), RedirectURIs: []string{"https://rp.example/cb"},
	}
	authority := Authority{
		CodeID: uuid.New(), GrantID: uuid.New(), User: user, Client: clientValue,
		Scopes: canonical, Nonce: "nonce-canary", AuthenticatedAt: now.Add(-5 * time.Minute), IssuedAt: now,
	}
	keys := newTestKeyStore(t)
	repository := &fakeRepository{exchangeAuthority: authority}
	service, err := NewService(repository, keys, bytes.NewReader(make([]byte, 128)), testIssuer, 5*time.Minute, 10*time.Minute, 30*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &tokenFixture{now: now, keys: keys, repository: repository, service: service, authority: authority}
}

func (f *tokenFixture) exchangeInput() ExchangeInput {
	digest := sha256.Sum256([]byte("code digest fixture"))
	return ExchangeInput{
		CodeHash: digest[:], Client: f.authority.Client, RedirectURI: "https://rp.example/cb",
		CodeVerifier: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
		RequestID:    "req-token-test", Now: f.now,
	}
}

func (f *tokenFixture) accessAuthority() AccessAuthority {
	minted := f.repository.minted
	return AccessAuthority{
		Metadata: AccessMetadata{
			ID: minted.AccessTokenID, JTIHash: append([]byte(nil), minted.JTIHash...),
			AuthorizationCodeID: &f.authority.CodeID, ConsentGrantID: f.authority.GrantID,
			UserID: f.authority.User.ID, ClientID: f.authority.Client.ID,
			Scopes: append([]string(nil), f.authority.Scopes...), IssuedAt: minted.IssuedAt, ExpiresAt: minted.AccessExpiresAt,
			IssuanceSource: IssuanceAuthorizationCode,
		},
		Grant: consent.Grant{
			ID: f.authority.GrantID, UserID: f.authority.User.ID, ClientID: f.authority.Client.ID,
			Scopes: append([]string(nil), f.authority.Scopes...), CreatedAt: f.now.Add(-time.Hour), UpdatedAt: f.now, Version: 1,
		},
		User: f.authority.User, Client: f.authority.Client,
	}
}

type fakeRepository struct {
	exchangeAuthority Authority
	exchangeErr       error
	commitErr         error
	mintCalled        bool
	committed         bool
	minted            Minted
	lastInput         ExchangeInput
	accessAuthority   AccessAuthority
	accessErr         error
	lookupHash        []byte
	lookupCount       int
}

func (r *fakeRepository) ExchangeAuthorizationCode(ctx context.Context, input ExchangeInput, mint MintFunc) (Response, error) {
	r.lastInput = input
	if r.exchangeErr != nil {
		return Response{}, r.exchangeErr
	}
	r.mintCalled = true
	minted, err := mint(ctx, r.exchangeAuthority)
	if err != nil {
		return Response{}, err
	}
	r.minted = minted
	if r.commitErr != nil {
		return Response{}, r.commitErr
	}
	r.committed = true
	return Response{
		AccessToken: minted.AccessToken, TokenType: "Bearer",
		ExpiresIn: int64(minted.AccessExpiresAt.Sub(minted.IssuedAt) / time.Second), IDToken: minted.IDToken,
		Scope: strings.Join(r.exchangeAuthority.Scopes, " "),
	}, nil
}

func (r *fakeRepository) ExchangeRefreshToken(context.Context, RefreshInput, RefreshMintFunc) (Response, error) {
	return Response{}, ErrInvalidGrant
}

func (r *fakeRepository) RevokeToken(context.Context, RevocationLookup) error { return nil }

func (r *fakeRepository) GetRefreshTokenAuthority(context.Context, []byte) (RefreshTokenAuthority, error) {
	return RefreshTokenAuthority{}, ErrInvalidGrant
}

func (r *fakeRepository) GetAccessTokenAuthority(_ context.Context, hash []byte, _ time.Time) (AccessAuthority, error) {
	r.lookupCount++
	r.lookupHash = append([]byte(nil), hash...)
	if r.accessErr != nil {
		return AccessAuthority{}, r.accessErr
	}
	return r.accessAuthority, nil
}

type testKeyStore struct {
	private  *rsa.PrivateKey
	kid      string
	public   []jose.JSONWebKey
	failAt   int
	signCall int
}

func newTestKeyStore(t *testing.T) *testKeyStore {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(private.N.Bytes())
	kid := base64.RawURLEncoding.EncodeToString(digest[:])
	return &testKeyStore{
		private: private, kid: kid,
		public: []jose.JSONWebKey{{Key: &private.PublicKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"}},
	}
}

func (k *testKeyStore) Sign(payload []byte, typ string) (string, error) {
	k.signCall++
	if k.failAt != 0 && k.signCall == k.failAt {
		return "", errors.New("test signer failure")
	}
	return signPayload(k.private, jose.RS256, k.kid, typ, payload, nil)
}

func (k *testKeyStore) PublicKeys() []jose.JSONWebKey {
	return append([]jose.JSONWebKey(nil), k.public...)
}

func signClaims(t *testing.T, keys *testKeyStore, claims any, typ, kid string, extra map[jose.HeaderKey]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signPayload(keys.private, jose.RS256, kid, typ, payload, extra)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func signHMACClaims(t *testing.T, claims any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{9}, 32)
	compact, err := signPayload(key, jose.HS256, "hmac", "at+jwt", payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func signPayload(key any, algorithm jose.SignatureAlgorithm, kid, typ string, payload []byte, extra map[jose.HeaderKey]any) (string, error) {
	options := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
	for name, value := range extra {
		options.WithHeader(name, value)
	}
	signingKey := jose.SigningKey{Algorithm: algorithm, Key: jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: string(algorithm), Use: "sig"}}
	signer, err := jose.NewSigner(signingKey, options)
	if err != nil {
		return "", err
	}
	object, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return object.CompactSerialize()
}

func parseAndVerify(t *testing.T, compact string, keys *testKeyStore, algorithm jose.SignatureAlgorithm) (jose.Header, []byte) {
	t.Helper()
	object, err := jose.ParseSignedCompact(compact, []jose.SignatureAlgorithm{algorithm})
	if err != nil || len(object.Signatures) != 1 {
		t.Fatalf("parse JWS: %v", err)
	}
	payload, err := object.Verify(keys.public[0].Key)
	if err != nil {
		t.Fatalf("verify JWS: %v", err)
	}
	return object.Signatures[0].Header, payload
}

func assertHeader(t *testing.T, header jose.Header, kid, typ string) {
	t.Helper()
	if header.Algorithm != string(jose.RS256) || header.KeyID != kid || header.ExtraHeaders[jose.HeaderType] != typ || len(header.ExtraHeaders) != 1 {
		t.Fatalf("unexpected JOSE header: %+v", header)
	}
}

func decodeExact(t *testing.T, payload []byte, destination any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(destination); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		t.Fatalf("decode payload %q: %v", payload, err)
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestHashJTIIsDomainSeparatedAndDeterministic(t *testing.T) {
	t.Parallel()
	jti := "jti_" + base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	first := HashJTI(jti)
	second := HashJTI(jti)
	raw := sha256.Sum256([]byte(jti))
	if len(first) != sha256.Size || !slices.Equal(first, second) || slices.Equal(first, raw[:]) {
		t.Fatalf("unexpected jti digest: %x", first)
	}
	if strings.Contains(fmt.Sprintf("%x", first), jti) {
		t.Fatal("digest representation unexpectedly contains clear jti")
	}
}
