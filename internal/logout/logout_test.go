package logout

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/identity"
	"github.com/oneissuer/oneissuer/internal/session"
	tokendomain "github.com/oneissuer/oneissuer/internal/token"
)

const (
	testIssuer    = "https://id.example.test"
	testClientID  = "ois_cli_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testLogoutURI = "https://rp.example.test/signed-out?fixed=a%2Fb"
)

var (
	testRSAOnce sync.Once
	testRSAKey  *rsa.PrivateKey
	testRSAErr  error
)

func logoutTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testRSAOnce.Do(func() { testRSAKey, testRSAErr = rsa.GenerateKey(rand.Reader, 2048) })
	if testRSAErr != nil {
		t.Fatalf("generate RSA key: %v", testRSAErr)
	}
	return testRSAKey
}

type logoutTestRepository struct {
	created   []Transaction
	createErr error
	bind      func(BindInput) (Transaction, error)
	complete  func(CompleteInput) (CompletionCandidate, error)
}

func (r *logoutTestRepository) CreateLogoutTransaction(_ context.Context, value Transaction) error {
	copyValue := value
	copyValue.LookupHash = append([]byte(nil), value.LookupHash...)
	copyValue.CSRFHash = append([]byte(nil), value.CSRFHash...)
	r.created = append(r.created, copyValue)
	return r.createErr
}

func (r *logoutTestRepository) BindLogoutTransaction(_ context.Context, input BindInput) (Transaction, error) {
	if r.bind == nil {
		return Transaction{}, ErrNotFound
	}
	return r.bind(input)
}

func (r *logoutTestRepository) CompleteLogoutTransaction(_ context.Context, input CompleteInput) (CompletionCandidate, error) {
	if r.complete == nil {
		return CompletionCandidate{}, ErrNotFound
	}
	return r.complete(input)
}

type logoutTestClients struct {
	byPublic   map[string]clientdomain.Client
	byID       map[uuid.UUID]clientdomain.Client
	resolveErr error
	getErr     error
}

func (c *logoutTestClients) ResolveActive(_ context.Context, publicID string) (clientdomain.Client, error) {
	if c.resolveErr != nil {
		return clientdomain.Client{}, c.resolveErr
	}
	value, ok := c.byPublic[publicID]
	if !ok || value.Status != clientdomain.StatusActive {
		return clientdomain.Client{}, clientdomain.ErrNotFound
	}
	return value, nil
}

func (c *logoutTestClients) GetActive(_ context.Context, id uuid.UUID) (clientdomain.Client, error) {
	if c.getErr != nil {
		return clientdomain.Client{}, c.getErr
	}
	value, ok := c.byID[id]
	if !ok || value.Status != clientdomain.StatusActive {
		return clientdomain.Client{}, clientdomain.ErrNotFound
	}
	return value, nil
}

type logoutTestKeys []jose.JSONWebKey

func (k logoutTestKeys) PublicKeys() []jose.JSONWebKey { return append([]jose.JSONWebKey(nil), k...) }

type logoutTestMetrics struct{ values []string }

func (m *logoutTestMetrics) RPLogout(value string) { m.values = append(m.values, value) }

func logoutTestClient() clientdomain.Client {
	return clientdomain.Client{
		ID: uuid.MustParse("10000000-0000-4000-8000-000000000001"), ClientID: testClientID,
		Type: clientdomain.TypeConfidential, TokenEndpointAuthMethod: clientdomain.AuthMethodClientSecretBasic,
		Status: clientdomain.StatusActive, LogoutURIs: []string{testLogoutURI}, Scopes: []string{"offline_access", "openid"},
	}
}

func logoutTestService(t *testing.T, repository *logoutTestRepository, clients *logoutTestClients, now time.Time, randomSource io.Reader, metrics ...Metrics) (*Service, *rsa.PrivateKey) {
	t.Helper()
	key := logoutTestRSAKey(t)
	jwk := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "logout-test-key", Algorithm: string(jose.RS256), Use: "sig"}
	if repository == nil {
		repository = &logoutTestRepository{}
	}
	if clients == nil {
		value := logoutTestClient()
		clients = &logoutTestClients{byPublic: map[string]clientdomain.Client{value.ClientID: value}, byID: map[uuid.UUID]clientdomain.Client{value.ID: value}}
	}
	service, err := NewService(repository, clients, logoutTestKeys{jwk}, testIssuer, 5*time.Minute, 24*time.Hour, time.Minute, 3, randomSource, metrics...)
	if err != nil {
		t.Fatalf("NewService() error = %v at %s", err, now)
	}
	return service, key
}

func validLogoutClaims(now time.Time) tokendomain.IDTokenClaims {
	return tokendomain.IDTokenClaims{
		Issuer: testIssuer, Subject: "usr_public_subject", Audience: testClientID, AuthorizedParty: testClientID,
		IssuedAt: now.Add(-time.Hour).Unix(), ExpiresAt: now.Add(-50 * time.Minute).Unix(), AuthTime: now.Add(-2 * time.Hour).Unix(),
	}
}

func signLogoutPayload(t *testing.T, key *rsa.PrivateKey, keyID string, payload []byte) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": keyID, "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	return signLogoutRaw(t, key, header, payload)
}

func signLogoutClaims(t *testing.T, key *rsa.PrivateKey, keyID string, claims tokendomain.IDTokenClaims) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return signLogoutPayload(t, key, keyID, payload)
}

func signLogoutRaw(t *testing.T, key *rsa.PrivateKey, header, payload []byte) string {
	t.Helper()
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	input := encodedHeader + "." + encodedPayload
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign JWS: %v", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func testPrincipal() session.Principal {
	return session.Principal{
		SessionID:        uuid.MustParse("20000000-0000-4000-8000-000000000001"),
		SessionBindingID: uuid.MustParse("30000000-0000-4000-8000-000000000001"),
		User:             identity.User{ID: uuid.MustParse("40000000-0000-4000-8000-000000000001"), Subject: "usr_public_subject", Status: identity.StatusActive},
	}
}

func TestLogoutLookupAndProofGrammarEntropyAndDomains(t *testing.T) {
	t.Parallel()
	seed := bytes.Repeat([]byte{0x5a}, 64)
	lookup, lookupHash, err := newSecret(bytes.NewReader(seed), lookupPrefix, hashLookup)
	if err != nil {
		t.Fatal(err)
	}
	proof, proofHash, err := newSecret(bytes.NewReader(seed), csrfPrefix, hashCSRF)
	if err != nil {
		t.Fatal(err)
	}
	if len(lookup) != 47 || len(proof) != 47 || lookup[:4] != lookupPrefix || proof[:4] != csrfPrefix {
		t.Fatalf("unexpected clear grammars lookup=%q proof=%q", lookup, proof)
	}
	if bytes.Equal(lookupHash, proofHash) || bytes.Equal(hashLookup(lookup), hashCSRF(lookup)) {
		t.Fatal("lookup and proof digest domains are not separated")
	}
	if digest, err := DigestLookupToken(lookup); err != nil || !bytes.Equal(digest, lookupHash) {
		t.Fatalf("DigestLookupToken() = %x, %v", digest, err)
	}
	if digest, err := DigestCSRFProof(proof); err != nil || !bytes.Equal(digest, proofHash) {
		t.Fatalf("DigestCSRFProof() = %x, %v", digest, err)
	}
	for _, invalid := range []string{"", "lt1_", proof, lookup + "=", strings.ToUpper(lookup), " " + lookup} {
		if _, err := DigestLookupToken(invalid); err == nil {
			t.Errorf("invalid lookup accepted: %q", invalid)
		}
	}
	for _, invalid := range []string{"", "lc1_", lookup, proof + "=", " " + proof} {
		if _, err := DigestCSRFProof(invalid); err == nil {
			t.Errorf("invalid proof accepted: %q", invalid)
		}
	}
}

func TestLogoutServiceRequiresCanonicalIssuerAndBoundedConfiguration(t *testing.T) {
	t.Parallel()
	repo := &logoutTestRepository{}
	clients := &logoutTestClients{}
	key := logoutTestRSAKey(t)
	keys := logoutTestKeys{{Key: &key.PublicKey, KeyID: "k", Algorithm: "RS256", Use: "sig"}}
	for _, issuer := range []string{"https://id.example.test/path", "https://id.example.test?x=1", "https://user@id.example.test", "ftp://id.example.test", "relative"} {
		if _, err := NewService(repo, clients, keys, issuer, 5*time.Minute, time.Hour, 0, 1, nil); !errors.Is(err, ErrInvalid) {
			t.Errorf("issuer %q error = %v, want ErrInvalid", issuer, err)
		}
	}
	if _, err := NewService(repo, clients, keys, testIssuer, time.Second, time.Hour, 0, 1, nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("short TTL accepted: %v", err)
	}
	if _, err := NewService(repo, clients, keys, testIssuer, 5*time.Minute, time.Minute, 0, 1, nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("short Hint age accepted: %v", err)
	}
	if _, err := NewService(repo, clients, keys, testIssuer, 5*time.Minute, time.Hour, 6*time.Minute, 1, nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("large skew accepted: %v", err)
	}
	if _, err := NewService(repo, clients, keys, testIssuer, 5*time.Minute, time.Hour, 0, 6, nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("large cap accepted: %v", err)
	}
}

func TestLogoutStartPersistsDigestOnlyZeroAuthority(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	repository := &logoutTestRepository{}
	metrics := &logoutTestMetrics{}
	randomSource := bytes.NewReader(bytes.Repeat([]byte{0x42}, 64))
	service, _ := logoutTestService(t, repository, nil, now, randomSource, metrics)
	issued, err := service.Start(context.Background(), StartInput{LogoutHint: "ignored-canary", UILocales: "fr zh-CN", Now: now})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if len(repository.created) != 1 {
		t.Fatalf("created rows = %d", len(repository.created))
	}
	stored := repository.created[0]
	if stored.Stage != StagePreConfirm || stored.UserID != nil || stored.SessionID != nil || stored.SessionBindingID != nil || len(stored.CSRFHash) != 0 {
		t.Fatalf("initial transaction acquired authority: %#v", stored)
	}
	if strings.Contains(string(stored.LookupHash), issued.LookupToken) || bytes.Equal(stored.LookupHash, []byte(issued.LookupToken)) {
		t.Fatal("repository received clear lookup value")
	}
	if strings.Contains(strings.Join([]string{stored.State, stored.HintSubject, stored.PostLogoutRedirectURI}, "|"), "ignored-canary") {
		t.Fatal("ignored request values reached persistence")
	}
	if digest, err := DigestLookupToken(issued.LookupToken); err != nil || !bytes.Equal(digest, stored.LookupHash) {
		t.Fatalf("stored digest mismatch: %v", err)
	}
	if !stored.ExpiresAt.Equal(now.Add(5*time.Minute)) || len(metrics.values) != 1 || metrics.values[0] != "started" {
		t.Fatalf("expiry=%s metrics=%v", stored.ExpiresAt, metrics.values)
	}
}

func TestLogoutHintVerificationStrictMatrixAndTimeBoundaries(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	service, key := logoutTestService(t, nil, nil, now, nil)
	base := validLogoutClaims(now)

	tests := []struct {
		name   string
		claims tokendomain.IDTokenClaims
		keyID  string
		at     time.Time
		want   bool
	}{
		{name: "recently expired", claims: base, keyID: "logout-test-key", at: now, want: true},
		{name: "wrong issuer", claims: func() tokendomain.IDTokenClaims { v := base; v.Issuer = "https://other.example"; return v }(), keyID: "logout-test-key", at: now},
		{name: "wrong audience", claims: func() tokendomain.IDTokenClaims { v := base; v.Audience = "other"; return v }(), keyID: "logout-test-key", at: now},
		{name: "wrong azp", claims: func() tokendomain.IDTokenClaims { v := base; v.AuthorizedParty = "other"; return v }(), keyID: "logout-test-key", at: now},
		{name: "empty subject", claims: func() tokendomain.IDTokenClaims { v := base; v.Subject = ""; return v }(), keyID: "logout-test-key", at: now},
		{name: "NUL subject", claims: func() tokendomain.IDTokenClaims { v := base; v.Subject = "bad\x00subject"; return v }(), keyID: "logout-test-key", at: now},
		{name: "long subject", claims: func() tokendomain.IDTokenClaims { v := base; v.Subject = strings.Repeat("x", 256); return v }(), keyID: "logout-test-key", at: now},
		{name: "unknown kid", claims: base, keyID: "unknown", at: now},
		{name: "future iat boundary", claims: func() tokendomain.IDTokenClaims {
			v := base
			v.IssuedAt = now.Add(time.Minute).Unix()
			v.ExpiresAt = now.Add(10 * time.Minute).Unix()
			return v
		}(), keyID: "logout-test-key", at: now, want: true},
		{name: "future iat beyond skew", claims: func() tokendomain.IDTokenClaims {
			v := base
			v.IssuedAt = now.Add(time.Minute + time.Second).Unix()
			v.ExpiresAt = now.Add(10 * time.Minute).Unix()
			return v
		}(), keyID: "logout-test-key", at: now},
		{name: "lifetime exact", claims: func() tokendomain.IDTokenClaims {
			v := base
			v.IssuedAt = now.Add(-time.Hour).Unix()
			v.ExpiresAt = now.Add(-45 * time.Minute).Unix()
			return v
		}(), keyID: "logout-test-key", at: now, want: true},
		{name: "lifetime too long", claims: func() tokendomain.IDTokenClaims {
			v := base
			v.IssuedAt = now.Add(-time.Hour).Unix()
			v.ExpiresAt = now.Add(-45*time.Minute + time.Second).Unix()
			return v
		}(), keyID: "logout-test-key", at: now},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			compact := signLogoutClaims(t, key, test.keyID, test.claims)
			_, got := service.verifyHint(compact, test.at)
			if got != test.want {
				t.Fatalf("verifyHint() = %v, want %v", got, test.want)
			}
		})
	}

	fresh := base
	fresh.IssuedAt = now.Add(-5 * time.Minute).Unix()
	fresh.ExpiresAt = now.Unix()
	compact := signLogoutClaims(t, key, "logout-test-key", fresh)
	if _, ok := service.verifyHint(compact, now.Add(time.Minute)); !ok {
		t.Fatal("exp + skew boundary rejected")
	}
	if _, ok := service.verifyHint(compact, now.Add(time.Minute+time.Nanosecond)); !ok {
		// Hint age is still live, so expiration alone must not end the accepted recently-expired window.
		t.Fatal("recently-expired Hint rejected before max-age boundary")
	}
	ageBoundary := time.Unix(fresh.IssuedAt, 0).Add(24*time.Hour + time.Minute)
	if _, ok := service.verifyHint(compact, ageBoundary); !ok {
		t.Fatal("iat + max age + skew boundary rejected")
	}
	if _, ok := service.verifyHint(compact, ageBoundary.Add(time.Nanosecond)); ok {
		t.Fatal("Hint accepted after both exact boundaries")
	}
}

func TestLogoutHintRejectsHeaderAndClaimAmbiguity(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	service, key := logoutTestService(t, nil, nil, now, nil)
	claims := validLogoutClaims(now)
	payload, _ := json.Marshal(claims)
	validHeader := `{"alg":"RS256","kid":"logout-test-key","typ":"JWT"}`
	cases := map[string]string{
		"extra header":  `{"alg":"RS256","kid":"logout-test-key","typ":"JWT","jku":"https://evil.test/jwks"}`,
		"embedded jwk":  `{"alg":"RS256","kid":"logout-test-key","typ":"JWT","jwk":{}}`,
		"duplicate kid": `{"alg":"RS256","kid":"logout-test-key","kid":"other","typ":"JWT"}`,
		"wrong typ":     `{"alg":"RS256","kid":"logout-test-key","typ":"at+jwt"}`,
		"wrong alg":     `{"alg":"PS256","kid":"logout-test-key","typ":"JWT"}`,
	}
	for name, rawHeader := range cases {
		t.Run(name, func(t *testing.T) {
			compact := signLogoutRaw(t, key, []byte(rawHeader), payload)
			if _, ok := service.verifyHint(compact, now); ok {
				t.Fatal("ambiguous header accepted")
			}
		})
	}
	// Use a complete duplicate-claim payload so rejection cannot be attributed to a missing field.
	duplicateClaims := strings.Replace(string(payload), `"sub":"usr_public_subject"`, `"sub":"usr_public_subject","sub":"other"`, 1)
	if _, ok := service.verifyHint(signLogoutRaw(t, key, []byte(validHeader), []byte(duplicateClaims)), now); ok {
		t.Fatal("duplicate claim accepted")
	}
	unknownClaims := strings.TrimSuffix(string(payload), "}") + `,"unexpected":"value"}`
	if _, ok := service.verifyHint(signLogoutRaw(t, key, []byte(validHeader), []byte(unknownClaims)), now); ok {
		t.Fatal("unknown claim accepted")
	}

	duplicateKey := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "logout-test-key", Algorithm: "RS256", Use: "sig"}
	service.keys = logoutTestKeys{duplicateKey, duplicateKey}
	if _, ok := service.verifyHint(signLogoutClaims(t, key, "logout-test-key", claims), now); ok {
		t.Fatal("duplicate verification kid accepted")
	}
}

func TestLogoutStartRedirectAuthorityAndLocalOnlyDowngrades(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name         string
		mutate       func(*StartInput)
		wantRedirect bool
	}{
		{name: "exact registered", wantRedirect: true},
		{name: "client mismatch", mutate: func(v *StartInput) { v.ClientID = "other" }},
		{name: "URI mismatch", mutate: func(v *StartInput) { v.PostLogoutRedirectURI += "/" }},
		{name: "existing decoded state", mutate: func(v *StartInput) { v.PostLogoutRedirectURI = "https://rp.example.test/signed-out?st%61te=old" }},
		{name: "invalid hint", mutate: func(v *StartInput) { v.IDTokenHint = "not.a.jwt" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			repository := &logoutTestRepository{}
			service, key := logoutTestService(t, repository, nil, now, nil)
			input := StartInput{IDTokenHint: signLogoutClaims(t, key, "logout-test-key", validLogoutClaims(now)), PostLogoutRedirectURI: testLogoutURI, State: "opaque state/%", Now: now}
			if test.mutate != nil {
				test.mutate(&input)
			}
			if strings.Contains(input.PostLogoutRedirectURI, "st%61te") {
				clientValue := logoutTestClient()
				clientValue.LogoutURIs = append(clientValue.LogoutURIs, input.PostLogoutRedirectURI)
				service.clients = &logoutTestClients{byPublic: map[string]clientdomain.Client{testClientID: clientValue}, byID: map[uuid.UUID]clientdomain.Client{clientValue.ID: clientValue}}
			}
			issued, err := service.Start(context.Background(), input)
			if err != nil {
				t.Fatalf("Start() error = %v", err)
			}
			stored := issued.Transaction
			gotRedirect := stored.PostLogoutRedirectURI != ""
			if gotRedirect != test.wantRedirect {
				t.Fatalf("redirect authority = %v, want %v: %#v", gotRedirect, test.wantRedirect, stored)
			}
			if !test.wantRedirect && stored.State != "" {
				t.Fatalf("local-only transaction retained State: %#v", stored)
			}
			if test.wantRedirect && (stored.State != input.State || stored.VerifiedClientID == nil || stored.HintSubject == "") {
				t.Fatalf("verified authority incomplete: %#v", stored)
			}
		})
	}
}

func TestLogoutBindRotatesProofAndPassesOnlyDigests(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	principal := testPrincipal()
	lookup, lookupHash, err := newSecret(rand.Reader, lookupPrefix, hashLookup)
	if err != nil {
		t.Fatal(err)
	}
	var seen []BindInput
	repository := &logoutTestRepository{}
	repository.bind = func(input BindInput) (Transaction, error) {
		seen = append(seen, input)
		return Transaction{Stage: StageBoundConfirm, UserID: &principal.User.ID, SessionID: &principal.SessionID, SessionBindingID: &principal.SessionBindingID, PostLogoutRedirectURI: "https://rp.example.test/logged-out", ExpiresAt: now.Add(5 * time.Minute)}, nil
	}
	service, _ := logoutTestService(t, repository, nil, now, nil)
	first, err := service.Bind(context.Background(), lookup, principal, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Bind(context.Background(), lookup, principal, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if first.CSRFProof == second.CSRFProof || len(seen) != 2 {
		t.Fatalf("proofs were not rotated: %#v %#v", first, second)
	}
	if first.PostLogoutRedirectURI != "https://rp.example.test/logged-out" {
		t.Fatalf("bound logout redirect URI was not retained for CSP: %#v", first)
	}
	for index, input := range seen {
		if !bytes.Equal(input.LookupHash, lookupHash) || bytes.Equal(input.CSRFHash, []byte(first.CSRFProof)) || input.MaxActive != 3 || input.MaxAttempts != maxTransactionTries {
			t.Fatalf("bind input %d leaked/omitted authority: %#v", index, input)
		}
	}
	if _, err := service.Bind(context.Background(), "bad", principal, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad lookup error = %v", err)
	}
}

func TestLogoutCompleteRechecksExactURIAndAppendsStateAfterCommit(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	principal := testPrincipal()
	clientValue := logoutTestClient()
	lookup, _, _ := newSecret(rand.Reader, lookupPrefix, hashLookup)
	proof, _, _ := newSecret(rand.Reader, csrfPrefix, hashCSRF)
	var completeCalls int
	repository := &logoutTestRepository{complete: func(input CompleteInput) (CompletionCandidate, error) {
		completeCalls++
		if input.Decision != DecisionConfirm || input.SessionID != principal.SessionID || len(input.LookupHash) != 32 || len(input.CSRFHash) != 32 {
			return CompletionCandidate{}, ErrInvalid
		}
		return CompletionCandidate{Confirmed: true, VerifiedClientID: &clientValue.ID, PostLogoutRedirectURI: testLogoutURI, State: "opaque state/%"}, nil
	}}
	clients := &logoutTestClients{byPublic: map[string]clientdomain.Client{clientValue.ClientID: clientValue}, byID: map[uuid.UUID]clientdomain.Client{clientValue.ID: clientValue}}
	service, _ := logoutTestService(t, repository, clients, now, nil)
	completion, err := service.Complete(context.Background(), lookup, proof, DecisionConfirm, principal, "request", now)
	if err != nil {
		t.Fatal(err)
	}
	want := testLogoutURI + "&state=opaque+state%2F%25"
	if completion.Location != want || !completion.Confirmed || completeCalls != 1 {
		t.Fatalf("completion=%#v calls=%d want=%q", completion, completeCalls, want)
	}

	clients.byID[clientValue.ID] = func() clientdomain.Client { v := clientValue; v.LogoutURIs = nil; return v }()
	completion, err = service.Complete(context.Background(), lookup, proof, DecisionConfirm, principal, "request", now)
	if err != nil || !completion.Confirmed || completion.Location != "" {
		t.Fatalf("removed URI was not suppressed: %#v %v", completion, err)
	}
	clients.getErr = errors.New("registry unavailable")
	completion, err = service.Complete(context.Background(), lookup, proof, DecisionConfirm, principal, "request", now)
	if err != nil || !completion.Confirmed || completion.Location != "" {
		t.Fatalf("post-commit lookup failure changed local result: %#v %v", completion, err)
	}
}

func TestLogoutCompleteCancelNeverReturnsState(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	principal := testPrincipal()
	lookup, _, _ := newSecret(rand.Reader, lookupPrefix, hashLookup)
	proof, _, _ := newSecret(rand.Reader, csrfPrefix, hashCSRF)
	clientValue := logoutTestClient()
	repository := &logoutTestRepository{complete: func(CompleteInput) (CompletionCandidate, error) {
		return CompletionCandidate{Confirmed: false, VerifiedClientID: &clientValue.ID, PostLogoutRedirectURI: testLogoutURI, State: "secret-state"}, nil
	}}
	service, _ := logoutTestService(t, repository, nil, now, nil)
	completion, err := service.Complete(context.Background(), lookup, proof, DecisionCancel, principal, "request", now)
	if err != nil || completion.Confirmed || completion.Location != "" {
		t.Fatalf("cancel completion = %#v, %v", completion, err)
	}
}

func TestLogoutCookieManagerExactAttributesAndCleanup(t *testing.T) {
	t.Parallel()
	secure := NewCookieManager("__Host-oneissuer_session", true, 5*time.Minute)
	if secure.Name != "__Secure-oneissuer_session_logout_transaction" {
		t.Fatalf("secure cookie name = %q", secure.Name)
	}
	response := httptest.NewRecorder()
	secure.Set(response, "lt1_value")
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie count = %d", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Path != ConfirmPath || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Domain != "" || cookie.MaxAge != 300 {
		t.Fatalf("cookie attributes = %#v", cookie)
	}
	request := httptest.NewRequest(http.MethodGet, ConfirmPath, nil)
	request.AddCookie(cookie)
	if got := secure.Token(request); got != "lt1_value" {
		t.Fatalf("Token() = %q", got)
	}

	response = httptest.NewRecorder()
	secure.Clear(response)
	cleared := response.Result().Cookies()[0]
	if cleared.Name != cookie.Name || cleared.Path != cookie.Path || cleared.Secure != cookie.Secure || !cleared.HttpOnly || cleared.SameSite != cookie.SameSite || cleared.MaxAge != -1 || !cleared.Expires.Before(time.Now()) {
		t.Fatalf("terminal cleanup mismatch: set=%#v clear=%#v", cookie, cleared)
	}
	development := NewCookieManager("oneissuer_session", false, time.Second)
	if development.Name != "oneissuer_session_logout_transaction" || development.Secure {
		t.Fatalf("development cookie = %#v", development)
	}
}
