package postgres_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/admin"
	"github.com/oneissuer/oneissuer/internal/authflow"
	"github.com/oneissuer/oneissuer/internal/authn"
	"github.com/oneissuer/oneissuer/internal/authorization"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/config"
	"github.com/oneissuer/oneissuer/internal/consent"
	"github.com/oneissuer/oneissuer/internal/httpserver"
	"github.com/oneissuer/oneissuer/internal/identity"
	"github.com/oneissuer/oneissuer/internal/keystore"
	"github.com/oneissuer/oneissuer/internal/observability"
	"github.com/oneissuer/oneissuer/internal/session"
	"github.com/oneissuer/oneissuer/internal/storage/postgres"
	tokendomain "github.com/oneissuer/oneissuer/internal/token"
)

var hiddenInputPattern = regexp.MustCompile(`name="(csrf_token|transaction)" value="([^"]+)"`)

type phaseTwoServices struct {
	identities    *identity.Service
	clients       *clientdomain.Service
	transactions  *authflow.Service
	consents      *consent.Service
	authorization *authorization.Service
	authn         *authn.Service
	sessions      *session.Service
	admin         *admin.Service
	cookies       session.CookieManager
}

func testPhaseTwoLifecycle(ctx context.Context, t *testing.T, store *postgres.Store, databaseURL string) {
	t.Helper()
	if err := postgres.RunMigrationCommand(ctx, databaseURL, postgres.MigrationUp, io.Discard); err != nil {
		t.Fatalf("phase-two migration setup: %v", err)
	}
	services := newPhaseTwoServices(ctx, t, store)

	const adminPassword = "bootstrap-password-strong"
	errorsByRun := make(chan error, 2)
	var bootstrapWG sync.WaitGroup
	for range 2 {
		bootstrapWG.Add(1)
		go func() {
			defer bootstrapWG.Done()
			_, err := services.admin.Bootstrap(ctx, identity.CreateInput{
				Username: "admin", DisplayName: "Administrator", Email: "admin@example.invalid", Password: adminPassword,
			}, "bootstrap-test", time.Now())
			errorsByRun <- err
		}()
	}
	bootstrapWG.Wait()
	close(errorsByRun)
	successes, conflicts := 0, 0
	for err := range errorsByRun {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, identity.ErrBootstrapExists):
			conflicts++
		default:
			t.Fatalf("concurrent Bootstrap() error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent bootstrap successes=%d conflicts=%d", successes, conflicts)
	}
	debugBegin, debugErr := services.authn.Begin(ctx, authn.BeginRegister, "", "direct-registration", time.Now())
	if debugErr != nil {
		t.Fatalf("direct Begin(register): %v", debugErr)
	}
	if _, debugErr = services.authn.Register(ctx, authn.RegisterInput{
		PreAuthToken: debugBegin.PreAuth.Token, CSRFToken: debugBegin.PreAuth.CSRFToken,
		TransactionToken: debugBegin.TransactionToken,
		Account:          identity.CreateInput{Username: "direct", Email: "direct@example.invalid", Password: "direct-password-strong"},
		RequestID:        "direct-registration",
	}, time.Now()); debugErr != nil {
		t.Fatalf("direct Register() error = %T %v", debugErr, debugErr)
	}

	application, err := httpserver.NewApplicationHandler(httpserver.ApplicationOptions{
		Authn: services.authn, Sessions: services.sessions, Admin: services.admin,
		Cookies: services.cookies, Issuer: mustURL(t, "http://issuer.example.test"),
	})
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	metrics := observability.NewMetrics(observability.NewBuildInfo("phase-two-test", "test", "test"))
	readiness := httpserver.NewReadiness(metrics.SetReady)
	readiness.Set(true)
	handler := httpserver.NewHandler(httpserver.HandlerOptions{
		Readiness: readiness, Database: store, DatabaseErrorClass: postgres.ErrorClass,
		Metrics: metrics, Gatherer: metrics.Gatherer(), Application: application,
	})
	server := httptest.NewServer(handler)
	defer server.Close()
	openRedirect := doRequest(t, newBrowser(t), http.MethodGet, server.URL+"/login?return_to=https://evil.example", "", nil)
	defer func() { _ = openRedirect.Body.Close() }()
	if openRedirect.StatusCode != http.StatusBadRequest || openRedirect.Header.Get("Location") != "" {
		t.Fatalf("untrusted return_to status=%d location=%q", openRedirect.StatusCode, openRedirect.Header.Get("Location"))
	}
	_ = readBody(t, openRedirect)

	ordinary := newBrowser(t)
	registerResponse := submitAuthForm(t, ordinary, server.URL, "/register", url.Values{
		"username": {"alice"}, "display_name": {"Alice <script>"},
		"email": {"Alice@example.invalid"}, "password": {"correct horse battery staple"},
	})
	defer func() { _ = registerResponse.Body.Close() }()
	registerBody := readBody(t, registerResponse)
	if registerResponse.StatusCode != http.StatusOK || !strings.Contains(registerBody, "Alice &lt;script&gt;") {
		t.Fatalf("registration completion status=%d body=%s", registerResponse.StatusCode, registerBody)
	}
	ordinaryMe, _ := getMe(t, ordinary, server.URL, http.StatusOK)
	ordinaryID := ordinaryMe.User.ID
	firstSessionID := ordinaryMe.SessionID
	rotatedLogin := submitAuthForm(t, ordinary, server.URL, "/login", url.Values{
		"identifier": {"alice"}, "password": {"correct horse battery staple"},
	})
	defer func() { _ = rotatedLogin.Body.Close() }()
	if rotatedLogin.StatusCode != http.StatusOK {
		t.Fatalf("same-browser reauthentication status=%d", rotatedLogin.StatusCode)
	}
	_ = readBody(t, rotatedLogin)
	ordinaryMe, ordinaryCSRF := getMe(t, ordinary, server.URL, http.StatusOK)
	if ordinaryMe.SessionID == firstSessionID {
		t.Fatal("login did not rotate the authenticated session identifier")
	}
	missingCSRF := doRequest(t, ordinary, http.MethodPost, server.URL+"/api/v1/me/sessions/revoke-others", "", nil)
	defer func() { _ = missingCSRF.Body.Close() }()
	if missingCSRF.StatusCode != http.StatusForbidden || !strings.Contains(readBody(t, missingCSRF), "csrf_failed") {
		t.Fatal("state change without CSRF was not rejected")
	}

	secondBrowser := newBrowser(t)
	loginResponse := submitAuthForm(t, secondBrowser, server.URL, "/login", url.Values{
		"identifier": {"ALICE@EXAMPLE.INVALID"}, "password": {"correct horse battery staple"},
	})
	defer func() { _ = loginResponse.Body.Close() }()
	if loginResponse.StatusCode != http.StatusOK {
		t.Fatalf("normalized email login status = %d", loginResponse.StatusCode)
	}
	_ = readBody(t, loginResponse)

	sessionsResponse := doRequest(t, ordinary, http.MethodGet, server.URL+"/api/v1/me/sessions", "", nil)
	defer func() { _ = sessionsResponse.Body.Close() }()
	if sessionsResponse.StatusCode != http.StatusOK {
		t.Fatalf("list own sessions status=%d body=%s", sessionsResponse.StatusCode, readBody(t, sessionsResponse))
	}
	var ownSessions struct {
		Items []session.Summary `json:"items"`
	}
	decodeBody(t, sessionsResponse, &ownSessions)
	var otherSession uuid.UUID
	for _, item := range ownSessions.Items {
		if !item.Current && item.RevokedAt == nil {
			otherSession = item.ID
		}
	}
	if otherSession == uuid.Nil {
		t.Fatalf("second session missing: %+v", ownSessions.Items)
	}
	revokeResponse := doRequest(t, ordinary, http.MethodPost, server.URL+"/api/v1/me/sessions/"+otherSession.String()+"/revoke", ordinaryCSRF, nil)
	if revokeResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke own session status=%d body=%s", revokeResponse.StatusCode, readBody(t, revokeResponse))
	}
	_ = revokeResponse.Body.Close()
	getMe(t, secondBrowser, server.URL, http.StatusUnauthorized)

	adminBrowser := newBrowser(t)
	adminLogin := submitAuthForm(t, adminBrowser, server.URL, "/login", url.Values{
		"identifier": {"admin"}, "password": {adminPassword},
	})
	defer func() { _ = adminLogin.Body.Close() }()
	if adminLogin.StatusCode != http.StatusOK {
		t.Fatalf("administrator login status=%d", adminLogin.StatusCode)
	}
	_ = readBody(t, adminLogin)
	adminMe, adminCSRF := getAdminMe(t, adminBrowser, server.URL)
	lastAdminBody, _ := json.Marshal(map[string]any{"status": identity.StatusDisabled})
	lastAdminResponse := doRequest(t, adminBrowser, http.MethodPatch,
		server.URL+"/api/admin/v1/users/"+adminMe.User.ID.String(), adminCSRF, lastAdminBody)
	defer func() { _ = lastAdminResponse.Body.Close() }()
	if lastAdminResponse.StatusCode != http.StatusConflict || !strings.Contains(readBody(t, lastAdminResponse), "last_admin_protected") {
		t.Fatal("last active administrator protection was not enforced")
	}
	foreignRevoke := doRequest(t, ordinary, http.MethodPost,
		server.URL+"/api/v1/me/sessions/"+adminMe.SessionID.String()+"/revoke", ordinaryCSRF, nil)
	if foreignRevoke.StatusCode != http.StatusNotFound {
		t.Fatalf("foreign session visibility status=%d body=%s", foreignRevoke.StatusCode, readBody(t, foreignRevoke))
	}
	_ = foreignRevoke.Body.Close()

	publicCreated := createClientHTTP(t, adminBrowser, server.URL, adminCSRF, "public")
	if publicCreated.Secret != "" {
		t.Fatal("public client unexpectedly received a secret")
	}
	publicRotate := doRequest(t, adminBrowser, http.MethodPost,
		server.URL+"/api/admin/v1/clients/"+publicCreated.Client.ID.String()+"/secrets/rotate", adminCSRF, nil)
	defer func() { _ = publicRotate.Body.Close() }()
	if publicRotate.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(readBody(t, publicRotate), "invalid_input") {
		t.Fatal("public client secret rotation did not return a stable validation error")
	}
	confidentialCreated := createClientHTTP(t, adminBrowser, server.URL, adminCSRF, "confidential")
	if confidentialCreated.Secret == "" {
		t.Fatal("confidential client did not receive a one-time secret")
	}
	oldSecret := confidentialCreated.Secret
	if _, err := services.clients.ValidateSecret(ctx, confidentialCreated.Client.ClientID, oldSecret); err != nil {
		t.Fatalf("new client secret validation error = %v", err)
	}
	rotateResponse := doRequest(t, adminBrowser, http.MethodPost,
		server.URL+"/api/admin/v1/clients/"+confidentialCreated.Client.ID.String()+"/secrets/rotate", adminCSRF, nil)
	defer func() { _ = rotateResponse.Body.Close() }()
	if rotateResponse.StatusCode != http.StatusOK || rotateResponse.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("rotate secret status/cache=%d/%q body=%s", rotateResponse.StatusCode, rotateResponse.Header.Get("Cache-Control"), readBody(t, rotateResponse))
	}
	var rotated struct {
		Secret string `json:"client_secret"`
	}
	decodeBody(t, rotateResponse, &rotated)
	if rotated.Secret == "" || rotated.Secret == oldSecret {
		t.Fatal("rotated secret missing or unchanged")
	}
	if _, err := services.clients.ValidateSecret(ctx, confidentialCreated.Client.ClientID, oldSecret); !errors.Is(err, clientdomain.ErrNotFound) {
		t.Fatalf("old secret remained valid: %v", err)
	}
	if _, err := services.clients.ValidateSecret(ctx, confidentialCreated.Client.ClientID, rotated.Secret); err != nil {
		t.Fatalf("rotated secret validation error = %v", err)
	}
	clientGet := doRequest(t, adminBrowser, http.MethodGet,
		server.URL+"/api/admin/v1/clients/"+confidentialCreated.Client.ID.String(), "", nil)
	clientBody := readBody(t, clientGet)
	_ = clientGet.Body.Close()
	if strings.Contains(clientBody, oldSecret) || strings.Contains(clientBody, rotated.Secret) || strings.Contains(clientBody, "secret_hash") {
		t.Fatalf("client GET leaked secret material: %s", clientBody)
	}

	disabled := identity.StatusDisabled
	disableBody, _ := json.Marshal(map[string]any{"status": disabled})
	disableResponse := doRequest(t, adminBrowser, http.MethodPatch,
		server.URL+"/api/admin/v1/users/"+ordinaryID.String(), adminCSRF, disableBody)
	defer func() { _ = disableResponse.Body.Close() }()
	if disableResponse.StatusCode != http.StatusOK {
		t.Fatalf("disable user status=%d body=%s", disableResponse.StatusCode, readBody(t, disableResponse))
	}
	_ = readBody(t, disableResponse)
	getMe(t, ordinary, server.URL, http.StatusUnauthorized)
	disabledLogin := submitAuthForm(t, newBrowser(t), server.URL, "/login", url.Values{
		"identifier": {"alice"}, "password": {"correct horse battery staple"},
	})
	defer func() { _ = disabledLogin.Body.Close() }()
	disabledLoginBody := readBody(t, disabledLogin)
	missingLogin := submitAuthForm(t, newBrowser(t), server.URL, "/login", url.Values{
		"identifier": {"missing-user"}, "password": {"correct horse battery staple"},
	})
	defer func() { _ = missingLogin.Body.Close() }()
	missingLoginBody := readBody(t, missingLogin)
	if disabledLogin.StatusCode != http.StatusUnauthorized || missingLogin.StatusCode != http.StatusUnauthorized ||
		!strings.Contains(disabledLoginBody, `data-error-code="invalid_credentials"`) ||
		!strings.Contains(missingLoginBody, `data-error-code="invalid_credentials"`) {
		t.Fatalf("enumeration-safe login responses diverged: disabled=%d missing=%d", disabledLogin.StatusCode, missingLogin.StatusCode)
	}
	for _, sensitive := range []string{"correct horse battery staple", "missing-user", "alice"} {
		if strings.Contains(disabledLoginBody, sensitive) || strings.Contains(missingLoginBody, sensitive) {
			t.Fatalf("failed login HTML reflected sensitive input %q", sensitive)
		}
	}

	auditResponse := doRequest(t, adminBrowser, http.MethodGet, server.URL+"/api/admin/v1/audit-events?limit=100", "", nil)
	auditBody := readBody(t, auditResponse)
	_ = auditResponse.Body.Close()
	for _, event := range []string{"admin_bootstrap_succeeded", "user_registered", "client_secret_rotated", "user_status_changed"} {
		if !strings.Contains(auditBody, event) {
			t.Fatalf("audit response missing %q: %s", event, auditBody)
		}
	}
	for _, secret := range []string{adminPassword, "correct horse battery staple", oldSecret, rotated.Secret} {
		if strings.Contains(auditBody, secret) {
			t.Fatalf("audit response leaked secret material")
		}
	}

	testConcurrentRegistration(ctx, t, services)

	reopened, err := postgres.Open(ctx, databaseURL, 2)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopened.Close()
	persistedClient, err := reopened.GetClient(ctx, confidentialCreated.Client.ID)
	if err != nil || persistedClient.ClientID != confidentialCreated.Client.ClientID {
		t.Fatalf("client did not persist across store restart: client=%+v err=%v", persistedClient, err)
	}
	persistedUser, err := reopened.GetUser(ctx, ordinaryID)
	if err != nil || persistedUser.Status != identity.StatusDisabled {
		t.Fatalf("disabled user did not persist: user=%+v err=%v", persistedUser, err)
	}
}

func newPhaseTwoServices(ctx context.Context, t *testing.T, store *postgres.Store) phaseTwoServices {
	t.Helper()
	password := config.PasswordConfig{MinLength: 15, MaxBytes: 1024, Argon2MemoryKiB: 8 * 1024, Argon2Time: 2, Argon2Threads: 1, MaxConcurrent: 4}
	identities, err := identity.NewService(ctx, password, nil)
	if err != nil {
		t.Fatalf("identity.NewService() error = %v", err)
	}
	metrics := observability.NewMetrics(observability.NewBuildInfo("test", "test", "test"))
	tokens, err := session.NewTokenManager(nil, 24*time.Hour, 2*time.Hour, 15*time.Minute)
	if err != nil {
		t.Fatalf("session.NewTokenManager() error = %v", err)
	}
	clients := clientdomain.NewService(store, nil, true, metrics)
	transactions, err := authflow.NewService(store, nil, 10*time.Minute, metrics)
	if err != nil {
		t.Fatalf("authflow.NewService() error = %v", err)
	}
	consents, err := consent.NewService(store)
	if err != nil {
		t.Fatalf("consent.NewService() error = %v", err)
	}
	authorizationService, err := authorization.NewService(store, nil, time.Minute, metrics)
	if err != nil {
		t.Fatalf("authorization.NewService() error = %v", err)
	}
	return phaseTwoServices{
		identities: identities, clients: clients, transactions: transactions, consents: consents, authorization: authorizationService,
		authn:    authn.NewService(store, identities, tokens, transactions, clients, true, metrics),
		sessions: session.NewService(store, tokens, metrics),
		admin:    admin.NewService(store, identities, clients, 15*time.Minute),
		cookies:  session.NewCookieManager("oneissuer_session", false, 24*time.Hour, 15*time.Minute),
	}
}

func testPhaseThreeAuthorizationLifecycle(ctx context.Context, t *testing.T, store *postgres.Store, databaseURL string) {
	t.Helper()
	services := newPhaseTwoServices(ctx, t, store)
	base := time.Now().UTC().Truncate(time.Microsecond)
	begin, err := services.authn.Begin(ctx, authn.BeginRegister, "", "p3-register", base)
	if err != nil {
		t.Fatalf("begin phase-three user registration: %v", err)
	}
	issuedSession, err := services.authn.Register(ctx, authn.RegisterInput{
		PreAuthToken: begin.PreAuth.Token, CSRFToken: begin.PreAuth.CSRFToken, TransactionToken: begin.TransactionToken,
		Account: identity.CreateInput{
			Username: "phase-three-user", DisplayName: "Phase Three User", Email: "phase-three@example.invalid", Password: "phase-three-password-safe",
		},
		RequestID: "p3-register",
	}, base.Add(time.Second))
	if err != nil {
		t.Fatalf("register phase-three user: %v", err)
	}
	principal, err := services.sessions.Authenticate(ctx, issuedSession.Token, base.Add(2*time.Second))
	if err != nil {
		t.Fatalf("authenticate phase-three user: %v", err)
	}
	createdClient, err := services.clients.Create(ctx, principal.User.ID, clientdomain.CreateInput{
		Type: clientdomain.TypePublic, Name: "Phase Three RP", RegistrationEnabled: true,
		RedirectURIs: []string{"http://127.0.0.1:4545/callback?tenant=fixed"},
		Scopes:       []string{"email", "openid", "profile"},
	}, "p3-client", base.Add(2*time.Second))
	if err != nil {
		t.Fatalf("create phase-three Client: %v", err)
	}

	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	challengeDigest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeDigest[:])
	createTransaction := func(scopes []string, requestID string, at time.Time) (string, authflow.Transaction) {
		token, _, createErr := services.transactions.CreateVerified(ctx, authflow.VerifiedInput{
			ClientID: createdClient.Client.ID, RedirectURI: createdClient.Client.RedirectURIs[0], Scopes: scopes,
			PKCEChallenge: challenge, State: "state-canary", Nonce: "nonce-canary",
			ResponseType: "code", ResponseMode: "query",
		}, requestID, at)
		if createErr != nil {
			t.Fatalf("CreateVerified(%s): %v", requestID, createErr)
		}
		resolved, resolveErr := services.transactions.Resolve(ctx, token, at.Add(time.Millisecond))
		if resolveErr != nil {
			t.Fatalf("Resolve(%s): %v", requestID, resolveErr)
		}
		return token, resolved
	}

	_, transaction := createTransaction([]string{"openid", "profile"}, "p3-concurrent-approve", base.Add(3*time.Second))
	type issueResult struct {
		issued authorization.Issued
		err    error
	}
	results := make(chan issueResult, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			value, issueErr := services.authorization.Issue(ctx, transaction, principal.User.ID, principal.AuthenticatedAt, true, "p3-concurrent-approve", base.Add(4*time.Second))
			results <- issueResult{issued: value, err: issueErr}
		}()
	}
	wait.Wait()
	close(results)
	successes, consumed := 0, 0
	var clearCode string
	for result := range results {
		switch {
		case result.err == nil:
			successes++
			clearCode = result.issued.Code
		case errors.Is(result.err, authorization.ErrConsumed):
			consumed++
		default:
			t.Fatalf("concurrent approval error = %v", result.err)
		}
	}
	if successes != 1 || consumed != 1 || clearCode == "" {
		t.Fatalf("concurrent approval successes=%d consumed=%d clear_code_present=%v", successes, consumed, clearCode != "")
	}
	if err := authorization.VerifyS256(verifier, challenge); err != nil {
		t.Fatalf("persisted transaction PKCE fixture invalid: %v", err)
	}

	evaluation, err := services.consents.Evaluate(ctx, principal.User.ID, createdClient.Client, []string{"openid", "profile"})
	if err != nil || !evaluation.Covers || evaluation.Grant == nil {
		t.Fatalf("first Consent Grant evaluation=%#v error=%v", evaluation, err)
	}

	_, expansion := createTransaction([]string{"email", "openid", "profile"}, "p3-expand-consent", base.Add(5*time.Second))
	if _, err := services.authorization.Issue(ctx, expansion, principal.User.ID, principal.AuthenticatedAt, true, "p3-expand-consent", base.Add(6*time.Second)); err != nil {
		t.Fatalf("expand Consent and issue Code: %v", err)
	}
	evaluation, err = services.consents.Evaluate(ctx, principal.User.ID, createdClient.Client, []string{"email", "openid", "profile"})
	if err != nil || !evaluation.Covers || len(evaluation.Effective) != 3 {
		t.Fatalf("expanded Consent evaluation=%#v error=%v", evaluation, err)
	}

	_, silent := createTransaction([]string{"email", "openid"}, "p3-silent-grant", base.Add(7*time.Second))
	if _, err := services.authorization.Issue(ctx, silent, principal.User.ID, principal.AuthenticatedAt, false, "p3-silent-grant", base.Add(8*time.Second)); err != nil {
		t.Fatalf("silent covering Grant issue: %v", err)
	}

	_, denied := createTransaction([]string{"openid"}, "p3-deny", base.Add(9*time.Second))
	if err := services.authorization.Deny(ctx, denied, principal.User.ID, "p3-deny", base.Add(10*time.Second)); err != nil {
		t.Fatalf("Deny() error = %v", err)
	}
	if err := services.authorization.Deny(ctx, denied, principal.User.ID, "p3-deny-replay", base.Add(11*time.Second)); !errors.Is(err, authorization.ErrConsumed) {
		t.Fatalf("Deny() replay error = %v", err)
	}
	if _, err := services.authorization.Issue(ctx, denied, principal.User.ID, principal.AuthenticatedAt, true, "p3-deny-issue", base.Add(11*time.Second)); !errors.Is(err, authorization.ErrConsumed) && !errors.Is(err, authorization.ErrInvalid) {
		t.Fatalf("denied transaction Issue() error = %v", err)
	}

	database := openSQLDatabase(ctx, t, databaseURL)
	defer func() { _ = database.Close() }()
	var codeRows, distinctHashes, denialCodeRows int
	if err := database.QueryRowContext(ctx, `SELECT count(*)::int, count(DISTINCT encode(code_hash, 'hex'))::int FROM authorization_codes WHERE auth_transaction_id = $1`, transaction.ID).Scan(&codeRows, &distinctHashes); err != nil {
		t.Fatalf("count concurrent authorization codes: %v", err)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*)::int FROM authorization_codes WHERE auth_transaction_id = $1`, denied.ID).Scan(&denialCodeRows); err != nil {
		t.Fatalf("count denied authorization codes: %v", err)
	}
	if codeRows != 1 || distinctHashes != 1 || denialCodeRows != 0 {
		t.Fatalf("authorization code rows=%d hashes=%d denied_rows=%d", codeRows, distinctHashes, denialCodeRows)
	}
	var clearCodeStored bool
	if err := database.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema='public' AND table_name='authorization_codes'
			  AND column_name IN ('code', 'clear_code', 'token')
		)`).Scan(&clearCodeStored); err != nil {
		t.Fatalf("inspect authorization code schema: %v", err)
	}
	if clearCodeStored {
		t.Fatal("authorization_codes exposes a clear-value column")
	}

	keyPath := filepath.Join(t.TempDir(), "phase-three-signing.jwk")
	if _, err := keystore.Generate(keyPath, 2048, nil); err != nil {
		t.Fatalf("generate integration signing key: %v", err)
	}
	keys, err := keystore.Load(keyPath, "")
	if err != nil {
		t.Fatalf("load integration signing key: %v", err)
	}
	metrics := observability.NewMetrics(observability.NewBuildInfo("phase-three-token-test", "test", "test"))
	protocolTokens, err := tokendomain.NewService(store, keys, nil, "https://issuer.example", 5*time.Minute, 10*time.Minute, 30*time.Second, metrics)
	if err != nil {
		t.Fatalf("token.NewService(): %v", err)
	}

	codeHash, err := authorization.DigestPresentedCode(clearCode)
	if err != nil {
		t.Fatalf("digest issued Code: %v", err)
	}
	exchangeAt := base.Add(12 * time.Second)
	exchangeInput := tokendomain.ExchangeInput{
		CodeHash: codeHash, Client: createdClient.Client, RedirectURI: createdClient.Client.RedirectURIs[0],
		CodeVerifier: verifier, RequestID: "p3-concurrent-exchange", Now: exchangeAt,
	}
	type exchangeResult struct {
		response tokendomain.Response
		err      error
	}
	exchanges := make(chan exchangeResult, 2)
	var exchangeWait sync.WaitGroup
	for range 2 {
		exchangeWait.Add(1)
		go func() {
			defer exchangeWait.Done()
			response, exchangeErr := protocolTokens.Exchange(ctx, exchangeInput)
			exchanges <- exchangeResult{response: response, err: exchangeErr}
		}()
	}
	exchangeWait.Wait()
	close(exchanges)
	exchangeSuccesses, exchangeReplays := 0, 0
	var committedTokens tokendomain.Response
	for result := range exchanges {
		switch {
		case result.err == nil:
			exchangeSuccesses++
			committedTokens = result.response
		case errors.Is(result.err, tokendomain.ErrInvalidGrant):
			exchangeReplays++
			if result.response != (tokendomain.Response{}) {
				t.Fatal("failed concurrent exchange returned transient JWTs")
			}
		default:
			t.Fatalf("concurrent Code exchange error = %v", result.err)
		}
	}
	if exchangeSuccesses != 1 || exchangeReplays != 1 || committedTokens.AccessToken == "" || committedTokens.IDToken == "" || committedTokens.TokenType != "Bearer" || committedTokens.Scope != "openid profile" {
		t.Fatalf("concurrent exchanges successes=%d replays=%d response=%+v", exchangeSuccesses, exchangeReplays, committedTokens)
	}
	userinfo, err := protocolTokens.UserInfoForAccessToken(ctx, committedTokens.AccessToken, exchangeAt.Add(time.Second))
	if err != nil || userinfo.Subject != principal.User.Subject || userinfo.Name == nil || *userinfo.Name != principal.User.DisplayName || userinfo.Email != nil {
		t.Fatalf("UserInfo=%+v error=%v", userinfo, err)
	}

	var accessRows, distinctJTIHashes int
	if err := database.QueryRowContext(ctx, `
			SELECT count(*)::int, count(DISTINCT encode(jti_hash, 'hex'))::int
			FROM access_tokens WHERE authorization_code_id = (
				SELECT id FROM authorization_codes WHERE code_hash = $1
			)`, codeHash).Scan(&accessRows, &distinctJTIHashes); err != nil {
		t.Fatalf("count concurrent Access metadata: %v", err)
	}
	if accessRows != 1 || distinctJTIHashes != 1 {
		t.Fatalf("Access metadata rows=%d distinct hashes=%d", accessRows, distinctJTIHashes)
	}
	var replayAuditRows int
	if err := database.QueryRowContext(ctx, `
			SELECT count(*)::int FROM audit_events
			WHERE event_type='authorization_code_exchange_rejected'
			  AND target_type='authorization_code'
			  AND target_id=(SELECT id FROM authorization_codes WHERE code_hash=$1)`, codeHash).Scan(&replayAuditRows); err != nil {
		t.Fatalf("count bounded Code replay audit: %v", err)
	}
	if replayAuditRows != 1 {
		t.Fatalf("Code replay audit rows=%d, want one per consumed Code", replayAuditRows)
	}
	var clearAccessStored bool
	if err := database.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema='public' AND table_name='access_tokens'
				  AND column_name IN ('token', 'access_token', 'jwt', 'jti', 'clear_jti')
			)`).Scan(&clearAccessStored); err != nil {
		t.Fatalf("inspect Access metadata schema: %v", err)
	}
	if clearAccessStored {
		t.Fatal("access_tokens exposes a clear Token/JTI column")
	}

	createTransactionFor := func(clientValue clientdomain.Client, scopes []string, requestID string, at time.Time) authflow.Transaction {
		tokenValue, _, createErr := services.transactions.CreateVerified(ctx, authflow.VerifiedInput{
			ClientID: clientValue.ID, RedirectURI: clientValue.RedirectURIs[0], Scopes: scopes,
			PKCEChallenge: challenge, ResponseType: "code", ResponseMode: "query",
		}, requestID, at)
		if createErr != nil {
			t.Fatalf("CreateVerified(%s): %v", requestID, createErr)
		}
		resolved, resolveErr := services.transactions.Resolve(ctx, tokenValue, at.Add(time.Millisecond))
		if resolveErr != nil {
			t.Fatalf("Resolve(%s): %v", requestID, resolveErr)
		}
		return resolved
	}
	issueFor := func(clientValue clientdomain.Client, scopes []string, requestID string, at time.Time) authorization.Issued {
		transactionValue := createTransactionFor(clientValue, scopes, requestID, at)
		issued, issueErr := services.authorization.Issue(ctx, transactionValue, principal.User.ID, principal.AuthenticatedAt, true, requestID, at.Add(time.Second))
		if issueErr != nil {
			t.Fatalf("Issue(%s): %v", requestID, issueErr)
		}
		return issued
	}
	exchangeIssued := func(issued authorization.Issued, clientValue clientdomain.Client, redirect, requestID, verifierValue string, at time.Time, service *tokendomain.Service) (tokendomain.Response, error) {
		hash, digestErr := authorization.DigestPresentedCode(issued.Code)
		if digestErr != nil {
			t.Fatalf("digest Code %s: %v", requestID, digestErr)
		}
		return service.Exchange(ctx, tokendomain.ExchangeInput{
			CodeHash: hash, Client: clientValue, RedirectURI: redirect, CodeVerifier: verifierValue,
			RequestID: requestID, Now: at,
		})
	}

	rollbackCode := issueFor(createdClient.Client, []string{"openid"}, "p3-signer-rollback", base.Add(14*time.Second))
	failingTokens, err := tokendomain.NewService(store, &failingProtocolKeyStore{Store: keys}, nil, "https://issuer.example", 5*time.Minute, 10*time.Minute, 30*time.Second, metrics)
	if err != nil {
		t.Fatalf("failing token service: %v", err)
	}
	if response, exchangeErr := exchangeIssued(rollbackCode, createdClient.Client, createdClient.Client.RedirectURIs[0], "p3-signer-failure", verifier, base.Add(16*time.Second), failingTokens); exchangeErr == nil || response != (tokendomain.Response{}) {
		t.Fatalf("signer failure response=%+v error=%v", response, exchangeErr)
	}
	if response, exchangeErr := exchangeIssued(rollbackCode, createdClient.Client, createdClient.Client.RedirectURIs[0], "p3-after-signer-failure", verifier, base.Add(17*time.Second), protocolTokens); exchangeErr != nil || response.AccessToken == "" {
		t.Fatalf("Code did not roll back after signer failure: response=%+v error=%v", response, exchangeErr)
	}

	bindingCode := issueFor(createdClient.Client, []string{"openid"}, "p3-binding-code", base.Add(18*time.Second))
	otherClient, err := services.clients.Create(ctx, principal.User.ID, clientdomain.CreateInput{
		Type: clientdomain.TypePublic, Name: "Other RP", RedirectURIs: []string{"http://127.0.0.1:4646/callback"}, Scopes: []string{"openid"},
	}, "p3-other-client", base.Add(18*time.Second))
	if err != nil {
		t.Fatalf("create other Client: %v", err)
	}
	wrongVerifier := verifier[:len(verifier)-1] + "A"
	bindingFailures := []struct {
		name     string
		client   clientdomain.Client
		redirect string
		verifier string
	}{
		{name: "verifier", client: createdClient.Client, redirect: createdClient.Client.RedirectURIs[0], verifier: wrongVerifier},
		{name: "redirect", client: createdClient.Client, redirect: "http://127.0.0.1:4545/other", verifier: verifier},
		{name: "client", client: otherClient.Client, redirect: createdClient.Client.RedirectURIs[0], verifier: verifier},
	}
	for index, test := range bindingFailures {
		if response, exchangeErr := exchangeIssued(bindingCode, test.client, test.redirect, "p3-wrong-"+test.name, test.verifier, base.Add(time.Duration(20+index)*time.Second), protocolTokens); !errors.Is(exchangeErr, tokendomain.ErrInvalidGrant) || response != (tokendomain.Response{}) {
			t.Fatalf("wrong %s response=%+v error=%v", test.name, response, exchangeErr)
		}
	}
	bindingHash, _ := authorization.DigestPresentedCode(bindingCode.Code)
	if err := database.QueryRowContext(ctx, `SELECT count(*)::int FROM access_tokens WHERE authorization_code_id=(SELECT id FROM authorization_codes WHERE code_hash=$1)`, bindingHash).Scan(&accessRows); err != nil || accessRows != 0 {
		t.Fatalf("binding failures created Access metadata: rows=%d error=%v", accessRows, err)
	}
	if response, exchangeErr := exchangeIssued(bindingCode, createdClient.Client, createdClient.Client.RedirectURIs[0], "p3-binding-success", verifier, base.Add(24*time.Second), protocolTokens); exchangeErr != nil || response.AccessToken == "" {
		t.Fatalf("binding failure consumed Code: response=%+v error=%v", response, exchangeErr)
	}

	disabledCode := issueFor(createdClient.Client, []string{"openid"}, "p3-disabled-state", base.Add(25*time.Second))
	if _, err := database.ExecContext(ctx, `UPDATE users SET status='disabled', updated_at=$2 WHERE id=$1`, principal.User.ID, base.Add(27*time.Second)); err != nil {
		t.Fatalf("disable Code user: %v", err)
	}
	if _, exchangeErr := exchangeIssued(disabledCode, createdClient.Client, createdClient.Client.RedirectURIs[0], "p3-disabled-user", verifier, base.Add(28*time.Second), protocolTokens); !errors.Is(exchangeErr, tokendomain.ErrInvalidGrant) {
		t.Fatalf("disabled User exchange error=%v", exchangeErr)
	}
	if _, userInfoErr := protocolTokens.UserInfoForAccessToken(ctx, committedTokens.AccessToken, base.Add(28*time.Second)); !errors.Is(userInfoErr, tokendomain.ErrInvalidToken) {
		t.Fatalf("disabled User UserInfo error=%v", userInfoErr)
	}
	if _, err := database.ExecContext(ctx, `UPDATE users SET status='active', updated_at=$2 WHERE id=$1`, principal.User.ID, base.Add(29*time.Second)); err != nil {
		t.Fatalf("restore Code user: %v", err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE oidc_clients SET status='disabled', updated_at=$2 WHERE id=$1`, createdClient.Client.ID, base.Add(30*time.Second)); err != nil {
		t.Fatalf("disable Code Client: %v", err)
	}
	if _, exchangeErr := exchangeIssued(disabledCode, createdClient.Client, createdClient.Client.RedirectURIs[0], "p3-disabled-client", verifier, base.Add(31*time.Second), protocolTokens); !errors.Is(exchangeErr, tokendomain.ErrInvalidGrant) {
		t.Fatalf("disabled Client exchange error=%v", exchangeErr)
	}
	if _, userInfoErr := protocolTokens.UserInfoForAccessToken(ctx, committedTokens.AccessToken, base.Add(31*time.Second)); !errors.Is(userInfoErr, tokendomain.ErrInvalidToken) {
		t.Fatalf("disabled Client UserInfo error=%v", userInfoErr)
	}
	if _, err := database.ExecContext(ctx, `UPDATE oidc_clients SET status='active', updated_at=$2 WHERE id=$1`, createdClient.Client.ID, base.Add(32*time.Second)); err != nil {
		t.Fatalf("restore Code Client: %v", err)
	}
	if response, exchangeErr := exchangeIssued(disabledCode, createdClient.Client, createdClient.Client.RedirectURIs[0], "p3-restored-authority", verifier, base.Add(33*time.Second), protocolTokens); exchangeErr != nil || response.AccessToken == "" {
		t.Fatalf("disabled authority consumed Code: response=%+v error=%v", response, exchangeErr)
	}

	if _, err := database.ExecContext(ctx, `DELETE FROM oidc_client_scopes WHERE client_id=$1 AND scope='profile'`, createdClient.Client.ID); err != nil {
		t.Fatalf("shrink Client scope: %v", err)
	}
	if _, userInfoErr := protocolTokens.UserInfoForAccessToken(ctx, committedTokens.AccessToken, base.Add(34*time.Second)); !errors.Is(userInfoErr, tokendomain.ErrInvalidToken) {
		t.Fatalf("Client scope shrink UserInfo error=%v", userInfoErr)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO oidc_client_scopes (client_id, scope, created_at) VALUES ($1, 'profile', $2)`, createdClient.Client.ID, base.Add(35*time.Second)); err != nil {
		t.Fatalf("restore Client scope: %v", err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE consent_grants SET scopes=ARRAY['openid']::text[], updated_at=$2 WHERE user_id=$1 AND client_id=$3`, principal.User.ID, base.Add(36*time.Second), createdClient.Client.ID); err != nil {
		t.Fatalf("shrink Consent Grant: %v", err)
	}
	if _, userInfoErr := protocolTokens.UserInfoForAccessToken(ctx, committedTokens.AccessToken, base.Add(36*time.Second)); !errors.Is(userInfoErr, tokendomain.ErrInvalidToken) {
		t.Fatalf("Grant shrink UserInfo error=%v", userInfoErr)
	}
	if _, err := database.ExecContext(ctx, `UPDATE consent_grants SET scopes=ARRAY['email','openid','profile']::text[], updated_at=$2 WHERE user_id=$1 AND client_id=$3`, principal.User.ID, base.Add(37*time.Second), createdClient.Client.ID); err != nil {
		t.Fatalf("restore Consent Grant: %v", err)
	}
	if _, userInfoErr := protocolTokens.UserInfoForAccessToken(ctx, committedTokens.AccessToken, base.Add(38*time.Second)); userInfoErr != nil {
		t.Fatalf("restored authority UserInfo error=%v", userInfoErr)
	}

	expiredCode := issueFor(createdClient.Client, []string{"openid"}, "p3-expired-code", base.Add(40*time.Second))
	if response, exchangeErr := exchangeIssued(expiredCode, createdClient.Client, createdClient.Client.RedirectURIs[0], "p3-expired-code", verifier, base.Add(2*time.Minute), protocolTokens); !errors.Is(exchangeErr, tokendomain.ErrInvalidGrant) || response != (tokendomain.Response{}) {
		t.Fatalf("expired Code response=%+v error=%v", response, exchangeErr)
	}
	expiredHash, _ := authorization.DigestPresentedCode(expiredCode.Code)
	if err := database.QueryRowContext(ctx, `SELECT count(*)::int FROM access_tokens WHERE authorization_code_id=(SELECT id FROM authorization_codes WHERE code_hash=$1)`, expiredHash).Scan(&accessRows); err != nil || accessRows != 0 {
		t.Fatalf("expired Code created metadata: rows=%d error=%v", accessRows, err)
	}

	confidential, err := services.clients.Create(ctx, principal.User.ID, clientdomain.CreateInput{
		Type: clientdomain.TypeConfidential, Name: "Confidential RP", RedirectURIs: []string{"http://127.0.0.1:4747/callback"}, Scopes: []string{"openid"},
	}, "p3-confidential", base.Add(42*time.Second))
	if err != nil || confidential.Secret == "" {
		t.Fatalf("create Confidential Client: client=%+v error=%v", confidential.Client, err)
	}
	authenticatedClient, err := services.clients.ValidateSecret(ctx, confidential.Client.ClientID, confidential.Secret)
	if err != nil {
		t.Fatalf("authenticate Confidential Client: %v", err)
	}
	confidentialCode := issueFor(confidential.Client, []string{"openid"}, "p3-confidential-code", base.Add(43*time.Second))
	confidentialTokens, exchangeErr := exchangeIssued(confidentialCode, authenticatedClient, confidential.Client.RedirectURIs[0], "p3-confidential-exchange", verifier, base.Add(45*time.Second), protocolTokens)
	if exchangeErr != nil || confidentialTokens.AccessToken == "" || confidentialTokens.IDToken == "" {
		t.Fatalf("Confidential exchange response=%+v error=%v", confidentialTokens, exchangeErr)
	}
	if _, userInfoErr := protocolTokens.UserInfoForAccessToken(ctx, confidentialTokens.AccessToken, base.Add(46*time.Second)); userInfoErr != nil {
		t.Fatalf("Confidential UserInfo: %v", userInfoErr)
	}

	reopened, err := postgres.Open(ctx, databaseURL, 2)
	if err != nil {
		t.Fatalf("reopen Store for Token replay: %v", err)
	}
	restartedTokens, err := tokendomain.NewService(reopened, keys, nil, "https://issuer.example", 5*time.Minute, 10*time.Minute, 30*time.Second, metrics)
	if err != nil {
		reopened.Close()
		t.Fatalf("restart Token service: %v", err)
	}
	if response, replayErr := restartedTokens.Exchange(ctx, exchangeInput); !errors.Is(replayErr, tokendomain.ErrInvalidGrant) || response != (tokendomain.Response{}) {
		reopened.Close()
		t.Fatalf("restart replay response=%+v error=%v", response, replayErr)
	}
	if err := database.QueryRowContext(ctx, `
			SELECT count(*)::int FROM audit_events
			WHERE event_type='authorization_code_exchange_rejected'
			  AND target_type='authorization_code'
			  AND target_id=(SELECT id FROM authorization_codes WHERE code_hash=$1)`, codeHash).Scan(&replayAuditRows); err != nil || replayAuditRows != 1 {
		reopened.Close()
		t.Fatalf("restart replay audit rows=%d error=%v, want bounded one", replayAuditRows, err)
	}
	if restartedInfo, userInfoErr := restartedTokens.UserInfoForAccessToken(ctx, committedTokens.AccessToken, base.Add(47*time.Second)); userInfoErr != nil || restartedInfo.Subject != principal.User.Subject {
		reopened.Close()
		t.Fatalf("restart UserInfo=%+v error=%v", restartedInfo, userInfoErr)
	}
	reopened.Close()

	if cleaned, cleanupErr := store.CleanupProtocolArtifacts(ctx, base.Add(48*time.Hour)); cleanupErr != nil || cleaned == 0 {
		t.Fatalf("protocol cleanup count=%d error=%v", cleaned, cleanupErr)
	}
	var remainingCodes, remainingAccess int
	if err := database.QueryRowContext(ctx, `SELECT (SELECT count(*)::int FROM authorization_codes), (SELECT count(*)::int FROM access_tokens)`).Scan(&remainingCodes, &remainingAccess); err != nil {
		t.Fatalf("count cleaned protocol metadata: %v", err)
	}
	if remainingCodes != 0 || remainingAccess != 0 {
		t.Fatalf("protocol cleanup left codes=%d access=%d", remainingCodes, remainingAccess)
	}
}

type failingProtocolKeyStore struct {
	*keystore.Store
}

func (f *failingProtocolKeyStore) Sign(_ []byte, _ string) (string, error) {
	return "", errors.New("integration signer failure")
}

func testConcurrentRegistration(ctx context.Context, t *testing.T, services phaseTwoServices) {
	t.Helper()
	type attempt struct {
		begin authn.BeginResult
		err   error
	}
	attempts := make([]attempt, 2)
	for index := range attempts {
		attempts[index].begin, attempts[index].err = services.authn.Begin(ctx, authn.BeginRegister, "", "concurrent-registration", time.Now())
		if attempts[index].err != nil {
			t.Fatalf("Begin(register) error = %v", attempts[index].err)
		}
	}
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for _, item := range attempts {
		wait.Add(1)
		go func(begin authn.BeginResult) {
			defer wait.Done()
			_, err := services.authn.Register(ctx, authn.RegisterInput{
				PreAuthToken: begin.PreAuth.Token, CSRFToken: begin.PreAuth.CSRFToken, TransactionToken: begin.TransactionToken,
				Account:   identity.CreateInput{Username: "duplicate", Email: "duplicate@example.invalid", Password: "duplicate-password-safe"},
				RequestID: "concurrent-registration",
			}, time.Now())
			results <- err
		}(item.begin)
	}
	wait.Wait()
	close(results)
	successes, duplicates := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, identity.ErrDuplicate) {
			duplicates++
		} else {
			t.Fatalf("concurrent registration error = %v", err)
		}
	}
	if successes != 1 || duplicates != 1 {
		t.Fatalf("concurrent registration successes=%d duplicates=%d", successes, duplicates)
	}
}

func submitAuthForm(t *testing.T, client *http.Client, base, path string, values url.Values) *http.Response {
	t.Helper()
	getResponse := doRequest(t, client, http.MethodGet, base+path, "", nil)
	body := readBody(t, getResponse)
	hidden := map[string]string{}
	for _, match := range hiddenInputPattern.FindAllStringSubmatch(body, -1) {
		hidden[match[1]] = match[2]
	}
	if hidden["csrf_token"] == "" || hidden["transaction"] == "" {
		t.Fatalf("authentication form lacked server values: %s", body)
	}
	values.Set("csrf_token", hidden["csrf_token"])
	values.Set("transaction", hidden["transaction"])
	request, err := http.NewRequest(http.MethodPost, base+path, strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("POST %s error = %v", path, err)
	}
	return response
}

func newBrowser(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar, Timeout: 10 * time.Second}
}

func doRequest(t *testing.T, client *http.Client, method, target, csrf string, body []byte) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequest(method, target, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("%s %s error = %v", method, target, err)
	}
	return response
}

func getMe(t *testing.T, browser *http.Client, base string, wantStatus int) (meResponseForTest, string) {
	t.Helper()
	response := doRequest(t, browser, http.MethodGet, base+"/api/v1/me", "", nil)
	if response.StatusCode != wantStatus {
		t.Fatalf("GET me status=%d want=%d body=%s", response.StatusCode, wantStatus, readBody(t, response))
	}
	if wantStatus != http.StatusOK {
		_ = response.Body.Close()
		return meResponseForTest{}, ""
	}
	csrf := response.Header.Get("X-CSRF-Token")
	var result meResponseForTest
	decodeBody(t, response, &result)
	return result, csrf
}

type meResponseForTest struct {
	User      identity.User `json:"user"`
	SessionID uuid.UUID     `json:"session_id"`
}

func getAdminMe(t *testing.T, browser *http.Client, base string) (meResponseForTest, string) {
	t.Helper()
	response := doRequest(t, browser, http.MethodGet, base+"/api/admin/v1/me", "", nil)
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET admin me status=%d body=%s", response.StatusCode, readBody(t, response))
	}
	csrf := response.Header.Get("X-CSRF-Token")
	var result meResponseForTest
	decodeBody(t, response, &result)
	return result, csrf
}

func createClientHTTP(t *testing.T, browser *http.Client, base, csrf, clientType string) clientdomain.Created {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{
		"client_type": clientType, "name": "Test " + clientType,
		"registration_enabled": true,
		"redirect_uris":        []string{"http://127.0.0.1:4040/callback"},
		"logout_uris":          []string{"http://127.0.0.1:4040/logout"},
		"scopes":               []string{"openid", "profile"},
	})
	response := doRequest(t, browser, http.MethodPost, base+"/api/admin/v1/clients", csrf, payload)
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create %s client status=%d body=%s", clientType, response.StatusCode, readBody(t, response))
	}
	var result clientdomain.Created
	decodeBody(t, response, &result)
	return result
}

func decodeBody(t *testing.T, response *http.Response, destination any) {
	t.Helper()
	defer func() { _ = response.Body.Close() }()
	if err := json.NewDecoder(response.Body).Decode(destination); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

func readBody(t *testing.T, response *http.Response) string {
	t.Helper()
	defer func() { _ = response.Body.Close() }()
	value, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	value, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
