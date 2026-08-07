package postgres_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/oneissuer/oneissuer/internal/admin"
	"github.com/oneissuer/oneissuer/internal/audit"
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
	"github.com/prometheus/client_golang/prometheus/testutil"
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
	testConcurrentPreAuthAttemptReservation(ctx, t, store, services.authn)

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
		t.Fatalf("direct Register() error = %v", debugErr)
	}

	application, err := httpserver.NewApplicationHandler(httpserver.ApplicationOptions{
		Authn: services.authn, Sessions: services.sessions, Admin: services.admin,
		Cookies: services.cookies, Issuer: mustURL(t, "http://issuer.example.test"),
		AuthRateLimit: httpserver.AuthenticationRateLimitConfig{
			PerMinute: 60_000, Burst: 1_000, GlobalPerSecond: 10_000, GlobalBurst: 20_000,
		},
	})
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	metrics := observability.NewMetrics(observability.NewBuildInfo("phase-two-test", "test", "test"))
	store.SetAuditObserver(metrics)
	readiness := httpserver.NewReadiness(metrics.SetReady)
	readiness.Set(true)
	handler := httpserver.NewHandler(httpserver.HandlerOptions{
		Readiness: readiness, Database: store, DatabaseErrorClass: postgres.ErrorClass,
		Metrics: metrics, Gatherer: metrics.Gatherer(), Application: application,
	})
	server := httptest.NewServer(handler)
	defer server.Close()
	metricEvent, err := audit.New(audit.LoginFailed, audit.ResultRejected, nil, "", nil, "metric-integration", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AppendAudit(ctx, metricEvent); err != nil {
		t.Fatalf("append metric integration audit: %v", err)
	}
	if err := store.AppendAudit(ctx, metricEvent); err == nil {
		t.Fatal("duplicate audit event unexpectedly succeeded")
	}
	metricResponse := doRequest(t, newBrowser(t), http.MethodGet, server.URL+"/metrics", "", nil)
	metricBody := readBody(t, metricResponse)
	_ = metricResponse.Body.Close()
	if !strings.Contains(metricBody, `oneissuer_audit_events_total{event="login_failed",result="rejected"} 1`) ||
		!strings.Contains(metricBody, `oneissuer_audit_write_failures_total{event="login_failed"} 1`) {
		t.Fatalf("real audit writes did not reach metrics: %s", metricBody)
	}
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
	assertUserVersionsAdvanceAtSameTimestamp(ctx, t, store, services.identities, adminMe.User.ID, ordinaryID)
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
	assertClientVersionsAdvanceAtSameTimestamp(ctx, t, store, adminMe.User.ID, publicCreated.Client.ID)
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

func assertUserVersionsAdvanceAtSameTimestamp(ctx context.Context, t *testing.T, store *postgres.Store, identities *identity.Service, actorID, userID uuid.UUID) {
	t.Helper()
	base, err := store.GetUser(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	at := base.UpdatedAt.Add(time.Second).UTC()
	firstName, staleName, nextName := "Version One", "Stale Writer", "Version Two"
	first, firstChanged, err := identities.PrepareUpdate(base, identity.UpdateInput{DisplayName: &firstName}, at)
	if err != nil {
		t.Fatal(err)
	}
	stale, staleChanged, err := identities.PrepareUpdate(base, identity.UpdateInput{DisplayName: &staleName}, at)
	if err != nil {
		t.Fatal(err)
	}
	newEvent := func(updated identity.User, changed []string) audit.Event {
		event, eventErr := audit.New(audit.UserUpdated, audit.ResultSuccess, &actorID, audit.TargetUser, &updated.ID, "version-test", changed, at)
		if eventErr != nil {
			t.Fatal(eventErr)
		}
		return event
	}
	firstResult, err := store.UpdateManagedUser(ctx, admin.UpdateUserCommit{Updated: first, Event: newEvent(first, firstChanged)})
	if err != nil {
		t.Fatal(err)
	}
	if firstResult.Version != base.Version+1 || !firstResult.UpdatedAt.Equal(at) {
		t.Fatalf("first user version result = %+v, base version %d", firstResult, base.Version)
	}
	if _, err := store.UpdateManagedUser(ctx, admin.UpdateUserCommit{Updated: stale, Event: newEvent(stale, staleChanged)}); !errors.Is(err, identity.ErrConflict) {
		t.Fatalf("stale user writer error = %v, want conflict", err)
	}
	next, nextChanged, err := identities.PrepareUpdate(firstResult, identity.UpdateInput{DisplayName: &nextName}, at)
	if err != nil {
		t.Fatal(err)
	}
	nextResult, err := store.UpdateManagedUser(ctx, admin.UpdateUserCommit{Updated: next, Event: newEvent(next, nextChanged)})
	if err != nil {
		t.Fatal(err)
	}
	if nextResult.Version != base.Version+2 || !nextResult.UpdatedAt.Equal(at) {
		t.Fatalf("same-timestamp user updates did not advance version: base=%d first=%d next=%d", base.Version, firstResult.Version, nextResult.Version)
	}
}

func assertClientVersionsAdvanceAtSameTimestamp(ctx context.Context, t *testing.T, store *postgres.Store, actorID, clientID uuid.UUID) {
	t.Helper()
	base, err := store.GetClient(ctx, clientID)
	if err != nil {
		t.Fatal(err)
	}
	at := base.UpdatedAt.Add(time.Second).UTC()
	first, stale := base, base
	first.Name, first.UpdatedAt = "Version One Client", at
	stale.Name, stale.UpdatedAt = "Stale Client Writer", at
	newEvent := func(target uuid.UUID) audit.Event {
		event, eventErr := audit.New(audit.ClientUpdated, audit.ResultSuccess, &actorID, audit.TargetClient, &target, "client-version-test", []string{"name"}, at)
		if eventErr != nil {
			t.Fatal(eventErr)
		}
		return event
	}
	if err := store.UpdateClient(ctx, first, newEvent(clientID)); err != nil {
		t.Fatal(err)
	}
	first.Version++
	if err := store.UpdateClient(ctx, stale, newEvent(clientID)); !errors.Is(err, clientdomain.ErrConflict) {
		t.Fatalf("stale client writer error = %v, want conflict", err)
	}
	next := first
	next.Name, next.UpdatedAt = "Version Two Client", at
	if err := store.UpdateClient(ctx, next, newEvent(clientID)); err != nil {
		t.Fatal(err)
	}
	stored, err := store.GetClient(ctx, clientID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Version != base.Version+2 || !stored.UpdatedAt.Equal(at) {
		t.Fatalf("same-timestamp client updates did not advance version: base=%d stored=%d", base.Version, stored.Version)
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
			value, issueErr := services.authorization.Issue(ctx, transaction, principal.User.ID, principal.SessionID, principal.SessionBindingID, principal.AuthenticatedAt, true, "p3-concurrent-approve", base.Add(4*time.Second))
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
	if _, err := services.authorization.Issue(ctx, expansion, principal.User.ID, principal.SessionID, principal.SessionBindingID, principal.AuthenticatedAt, true, "p3-expand-consent", base.Add(6*time.Second)); err != nil {
		t.Fatalf("expand Consent and issue Code: %v", err)
	}
	evaluation, err = services.consents.Evaluate(ctx, principal.User.ID, createdClient.Client, []string{"email", "openid", "profile"})
	if err != nil || !evaluation.Covers || len(evaluation.Effective) != 3 {
		t.Fatalf("expanded Consent evaluation=%#v error=%v", evaluation, err)
	}

	_, silent := createTransaction([]string{"email", "openid"}, "p3-silent-grant", base.Add(7*time.Second))
	if _, err := services.authorization.Issue(ctx, silent, principal.User.ID, principal.SessionID, principal.SessionBindingID, principal.AuthenticatedAt, false, "p3-silent-grant", base.Add(8*time.Second)); err != nil {
		t.Fatalf("silent covering Grant issue: %v", err)
	}

	_, denied := createTransaction([]string{"openid"}, "p3-deny", base.Add(9*time.Second))
	if err := services.authorization.Deny(ctx, denied, principal.User.ID, "p3-deny", base.Add(10*time.Second)); err != nil {
		t.Fatalf("Deny() error = %v", err)
	}
	if err := services.authorization.Deny(ctx, denied, principal.User.ID, "p3-deny-replay", base.Add(11*time.Second)); !errors.Is(err, authorization.ErrConsumed) {
		t.Fatalf("Deny() replay error = %v", err)
	}
	if _, err := services.authorization.Issue(ctx, denied, principal.User.ID, principal.SessionID, principal.SessionBindingID, principal.AuthenticatedAt, true, "p3-deny-issue", base.Add(11*time.Second)); !errors.Is(err, authorization.ErrConsumed) && !errors.Is(err, authorization.ErrInvalid) {
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
	store.SetAuditObserver(metrics)
	protocolTokens, err := tokendomain.NewService(store, keys, nil, "https://issuer.example", 5*time.Minute, 10*time.Minute, 30*time.Second, metrics)
	if err != nil {
		t.Fatalf("token.NewService(): %v", err)
	}

	staleCodeHash, err := authorization.DigestPresentedCode(clearCode)
	if err != nil {
		t.Fatalf("digest issued Code: %v", err)
	}
	staleResponse, err := protocolTokens.Exchange(ctx, tokendomain.ExchangeInput{
		CodeHash: staleCodeHash, Client: createdClient.Client, RedirectURI: createdClient.Client.RedirectURIs[0],
		CodeVerifier: verifier, RequestID: "p4-stale-grant-version", Now: base.Add(11 * time.Second),
	})
	if !errors.Is(err, tokendomain.ErrInvalidGrant) || staleResponse != (tokendomain.Response{}) {
		t.Fatalf("Code issued under superseded Grant version response=%+v error=%v", staleResponse, err)
	}

	_, freshTransaction := createTransaction([]string{"openid", "profile"}, "p4-current-grant-code", base.Add(11*time.Second))
	freshIssued, err := services.authorization.Issue(ctx, freshTransaction, principal.User.ID, principal.SessionID, principal.SessionBindingID, principal.AuthenticatedAt, false, "p4-current-grant-code", base.Add(11*time.Second+500*time.Millisecond))
	if err != nil {
		t.Fatalf("issue Code under current Grant version: %v", err)
	}
	codeHash, err := authorization.DigestPresentedCode(freshIssued.Code)
	if err != nil {
		t.Fatalf("digest current-Grant Code: %v", err)
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
		issued, issueErr := services.authorization.Issue(ctx, transactionValue, principal.User.ID, principal.SessionID, principal.SessionBindingID, principal.AuthenticatedAt, true, requestID, at.Add(time.Second))
		if issueErr != nil {
			t.Fatalf("Issue(%s): %v", requestID, issueErr)
		}
		return issued
	}
	assertIssueRolledBack := func(transactionValue authflow.Transaction, label string) {
		t.Helper()
		var intact bool
		if err := database.QueryRowContext(ctx, `
				SELECT txrow.consumed_at IS NULL
				       AND NOT EXISTS (SELECT 1 FROM authorization_codes WHERE auth_transaction_id=txrow.id)
				FROM auth_transactions AS txrow WHERE txrow.id=$1`, transactionValue.ID).Scan(&intact); err != nil {
			t.Fatalf("inspect %s authorization rollback: %v", label, err)
		}
		if !intact {
			t.Fatalf("%s authorization failure consumed its transaction or created a Code", label)
		}
	}

	userPageTransaction := createTransactionFor(createdClient.Client, []string{"openid"}, "p3-user-disabled-before-issue", base.Add(11*time.Second+100*time.Millisecond))
	if _, err := database.ExecContext(ctx, `UPDATE users SET status='disabled', updated_at=$2 WHERE id=$1`, principal.User.ID, base.Add(11*time.Second+150*time.Millisecond)); err != nil {
		t.Fatalf("disable User before Code issue: %v", err)
	}
	if issued, issueErr := services.authorization.Issue(ctx, userPageTransaction, principal.User.ID, principal.SessionID, principal.SessionBindingID, principal.AuthenticatedAt, true, "p3-user-disabled-before-issue", base.Add(11*time.Second+200*time.Millisecond)); !errors.Is(issueErr, authorization.ErrInactive) || issued.Code != "" {
		t.Fatalf("disabled User Code issue=%+v error=%v", issued, issueErr)
	}
	assertIssueRolledBack(userPageTransaction, "disabled User")
	if _, err := database.ExecContext(ctx, `UPDATE users SET status='active', updated_at=$2 WHERE id=$1`, principal.User.ID, base.Add(11*time.Second+300*time.Millisecond)); err != nil {
		t.Fatalf("restore User after failed Code issue: %v", err)
	}
	if issued, issueErr := services.authorization.Issue(ctx, userPageTransaction, principal.User.ID, principal.SessionID, principal.SessionBindingID, principal.AuthenticatedAt, true, "p3-user-restored-before-issue", base.Add(11*time.Second+400*time.Millisecond)); issueErr != nil || issued.Code == "" {
		t.Fatalf("User-disabled transaction did not recover: issued=%+v error=%v", issued, issueErr)
	}

	clientPageTransaction := createTransactionFor(createdClient.Client, []string{"openid"}, "p3-client-disabled-before-issue", base.Add(11*time.Second+500*time.Millisecond))
	if _, err := database.ExecContext(ctx, `UPDATE oidc_clients SET status='disabled', updated_at=$2 WHERE id=$1`, createdClient.Client.ID, base.Add(11*time.Second+550*time.Millisecond)); err != nil {
		t.Fatalf("disable Client before Code issue: %v", err)
	}
	if issued, issueErr := services.authorization.Issue(ctx, clientPageTransaction, principal.User.ID, principal.SessionID, principal.SessionBindingID, principal.AuthenticatedAt, true, "p3-client-disabled-before-issue", base.Add(11*time.Second+600*time.Millisecond)); !errors.Is(issueErr, authorization.ErrInactive) || issued.Code != "" {
		t.Fatalf("disabled Client Code issue=%+v error=%v", issued, issueErr)
	}
	assertIssueRolledBack(clientPageTransaction, "disabled Client")
	if _, err := database.ExecContext(ctx, `UPDATE oidc_clients SET status='active', updated_at=$2 WHERE id=$1`, createdClient.Client.ID, base.Add(11*time.Second+700*time.Millisecond)); err != nil {
		t.Fatalf("restore Client after failed Code issue: %v", err)
	}
	if issued, issueErr := services.authorization.Issue(ctx, clientPageTransaction, principal.User.ID, principal.SessionID, principal.SessionBindingID, principal.AuthenticatedAt, true, "p3-client-restored-before-issue", base.Add(11*time.Second+800*time.Millisecond)); issueErr != nil || issued.Code == "" {
		t.Fatalf("Client-disabled transaction did not recover: issued=%+v error=%v", issued, issueErr)
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

	assertFailedExchangeRolledBack := func(issued authorization.Issued, requestID, failureKind string) {
		t.Helper()
		hash, digestErr := authorization.DigestPresentedCode(issued.Code)
		if digestErr != nil {
			t.Fatalf("digest %s rollback Code: %v", failureKind, digestErr)
		}
		var unconsumed bool
		var accessMetadata, exchangeAudits int
		if queryErr := database.QueryRowContext(ctx, `
				SELECT code.consumed_at IS NULL,
				       (SELECT count(*)::int FROM access_tokens WHERE authorization_code_id=code.id),
				       (SELECT count(*)::int FROM audit_events WHERE request_id=$2)
				FROM authorization_codes AS code WHERE code.code_hash=$1`, hash, requestID).Scan(&unconsumed, &accessMetadata, &exchangeAudits); queryErr != nil {
			t.Fatalf("inspect %s rollback: %v", failureKind, queryErr)
		}
		if !unconsumed || accessMetadata != 0 || exchangeAudits != 0 {
			t.Fatalf("%s rollback unconsumed=%v access_metadata=%d audits=%d", failureKind, unconsumed, accessMetadata, exchangeAudits)
		}
	}

	auditRollbackCode := issueFor(createdClient.Client, []string{"openid"}, "p3-audit-rollback", base.Add(18*time.Second))
	if _, err := database.ExecContext(ctx, `
		CREATE FUNCTION oneissuer_test_reject_exchange_audit() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.request_id = 'p3-audit-failure' THEN
				RAISE EXCEPTION 'injected audit insert failure';
			END IF;
			RETURN NEW;
		END
		$$`); err != nil {
		t.Fatalf("create Audit failure trigger function: %v", err)
	}
	if _, err := database.ExecContext(ctx, `
		CREATE TRIGGER oneissuer_test_reject_exchange_audit
		BEFORE INSERT ON audit_events
		FOR EACH ROW EXECUTE FUNCTION oneissuer_test_reject_exchange_audit()`); err != nil {
		t.Fatalf("create Audit failure trigger: %v", err)
	}
	t.Cleanup(func() {
		_, _ = database.ExecContext(context.Background(), `DROP TRIGGER IF EXISTS oneissuer_test_reject_exchange_audit ON audit_events`)
		_, _ = database.ExecContext(context.Background(), `DROP FUNCTION IF EXISTS oneissuer_test_reject_exchange_audit()`)
	})
	if response, exchangeErr := exchangeIssued(auditRollbackCode, createdClient.Client, createdClient.Client.RedirectURIs[0], "p3-audit-failure", verifier, base.Add(20*time.Second), protocolTokens); exchangeErr == nil || response != (tokendomain.Response{}) {
		t.Fatalf("Audit failure response=%+v error=%v", response, exchangeErr)
	}
	assertFailedExchangeRolledBack(auditRollbackCode, "p3-audit-failure", "Audit failure")
	if err := testutil.GatherAndCompare(metrics.Gatherer(), strings.NewReader(`# HELP oneissuer_audit_write_failures_total Failed audit append operations by bounded event.
# TYPE oneissuer_audit_write_failures_total counter
oneissuer_audit_write_failures_total{event="authorization_code_exchange_succeeded"} 1
`), "oneissuer_audit_write_failures_total"); err != nil {
		t.Fatalf("transactional Audit failure metric: %v", err)
	}
	if _, err := database.ExecContext(ctx, `DROP TRIGGER oneissuer_test_reject_exchange_audit ON audit_events`); err != nil {
		t.Fatalf("drop Audit failure trigger: %v", err)
	}
	if _, err := database.ExecContext(ctx, `DROP FUNCTION oneissuer_test_reject_exchange_audit()`); err != nil {
		t.Fatalf("drop Audit failure trigger function: %v", err)
	}
	if response, exchangeErr := exchangeIssued(auditRollbackCode, createdClient.Client, createdClient.Client.RedirectURIs[0], "p3-after-audit-failure", verifier, base.Add(21*time.Second), protocolTokens); exchangeErr != nil || response.AccessToken == "" {
		t.Fatalf("Code did not roll back after Audit failure: response=%+v error=%v", response, exchangeErr)
	}

	commitRollbackCode := issueFor(createdClient.Client, []string{"openid"}, "p3-commit-rollback", base.Add(22*time.Second))
	if _, err := database.ExecContext(ctx, `
		CREATE FUNCTION oneissuer_test_reject_exchange_commit() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION 'injected deferred commit failure';
		END
		$$`); err != nil {
		t.Fatalf("create Commit failure trigger function: %v", err)
	}
	if _, err := database.ExecContext(ctx, `
		CREATE CONSTRAINT TRIGGER oneissuer_test_reject_exchange_commit
		AFTER INSERT ON access_tokens
		DEFERRABLE INITIALLY DEFERRED
		FOR EACH ROW EXECUTE FUNCTION oneissuer_test_reject_exchange_commit()`); err != nil {
		t.Fatalf("create deferred Commit failure trigger: %v", err)
	}
	t.Cleanup(func() {
		_, _ = database.ExecContext(context.Background(), `DROP TRIGGER IF EXISTS oneissuer_test_reject_exchange_commit ON access_tokens`)
		_, _ = database.ExecContext(context.Background(), `DROP FUNCTION IF EXISTS oneissuer_test_reject_exchange_commit()`)
	})
	if response, exchangeErr := exchangeIssued(commitRollbackCode, createdClient.Client, createdClient.Client.RedirectURIs[0], "p3-commit-failure", verifier, base.Add(24*time.Second), protocolTokens); exchangeErr == nil || response != (tokendomain.Response{}) {
		t.Fatalf("Commit failure response=%+v error=%v", response, exchangeErr)
	}
	assertFailedExchangeRolledBack(commitRollbackCode, "p3-commit-failure", "Commit failure")
	if _, err := database.ExecContext(ctx, `DROP TRIGGER oneissuer_test_reject_exchange_commit ON access_tokens`); err != nil {
		t.Fatalf("drop deferred Commit failure trigger: %v", err)
	}
	if _, err := database.ExecContext(ctx, `DROP FUNCTION oneissuer_test_reject_exchange_commit()`); err != nil {
		t.Fatalf("drop Commit failure trigger function: %v", err)
	}
	if response, exchangeErr := exchangeIssued(commitRollbackCode, createdClient.Client, createdClient.Client.RedirectURIs[0], "p3-after-commit-failure", verifier, base.Add(25*time.Second), protocolTokens); exchangeErr != nil || response.AccessToken == "" {
		t.Fatalf("Code did not roll back after Commit failure: response=%+v error=%v", response, exchangeErr)
	}

	// A classified serialization failure before Commit is retried exactly once.
	// The sequence is intentionally non-transactional so the trigger fails only
	// the first attempt; a rolled-back Audit insert must not be observed twice.
	retryCode := issueFor(createdClient.Client, []string{"openid"}, "p4-retry-code-issue", base.Add(26*time.Second))
	if _, err := database.ExecContext(ctx, `CREATE SEQUENCE oneissuer_test_retry_exchange_seq`); err != nil {
		t.Fatalf("create retry probe sequence: %v", err)
	}
	if _, err := database.ExecContext(ctx, `
		CREATE FUNCTION oneissuer_test_retry_exchange() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.request_id = 'p4-retry-code' AND nextval('oneissuer_test_retry_exchange_seq') = 1 THEN
				RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'injected serialization failure';
			END IF;
			RETURN NEW;
		END
		$$`); err != nil {
		t.Fatalf("create serialization retry trigger function: %v", err)
	}
	if _, err := database.ExecContext(ctx, `
		CREATE TRIGGER oneissuer_test_retry_exchange
		BEFORE INSERT ON audit_events
		FOR EACH ROW EXECUTE FUNCTION oneissuer_test_retry_exchange()`); err != nil {
		t.Fatalf("create serialization retry trigger: %v", err)
	}
	t.Cleanup(func() {
		_, _ = database.ExecContext(context.Background(), `DROP TRIGGER IF EXISTS oneissuer_test_retry_exchange ON audit_events`)
		_, _ = database.ExecContext(context.Background(), `DROP FUNCTION IF EXISTS oneissuer_test_retry_exchange()`)
		_, _ = database.ExecContext(context.Background(), `DROP SEQUENCE IF EXISTS oneissuer_test_retry_exchange_seq`)
	})
	if response, exchangeErr := exchangeIssued(retryCode, createdClient.Client, createdClient.Client.RedirectURIs[0], "p4-retry-code", verifier, base.Add(27*time.Second), protocolTokens); exchangeErr != nil || response.AccessToken == "" || response.IDToken == "" {
		t.Fatalf("serialization retry exchange response=%+v error=%v", response, exchangeErr)
	}
	var retryAttempts, retryAccessRows, retryAuditRows int
	if err := database.QueryRowContext(ctx, `SELECT last_value::int FROM oneissuer_test_retry_exchange_seq`).Scan(&retryAttempts); err != nil {
		t.Fatalf("inspect serialization retry attempts: %v", err)
	}
	retryHash, err := authorization.DigestPresentedCode(retryCode.Code)
	if err != nil {
		t.Fatalf("digest serialization retry Code: %v", err)
	}
	if err := database.QueryRowContext(ctx, `
		SELECT (SELECT count(*)::int FROM access_tokens WHERE authorization_code_id=(SELECT id FROM authorization_codes WHERE code_hash=$1)),
		       (SELECT count(*)::int FROM audit_events WHERE request_id='p4-retry-code')`, retryHash).Scan(&retryAccessRows, &retryAuditRows); err != nil {
		t.Fatalf("inspect serialization retry commit: %v", err)
	}
	if retryAttempts != 3 || retryAccessRows != 1 || retryAuditRows != 2 {
		t.Fatalf("serialization retry attempts=%d access_rows=%d audit_rows=%d", retryAttempts, retryAccessRows, retryAuditRows)
	}
	if _, err := database.ExecContext(ctx, `DROP TRIGGER oneissuer_test_retry_exchange ON audit_events`); err != nil {
		t.Fatalf("drop serialization retry trigger: %v", err)
	}
	if _, err := database.ExecContext(ctx, `DROP FUNCTION oneissuer_test_retry_exchange()`); err != nil {
		t.Fatalf("drop serialization retry trigger function: %v", err)
	}
	if _, err := database.ExecContext(ctx, `DROP SEQUENCE oneissuer_test_retry_exchange_seq`); err != nil {
		t.Fatalf("drop serialization retry probe sequence: %v", err)
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
		Type: clientdomain.TypeConfidential, Name: "Confidential RP", RedirectURIs: []string{"http://127.0.0.1:4747/callback"}, Scopes: []string{"offline_access", "openid", "profile"},
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

	offlineClient, err := services.clients.Create(ctx, principal.User.ID, clientdomain.CreateInput{
		Type: clientdomain.TypePublic, Name: "Offline RP",
		RedirectURIs: []string{"http://127.0.0.1:4848/callback"},
		Scopes:       []string{"offline_access", "openid", "profile"},
	}, "p4-offline-client", base.Add(47*time.Second))
	if err != nil {
		t.Fatalf("create offline Client: %v", err)
	}
	issueOffline := func(label string, at time.Time) tokendomain.Response {
		t.Helper()
		issued := issueFor(offlineClient.Client, []string{"offline_access", "openid", "profile"}, label, at)
		response, exchangeErr := exchangeIssued(issued, offlineClient.Client, offlineClient.Client.RedirectURIs[0], label, verifier, at.Add(2*time.Second), protocolTokens)
		if exchangeErr != nil || response.AccessToken == "" || response.IDToken == "" || response.RefreshToken == "" || response.Scope != "offline_access openid profile" {
			t.Fatalf("initial offline exchange %s response=%+v error=%v", label, response, exchangeErr)
		}
		return response
	}

	initialOffline := issueOffline("p4-initial-offline", base.Add(48*time.Second))
	initialRefreshHash, err := tokendomain.DigestPresentedRefreshToken(initialOffline.RefreshToken)
	if err != nil {
		t.Fatalf("digest initial Refresh Token: %v", err)
	}
	narrowed, err := protocolTokens.Refresh(ctx, tokendomain.RefreshInput{
		TokenHash: initialRefreshHash, Client: offlineClient.Client, RequestedScopes: []string{"openid"},
		RequestID: "p4-refresh-narrow", Now: base.Add(51 * time.Second),
	})
	if err != nil || narrowed.AccessToken == "" || narrowed.RefreshToken == "" || narrowed.IDToken != "" || narrowed.Scope != "openid" {
		t.Fatalf("narrowed refresh response=%+v error=%v", narrowed, err)
	}
	var familyScopesPreserved bool
	var familyTokens int
	if err := database.QueryRowContext(ctx, `
		SELECT families.scopes=ARRAY['offline_access','openid','profile']::text[], count(tokens.id)::int
		FROM refresh_token_families AS families
		JOIN refresh_tokens AS origin ON origin.family_id=families.id
		JOIN refresh_tokens AS tokens ON tokens.family_id=families.id
		WHERE origin.token_hash=$1
		GROUP BY families.id`, initialRefreshHash).Scan(&familyScopesPreserved, &familyTokens); err != nil {
		t.Fatalf("inspect rotated Refresh family: %v", err)
	}
	if !familyScopesPreserved || familyTokens != 2 {
		t.Fatalf("replacement changed family authority scopes_preserved=%v generations=%d", familyScopesPreserved, familyTokens)
	}

	// Disabling a Client is a cross-authority transition: the same transaction
	// must retire its Refresh family and linked live Access metadata, rather
	// than merely preventing future issuance.
	cascadeClient, err := services.clients.Create(ctx, principal.User.ID, clientdomain.CreateInput{
		Type: clientdomain.TypePublic, Name: "Client Cascade RP", RedirectURIs: []string{"http://127.0.0.1:4848/callback"},
		Scopes: []string{"offline_access", "openid", "profile"},
	}, "p4-client-cascade-create", base.Add(51*time.Second))
	if err != nil {
		t.Fatalf("create Client cascade fixture: %v", err)
	}
	cascadeIssued := issueFor(cascadeClient.Client, []string{"offline_access", "openid", "profile"}, "p4-client-cascade-issue", base.Add(51*time.Second+time.Millisecond))
	cascadeResponse, err := exchangeIssued(cascadeIssued, cascadeClient.Client, cascadeClient.Client.RedirectURIs[0], "p4-client-cascade-exchange", verifier, base.Add(53*time.Second), protocolTokens)
	if err != nil || cascadeResponse.AccessToken == "" || cascadeResponse.RefreshToken == "" {
		t.Fatalf("Client cascade fixture exchange failed: access=%t refresh=%t error=%v", cascadeResponse.AccessToken != "", cascadeResponse.RefreshToken != "", err)
	}
	cascadeHash, err := tokendomain.DigestPresentedRefreshToken(cascadeResponse.RefreshToken)
	if err != nil {
		t.Fatalf("digest Client cascade Refresh Token: %v", err)
	}
	disabledStatus := clientdomain.StatusDisabled
	type clientCascadeResult struct {
		response   tokendomain.Response
		refreshErr error
		updateErr  error
	}
	startClientCascade := make(chan struct{})
	cascadeResults := make(chan clientCascadeResult, 2)
	var cascadeWait sync.WaitGroup
	cascadeWait.Add(2)
	go func() {
		defer cascadeWait.Done()
		<-startClientCascade
		_, _, updateErr := services.clients.Update(ctx, principal.User.ID, cascadeClient.Client.ID, clientdomain.UpdateInput{Status: &disabledStatus}, "p4-client-cascade-disable", base.Add(53*time.Second))
		cascadeResults <- clientCascadeResult{updateErr: updateErr}
	}()
	go func() {
		defer cascadeWait.Done()
		<-startClientCascade
		response, refreshErr := protocolTokens.Refresh(ctx, tokendomain.RefreshInput{
			TokenHash: cascadeHash, Client: cascadeClient.Client, RequestID: "p4-client-cascade-refresh", Now: base.Add(53 * time.Second),
		})
		cascadeResults <- clientCascadeResult{response: response, refreshErr: refreshErr}
	}()
	close(startClientCascade)
	cascadeWait.Wait()
	close(cascadeResults)
	var cascadeRefresh clientCascadeResult
	for result := range cascadeResults {
		if result.updateErr != nil {
			t.Fatalf("disable Client cascade fixture: %v", result.updateErr)
		}
		if result.refreshErr != nil || result.response.AccessToken != "" || result.response.RefreshToken != "" {
			cascadeRefresh = result
		}
	}
	if cascadeRefresh.refreshErr != nil && !errors.Is(cascadeRefresh.refreshErr, tokendomain.ErrInvalidGrant) {
		t.Fatalf("disabled Client concurrent Refresh error=%v", cascadeRefresh.refreshErr)
	}
	if cascadeRefresh.refreshErr == nil && (cascadeRefresh.response.AccessToken == "" || cascadeRefresh.response.RefreshToken == "") {
		t.Fatalf("disabled Client concurrent Refresh returned incomplete response")
	}
	if _, err := protocolTokens.UserInfoForAccessToken(ctx, cascadeResponse.AccessToken, base.Add(54*time.Second)); !errors.Is(err, tokendomain.ErrInvalidToken) {
		t.Fatalf("disabled Client Access remained usable: %v", err)
	}
	if response, err := protocolTokens.Refresh(ctx, tokendomain.RefreshInput{
		TokenHash: cascadeHash, Client: cascadeClient.Client, RequestID: "p4-client-cascade-refresh", Now: base.Add(54 * time.Second),
	}); !errors.Is(err, tokendomain.ErrInvalidGrant) || response != (tokendomain.Response{}) {
		t.Fatalf("disabled Client Refresh response=%+v error=%v", response, err)
	}
	var cascadeFamilyRevoked, cascadeAccessRevoked bool
	var cascadeFamilyReason, cascadeAccessReason string
	if err := database.QueryRowContext(ctx, `
		SELECT families.revoked_at IS NOT NULL, families.revoke_reason,
		       accesses.revoked_at IS NOT NULL, accesses.revoke_reason
		FROM refresh_token_families AS families
		JOIN refresh_tokens AS generations ON generations.family_id=families.id AND generations.token_hash=$1
		JOIN access_tokens AS accesses ON accesses.refresh_family_id=families.id
		LIMIT 1`, cascadeHash).Scan(&cascadeFamilyRevoked, &cascadeFamilyReason, &cascadeAccessRevoked, &cascadeAccessReason); err != nil {
		t.Fatalf("inspect disabled Client cascade: %v", err)
	}
	if !cascadeFamilyRevoked || cascadeFamilyReason != "client_disabled" || !cascadeAccessRevoked || cascadeAccessReason != "client_disabled" {
		t.Fatalf("disabled Client cascade family=%v/%q access=%v/%q", cascadeFamilyRevoked, cascadeFamilyReason, cascadeAccessRevoked, cascadeAccessReason)
	}

	scopeClient, err := services.clients.Create(ctx, principal.User.ID, clientdomain.CreateInput{
		Type: clientdomain.TypePublic, Name: "Offline Scope Removal RP", RedirectURIs: []string{"http://127.0.0.1:4849/callback"},
		Scopes: []string{"offline_access", "openid", "profile"},
	}, "p4-client-scope-create", base.Add(55*time.Second))
	if err != nil {
		t.Fatalf("create offline-scope Client fixture: %v", err)
	}
	scopeIssued := issueFor(scopeClient.Client, []string{"offline_access", "openid", "profile"}, "p4-client-scope-issue", base.Add(55*time.Second+time.Millisecond))
	scopeResponse, err := exchangeIssued(scopeIssued, scopeClient.Client, scopeClient.Client.RedirectURIs[0], "p4-client-scope-exchange", verifier, base.Add(57*time.Second), protocolTokens)
	if err != nil || scopeResponse.AccessToken == "" || scopeResponse.RefreshToken == "" {
		t.Fatalf("offline-scope Client exchange failed: access=%t refresh=%t error=%v", scopeResponse.AccessToken != "", scopeResponse.RefreshToken != "", err)
	}
	smallerScopes := []string{"openid", "profile"}
	if _, _, err := services.clients.Update(ctx, principal.User.ID, scopeClient.Client.ID, clientdomain.UpdateInput{Scopes: &smallerScopes}, "p4-client-scope-remove-offline", base.Add(57*time.Second)); err != nil {
		t.Fatalf("remove Client offline scope: %v", err)
	}
	scopeHash, err := tokendomain.DigestPresentedRefreshToken(scopeResponse.RefreshToken)
	if err != nil {
		t.Fatalf("digest offline-scope Refresh Token: %v", err)
	}
	if response, err := protocolTokens.Refresh(ctx, tokendomain.RefreshInput{
		TokenHash: scopeHash, Client: scopeClient.Client, RequestID: "p4-client-scope-refresh", Now: base.Add(58 * time.Second),
	}); !errors.Is(err, tokendomain.ErrInvalidGrant) || response != (tokendomain.Response{}) {
		t.Fatalf("offline-scope removal Refresh response=%+v error=%v", response, err)
	}
	var scopeFamilyReason, scopeAccessReason string
	if err := database.QueryRowContext(ctx, `
		SELECT families.revoke_reason, accesses.revoke_reason
		FROM refresh_token_families AS families
		JOIN refresh_tokens AS generations ON generations.family_id=families.id AND generations.token_hash=$1
		JOIN access_tokens AS accesses ON accesses.refresh_family_id=families.id
		LIMIT 1`, scopeHash).Scan(&scopeFamilyReason, &scopeAccessReason); err != nil {
		t.Fatalf("inspect offline-scope removal cascade: %v", err)
	}
	if scopeFamilyReason != "offline_scope_removed" || scopeAccessReason != "offline_scope_removed" {
		t.Fatalf("offline-scope removal reasons family=%q access=%q", scopeFamilyReason, scopeAccessReason)
	}

	if info, infoErr := protocolTokens.UserInfoForAccessToken(ctx, narrowed.AccessToken, base.Add(52*time.Second)); infoErr != nil || info.Subject != principal.User.Subject || info.Name != nil {
		t.Fatalf("narrowed refresh UserInfo=%+v error=%v", info, infoErr)
	}
	if replay, replayErr := protocolTokens.Refresh(ctx, tokendomain.RefreshInput{
		TokenHash: initialRefreshHash, Client: offlineClient.Client, RequestID: "p4-refresh-reuse", Now: base.Add(53 * time.Second),
	}); !errors.Is(replayErr, tokendomain.ErrInvalidGrant) || replay != (tokendomain.Response{}) {
		t.Fatalf("Refresh reuse response=%+v error=%v", replay, replayErr)
	}
	if _, infoErr := protocolTokens.UserInfoForAccessToken(ctx, narrowed.AccessToken, base.Add(54*time.Second)); !errors.Is(infoErr, tokendomain.ErrInvalidToken) {
		t.Fatalf("family-linked Access survived reuse: %v", infoErr)
	}
	narrowedHash, _ := tokendomain.DigestPresentedRefreshToken(narrowed.RefreshToken)
	if response, refreshErr := protocolTokens.Refresh(ctx, tokendomain.RefreshInput{
		TokenHash: narrowedHash, Client: offlineClient.Client, RequestID: "p4-revoked-descendant", Now: base.Add(54 * time.Second),
	}); !errors.Is(refreshErr, tokendomain.ErrInvalidGrant) || response != (tokendomain.Response{}) {
		t.Fatalf("replacement survived family reuse revoke response=%+v error=%v", response, refreshErr)
	}

	concurrentOffline := issueOffline("p4-concurrent-refresh", base.Add(54*time.Second+500*time.Millisecond))
	concurrentRefreshHash, err := tokendomain.DigestPresentedRefreshToken(concurrentOffline.RefreshToken)
	if err != nil {
		t.Fatalf("digest concurrent Refresh Token: %v", err)
	}
	type concurrentRefreshResult struct {
		response tokendomain.Response
		err      error
	}
	concurrentRefreshes := make(chan concurrentRefreshResult, 2)
	var concurrentRefreshWait sync.WaitGroup
	for range 2 {
		concurrentRefreshWait.Add(1)
		go func() {
			defer concurrentRefreshWait.Done()
			response, refreshErr := protocolTokens.Refresh(ctx, tokendomain.RefreshInput{
				TokenHash: concurrentRefreshHash, Client: offlineClient.Client,
				RequestID: "p4-concurrent-refresh", Now: base.Add(58 * time.Second),
			})
			concurrentRefreshes <- concurrentRefreshResult{response: response, err: refreshErr}
		}()
	}
	concurrentRefreshWait.Wait()
	close(concurrentRefreshes)
	concurrentRefreshSuccesses, concurrentRefreshReplays := 0, 0
	var concurrentRefreshResponse tokendomain.Response
	for result := range concurrentRefreshes {
		switch {
		case result.err == nil:
			concurrentRefreshSuccesses++
			concurrentRefreshResponse = result.response
		case errors.Is(result.err, tokendomain.ErrInvalidGrant):
			concurrentRefreshReplays++
			if result.response != (tokendomain.Response{}) {
				t.Fatal("failed concurrent Refresh returned transient JWTs")
			}
		default:
			var postgresErr *pgconn.PgError
			if errors.As(result.err, &postgresErr) {
				t.Fatalf("concurrent Refresh error = %v (sqlstate=%s message=%s detail=%s)", result.err, postgresErr.Code, postgresErr.Message, postgresErr.Detail)
			}
			t.Fatalf("concurrent Refresh error = %v", result.err)
		}
	}
	if concurrentRefreshSuccesses != 1 || concurrentRefreshReplays != 1 || concurrentRefreshResponse.AccessToken == "" || concurrentRefreshResponse.RefreshToken == "" {
		t.Fatalf("concurrent Refresh successes=%d replays=%d response=%+v", concurrentRefreshSuccesses, concurrentRefreshReplays, concurrentRefreshResponse)
	}
	var concurrentFamilyRevoked, concurrentLiveAccess int
	if err := database.QueryRowContext(ctx, `
		SELECT (SELECT count(*)::int FROM refresh_token_families WHERE id=(SELECT family_id FROM refresh_tokens WHERE token_hash=$1 AND generation=0) AND revoked_at IS NOT NULL),
		       (SELECT count(*)::int FROM access_tokens WHERE refresh_family_id=(SELECT family_id FROM refresh_tokens WHERE token_hash=$1 AND generation=0) AND revoked_at IS NULL AND expires_at>$2)`, concurrentRefreshHash, base.Add(58*time.Second)).Scan(&concurrentFamilyRevoked, &concurrentLiveAccess); err != nil {
		t.Fatalf("inspect concurrent Refresh family: %v", err)
	}
	if concurrentFamilyRevoked != 1 || concurrentLiveAccess != 0 {
		t.Fatalf("concurrent Refresh family_revoked=%d live_access=%d", concurrentFamilyRevoked, concurrentLiveAccess)
	}

	confidentialOfflineCode := issueFor(confidential.Client, []string{"offline_access", "openid", "profile"}, "p4-confidential-offline", base.Add(54*time.Second))
	confidentialOffline, err := exchangeIssued(confidentialOfflineCode, authenticatedClient, confidential.Client.RedirectURIs[0], "p4-confidential-offline", verifier, base.Add(56*time.Second), protocolTokens)
	if err != nil || confidentialOffline.RefreshToken == "" {
		t.Fatalf("Confidential initial offline response=%+v error=%v", confidentialOffline, err)
	}
	accessState, err := protocolTokens.Introspect(ctx, tokendomain.IntrospectionInput{
		Client: authenticatedClient, Token: confidentialOffline.AccessToken, Hint: "access_token", Now: base.Add(57 * time.Second),
	})
	if err != nil || !accessState.Active || accessState.TokenType != "Bearer" || accessState.ClientID != confidential.Client.ClientID || accessState.Subject != principal.User.Subject || accessState.Audience == "" {
		t.Fatalf("active Access introspection=%+v error=%v", accessState, err)
	}
	refreshState, err := protocolTokens.Introspect(ctx, tokendomain.IntrospectionInput{
		Client: authenticatedClient, Token: confidentialOffline.RefreshToken, Hint: "refresh_token", Now: base.Add(57 * time.Second),
	})
	if err != nil || !refreshState.Active || refreshState.TokenType != "" || refreshState.Audience != "" || refreshState.Scope != "offline_access openid profile" {
		t.Fatalf("active Refresh introspection=%+v error=%v", refreshState, err)
	}
	wrongOwnerState, err := protocolTokens.Introspect(ctx, tokendomain.IntrospectionInput{
		Client: authenticatedClient, Token: initialOffline.AccessToken, Now: base.Add(57 * time.Second),
	})
	if err != nil || wrongOwnerState != (tokendomain.IntrospectionResponse{Active: false}) {
		t.Fatalf("cross-Client introspection=%+v error=%v", wrongOwnerState, err)
	}
	if err := protocolTokens.Revoke(ctx, tokendomain.RevocationInput{
		Client: authenticatedClient, Token: confidentialOffline.AccessToken, Hint: "refresh_token",
		RequestID: "p4-revoke-access", Now: base.Add(58 * time.Second),
	}); err != nil {
		t.Fatalf("revoke owning Access: %v", err)
	}
	accessState, err = protocolTokens.Introspect(ctx, tokendomain.IntrospectionInput{
		Client: authenticatedClient, Token: confidentialOffline.AccessToken, Now: base.Add(59 * time.Second),
	})
	if err != nil || accessState.Active {
		t.Fatalf("revoked Access introspection=%+v error=%v", accessState, err)
	}
	refreshState, err = protocolTokens.Introspect(ctx, tokendomain.IntrospectionInput{
		Client: authenticatedClient, Token: confidentialOffline.RefreshToken, Now: base.Add(59 * time.Second),
	})
	if err != nil || !refreshState.Active {
		t.Fatalf("Access revoke unexpectedly revoked family introspection=%+v error=%v", refreshState, err)
	}
	confidentialRefreshHash, _ := tokendomain.DigestPresentedRefreshToken(confidentialOffline.RefreshToken)
	confidentialReplacement, err := protocolTokens.Refresh(ctx, tokendomain.RefreshInput{
		TokenHash: confidentialRefreshHash, Client: authenticatedClient,
		RequestID: "p4-confidential-refresh", Now: base.Add(60 * time.Second),
	})
	if err != nil || confidentialReplacement.RefreshToken == "" {
		t.Fatalf("Confidential refresh response=%+v error=%v", confidentialReplacement, err)
	}
	if err := protocolTokens.Revoke(ctx, tokendomain.RevocationInput{
		Client: authenticatedClient, Token: confidentialOffline.RefreshToken, Hint: "access_token",
		RequestID: "p4-revoke-consumed-refresh", Now: base.Add(61 * time.Second),
	}); err != nil {
		t.Fatalf("revoke consumed owning Refresh: %v", err)
	}
	refreshState, err = protocolTokens.Introspect(ctx, tokendomain.IntrospectionInput{
		Client: authenticatedClient, Token: confidentialReplacement.RefreshToken, Now: base.Add(62 * time.Second),
	})
	if err != nil || refreshState.Active {
		t.Fatalf("Refresh family revoke did not inactivate replacement=%+v error=%v", refreshState, err)
	}
	if _, infoErr := protocolTokens.UserInfoForAccessToken(ctx, confidentialReplacement.AccessToken, base.Add(62*time.Second)); !errors.Is(infoErr, tokendomain.ErrInvalidToken) {
		t.Fatalf("Refresh revoke left linked Access active: %v", infoErr)
	}
	if err := protocolTokens.Revoke(ctx, tokendomain.RevocationInput{
		Client: authenticatedClient, Token: confidentialOffline.RefreshToken,
		RequestID: "p4-revoke-idempotent", Now: base.Add(63 * time.Second),
	}); err != nil {
		t.Fatalf("idempotent Refresh revoke: %v", err)
	}

	persistentOffline := issueOffline("p4-persistent-offline", base.Add(55*time.Second))
	persistentHash, err := tokendomain.DigestPresentedRefreshToken(persistentOffline.RefreshToken)
	if err != nil {
		t.Fatalf("digest persistent Refresh Token: %v", err)
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
	restartedRefresh, refreshErr := restartedTokens.Refresh(ctx, tokendomain.RefreshInput{
		TokenHash: persistentHash, Client: offlineClient.Client, RequestID: "p4-refresh-after-restart", Now: base.Add(58 * time.Second),
	})
	if refreshErr != nil || restartedRefresh.AccessToken == "" || restartedRefresh.RefreshToken == "" {
		reopened.Close()
		t.Fatalf("Refresh did not persist across Store restart response=%+v error=%v", restartedRefresh, refreshErr)
	}
	reopened.Close()

	staleGrantCode := issueFor(offlineClient.Client, []string{"offline_access", "openid", "profile"}, "p4-code-before-grant-revoke", base.Add(64*time.Second))
	grantPage, err := services.consents.ListMine(ctx, principal.User.ID, "", 100, base.Add(65*time.Second))
	if err != nil {
		t.Fatalf("list current user Grants: %v", err)
	}
	var listedOffline *consent.ManagedGrant
	for index := range grantPage.Items {
		if grantPage.Items[index].ClientID == offlineClient.Client.ClientID {
			listedOffline = &grantPage.Items[index]
			break
		}
	}
	if listedOffline == nil || !listedOffline.HasActiveOfflineFamily || listedOffline.ClientName != offlineClient.Client.Name || listedOffline.RevokedAt != nil {
		t.Fatalf("offline Grant missing or unsafe summary: %+v", listedOffline)
	}
	var internalGrantID uuid.UUID
	var versionBeforeRevoke int64
	if err := database.QueryRowContext(ctx, `SELECT id, version FROM consent_grants WHERE user_id=$1 AND client_id=$2`, principal.User.ID, offlineClient.Client.ID).Scan(&internalGrantID, &versionBeforeRevoke); err != nil {
		t.Fatalf("inspect Grant before owner revoke: %v", err)
	}
	encodedPage, err := json.Marshal(grantPage)
	if err != nil || bytes.Contains(encodedPage, []byte(internalGrantID.String())) || bytes.Contains(encodedPage, []byte(`"id"`)) {
		t.Fatalf("owner Grant page exposed an internal identifier: body=%s error=%v", encodedPage, err)
	}
	if _, err := services.consents.RevokeMine(ctx, uuid.New(), offlineClient.Client.ClientID, "p4-grant-wrong-owner", base.Add(66*time.Second)); !errors.Is(err, consent.ErrNotFound) {
		t.Fatalf("wrong-owner Grant revoke error=%v", err)
	}
	revokedGrant, err := services.consents.RevokeMine(ctx, principal.User.ID, offlineClient.Client.ClientID, "p4-grant-revoke", base.Add(67*time.Second))
	if err != nil || revokedGrant.RevokedAt == nil || revokedGrant.HasActiveOfflineFamily {
		t.Fatalf("owner Grant revoke=%+v error=%v", revokedGrant, err)
	}
	idempotentGrant, err := services.consents.RevokeMine(ctx, principal.User.ID, offlineClient.Client.ClientID, "p4-grant-revoke-repeat", base.Add(68*time.Second))
	if err != nil || idempotentGrant.RevokedAt == nil || !idempotentGrant.RevokedAt.Equal(*revokedGrant.RevokedAt) {
		t.Fatalf("idempotent Grant revoke=%+v error=%v", idempotentGrant, err)
	}
	var versionAfterRevoke int64
	var liveGrantFamilies, liveGrantAccess, grantRevokeAudits int
	if err := database.QueryRowContext(ctx, `
		SELECT grants.version,
		       (SELECT count(*)::int FROM refresh_token_families WHERE consent_grant_id=grants.id AND revoked_at IS NULL),
		       (SELECT count(*)::int FROM access_tokens WHERE consent_grant_id=grants.id AND revoked_at IS NULL AND expires_at>$2),
		       (SELECT count(*)::int FROM audit_events WHERE event_type='consent_grant_revoked' AND target_type='consent_grant' AND target_id=grants.id)
		FROM consent_grants AS grants WHERE grants.id=$1`, internalGrantID, base.Add(68*time.Second)).Scan(
		&versionAfterRevoke, &liveGrantFamilies, &liveGrantAccess, &grantRevokeAudits,
	); err != nil {
		t.Fatalf("inspect owner Grant cascade: %v", err)
	}
	if versionAfterRevoke != versionBeforeRevoke+1 || liveGrantFamilies != 0 || liveGrantAccess != 0 || grantRevokeAudits != 1 {
		t.Fatalf("Grant cascade version=%d/%d families=%d access=%d audits=%d", versionAfterRevoke, versionBeforeRevoke, liveGrantFamilies, liveGrantAccess, grantRevokeAudits)
	}
	if _, userInfoErr := protocolTokens.UserInfoForAccessToken(ctx, restartedRefresh.AccessToken, base.Add(69*time.Second)); !errors.Is(userInfoErr, tokendomain.ErrInvalidToken) {
		t.Fatalf("Grant revoke left linked Access active: %v", userInfoErr)
	}
	restartedRefreshHash, err := tokendomain.DigestPresentedRefreshToken(restartedRefresh.RefreshToken)
	if err != nil {
		t.Fatalf("digest restart replacement after Grant revoke: %v", err)
	}
	if response, refreshErr := protocolTokens.Refresh(ctx, tokendomain.RefreshInput{
		TokenHash: restartedRefreshHash, Client: offlineClient.Client, RequestID: "p4-refresh-after-grant-revoke", Now: base.Add(69 * time.Second),
	}); !errors.Is(refreshErr, tokendomain.ErrInvalidGrant) || response != (tokendomain.Response{}) {
		t.Fatalf("Grant-revoked Refresh response=%+v error=%v", response, refreshErr)
	}

	freshReconsentCode := issueFor(offlineClient.Client, []string{"offline_access", "openid"}, "p4-grant-reconsent", base.Add(70*time.Second))
	evaluation, err = services.consents.Evaluate(ctx, principal.User.ID, offlineClient.Client, []string{"offline_access", "openid"})
	if err != nil || !evaluation.Covers || !reflect.DeepEqual(evaluation.Effective, []string{"offline_access", "openid"}) || evaluation.Grant == nil || evaluation.Grant.RevokedAt != nil {
		t.Fatalf("Grant reconsent restored revoked Scope: evaluation=%+v error=%v", evaluation, err)
	}
	if response, exchangeErr := exchangeIssued(staleGrantCode, offlineClient.Client, offlineClient.Client.RedirectURIs[0], "p4-stale-code-after-reconsent", verifier, base.Add(72*time.Second), protocolTokens); !errors.Is(exchangeErr, tokendomain.ErrInvalidGrant) || response != (tokendomain.Response{}) {
		t.Fatalf("old Grant-version Code survived revoke/reconsent response=%+v error=%v", response, exchangeErr)
	}
	if response, exchangeErr := exchangeIssued(freshReconsentCode, offlineClient.Client, offlineClient.Client.RedirectURIs[0], "p4-fresh-code-after-reconsent", verifier, base.Add(73*time.Second), protocolTokens); exchangeErr != nil || response.RefreshToken == "" || response.Scope != "offline_access openid" {
		t.Fatalf("fresh reconsent Code exchange response=%+v error=%v", response, exchangeErr)
	}

	// Refresh and Grant revoke use the same User -> Client -> Grant prefix. The
	// pair must converge without a deadlock or an authority leak regardless of
	// which transaction wins the Grant lock.
	grantRace := issueOffline("p4-refresh-grant-race", base.Add(74*time.Second))
	grantRaceHash, err := tokendomain.DigestPresentedRefreshToken(grantRace.RefreshToken)
	if err != nil {
		t.Fatalf("digest Refresh/Grant race Token: %v", err)
	}
	type grantRaceResult struct {
		refresh    tokendomain.Response
		refreshErr error
		grant      consent.ManagedGrant
		grantErr   error
	}
	grantRaceResults := make(chan grantRaceResult, 2)
	grantRaceStart := make(chan struct{})
	go func() {
		<-grantRaceStart
		response, refreshErr := protocolTokens.Refresh(ctx, tokendomain.RefreshInput{
			TokenHash: grantRaceHash, Client: offlineClient.Client, RequestID: "p4-refresh-grant-race", Now: base.Add(77 * time.Second),
		})
		grantRaceResults <- grantRaceResult{refresh: response, refreshErr: refreshErr}
	}()
	go func() {
		<-grantRaceStart
		grant, grantErr := services.consents.RevokeMine(ctx, principal.User.ID, offlineClient.Client.ClientID, "p4-refresh-grant-race", base.Add(77*time.Second))
		grantRaceResults <- grantRaceResult{grant: grant, grantErr: grantErr}
	}()
	close(grantRaceStart)
	var grantRaceRefresh grantRaceResult
	var grantRaceGrant grantRaceResult
	for range 2 {
		result := <-grantRaceResults
		if result.refreshErr != nil || result.refresh.AccessToken != "" {
			grantRaceRefresh = result
		} else {
			grantRaceGrant = result
		}
	}
	if grantRaceGrant.grantErr != nil || grantRaceGrant.grant.RevokedAt == nil {
		t.Fatalf("Refresh/Grant race revoke=%+v error=%v", grantRaceGrant.grant, grantRaceGrant.grantErr)
	}
	if grantRaceRefresh.refreshErr != nil && !errors.Is(grantRaceRefresh.refreshErr, tokendomain.ErrInvalidGrant) {
		t.Fatalf("Refresh/Grant race refresh error=%v", grantRaceRefresh.refreshErr)
	}
	if grantRaceRefresh.refreshErr == nil && (grantRaceRefresh.refresh.AccessToken == "" || grantRaceRefresh.refresh.RefreshToken == "") {
		t.Fatalf("Refresh/Grant race returned incomplete refresh=%+v", grantRaceRefresh.refresh)
	}
	var grantRaceRevoked, grantRaceLiveAccess int
	if err := database.QueryRowContext(ctx, `
		SELECT (SELECT count(*)::int FROM refresh_token_families WHERE id=(SELECT family_id FROM refresh_tokens WHERE token_hash=$1 AND generation=0) AND revoked_at IS NOT NULL),
		       (SELECT count(*)::int FROM access_tokens WHERE refresh_family_id=(SELECT family_id FROM refresh_tokens WHERE token_hash=$1 AND generation=0) AND revoked_at IS NULL AND expires_at>$2)`, grantRaceHash, base.Add(77*time.Second)).Scan(&grantRaceRevoked, &grantRaceLiveAccess); err != nil {
		t.Fatalf("inspect Refresh/Grant race family: %v", err)
	}
	if grantRaceRevoked != 1 || grantRaceLiveAccess != 0 {
		t.Fatalf("Refresh/Grant race family_revoked=%d live_access=%d", grantRaceRevoked, grantRaceLiveAccess)
	}

	// Session binding revocation races a Refresh without the Refresh path ever
	// locking a browser Session. A committed rotation is still retired by the
	// binding cascade, while a refresh that observes the revoke is rejected.
	sessionRaceClient, err := services.clients.Create(ctx, principal.User.ID, clientdomain.CreateInput{
		Type: clientdomain.TypePublic, Name: "Session Race RP", RedirectURIs: []string{"http://127.0.0.1:4949/callback"},
		Scopes: []string{"offline_access", "openid"},
	}, "p4-refresh-session-race-client", base.Add(76*time.Second))
	if err != nil {
		t.Fatalf("create Refresh/Session race Client: %v", err)
	}
	sessionRaceIssued := issueFor(sessionRaceClient.Client, []string{"offline_access", "openid"}, "p4-refresh-session-race-issue", base.Add(77*time.Second))
	sessionRaceInitial, err := exchangeIssued(sessionRaceIssued, sessionRaceClient.Client, sessionRaceClient.Client.RedirectURIs[0], "p4-refresh-session-race-exchange", verifier, base.Add(79*time.Second), protocolTokens)
	if err != nil || sessionRaceInitial.RefreshToken == "" {
		t.Fatalf("issue Refresh/Session race Token response=%+v error=%v", sessionRaceInitial, err)
	}
	sessionRaceHash, err := tokendomain.DigestPresentedRefreshToken(sessionRaceInitial.RefreshToken)
	if err != nil {
		t.Fatalf("digest Refresh/Session race Token: %v", err)
	}
	type sessionRaceResult struct {
		refresh    tokendomain.Response
		refreshErr error
		sessionErr error
	}
	sessionRaceResults := make(chan sessionRaceResult, 2)
	sessionRaceStart := make(chan struct{})
	go func() {
		<-sessionRaceStart
		response, refreshErr := protocolTokens.Refresh(ctx, tokendomain.RefreshInput{
			TokenHash: sessionRaceHash, Client: sessionRaceClient.Client, RequestID: "p4-refresh-session-race", Now: base.Add(80 * time.Second),
		})
		sessionRaceResults <- sessionRaceResult{refresh: response, refreshErr: refreshErr}
	}()
	go func() {
		<-sessionRaceStart
		sessionErr := services.sessions.RevokeMine(ctx, principal, principal.SessionID, "p4-refresh-session-race", base.Add(80*time.Second))
		sessionRaceResults <- sessionRaceResult{sessionErr: sessionErr}
	}()
	close(sessionRaceStart)
	var sessionRaceRefresh sessionRaceResult
	var sessionRaceSession sessionRaceResult
	for range 2 {
		result := <-sessionRaceResults
		if result.sessionErr != nil || (result.refreshErr == nil && result.refresh.AccessToken == "") {
			sessionRaceSession = result
		} else {
			sessionRaceRefresh = result
		}
	}
	if sessionRaceSession.sessionErr != nil {
		t.Fatalf("Refresh/Session race revoke error=%v", sessionRaceSession.sessionErr)
	}
	if sessionRaceRefresh.refreshErr != nil && !errors.Is(sessionRaceRefresh.refreshErr, tokendomain.ErrInvalidGrant) {
		t.Fatalf("Refresh/Session race refresh error=%v", sessionRaceRefresh.refreshErr)
	}
	if sessionRaceRefresh.refreshErr == nil && (sessionRaceRefresh.refresh.AccessToken == "" || sessionRaceRefresh.refresh.RefreshToken == "") {
		t.Fatalf("Refresh/Session race returned incomplete refresh=%+v", sessionRaceRefresh.refresh)
	}
	var sessionRaceRevoked, sessionRaceLiveAccess int
	if err := database.QueryRowContext(ctx, `
		SELECT (SELECT count(*)::int FROM refresh_token_families WHERE id=(SELECT family_id FROM refresh_tokens WHERE token_hash=$1 AND generation=0) AND revoked_at IS NOT NULL),
		       (SELECT count(*)::int FROM access_tokens WHERE refresh_family_id=(SELECT family_id FROM refresh_tokens WHERE token_hash=$1 AND generation=0) AND revoked_at IS NULL AND expires_at>$2)`, sessionRaceHash, base.Add(80*time.Second)).Scan(&sessionRaceRevoked, &sessionRaceLiveAccess); err != nil {
		t.Fatalf("inspect Refresh/Session race family: %v", err)
	}
	if sessionRaceRevoked != 1 || sessionRaceLiveAccess != 0 {
		t.Fatalf("Refresh/Session race family_revoked=%d live_access=%d", sessionRaceRevoked, sessionRaceLiveAccess)
	}

	cleanupCutoff := base.Add(48 * time.Hour)
	testProtocolCleanupRollback(ctx, t, store, database, cleanupCutoff)
	testRefreshAndProtocolCleanup(ctx, t, store, database, initialRefreshHash, cleanupCutoff)
	testProtocolCleanupCommitsCompletedBatches(ctx, t, store, database, base.Add(72*time.Hour))
	testUserDisableRevokesUnboundAuthority(ctx, t, store, database, principal.User.ID, principal.User.ID)
}

func testUserDisableRevokesUnboundAuthority(ctx context.Context, t *testing.T, store *postgres.Store, database *sql.DB, userID, actorID uuid.UUID) {
	t.Helper()
	var grantID, clientID uuid.UUID
	if err := database.QueryRowContext(ctx, `
		SELECT id, client_id
		FROM consent_grants
		WHERE user_id=$1 AND revoked_at IS NULL
		  AND scopes @> ARRAY['offline_access','openid']::text[]
		ORDER BY updated_at DESC
		LIMIT 1`, userID).Scan(&grantID, &clientID); err != nil {
		t.Fatalf("select active offline Grant for user-disable cascade: %v", err)
	}
	var latestFamilyCreatedAt time.Time
	if err := database.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(created_at), CURRENT_TIMESTAMP)
		FROM refresh_token_families WHERE user_id=$1`, userID).Scan(&latestFamilyCreatedAt); err != nil {
		t.Fatalf("select latest family timestamp for user-disable cascade: %v", err)
	}
	now := latestFamilyCreatedAt.UTC().Add(time.Second).Truncate(time.Microsecond)
	familyID, refreshID, accessID := uuid.New(), uuid.New(), uuid.New()
	sessionBindingID := uuid.New()
	refreshHash := sha256.Sum256([]byte("user-disable-unbound-refresh"))
	jtiHash := sha256.Sum256([]byte("user-disable-unbound-access"))
	if _, err := database.ExecContext(ctx, `
		INSERT INTO refresh_token_families (
			id, consent_grant_id, user_id, client_id, session_binding_id,
			scopes, created_at, absolute_expires_at
		) VALUES ($1, $2, $3, $4, $5, ARRAY['offline_access','openid']::text[], $6, $7)`,
		familyID, grantID, userID, clientID, sessionBindingID, now, now.Add(24*time.Hour)); err != nil {
		t.Fatalf("insert unbound user-disable family: %v", err)
	}
	if _, err := database.ExecContext(ctx, `
		INSERT INTO refresh_tokens (id, family_id, token_hash, generation, issued_at, expires_at)
		VALUES ($1, $2, $3, 0, $4, $5)`,
		refreshID, familyID, refreshHash[:], now, now.Add(time.Hour)); err != nil {
		t.Fatalf("insert unbound user-disable generation: %v", err)
	}
	if _, err := database.ExecContext(ctx, `
		INSERT INTO access_tokens (
			id, jti_hash, consent_grant_id, user_id, client_id, scopes,
			issued_at, expires_at, issuance_source, source_refresh_token_id,
			refresh_family_id, session_binding_id
		) VALUES ($1, $2, $3, $4, $5, ARRAY['openid']::text[], $6, $7,
			'refresh_token', $8, $9, $10)`,
		accessID, jtiHash[:], grantID, userID, clientID, now, now.Add(10*time.Minute), refreshID, familyID, sessionBindingID); err != nil {
		t.Fatalf("insert unbound user-disable access: %v", err)
	}
	current, err := store.GetUser(ctx, userID)
	if err != nil {
		t.Fatalf("load user before disable cascade: %v", err)
	}
	updated := current
	updated.Status = identity.StatusDisabled
	updated.UpdatedAt = now.Add(time.Second)
	statusEvent, err := audit.New(audit.UserStatusChanged, audit.ResultSuccess, &actorID, audit.TargetUser, &userID, "p4-user-disable-unbound", []string{"status"}, updated.UpdatedAt)
	if err != nil {
		t.Fatal(err)
	}
	sessionsEvent, err := audit.New(audit.SessionsRevokedAll, audit.ResultSuccess, &actorID, audit.TargetUser, &userID, "p4-user-disable-unbound", []string{"revoked"}, updated.UpdatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateManagedUser(ctx, admin.UpdateUserCommit{
		Updated: updated, RevokeSessions: true, Event: statusEvent, SessionEvent: &sessionsEvent,
	}); err != nil {
		t.Fatalf("disable user with unbound authority: %v", err)
	}
	var familyRevoked, accessRevoked bool
	var familyReason, accessReason string
	if err := database.QueryRowContext(ctx, `
		SELECT families.revoked_at IS NOT NULL, families.revoke_reason,
		       accesses.revoked_at IS NOT NULL, accesses.revoke_reason
		FROM refresh_token_families AS families
		JOIN access_tokens AS accesses ON accesses.refresh_family_id=families.id
		WHERE families.id=$1 AND accesses.id=$2`, familyID, accessID).
		Scan(&familyRevoked, &familyReason, &accessRevoked, &accessReason); err != nil {
		t.Fatalf("inspect unbound user-disable cascade: %v", err)
	}
	if !familyRevoked || familyReason != "user_disabled" || !accessRevoked || accessReason != "user_disabled" {
		t.Fatalf("unbound user-disable cascade family=%v/%q access=%v/%q", familyRevoked, familyReason, accessRevoked, accessReason)
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

func testConcurrentPreAuthAttemptReservation(ctx context.Context, t *testing.T, store *postgres.Store, service *authn.Service) {
	t.Helper()
	now := time.Now().UTC()
	begin, err := service.Begin(ctx, authn.BeginLogin, "", "attempt-reservation", now)
	if err != nil {
		t.Fatal(err)
	}
	const maximum int16 = 5
	results := make(chan error, 32)
	var wait sync.WaitGroup
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results <- store.ReservePreAuthAttempt(ctx, begin.PreAuth.Record.ID, now.Add(time.Second), maximum)
		}()
	}
	wait.Wait()
	close(results)
	successes, rejected := 0, 0
	for reserveErr := range results {
		switch {
		case reserveErr == nil:
			successes++
		case errors.Is(reserveErr, session.ErrConsumed):
			rejected++
		default:
			t.Fatalf("ReservePreAuthAttempt() error = %v", reserveErr)
		}
	}
	if successes != int(maximum) || rejected != 32-int(maximum) {
		t.Fatalf("concurrent attempt reservations successes=%d rejected=%d", successes, rejected)
	}
	record, err := store.FindPreAuth(ctx, session.HashToken(begin.PreAuth.Token))
	if err != nil || record.AttemptCount != maximum {
		t.Fatalf("stored attempt count = %d error=%v, want %d", record.AttemptCount, err, maximum)
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
