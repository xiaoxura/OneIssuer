package postgres_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/admin"
	"github.com/oneissuer/oneissuer/internal/authflow"
	"github.com/oneissuer/oneissuer/internal/authn"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/config"
	"github.com/oneissuer/oneissuer/internal/httpserver"
	"github.com/oneissuer/oneissuer/internal/identity"
	"github.com/oneissuer/oneissuer/internal/observability"
	"github.com/oneissuer/oneissuer/internal/session"
	"github.com/oneissuer/oneissuer/internal/storage/postgres"
)

var hiddenInputPattern = regexp.MustCompile(`name="(csrf_token|transaction)" value="([^"]+)"`)

type phaseTwoServices struct {
	identities   *identity.Service
	clients      *clientdomain.Service
	transactions *authflow.Service
	authn        *authn.Service
	sessions     *session.Service
	admin        *admin.Service
	cookies      session.CookieManager
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
	return phaseTwoServices{
		identities: identities, clients: clients, transactions: transactions,
		authn:    authn.NewService(store, identities, tokens, transactions, clients, true, metrics),
		sessions: session.NewService(store, tokens, metrics),
		admin:    admin.NewService(store, identities, clients, 15*time.Minute),
		cookies:  session.NewCookieManager("oneissuer_session", false, 24*time.Hour, 15*time.Minute),
	}
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
