package postgres_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/oneissuer/oneissuer/internal/admin"
	"github.com/oneissuer/oneissuer/internal/audit"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/consent"
	"github.com/oneissuer/oneissuer/internal/identity"
	logoutdomain "github.com/oneissuer/oneissuer/internal/logout"
	"github.com/oneissuer/oneissuer/internal/session"
	"github.com/oneissuer/oneissuer/internal/storage/postgres"
	tokendomain "github.com/oneissuer/oneissuer/internal/token"
	productionmigrations "github.com/oneissuer/oneissuer/migrations"
	"github.com/testcontainers/testcontainers-go"
)

// TestProjectReviewFaultInjectionMatrix exercises every reviewed transaction
// boundary against a real PostgreSQL instance. Each fault is installed only on
// the fixture row for that subtest, and every failed operation is retried after
// the trigger has been removed.
func TestProjectReviewFaultInjectionMatrixIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PostgreSQL fault-injection integration test in short mode")
	}
	testcontainers.SkipIfProviderIsNotHealthy(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	container, databaseURL := startPostgres(ctx, t)
	defer func() {
		terminateCtx, terminateCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer terminateCancel()
		if err := testcontainers.TerminateContainer(container, testcontainers.StopContext(terminateCtx)); err != nil {
			t.Errorf("terminate PostgreSQL container: %v", err)
		}
	}()

	database := openSQLDatabase(ctx, t, databaseURL)
	defer func() { _ = database.Close() }()
	if err := postgres.MigrateUp(ctx, database, productionmigrations.FS, "."); err != nil {
		t.Fatalf("production migrations: %v", err)
	}
	store, err := postgres.Open(ctx, databaseURL, 8)
	if err != nil {
		t.Fatalf("postgres.Open: %v", err)
	}
	defer store.Close()

	t.Run("refresh signer failure rolls back and retry succeeds", func(t *testing.T) {
		fixture := projectReviewFaultInsertFixture(ctx, t, database, "refresh-signer")
		before := projectReviewFaultReadState(ctx, t, database, fixture)
		clientValue, err := store.GetClient(ctx, fixture.clientID)
		if err != nil {
			t.Fatalf("get refresh client: %v", err)
		}
		keys := &projectReviewFaultKeyStore{fail: true}
		service, err := tokendomain.NewService(
			store, keys, bytes.NewReader(bytes.Repeat([]byte{0x23}, 4096)),
			"https://issuer.example.test", 5*time.Minute, 10*time.Minute, 0, nil,
		)
		if err != nil {
			t.Fatalf("new token service: %v", err)
		}
		input := tokendomain.RefreshInput{
			TokenHash: fixture.refreshHash, Client: clientValue,
			RequestID: "project-review-fault-refresh-signer", Now: fixture.now.Add(time.Minute),
		}
		response, err := service.Refresh(ctx, input)
		if err == nil || !strings.Contains(err.Error(), "signing") {
			t.Fatalf("signer fault response=%+v error=%v, want safe signing error", response, err)
		}
		if response != (tokendomain.Response{}) || response.RefreshToken != "" {
			t.Fatalf("signer fault returned clear response: %+v", response)
		}
		after := projectReviewFaultReadState(ctx, t, database, fixture)
		projectReviewFaultAssertSame(t, before, after, "refresh signer rollback")
		if count := projectReviewFaultAuditCount(ctx, t, database, input.RequestID); count != 0 {
			t.Fatalf("signer fault audit rows=%d, want none", count)
		}

		keys.fail = false
		response, err = service.Refresh(ctx, input)
		if err != nil || response.AccessToken == "" || response.RefreshToken == "" {
			t.Fatalf("refresh retry response=%+v error=%v, want committed tokens", response, err)
		}
		projectReviewFaultAssertRefreshCommitted(ctx, t, database, fixture)
		if count := projectReviewFaultAuditCount(ctx, t, database, input.RequestID); count != 2 {
			t.Fatalf("signer retry audit rows=%d, want two", count)
		}
	})

	t.Run("refresh audit insert failure rolls back rotation and retry succeeds", func(t *testing.T) {
		fixture := projectReviewFaultInsertFixture(ctx, t, database, "refresh-audit")
		before := projectReviewFaultReadState(ctx, t, database, fixture)
		requestID := "project-review-fault-refresh-audit"
		cleanup := projectReviewFaultInstallTrigger(t, database, "audit_events", "BEFORE INSERT", "refresh audit", fmt.Sprintf("NEW.event_type = 'refresh_token_rotated' AND NEW.request_id = '%s'", requestID))
		input := tokendomain.RefreshInput{
			TokenHash: fixture.refreshHash, Client: projectReviewFaultClient(fixture),
			RequestID: requestID, Now: fixture.now.Add(time.Minute),
		}
		mint := projectReviewFaultMintFunc("refresh-audit-fault", input.Now)
		response, err := store.ExchangeRefreshToken(ctx, input, mint)
		projectReviewFaultAssertInjectedError(t, err, "refresh audit")
		if err == nil || postgres.ErrorClass(err) != string(postgres.ErrorKindQuery) {
			t.Fatalf("refresh audit fault response=%+v error=%v class=%q", response, err, postgres.ErrorClass(err))
		}
		if response != (tokendomain.Response{}) || response.RefreshToken != "" || strings.Contains(err.Error(), "refresh audit") {
			t.Fatalf("refresh audit fault leaked response/error: response=%+v error=%v", response, err)
		}
		projectReviewFaultAssertSame(t, before, projectReviewFaultReadState(ctx, t, database, fixture), "refresh audit rollback")
		if count := projectReviewFaultAuditCount(ctx, t, database, requestID); count != 0 {
			t.Fatalf("refresh audit fault rows=%d, want none", count)
		}
		if err := cleanup(); err != nil {
			t.Fatalf("remove refresh audit fault: %v", err)
		}

		response, err = store.ExchangeRefreshToken(ctx, input, projectReviewFaultMintFunc("refresh-audit-retry", input.Now))
		if err != nil || response.AccessToken == "" || response.RefreshToken == "" {
			t.Fatalf("refresh audit retry response=%+v error=%v", response, err)
		}
		projectReviewFaultAssertRefreshCommitted(ctx, t, database, fixture)
		if count := projectReviewFaultAuditCount(ctx, t, database, requestID); count != 2 {
			t.Fatalf("refresh audit retry rows=%d, want two", count)
		}
	})

	t.Run("grant revoke mid-cascade failure rolls back and retry succeeds", func(t *testing.T) {
		fixture := projectReviewFaultInsertFixture(ctx, t, database, "grant-mid")
		before := projectReviewFaultReadState(ctx, t, database, fixture)
		requestID := "project-review-fault-grant-mid"
		cleanup := projectReviewFaultInstallTrigger(t, database, "access_tokens", "BEFORE UPDATE OF revoked_at", "grant mid-cascade", fmt.Sprintf("NEW.id = '%s'::uuid", fixture.accessID))
		result, err := store.RevokeCurrentUserGrant(ctx, consent.RevokeInput{UserID: fixture.userID, PublicClientID: fixture.publicClientID, RequestID: requestID, Now: fixture.now.Add(time.Minute)})
		projectReviewFaultAssertInjectedError(t, err, "grant mid-cascade")
		if err == nil || !reflect.DeepEqual(result, consent.ManagedGrant{}) || postgres.ErrorClass(err) != string(postgres.ErrorKindQuery) {
			t.Fatalf("grant mid fault result=%+v error=%v class=%q", result, err, postgres.ErrorClass(err))
		}
		projectReviewFaultAssertSame(t, before, projectReviewFaultReadState(ctx, t, database, fixture), "grant mid rollback")
		if count := projectReviewFaultAuditCount(ctx, t, database, requestID); count != 0 {
			t.Fatalf("grant mid audit rows=%d, want none", count)
		}
		if err := cleanup(); err != nil {
			t.Fatalf("remove grant mid fault: %v", err)
		}
		result, err = store.RevokeCurrentUserGrant(ctx, consent.RevokeInput{UserID: fixture.userID, PublicClientID: fixture.publicClientID, RequestID: requestID + "-retry", Now: fixture.now.Add(time.Minute)})
		if err != nil || result.RevokedAt == nil {
			t.Fatalf("grant mid retry result=%+v error=%v", result, err)
		}
		projectReviewFaultAssertCascadeCommitted(ctx, t, database, fixture, "grant_revoked")
		if count := projectReviewFaultAuditCount(ctx, t, database, requestID+"-retry"); count != 1 {
			t.Fatalf("grant mid retry audit rows=%d, want one", count)
		}
	})

	t.Run("grant revoke audit failure rolls back and retry succeeds", func(t *testing.T) {
		fixture := projectReviewFaultInsertFixture(ctx, t, database, "grant-audit")
		before := projectReviewFaultReadState(ctx, t, database, fixture)
		requestID := "project-review-fault-grant-audit"
		cleanup := projectReviewFaultInstallTrigger(t, database, "audit_events", "BEFORE INSERT", "grant audit", fmt.Sprintf("NEW.event_type = 'consent_grant_revoked' AND NEW.request_id = '%s'", requestID))
		result, err := store.RevokeCurrentUserGrant(ctx, consent.RevokeInput{UserID: fixture.userID, PublicClientID: fixture.publicClientID, RequestID: requestID, Now: fixture.now.Add(time.Minute)})
		projectReviewFaultAssertInjectedError(t, err, "grant audit")
		if err == nil || !reflect.DeepEqual(result, consent.ManagedGrant{}) || postgres.ErrorClass(err) != string(postgres.ErrorKindQuery) {
			t.Fatalf("grant audit fault result=%+v error=%v class=%q", result, err, postgres.ErrorClass(err))
		}
		projectReviewFaultAssertSame(t, before, projectReviewFaultReadState(ctx, t, database, fixture), "grant audit rollback")
		if count := projectReviewFaultAuditCount(ctx, t, database, requestID); count != 0 {
			t.Fatalf("grant audit fault rows=%d, want none", count)
		}
		if err := cleanup(); err != nil {
			t.Fatalf("remove grant audit fault: %v", err)
		}
		result, err = store.RevokeCurrentUserGrant(ctx, consent.RevokeInput{UserID: fixture.userID, PublicClientID: fixture.publicClientID, RequestID: requestID + "-retry", Now: fixture.now.Add(time.Minute)})
		if err != nil || result.RevokedAt == nil {
			t.Fatalf("grant audit retry result=%+v error=%v", result, err)
		}
		projectReviewFaultAssertCascadeCommitted(ctx, t, database, fixture, "grant_revoked")
		if count := projectReviewFaultAuditCount(ctx, t, database, requestID+"-retry"); count != 1 {
			t.Fatalf("grant audit retry rows=%d, want one", count)
		}
	})

	t.Run("client disable mid-cascade failure rolls back and retry succeeds", func(t *testing.T) {
		fixture := projectReviewFaultInsertFixture(ctx, t, database, "client-mid")
		before := projectReviewFaultReadState(ctx, t, database, fixture)
		clientValue := projectReviewFaultClient(fixture)
		clientValue.Status = clientdomain.StatusDisabled
		clientValue.UpdatedAt = fixture.now.Add(time.Minute)
		requestID := "project-review-fault-client-mid"
		event := projectReviewFaultStatusAuditEvent(t, audit.ClientDisabled, fixture.userID, audit.TargetClient, fixture.clientID, requestID, clientValue.UpdatedAt)
		cleanup := projectReviewFaultInstallTrigger(t, database, "access_tokens", "BEFORE UPDATE OF revoked_at", "client mid-cascade", fmt.Sprintf("NEW.id = '%s'::uuid", fixture.accessID))
		err := store.UpdateClient(ctx, clientValue, event)
		projectReviewFaultAssertInjectedError(t, err, "client mid-cascade")
		if err == nil || postgres.ErrorClass(err) != string(postgres.ErrorKindQuery) {
			t.Fatalf("client mid fault error=%v class=%q", err, postgres.ErrorClass(err))
		}
		projectReviewFaultAssertSame(t, before, projectReviewFaultReadState(ctx, t, database, fixture), "client mid rollback")
		if count := projectReviewFaultAuditCount(ctx, t, database, requestID); count != 0 {
			t.Fatalf("client mid audit rows=%d, want none", count)
		}
		if err := cleanup(); err != nil {
			t.Fatalf("remove client mid fault: %v", err)
		}
		if err := store.UpdateClient(ctx, clientValue, event); err != nil {
			t.Fatalf("client mid retry: %v", err)
		}
		projectReviewFaultAssertCascadeCommitted(ctx, t, database, fixture, "client_disabled")
		if count := projectReviewFaultAuditCount(ctx, t, database, requestID); count != 1 {
			t.Fatalf("client mid retry audit rows=%d, want one", count)
		}
		clientAfter, err := store.GetClient(ctx, fixture.clientID)
		if err != nil || clientAfter.Status != clientdomain.StatusDisabled || clientAfter.Version != before.clientVersion+1 {
			t.Fatalf("client retry state=%+v error=%v", clientAfter, err)
		}
	})

	t.Run("client disable audit failure rolls back and retry succeeds", func(t *testing.T) {
		fixture := projectReviewFaultInsertFixture(ctx, t, database, "client-audit")
		before := projectReviewFaultReadState(ctx, t, database, fixture)
		clientValue := projectReviewFaultClient(fixture)
		clientValue.Status = clientdomain.StatusDisabled
		clientValue.UpdatedAt = fixture.now.Add(time.Minute)
		requestID := "project-review-fault-client-audit"
		event := projectReviewFaultStatusAuditEvent(t, audit.ClientDisabled, fixture.userID, audit.TargetClient, fixture.clientID, requestID, clientValue.UpdatedAt)
		cleanup := projectReviewFaultInstallTrigger(t, database, "audit_events", "BEFORE INSERT", "client audit", fmt.Sprintf("NEW.event_type = 'client_disabled' AND NEW.request_id = '%s'", requestID))
		err := store.UpdateClient(ctx, clientValue, event)
		projectReviewFaultAssertInjectedError(t, err, "client audit")
		if err == nil || postgres.ErrorClass(err) != string(postgres.ErrorKindQuery) {
			t.Fatalf("client audit fault error=%v class=%q", err, postgres.ErrorClass(err))
		}
		projectReviewFaultAssertSame(t, before, projectReviewFaultReadState(ctx, t, database, fixture), "client audit rollback")
		if count := projectReviewFaultAuditCount(ctx, t, database, requestID); count != 0 {
			t.Fatalf("client audit fault rows=%d, want none", count)
		}
		if err := cleanup(); err != nil {
			t.Fatalf("remove client audit fault: %v", err)
		}
		if err := store.UpdateClient(ctx, clientValue, event); err != nil {
			t.Fatalf("client audit retry: %v", err)
		}
		projectReviewFaultAssertCascadeCommitted(ctx, t, database, fixture, "client_disabled")
		if count := projectReviewFaultAuditCount(ctx, t, database, requestID); count != 1 {
			t.Fatalf("client audit retry rows=%d, want one", count)
		}
	})

	t.Run("user disable mid-cascade failure rolls back and retry succeeds", func(t *testing.T) {
		fixture := projectReviewFaultInsertFixture(ctx, t, database, "user-mid")
		before := projectReviewFaultReadState(ctx, t, database, fixture)
		commit, requestID := projectReviewFaultUserDisableCommit(t, fixture, "user-mid")
		cleanup := projectReviewFaultInstallTrigger(t, database, "access_tokens", "BEFORE UPDATE OF revoked_at", "user mid-cascade", fmt.Sprintf("NEW.id = '%s'::uuid", fixture.accessID))
		result, err := store.UpdateManagedUser(ctx, commit)
		projectReviewFaultAssertInjectedError(t, err, "user mid-cascade")
		if err == nil || result != (identity.User{}) || postgres.ErrorClass(err) != string(postgres.ErrorKindQuery) {
			t.Fatalf("user mid fault result=%+v error=%v class=%q", result, err, postgres.ErrorClass(err))
		}
		projectReviewFaultAssertSame(t, before, projectReviewFaultReadState(ctx, t, database, fixture), "user mid rollback")
		if count := projectReviewFaultAuditCount(ctx, t, database, requestID); count != 0 {
			t.Fatalf("user mid audit rows=%d, want none", count)
		}
		if err := cleanup(); err != nil {
			t.Fatalf("remove user mid fault: %v", err)
		}
		result, err = store.UpdateManagedUser(ctx, commit)
		if err != nil || result.Status != identity.StatusDisabled {
			t.Fatalf("user mid retry result=%+v error=%v", result, err)
		}
		projectReviewFaultAssertCascadeCommitted(ctx, t, database, fixture, "user_disabled")
		if count := projectReviewFaultAuditCount(ctx, t, database, requestID); count != 2 {
			t.Fatalf("user mid retry audit rows=%d, want two", count)
		}
		userAfter, err := store.GetUser(ctx, fixture.userID)
		if err != nil || userAfter.Status != identity.StatusDisabled || userAfter.Version != before.userVersion+1 {
			t.Fatalf("user retry state=%+v error=%v", userAfter, err)
		}
	})

	t.Run("user disable audit failure rolls back and retry succeeds", func(t *testing.T) {
		fixture := projectReviewFaultInsertFixture(ctx, t, database, "user-audit")
		before := projectReviewFaultReadState(ctx, t, database, fixture)
		commit, requestID := projectReviewFaultUserDisableCommit(t, fixture, "user-audit")
		cleanup := projectReviewFaultInstallTrigger(t, database, "audit_events", "BEFORE INSERT", "user audit", fmt.Sprintf("NEW.event_type = 'user_status_changed' AND NEW.request_id = '%s'", requestID))
		result, err := store.UpdateManagedUser(ctx, commit)
		projectReviewFaultAssertInjectedError(t, err, "user audit")
		if err == nil || result != (identity.User{}) || postgres.ErrorClass(err) != string(postgres.ErrorKindQuery) {
			t.Fatalf("user audit fault result=%+v error=%v class=%q", result, err, postgres.ErrorClass(err))
		}
		projectReviewFaultAssertSame(t, before, projectReviewFaultReadState(ctx, t, database, fixture), "user audit rollback")
		if count := projectReviewFaultAuditCount(ctx, t, database, requestID); count != 0 {
			t.Fatalf("user audit fault rows=%d, want none", count)
		}
		if err := cleanup(); err != nil {
			t.Fatalf("remove user audit fault: %v", err)
		}
		result, err = store.UpdateManagedUser(ctx, commit)
		if err != nil || result.Status != identity.StatusDisabled {
			t.Fatalf("user audit retry result=%+v error=%v", result, err)
		}
		projectReviewFaultAssertCascadeCommitted(ctx, t, database, fixture, "user_disabled")
		if count := projectReviewFaultAuditCount(ctx, t, database, requestID); count != 2 {
			t.Fatalf("user audit retry rows=%d, want two", count)
		}
	})

	t.Run("RP logout bind transaction insert failure leaves no transaction and retry succeeds", func(t *testing.T) {
		fixture := projectReviewFaultInsertFixture(ctx, t, database, "logout-insert")
		transaction := projectReviewFaultLogoutTransaction(fixture)
		cleanup := projectReviewFaultInstallTrigger(t, database, "logout_transactions", "BEFORE INSERT", "logout bind insert", fmt.Sprintf("NEW.id = '%s'::uuid", transaction.ID))
		err := store.CreateLogoutTransaction(ctx, transaction)
		projectReviewFaultAssertInjectedError(t, err, "logout bind insert")
		if err == nil || postgres.ErrorClass(err) != string(postgres.ErrorKindQuery) {
			t.Fatalf("logout insert fault error=%v class=%q", err, postgres.ErrorClass(err))
		}
		projectReviewFaultAssertLogoutAbsent(ctx, t, database, transaction.ID)
		if err := cleanup(); err != nil {
			t.Fatalf("remove logout insert fault: %v", err)
		}
		if err := store.CreateLogoutTransaction(ctx, transaction); err != nil {
			t.Fatalf("logout insert retry: %v", err)
		}
		projectReviewFaultAssertLogoutStage(ctx, t, database, transaction.ID, string(logoutdomain.StagePreConfirm), false)
	})

	t.Run("RP logout bind update failure leaves pre-confirm state and retry succeeds", func(t *testing.T) {
		fixture := projectReviewFaultInsertFixture(ctx, t, database, "logout-bind")
		transaction := projectReviewFaultLogoutTransaction(fixture)
		if err := store.CreateLogoutTransaction(ctx, transaction); err != nil {
			t.Fatalf("create logout bind fixture: %v", err)
		}
		cleanup := projectReviewFaultInstallTrigger(t, database, "logout_transactions", "BEFORE UPDATE OF stage", "logout bind update", fmt.Sprintf("NEW.id = '%s'::uuid", transaction.ID))
		input := logoutdomain.BindInput{
			LookupHash: transaction.LookupHash, CSRFHash: projectReviewFaultHash("logout-csrf"),
			UserID: fixture.userID, SessionID: fixture.sessionID, SessionBindingID: fixture.bindingID,
			Subject: "project-review-fault-subject", Now: fixture.now.Add(time.Minute), MaxActive: 1, MaxAttempts: 10,
		}
		bound, err := store.BindLogoutTransaction(ctx, input)
		projectReviewFaultAssertInjectedError(t, err, "logout bind update")
		if err == nil || !reflect.DeepEqual(bound, logoutdomain.Transaction{}) || postgres.ErrorClass(err) != string(postgres.ErrorKindQuery) {
			t.Fatalf("logout bind fault bound=%+v error=%v class=%q", bound, err, postgres.ErrorClass(err))
		}
		projectReviewFaultAssertLogoutStage(ctx, t, database, transaction.ID, string(logoutdomain.StagePreConfirm), false)
		if err := cleanup(); err != nil {
			t.Fatalf("remove logout bind fault: %v", err)
		}
		bound, err = store.BindLogoutTransaction(ctx, input)
		if err != nil || bound.Stage != logoutdomain.StageBoundConfirm {
			t.Fatalf("logout bind retry bound=%+v error=%v", bound, err)
		}
	})

	t.Run("RP logout complete audit failure rolls back authority and retry succeeds", func(t *testing.T) {
		fixture := projectReviewFaultInsertFixture(ctx, t, database, "logout-audit")
		transaction := projectReviewFaultLogoutTransaction(fixture)
		if err := store.CreateLogoutTransaction(ctx, transaction); err != nil {
			t.Fatalf("create logout audit fixture: %v", err)
		}
		bound, err := store.BindLogoutTransaction(ctx, logoutdomain.BindInput{
			LookupHash: transaction.LookupHash, CSRFHash: projectReviewFaultHash("logout-audit-csrf"),
			UserID: fixture.userID, SessionID: fixture.sessionID, SessionBindingID: fixture.bindingID,
			Subject: "project-review-fault-subject", Now: fixture.now.Add(time.Minute), MaxActive: 1, MaxAttempts: 10,
		})
		if err != nil {
			t.Fatalf("bind logout audit fixture: %v", err)
		}
		before := projectReviewFaultReadState(ctx, t, database, fixture)
		requestID := "project-review-fault-logout-audit"
		cleanup := projectReviewFaultInstallTrigger(t, database, "audit_events", "BEFORE INSERT", "logout complete audit", fmt.Sprintf("NEW.event_type = 'rp_logout_completed' AND NEW.request_id = '%s'", requestID))
		completeInput := logoutdomain.CompleteInput{
			LookupHash: transaction.LookupHash, CSRFHash: bound.CSRFHash, Decision: logoutdomain.DecisionConfirm,
			UserID: fixture.userID, SessionID: fixture.sessionID, SessionBindingID: fixture.bindingID,
			Now: fixture.now.Add(time.Minute), RequestID: requestID, MaxAttempts: 10,
		}
		candidate, err := store.CompleteLogoutTransaction(ctx, completeInput)
		projectReviewFaultAssertInjectedError(t, err, "logout complete audit")
		if err == nil || candidate != (logoutdomain.CompletionCandidate{}) || postgres.ErrorClass(err) != string(postgres.ErrorKindQuery) {
			t.Fatalf("logout audit fault candidate=%+v error=%v class=%q", candidate, err, postgres.ErrorClass(err))
		}
		projectReviewFaultAssertSame(t, before, projectReviewFaultReadState(ctx, t, database, fixture), "logout audit rollback")
		projectReviewFaultAssertLogoutStage(ctx, t, database, transaction.ID, string(logoutdomain.StageBoundConfirm), false)
		if count := projectReviewFaultAuditCount(ctx, t, database, requestID); count != 0 {
			t.Fatalf("logout audit fault rows=%d, want none", count)
		}
		if err := cleanup(); err != nil {
			t.Fatalf("remove logout audit fault: %v", err)
		}
		candidate, err = store.CompleteLogoutTransaction(ctx, completeInput)
		if err != nil || !candidate.Confirmed {
			t.Fatalf("logout audit retry candidate=%+v error=%v", candidate, err)
		}
		projectReviewFaultAssertLogoutStage(ctx, t, database, transaction.ID, string(logoutdomain.StageConfirmed), true)
		projectReviewFaultAssertCascadeCommitted(ctx, t, database, fixture, "session_revoked")
		if count := projectReviewFaultAuditCount(ctx, t, database, requestID); count != 2 {
			t.Fatalf("logout audit retry rows=%d, want two", count)
		}
	})

	t.Run("RP logout deferred commit failure clears candidate and is retryable", func(t *testing.T) {
		fixture := projectReviewFaultInsertFixture(ctx, t, database, "logout-commit")
		transaction := projectReviewFaultLogoutTransaction(fixture)
		if err := store.CreateLogoutTransaction(ctx, transaction); err != nil {
			t.Fatalf("create logout commit fixture: %v", err)
		}
		bound, err := store.BindLogoutTransaction(ctx, logoutdomain.BindInput{
			LookupHash: transaction.LookupHash, CSRFHash: projectReviewFaultHash("logout-commit-csrf"),
			UserID: fixture.userID, SessionID: fixture.sessionID, SessionBindingID: fixture.bindingID,
			Subject: "project-review-fault-subject", Now: fixture.now.Add(time.Minute), MaxActive: 1, MaxAttempts: 10,
		})
		if err != nil {
			t.Fatalf("bind logout commit fixture: %v", err)
		}
		before := projectReviewFaultReadState(ctx, t, database, fixture)
		cleanup := projectReviewFaultInstallDeferredTrigger(t, database, transaction.ID)
		completeInput := logoutdomain.CompleteInput{
			LookupHash: transaction.LookupHash, CSRFHash: bound.CSRFHash, Decision: logoutdomain.DecisionConfirm,
			UserID: fixture.userID, SessionID: fixture.sessionID, SessionBindingID: fixture.bindingID,
			Now: fixture.now.Add(time.Minute), RequestID: "project-review-fault-logout-commit", MaxAttempts: 10,
		}
		candidate, err := store.CompleteLogoutTransaction(ctx, completeInput)
		projectReviewFaultAssertInjectedError(t, err, "deferred logout commit failure")
		if err == nil || candidate != (logoutdomain.CompletionCandidate{}) || postgres.ErrorClass(err) != string(postgres.ErrorKindQuery) {
			t.Fatalf("logout commit fault candidate=%+v error=%v class=%q", candidate, err, postgres.ErrorClass(err))
		}
		projectReviewFaultAssertSame(t, before, projectReviewFaultReadState(ctx, t, database, fixture), "logout commit rollback")
		projectReviewFaultAssertLogoutStage(ctx, t, database, transaction.ID, string(logoutdomain.StageBoundConfirm), false)
		if count := projectReviewFaultAuditCount(ctx, t, database, completeInput.RequestID); count != 0 {
			t.Fatalf("logout commit fault audit rows=%d, want none", count)
		}
		if err := cleanup(); err != nil {
			t.Fatalf("remove logout commit fault: %v", err)
		}
		candidate, err = store.CompleteLogoutTransaction(ctx, completeInput)
		if err != nil || !candidate.Confirmed {
			t.Fatalf("logout commit retry candidate=%+v error=%v", candidate, err)
		}
		projectReviewFaultAssertLogoutStage(ctx, t, database, transaction.ID, string(logoutdomain.StageConfirmed), true)
		projectReviewFaultAssertCascadeCommitted(ctx, t, database, fixture, "session_revoked")
		if count := projectReviewFaultAuditCount(ctx, t, database, completeInput.RequestID); count != 2 {
			t.Fatalf("logout commit retry audit rows=%d, want two", count)
		}
	})
}

type projectReviewFaultFixture struct {
	userID, clientID, grantID, sessionID, bindingID  uuid.UUID
	familyID, refreshID, consumedRefreshID, accessID uuid.UUID
	authTransactionID, codeID                        uuid.UUID
	publicClientID                                   string
	refreshToken                                     string
	refreshHash                                      []byte
	now                                              time.Time
}

type projectReviewFaultState struct {
	userStatus         string
	userVersion        int64
	clientStatus       string
	clientVersion      int64
	clientScopes       string
	grantRevoked       bool
	grantVersion       int64
	sessionRevoked     bool
	sessionReason      string
	familyRevoked      bool
	familyReason       string
	generationConsumed bool
	accessRevoked      bool
	accessReason       string
	authConsumed       bool
	codeConsumed       bool
}

type projectReviewFaultKeyStore struct{ fail bool }

func (k *projectReviewFaultKeyStore) Sign(_ []byte, typ string) (string, error) {
	if k.fail {
		return "", errors.New("token signer unavailable")
	}
	return "signed-" + typ, nil
}

func (k *projectReviewFaultKeyStore) PublicKeys() []jose.JSONWebKey { return nil }

func projectReviewFaultInsertFixture(ctx context.Context, t *testing.T, database *sql.DB, label string) projectReviewFaultFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	fixture := projectReviewFaultFixture{
		userID: uuid.New(), clientID: uuid.New(), grantID: uuid.New(), sessionID: uuid.New(), bindingID: uuid.New(),
		familyID: uuid.New(), refreshID: uuid.New(), accessID: uuid.New(), authTransactionID: uuid.New(), codeID: uuid.New(), now: now,
	}
	fixture.consumedRefreshID = uuid.New()
	fixture.publicClientID = "ois_cli_" + strings.ReplaceAll(fixture.clientID.String(), "-", "")
	fixture.refreshToken, fixture.refreshHash = projectReviewFaultRefreshToken(label)
	userSubject := "project-review-fault-subject-" + fixture.userID.String()
	username := "project_review_fault_" + fixture.userID.String()[:8]
	email := username + "@example.invalid"
	sessionToken := "s1_" + strings.ReplaceAll(fixture.sessionID.String(), "-", "") + "AAAAAAAAAAAA"
	csrfHash := projectReviewFaultHash("csrf:" + label)
	codeHash := projectReviewFaultHash("code:" + label)
	authHash := projectReviewFaultHash("auth:" + label)
	if _, err := database.ExecContext(ctx, `INSERT INTO users
		(id, subject, username, username_normalized, display_name, email, email_normalized, status, role, created_at, updated_at)
		VALUES ($1,$2,$3,$3,$4,$5,$5,'active','user',$6,$6)`, fixture.userID, userSubject, username, "Project Review Fault", email, now); err != nil {
		t.Fatalf("insert fault user: %v", err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO oidc_clients
		(id, client_id, client_type, token_endpoint_auth_method, name, created_at, updated_at)
		VALUES ($1,$2,'public','none','Project Review Fault Client',$3,$3)`, fixture.clientID, fixture.publicClientID, now); err != nil {
		t.Fatalf("insert fault client: %v", err)
	}
	for _, scope := range []string{"offline_access", "openid", "profile"} {
		if _, err := database.ExecContext(ctx, `INSERT INTO oidc_client_scopes (client_id, scope, created_at) VALUES ($1,$2,$3)`, fixture.clientID, scope, now); err != nil {
			t.Fatalf("insert fault client scope %q: %v", scope, err)
		}
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO consent_grants
		(id, user_id, client_id, scopes, created_at, updated_at)
		VALUES ($1,$2,$3,ARRAY['offline_access','openid','profile']::text[],$4,$4)`, fixture.grantID, fixture.userID, fixture.clientID, now); err != nil {
		t.Fatalf("insert fault grant: %v", err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO login_sessions
		(id,user_id,token_hash,csrf_hash,csrf_expires_at,created_at,last_seen_at,authenticated_at,expires_at,idle_expires_at,user_agent_hash,ip_prefix,session_binding_id)
		VALUES ($1,$2,$3,$4,$5,$6,$6,$6,$7,$8,$9,$10,$11)`, fixture.sessionID, fixture.userID, session.HashToken(sessionToken), csrfHash, now.Add(time.Hour), now, now.Add(24*time.Hour), now.Add(2*time.Hour), projectReviewFaultHash("user-agent"), "192.0.2.0/24", fixture.bindingID); err != nil {
		t.Fatalf("insert fault session: %v", err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO auth_transactions
		(id,token_hash,transaction_kind,client_id,redirect_uri,scopes,pkce_challenge,pkce_method,state_value,nonce_value,prompt_create,response_type,response_mode,prompt_values,created_at,expires_at)
		VALUES ($1,$2,'authorization',$3,'https://fault.example/callback',ARRAY['openid']::text[],repeat('A',43),'S256','fault-state','fault-nonce',false,'code','query',ARRAY[]::text[],$4,$5)`, fixture.authTransactionID, authHash, fixture.clientID, now, now.Add(4*time.Minute)); err != nil {
		t.Fatalf("insert fault auth transaction: %v", err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO authorization_codes
		(id,code_hash,auth_transaction_id,consent_grant_id,user_id,client_id,redirect_uri,scopes,pkce_challenge,pkce_method,nonce_value,auth_time,created_at,expires_at,consent_grant_version,origin_session_id,session_binding_id)
		VALUES ($1,$2,$3,$4,$5,$6,'https://fault.example/callback',ARRAY['openid']::text[],repeat('A',43),'S256','fault-nonce',$7,$7,$8,1,NULL,NULL)`, fixture.codeID, codeHash, fixture.authTransactionID, fixture.grantID, fixture.userID, fixture.clientID, now, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("insert fault authorization code: %v", err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO refresh_token_families
		(id,origin_authorization_code_id,consent_grant_id,user_id,client_id,origin_session_id,session_binding_id,scopes,created_at,absolute_expires_at)
		VALUES ($1,NULL,$2,$3,$4,$5,$6,ARRAY['offline_access','openid','profile']::text[],$7,$8)`, fixture.familyID, fixture.grantID, fixture.userID, fixture.clientID, fixture.sessionID, fixture.bindingID, now, now.Add(24*time.Hour)); err != nil {
		t.Fatalf("insert fault family: %v", err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO refresh_tokens
		(id,family_id,token_hash,generation,issued_at,expires_at,consumed_at)
		VALUES ($1,$2,$3,0,$4,$5,$6)`, fixture.consumedRefreshID, fixture.familyID, projectReviewFaultHash("consumed-refresh:"+label), now, now.Add(time.Hour), now); err != nil {
		t.Fatalf("insert consumed fault refresh generation: %v", err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO refresh_tokens
		(id,family_id,token_hash,generation,issued_at,expires_at)
		VALUES ($1,$2,$3,1,$4,$5)`, fixture.refreshID, fixture.familyID, fixture.refreshHash, now, now.Add(time.Hour)); err != nil {
		t.Fatalf("insert presented fault refresh generation: %v", err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO access_tokens
		(id,jti_hash,authorization_code_id,consent_grant_id,user_id,client_id,scopes,issued_at,expires_at,issuance_source,source_refresh_token_id,refresh_family_id,origin_session_id,session_binding_id)
		VALUES ($1,$2,NULL,$3,$4,$5,ARRAY['offline_access','openid','profile']::text[],$6,$7,'refresh_token',$8,$9,$10,$11)`, fixture.accessID, projectReviewFaultHash("access:"+label), fixture.grantID, fixture.userID, fixture.clientID, now, now.Add(10*time.Minute), fixture.consumedRefreshID, fixture.familyID, fixture.sessionID, fixture.bindingID); err != nil {
		t.Fatalf("insert fault access metadata: %v", err)
	}
	return fixture
}

func projectReviewFaultRefreshToken(label string) (string, []byte) {
	seed := sha256.Sum256([]byte("project-review-fault-refresh:" + label))
	clearToken, digest, err := tokendomain.GenerateRefreshToken(bytes.NewReader(seed[:]))
	if err != nil {
		panic(err)
	}
	return clearToken, digest
}

func projectReviewFaultHash(value string) []byte {
	digest := sha256.Sum256([]byte("project-review-fault:" + value))
	return digest[:]
}

func projectReviewFaultClient(fixture projectReviewFaultFixture) clientdomain.Client {
	return clientdomain.Client{
		ID: fixture.clientID, ClientID: fixture.publicClientID, Type: clientdomain.TypePublic,
		TokenEndpointAuthMethod: clientdomain.AuthMethodNone, Status: clientdomain.StatusActive,
		Name: "Project Review Fault Client", Scopes: []string{"offline_access", "openid", "profile"},
		CreatedAt: fixture.now, UpdatedAt: fixture.now, Version: 1,
	}
}

func projectReviewFaultMintFunc(label string, now time.Time) tokendomain.RefreshMintFunc {
	return func(_ context.Context, _ tokendomain.RefreshAuthority) (tokendomain.RefreshMinted, error) {
		clearToken, hash := projectReviewFaultRefreshToken(label)
		jti := projectReviewFaultHash("jti:" + label)
		return tokendomain.RefreshMinted{
			AccessTokenID: uuid.New(), JTIHash: jti, AccessToken: "at_" + label,
			IssuedAt: now.UTC(), AccessExpiresAt: now.UTC().Add(10 * time.Minute),
			ReplacementTokenID: uuid.New(), ReplacementTokenHash: hash, ReplacementClearToken: clearToken,
			ReplacementExpiresAt: now.UTC().Add(time.Hour),
		}, nil
	}
}

func projectReviewFaultReadState(ctx context.Context, t *testing.T, database *sql.DB, fixture projectReviewFaultFixture) projectReviewFaultState {
	t.Helper()
	var state projectReviewFaultState
	if err := database.QueryRowContext(ctx, `SELECT status, version FROM users WHERE id=$1`, fixture.userID).Scan(&state.userStatus, &state.userVersion); err != nil {
		t.Fatalf("read fault user state: %v", err)
	}
	if err := database.QueryRowContext(ctx, `SELECT status, version, array_to_string((SELECT array_agg(scope ORDER BY scope) FROM oidc_client_scopes WHERE client_id=$1), ',') FROM oidc_clients WHERE id=$1`, fixture.clientID).Scan(&state.clientStatus, &state.clientVersion, &state.clientScopes); err != nil {
		t.Fatalf("read fault client state: %v", err)
	}
	var grantRevoked sql.NullTime
	if err := database.QueryRowContext(ctx, `SELECT revoked_at, version FROM consent_grants WHERE id=$1`, fixture.grantID).Scan(&grantRevoked, &state.grantVersion); err != nil {
		t.Fatalf("read fault grant state: %v", err)
	}
	state.grantRevoked = grantRevoked.Valid
	var sessionRevoked sql.NullTime
	var sessionReason sql.NullString
	if err := database.QueryRowContext(ctx, `SELECT revoked_at, revoke_reason FROM login_sessions WHERE id=$1`, fixture.sessionID).Scan(&sessionRevoked, &sessionReason); err != nil {
		t.Fatalf("read fault session state: %v", err)
	}
	state.sessionRevoked, state.sessionReason = sessionRevoked.Valid, sessionReason.String
	var familyRevoked sql.NullTime
	var familyReason sql.NullString
	if err := database.QueryRowContext(ctx, `SELECT revoked_at, revoke_reason FROM refresh_token_families WHERE id=$1`, fixture.familyID).Scan(&familyRevoked, &familyReason); err != nil {
		t.Fatalf("read fault family state: %v", err)
	}
	state.familyRevoked, state.familyReason = familyRevoked.Valid, familyReason.String
	var generationConsumed sql.NullTime
	if err := database.QueryRowContext(ctx, `SELECT consumed_at FROM refresh_tokens WHERE id=$1`, fixture.refreshID).Scan(&generationConsumed); err != nil {
		t.Fatalf("read fault refresh state: %v", err)
	}
	state.generationConsumed = generationConsumed.Valid
	var accessRevoked sql.NullTime
	var accessReason sql.NullString
	if err := database.QueryRowContext(ctx, `SELECT revoked_at, revoke_reason FROM access_tokens WHERE id=$1`, fixture.accessID).Scan(&accessRevoked, &accessReason); err != nil {
		t.Fatalf("read fault access state: %v", err)
	}
	state.accessRevoked, state.accessReason = accessRevoked.Valid, accessReason.String
	var authConsumed, codeConsumed sql.NullTime
	if err := database.QueryRowContext(ctx, `SELECT consumed_at FROM auth_transactions WHERE id=$1`, fixture.authTransactionID).Scan(&authConsumed); err != nil {
		t.Fatalf("read fault auth transaction state: %v", err)
	}
	if err := database.QueryRowContext(ctx, `SELECT consumed_at FROM authorization_codes WHERE id=$1`, fixture.codeID).Scan(&codeConsumed); err != nil {
		t.Fatalf("read fault code state: %v", err)
	}
	state.authConsumed, state.codeConsumed = authConsumed.Valid, codeConsumed.Valid
	return state
}

func projectReviewFaultAssertSame(t *testing.T, want, got projectReviewFaultState, label string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s state changed: before=%+v after=%+v", label, want, got)
	}
}

func projectReviewFaultAssertRefreshCommitted(ctx context.Context, t *testing.T, database *sql.DB, fixture projectReviewFaultFixture) {
	t.Helper()
	var consumed bool
	var generations, accesses int
	if err := database.QueryRowContext(ctx, `SELECT consumed_at IS NOT NULL FROM refresh_tokens WHERE id=$1`, fixture.refreshID).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*)::int FROM refresh_tokens WHERE family_id=$1`, fixture.familyID).Scan(&generations); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*)::int FROM access_tokens WHERE refresh_family_id=$1`, fixture.familyID).Scan(&accesses); err != nil {
		t.Fatal(err)
	}
	if !consumed || generations != 3 || accesses != 2 {
		t.Fatalf("refresh committed consumed=%v generations=%d accesses=%d, want true/3/2", consumed, generations, accesses)
	}
}

func projectReviewFaultAssertCascadeCommitted(ctx context.Context, t *testing.T, database *sql.DB, fixture projectReviewFaultFixture, reason string) {
	t.Helper()
	var familyReason, accessReason, sessionReason sql.NullString
	var grantRevoked, familyRevoked, accessRevoked, sessionRevoked sql.NullTime
	if err := database.QueryRowContext(ctx, `SELECT revoked_at FROM consent_grants WHERE id=$1`, fixture.grantID).Scan(&grantRevoked); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT revoked_at,revoke_reason FROM refresh_token_families WHERE id=$1`, fixture.familyID).Scan(&familyRevoked, &familyReason); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT revoked_at,revoke_reason FROM access_tokens WHERE id=$1`, fixture.accessID).Scan(&accessRevoked, &accessReason); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT revoked_at,revoke_reason FROM login_sessions WHERE id=$1`, fixture.sessionID).Scan(&sessionRevoked, &sessionReason); err != nil {
		t.Fatal(err)
	}
	if !familyRevoked.Valid || familyReason.String != reason || !accessRevoked.Valid || accessReason.String != reason {
		t.Fatalf("cascade family=%v/%q access=%v/%q, want revoked/%q", familyRevoked.Valid, familyReason.String, accessRevoked.Valid, accessReason.String, reason)
	}
	if reason == "grant_revoked" && !grantRevoked.Valid {
		t.Fatal("grant cascade left consent grant active")
	}
	if reason != "grant_revoked" && grantRevoked.Valid {
		t.Fatalf("cascade unexpectedly revoked consent grant for reason %q", reason)
	}
	if reason == "client_disabled" {
		var status string
		if err := database.QueryRowContext(ctx, `SELECT status FROM oidc_clients WHERE id=$1`, fixture.clientID).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status != string(clientdomain.StatusDisabled) {
			t.Fatalf("client cascade status=%q, want disabled", status)
		}
	}
	if reason == "user_disabled" {
		var status string
		if err := database.QueryRowContext(ctx, `SELECT status FROM users WHERE id=$1`, fixture.userID).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status != string(identity.StatusDisabled) {
			t.Fatalf("user cascade status=%q, want disabled", status)
		}
	}
	if reason == "session_revoked" || reason == "user_disabled" {
		if !sessionRevoked.Valid || sessionReason.String == "" {
			t.Fatalf("cascade session=%v/%q, want revoked", sessionRevoked.Valid, sessionReason.String)
		}
	} else if sessionRevoked.Valid || sessionReason.String != "" {
		t.Fatalf("cascade unexpectedly changed session=%v/%q for reason %q", sessionRevoked.Valid, sessionReason.String, reason)
	}
}

func projectReviewFaultAuditEvent(t *testing.T, eventType audit.EventType, actor uuid.UUID, targetType audit.TargetType, target uuid.UUID, requestID string, at time.Time) audit.Event {
	t.Helper()
	event, err := audit.New(eventType, audit.ResultSuccess, &actor, targetType, &target, requestID, []string{"revoked"}, at)
	if err != nil {
		t.Fatalf("new fault audit event: %v", err)
	}
	return event
}

func projectReviewFaultStatusAuditEvent(t *testing.T, eventType audit.EventType, actor uuid.UUID, targetType audit.TargetType, target uuid.UUID, requestID string, at time.Time) audit.Event {
	t.Helper()
	event, err := audit.New(eventType, audit.ResultSuccess, &actor, targetType, &target, requestID, []string{"status"}, at)
	if err != nil {
		t.Fatalf("new fault status audit event: %v", err)
	}
	return event
}

func projectReviewFaultUserDisableCommit(t *testing.T, fixture projectReviewFaultFixture, label string) (admin.UpdateUserCommit, string) {
	t.Helper()
	now := fixture.now.Add(time.Minute)
	requestID := "project-review-fault-user-" + label
	updated := identity.User{
		ID: fixture.userID, Subject: "project-review-fault-subject-" + fixture.userID.String(),
		Username: "project_review_fault_" + fixture.userID.String()[:8], UsernameNormalized: "project_review_fault_" + fixture.userID.String()[:8],
		DisplayName: "Project Review Fault", Email: "project_review_fault_" + fixture.userID.String()[:8] + "@example.invalid", EmailNormalized: "project_review_fault_" + fixture.userID.String()[:8] + "@example.invalid",
		Status: identity.StatusDisabled, Role: identity.RoleUser, CreatedAt: fixture.now, UpdatedAt: now, Version: 1,
	}
	event := projectReviewFaultStatusAuditEvent(t, audit.UserStatusChanged, fixture.userID, audit.TargetUser, fixture.userID, requestID, now)
	sessionEvent := projectReviewFaultAuditEvent(t, audit.SessionsRevokedAll, fixture.userID, audit.TargetUser, fixture.userID, requestID, now)
	return admin.UpdateUserCommit{Actor: fixture.userID, Updated: updated, RevokeSessions: true, Event: event, SessionEvent: &sessionEvent}, requestID
}

func projectReviewFaultLogoutTransaction(fixture projectReviewFaultFixture) logoutdomain.Transaction {
	return logoutdomain.Transaction{ID: uuid.New(), LookupHash: projectReviewFaultHash("logout-lookup:" + fixture.userID.String()), Stage: logoutdomain.StagePreConfirm, CreatedAt: fixture.now, ExpiresAt: fixture.now.Add(5 * time.Minute)}
}

func projectReviewFaultAuditCount(ctx context.Context, t *testing.T, database *sql.DB, requestID string) int {
	t.Helper()
	var count int
	if err := database.QueryRowContext(ctx, `SELECT count(*)::int FROM audit_events WHERE request_id=$1`, requestID).Scan(&count); err != nil {
		t.Fatalf("count fault audits %q: %v", requestID, err)
	}
	return count
}

func projectReviewFaultAssertInjectedError(t *testing.T, err error, message string) {
	t.Helper()
	var pgError *pgconn.PgError
	if err == nil || !errors.As(err, &pgError) || pgError.Code != "55000" || pgError.Message != message {
		t.Fatalf("fault error=%v, want PostgreSQL SQLSTATE 55000 message %q", err, message)
	}
}

func projectReviewFaultAssertLogoutAbsent(ctx context.Context, t *testing.T, database *sql.DB, id uuid.UUID) {
	t.Helper()
	var count int
	if err := database.QueryRowContext(ctx, `SELECT count(*)::int FROM logout_transactions WHERE id=$1`, id).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("failed logout insert left %d transaction rows", count)
	}
}

func projectReviewFaultAssertLogoutStage(ctx context.Context, t *testing.T, database *sql.DB, id uuid.UUID, wantStage string, wantConsumed bool) {
	t.Helper()
	var stage string
	var consumed sql.NullTime
	if err := database.QueryRowContext(ctx, `SELECT stage,consumed_at FROM logout_transactions WHERE id=$1`, id).Scan(&stage, &consumed); err != nil {
		t.Fatalf("read logout transaction %s: %v", id, err)
	}
	if stage != wantStage || consumed.Valid != wantConsumed {
		t.Fatalf("logout transaction stage=%q consumed=%v, want %q/%v", stage, consumed.Valid, wantStage, wantConsumed)
	}
}

func projectReviewFaultInstallTrigger(t *testing.T, database *sql.DB, table, operation, label, condition string) func() error {
	t.Helper()
	suffix := strings.ReplaceAll(uuid.New().String(), "-", "")[:20]
	functionName := "oneissuer_project_review_fault_fn_" + suffix
	triggerName := "oneissuer_project_review_fault_tr_" + suffix
	if _, err := database.ExecContext(context.Background(), fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF %s THEN RAISE EXCEPTION '%s' USING ERRCODE = '55000'; END IF; RETURN NEW; END $$`, functionName, condition, label)); err != nil {
		t.Fatalf("create fault function %s: %v", functionName, err)
	}
	if _, err := database.ExecContext(context.Background(), fmt.Sprintf(`CREATE TRIGGER %s %s ON %s FOR EACH ROW EXECUTE FUNCTION %s()`, triggerName, operation, table, functionName)); err != nil {
		_, _ = database.ExecContext(context.Background(), fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, functionName))
		t.Fatalf("create fault trigger %s: %v", triggerName, err)
	}
	cleanup := func() error {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var cleanupErrs []error
		if _, err := database.ExecContext(cleanupCtx, fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON %s`, triggerName, table)); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("drop trigger %s: %w", triggerName, err))
		}
		if _, err := database.ExecContext(cleanupCtx, fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, functionName)); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("drop function %s: %w", functionName, err))
		}
		return errors.Join(cleanupErrs...)
	}
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Errorf("cleanup %s fault: %v", label, err)
		}
	})
	return cleanup
}

func projectReviewFaultInstallDeferredTrigger(t *testing.T, database *sql.DB, transactionID uuid.UUID) func() error {
	t.Helper()
	suffix := strings.ReplaceAll(uuid.New().String(), "-", "")[:20]
	functionName := "oneissuer_project_review_fault_deferred_fn_" + suffix
	triggerName := "oneissuer_project_review_fault_deferred_tr_" + suffix
	if _, err := database.ExecContext(context.Background(), fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.id = '%s'::uuid AND NEW.stage = 'confirmed' THEN RAISE EXCEPTION 'deferred logout commit failure' USING ERRCODE = '55000'; END IF; RETURN NEW; END $$`, functionName, transactionID)); err != nil {
		t.Fatalf("create deferred fault function: %v", err)
	}
	if _, err := database.ExecContext(context.Background(), fmt.Sprintf(`CREATE CONSTRAINT TRIGGER %s AFTER UPDATE OF stage ON logout_transactions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION %s()`, triggerName, functionName)); err != nil {
		_, _ = database.ExecContext(context.Background(), fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, functionName))
		t.Fatalf("create deferred fault trigger: %v", err)
	}
	cleanup := func() error {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var cleanupErrs []error
		if _, err := database.ExecContext(cleanupCtx, fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON logout_transactions`, triggerName)); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("drop trigger %s: %w", triggerName, err))
		}
		if _, err := database.ExecContext(cleanupCtx, fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, functionName)); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("drop function %s: %w", functionName, err))
		}
		return errors.Join(cleanupErrs...)
	}
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Errorf("cleanup deferred fault: %v", err)
		}
	})
	return cleanup
}
