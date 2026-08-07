package postgres_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/storage/postgres"
)

const protocolCleanupAdvisoryLock int64 = 918273645

type protocolCleanupResult struct {
	deleted int64
	err     error
}

// testProtocolCleanupRollback proves that cancellation (the shutdown path) and
// an operation deadline cannot commit the Access-metadata deletion that runs
// before the dependent Authorization Code deletion in the cleanup transaction.
func testProtocolCleanupRollback(ctx context.Context, t *testing.T, store *postgres.Store, database *sql.DB, cutoff time.Time) {
	t.Helper()

	var initialCodes, initialAccess int
	if err := database.QueryRowContext(ctx, `
		SELECT (SELECT count(*)::int FROM authorization_codes),
		       (SELECT count(*)::int FROM access_tokens)`).Scan(&initialCodes, &initialAccess); err != nil {
		t.Fatalf("count protocol metadata before interrupted cleanup: %v", err)
	}
	if initialCodes == 0 || initialAccess == 0 {
		t.Fatalf("interrupted cleanup fixture codes=%d access=%d, want both non-zero", initialCodes, initialAccess)
	}

	blocker, err := database.Conn(ctx)
	if err != nil {
		t.Fatalf("reserve cleanup advisory-lock connection: %v", err)
	}
	if _, err := blocker.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, protocolCleanupAdvisoryLock); err != nil {
		_ = blocker.Close()
		t.Fatalf("acquire cleanup advisory lock: %v", err)
	}
	if _, err := database.ExecContext(ctx, `
		CREATE FUNCTION oneissuer_test_block_protocol_cleanup() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			PERFORM pg_advisory_xact_lock(918273645);
			RETURN OLD;
		END
		$$`); err != nil {
		_, _ = blocker.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, protocolCleanupAdvisoryLock)
		_ = blocker.Close()
		t.Fatalf("create protocol cleanup blocking function: %v", err)
	}
	if _, err := database.ExecContext(ctx, `
		CREATE TRIGGER oneissuer_test_block_protocol_cleanup
		BEFORE DELETE ON authorization_codes
		FOR EACH ROW EXECUTE FUNCTION oneissuer_test_block_protocol_cleanup()`); err != nil {
		_, _ = blocker.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, protocolCleanupAdvisoryLock)
		_ = blocker.Close()
		t.Fatalf("create protocol cleanup blocking trigger: %v", err)
	}

	cleanedUp := false
	cleanupFaultInjection := func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = blocker.ExecContext(cleanupCtx, `SELECT pg_advisory_unlock($1)`, protocolCleanupAdvisoryLock)
		_ = blocker.Close()
		_, _ = database.ExecContext(cleanupCtx, `DROP TRIGGER IF EXISTS oneissuer_test_block_protocol_cleanup ON authorization_codes`)
		_, _ = database.ExecContext(cleanupCtx, `DROP FUNCTION IF EXISTS oneissuer_test_block_protocol_cleanup()`)
	}
	t.Cleanup(func() {
		if !cleanedUp {
			cleanupFaultInjection()
		}
	})

	waitForBlockedDelete := func(label string) {
		t.Helper()
		if !waitUntil(3*time.Second, func() bool {
			queryCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
			defer cancel()
			var waiting bool
			err := database.QueryRowContext(queryCtx, `
				SELECT EXISTS (
					SELECT 1 FROM pg_stat_activity
					WHERE datname=current_database()
					  AND state='active'
					  AND wait_event_type='Lock'
					  AND query LIKE '%DELETE FROM authorization_codes%'
				)`).Scan(&waiting)
			return err == nil && waiting
		}) {
			t.Fatalf("%s cleanup never reached the blocked Code deletion", label)
		}
	}
	assertMetadataUnchanged := func(label string) {
		t.Helper()
		var codes, access int
		if err := database.QueryRowContext(ctx, `
			SELECT (SELECT count(*)::int FROM authorization_codes),
			       (SELECT count(*)::int FROM access_tokens)`).Scan(&codes, &access); err != nil {
			t.Fatalf("count protocol metadata after %s cleanup: %v", label, err)
		}
		if codes != initialCodes || access != initialAccess {
			t.Fatalf("%s cleanup left partial state codes=%d/%d access=%d/%d", label, codes, initialCodes, access, initialAccess)
		}
	}

	canceledCtx, cancelCleanup := context.WithCancel(ctx)
	canceledResult := make(chan protocolCleanupResult, 1)
	go func() {
		deleted, cleanupErr := store.CleanupProtocolArtifacts(canceledCtx, cutoff)
		canceledResult <- protocolCleanupResult{deleted: deleted, err: cleanupErr}
	}()
	waitForBlockedDelete("canceled")
	cancelCleanup()
	result := <-canceledResult
	if result.deleted != 0 || !errors.Is(result.err, context.Canceled) || postgres.ErrorClass(result.err) != string(postgres.ErrorKindCanceled) {
		t.Fatalf("canceled cleanup deleted=%d error=%v class=%q", result.deleted, result.err, postgres.ErrorClass(result.err))
	}
	assertMetadataUnchanged("canceled")

	deadlineCtx, cancelDeadline := context.WithTimeout(ctx, time.Second)
	defer cancelDeadline()
	deadlineResult := make(chan protocolCleanupResult, 1)
	go func() {
		deleted, cleanupErr := store.CleanupProtocolArtifacts(deadlineCtx, cutoff)
		deadlineResult <- protocolCleanupResult{deleted: deleted, err: cleanupErr}
	}()
	waitForBlockedDelete("deadline")
	result = <-deadlineResult
	if result.deleted != 0 || !errors.Is(result.err, context.DeadlineExceeded) || postgres.ErrorClass(result.err) != string(postgres.ErrorKindCanceled) {
		t.Fatalf("deadline cleanup deleted=%d error=%v class=%q", result.deleted, result.err, postgres.ErrorClass(result.err))
	}
	assertMetadataUnchanged("deadline")

	cleanupFaultInjection()
	cleanedUp = true
}

// testProtocolCleanupCommitsCompletedBatches proves that a deadline in a later
// batch does not roll back progress already committed by an earlier batch.
func testProtocolCleanupCommitsCompletedBatches(ctx context.Context, t *testing.T, store *postgres.Store, database *sql.DB, cutoff time.Time) {
	t.Helper()

	var userID, clientID, grantID uuid.UUID
	var redirectURI string
	if err := database.QueryRowContext(ctx, `
		SELECT grants.user_id, grants.client_id, grants.id,
		       (SELECT uri FROM oidc_client_redirect_uris WHERE client_id=grants.client_id ORDER BY uri LIMIT 1)
		FROM consent_grants AS grants
		ORDER BY grants.created_at LIMIT 1`).Scan(&userID, &clientID, &grantID, &redirectURI); err != nil {
		t.Fatalf("select bulk cleanup authority fixture: %v", err)
	}

	transactionIDs := make([]uuid.UUID, 0, 251)
	fixtureTx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fixtureTx.Rollback() }()
	for index := 0; index < 251; index++ {
		transactionID, codeID, accessID := uuid.New(), uuid.New(), uuid.New()
		transactionIDs = append(transactionIDs, transactionID)
		createdAt := cutoff.Add(-2 * time.Hour)
		if index == 250 {
			createdAt = cutoff.Add(-time.Hour)
		}
		transactionHash := sha256.Sum256([]byte(fmt.Sprintf("cleanup-transaction-%d", index)))
		codeHash := sha256.Sum256([]byte(fmt.Sprintf("cleanup-code-%d", index)))
		jtiHash := sha256.Sum256([]byte(fmt.Sprintf("cleanup-jti-%d", index)))
		if _, err := fixtureTx.ExecContext(ctx, `INSERT INTO auth_transactions (
			id, token_hash, transaction_kind, scopes, prompt_create, prompt_values,
			created_at, expires_at, consumed_at, failure_reason
		) VALUES ($1, $2, 'local', ARRAY[]::text[], false, ARRAY[]::text[], $3, $4, $5, 'consumed')`,
			transactionID, transactionHash[:], createdAt, createdAt.Add(time.Minute), createdAt.Add(30*time.Second)); err != nil {
			t.Fatalf("insert bulk cleanup transaction %d: %v", index, err)
		}
		var nonce *string
		if index == 250 {
			value := "cleanup-block"
			nonce = &value
		}
		if _, err := fixtureTx.ExecContext(ctx, `INSERT INTO authorization_codes (
			id, code_hash, auth_transaction_id, consent_grant_id, user_id, client_id,
			redirect_uri, scopes, pkce_challenge, pkce_method, nonce_value,
			auth_time, created_at, expires_at, consumed_at, consent_grant_version
		) VALUES ($1, $2, $3, $4, $5, $6, $7, ARRAY['openid']::text[], repeat('A', 43), 'S256', $8, $9, $9, $10, $11, 1)`,
			codeID, codeHash[:], transactionID, grantID, userID, clientID, redirectURI, nonce,
			createdAt, createdAt.Add(time.Minute), createdAt.Add(30*time.Second)); err != nil {
			t.Fatalf("insert bulk cleanup code %d: %v", index, err)
		}
		if _, err := fixtureTx.ExecContext(ctx, `INSERT INTO access_tokens (
			id, jti_hash, authorization_code_id, consent_grant_id, user_id, client_id,
			scopes, issued_at, expires_at, issuance_source
		) VALUES ($1, $2, $3, $4, $5, $6, ARRAY['openid']::text[], $7, $8, 'authorization_code')`,
			accessID, jtiHash[:], codeID, grantID, userID, clientID, createdAt, createdAt.Add(10*time.Minute)); err != nil {
			t.Fatalf("insert bulk cleanup access token %d: %v", index, err)
		}
	}
	if err := fixtureTx.Commit(); err != nil {
		t.Fatalf("commit bulk cleanup fixture: %v", err)
	}

	blocker, err := database.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blocker.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, protocolCleanupAdvisoryLock); err != nil {
		_ = blocker.Close()
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
		CREATE FUNCTION oneissuer_test_block_later_protocol_batch() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			IF OLD.nonce_value = 'cleanup-block' THEN
				PERFORM pg_advisory_xact_lock(918273645);
			END IF;
			RETURN OLD;
		END
		$$;
		CREATE TRIGGER oneissuer_test_block_later_protocol_batch
		BEFORE DELETE ON authorization_codes
		FOR EACH ROW EXECUTE FUNCTION oneissuer_test_block_later_protocol_batch()`); err != nil {
		_, _ = blocker.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, protocolCleanupAdvisoryLock)
		_ = blocker.Close()
		t.Fatalf("create later-batch blocking trigger: %v", err)
	}
	cleanedUp := false
	cleanupFault := func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = blocker.ExecContext(cleanupCtx, `SELECT pg_advisory_unlock($1)`, protocolCleanupAdvisoryLock)
		_ = blocker.Close()
		_, _ = database.ExecContext(cleanupCtx, `DROP TRIGGER IF EXISTS oneissuer_test_block_later_protocol_batch ON authorization_codes`)
		_, _ = database.ExecContext(cleanupCtx, `DROP FUNCTION IF EXISTS oneissuer_test_block_later_protocol_batch()`)
	}
	t.Cleanup(func() {
		if !cleanedUp {
			cleanupFault()
		}
	})

	deadlineCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	resultChannel := make(chan protocolCleanupResult, 1)
	go func() {
		deleted, cleanupErr := store.CleanupProtocolArtifacts(deadlineCtx, cutoff)
		resultChannel <- protocolCleanupResult{deleted: deleted, err: cleanupErr}
	}()
	if !waitUntil(3*time.Second, func() bool {
		queryCtx, queryCancel := context.WithTimeout(ctx, 250*time.Millisecond)
		defer queryCancel()
		var waiting bool
		err := database.QueryRowContext(queryCtx, `SELECT EXISTS (
			SELECT 1 FROM pg_stat_activity
			WHERE datname=current_database() AND state='active' AND wait_event_type='Lock'
			  AND query LIKE '%DELETE FROM authorization_codes%'
		)`).Scan(&waiting)
		return err == nil && waiting
	}) {
		t.Fatal("cleanup did not reach the blocked later batch")
	}
	var visibleCodes, visibleAccess int
	if err := database.QueryRowContext(ctx, `SELECT
		(SELECT count(*)::int FROM authorization_codes),
		(SELECT count(*)::int FROM access_tokens)`).Scan(&visibleCodes, &visibleAccess); err != nil {
		t.Fatal(err)
	}
	if visibleCodes != 1 || visibleAccess != 1 {
		t.Fatalf("first cleanup batch was not committed before later block: codes=%d access=%d", visibleCodes, visibleAccess)
	}
	result := <-resultChannel
	if result.deleted != 500 || !errors.Is(result.err, context.DeadlineExceeded) {
		t.Fatalf("partial cleanup deleted=%d error=%v, want 500 and deadline", result.deleted, result.err)
	}

	cleanupFault()
	cleanedUp = true
	if deleted, err := store.CleanupProtocolArtifacts(ctx, cutoff); err != nil || deleted != 2 {
		t.Fatalf("finish partial cleanup deleted=%d error=%v", deleted, err)
	}
	for _, transactionID := range transactionIDs {
		if _, err := database.ExecContext(ctx, `DELETE FROM auth_transactions WHERE id=$1`, transactionID); err != nil {
			t.Fatalf("delete bulk cleanup transaction: %v", err)
		}
	}
}

// testRefreshAndProtocolCleanup proves the dependency order and retention
// boundary for rotating Refresh metadata. A family referenced by Access
// metadata must survive the first Refresh cleanup pass; once protocol metadata
// is retired, the same family becomes removable. Rows exactly at the cutoff
// are eligible while rows after it remain evidence.
func testRefreshAndProtocolCleanup(ctx context.Context, t *testing.T, store *postgres.Store, database *sql.DB, refreshHash []byte, cutoff time.Time) {
	t.Helper()

	var familyID, grantID, userID, clientID uuid.UUID
	if err := database.QueryRowContext(ctx, `
		SELECT families.id, families.consent_grant_id, families.user_id, families.client_id
		FROM refresh_token_families AS families
		JOIN refresh_tokens AS generations ON generations.family_id=families.id
		JOIN access_tokens AS accesses ON accesses.refresh_family_id=families.id
		WHERE generations.token_hash=$1
		LIMIT 1`, refreshHash).Scan(&familyID, &grantID, &userID, &clientID); err != nil {
		t.Fatalf("select Refresh cleanup family with Access reference: %v", err)
	}
	retiredAt := cutoff.Add(-2 * time.Hour)
	if _, err := database.ExecContext(ctx, `
		UPDATE refresh_token_families
		SET absolute_expires_at=$2, revoked_at=$3, revoke_reason='grant_revoked'
		WHERE id=$1`, familyID, cutoff.Add(-time.Hour), retiredAt); err != nil {
		t.Fatalf("retire Refresh family with Access reference: %v", err)
	}
	if deleted, err := store.CleanupRefreshArtifacts(ctx, cutoff); err != nil {
		t.Fatalf("Refresh cleanup before Access retirement: deleted=%d error=%v", deleted, err)
	}
	var familyStillPresent, generationCount int
	if err := database.QueryRowContext(ctx, `
		SELECT (SELECT count(*)::int FROM refresh_token_families WHERE id=$1),
		       (SELECT count(*)::int FROM refresh_tokens WHERE family_id=$1)`, familyID).Scan(&familyStillPresent, &generationCount); err != nil {
		t.Fatalf("inspect FK-protected Refresh family: %v", err)
	}
	if familyStillPresent != 1 || generationCount == 0 {
		t.Fatalf("FK-protected Refresh family presence=%d generations=%d, want 1/non-zero", familyStillPresent, generationCount)
	}

	boundaryIDs := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	boundaryTimes := []time.Time{cutoff.Add(-time.Second), cutoff, cutoff.Add(time.Microsecond)}
	for index, id := range boundaryIDs {
		if _, err := database.ExecContext(ctx, `
			INSERT INTO refresh_token_families (
				id, consent_grant_id, user_id, client_id, session_binding_id,
				scopes, created_at, absolute_expires_at
			) VALUES ($1, $2, $3, $4, $5, ARRAY['offline_access','openid']::text[], $6, $7)`,
			id, grantID, userID, clientID, uuid.New(), cutoff.Add(-24*time.Hour), boundaryTimes[index]); err != nil {
			t.Fatalf("insert Refresh retention boundary family %d: %v", index, err)
		}
	}

	if deleted, err := store.CleanupProtocolArtifacts(ctx, cutoff); err != nil || deleted == 0 {
		t.Fatalf("protocol cleanup before family retirement: deleted=%d error=%v", deleted, err)
	}
	if deleted, err := store.CleanupRefreshArtifacts(ctx, cutoff); err != nil || deleted == 0 {
		t.Fatalf("Refresh cleanup after Access retirement: deleted=%d error=%v", deleted, err)
	}
	var remainingBoundary, targetFamilyRows, remainingCodes, remainingAccess int
	if err := database.QueryRowContext(ctx, `
		SELECT (SELECT count(*)::int FROM refresh_token_families WHERE id IN ($1, $2, $3)),
		       (SELECT count(*)::int FROM refresh_token_families WHERE id=$4),
		       (SELECT count(*)::int FROM authorization_codes),
		       (SELECT count(*)::int FROM access_tokens)`, boundaryIDs[0], boundaryIDs[1], boundaryIDs[2], familyID).
		Scan(&remainingBoundary, &targetFamilyRows, &remainingCodes, &remainingAccess); err != nil {
		t.Fatalf("inspect post-retirement metadata: %v", err)
	}
	if remainingBoundary != 1 || targetFamilyRows != 0 || remainingCodes != 0 || remainingAccess != 0 {
		t.Fatalf("retirement boundary families=%d/1 target=%d/0 codes=%d access=%d", remainingBoundary, targetFamilyRows, remainingCodes, remainingAccess)
	}
}
