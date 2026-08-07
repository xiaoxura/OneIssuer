package postgres_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/session"
)

const projectReviewLockBarrierKey int64 = 481516234

type projectReviewBindingAuthority struct {
	familyID uuid.UUID
	accessID uuid.UUID
}

func testProjectReviewBatchCascadeBoundaries(ctx context.Context, t *testing.T, services phaseTwoServices, database *sql.DB) {
	t.Helper()
	base := time.Now().UTC().Truncate(time.Microsecond)
	current, user, _ := projectReviewRegister(ctx, t, services, "batch-current", base, "")
	currentFixture := projectReviewInsertAuthority(ctx, t, database, services, user, current, "batch-current", base, false)

	peer := projectReviewInsertIndependentSession(ctx, t, database, user.ID, "batch-peer", base.Add(time.Second), uuid.Nil)
	peerAuthority := projectReviewInsertBindingAuthority(ctx, t, database, user.ID, peer, currentFixture.clientID, currentFixture.grantID, "batch-peer", base.Add(2*time.Second), uuid.Nil)

	foreign, foreignUser, _ := projectReviewRegister(ctx, t, services, "batch-foreign", base.Add(4*time.Minute), "")
	foreignFixture := projectReviewInsertAuthority(ctx, t, database, services, foreignUser, foreign, "batch-foreign", base.Add(4*time.Minute), false)

	principal, err := services.sessions.Authenticate(ctx, current.Token, base.Add(5*time.Second))
	if err != nil {
		t.Fatalf("authenticate current session for batch cascade: %v", err)
	}
	count, err := services.sessions.RevokeOthers(ctx, principal, "project-review-batch-revoke-others", base.Add(6*time.Second))
	if err != nil {
		t.Fatalf("RevokeOthers() batch cascade: %v", err)
	}
	if count != 1 {
		t.Fatalf("RevokeOthers() count=%d, want one peer session", count)
	}

	_, currentRevoked, currentReason := projectReviewSessionState(ctx, t, database, current.Record.ID)
	if currentRevoked || currentReason != "" {
		t.Fatalf("current session revoked=%v reason=%q, batch cascade must preserve it", currentRevoked, currentReason)
	}
	currentFamilyRevoked, currentFamilyReason := projectReviewFamilyState(ctx, t, database, currentFixture.offlineFamilyID)
	if currentFamilyRevoked || currentFamilyReason != "" {
		t.Fatalf("current family revoked=%v reason=%q, batch cascade must preserve it", currentFamilyRevoked, currentFamilyReason)
	}
	currentAccessRevoked, currentAccessReason := projectReviewAccessState(ctx, t, database, currentFixture.offlineAccessID)
	if currentAccessRevoked || currentAccessReason != "" {
		t.Fatalf("current Access revoked=%v reason=%q, batch cascade must preserve it", currentAccessRevoked, currentAccessReason)
	}
	peerBinding, peerRevoked, peerReason := projectReviewSessionState(ctx, t, database, peer.Record.ID)
	if peerBinding != peer.Record.SessionBindingID || !peerRevoked || peerReason != "others" {
		t.Fatalf("peer session binding=%s revoked=%v reason=%q, want others", peerBinding, peerRevoked, peerReason)
	}
	peerFamilyRevoked, peerFamilyReason := projectReviewFamilyState(ctx, t, database, peerAuthority.familyID)
	if !peerFamilyRevoked || peerFamilyReason != "session_revoked" {
		t.Fatalf("peer family revoked=%v reason=%q, want session_revoked", peerFamilyRevoked, peerFamilyReason)
	}
	peerAccessRevoked, peerAccessReason := projectReviewAccessState(ctx, t, database, peerAuthority.accessID)
	if !peerAccessRevoked || peerAccessReason != "session_revoked" {
		t.Fatalf("peer Access revoked=%v reason=%q, want session_revoked", peerAccessRevoked, peerAccessReason)
	}

	_, foreignRevoked, foreignReason := projectReviewSessionState(ctx, t, database, foreign.Record.ID)
	if foreignRevoked || foreignReason != "" {
		t.Fatalf("foreign-user session revoked=%v reason=%q, batch cascade crossed user boundary", foreignRevoked, foreignReason)
	}
	foreignFamilyRevoked, foreignFamilyReason := projectReviewFamilyState(ctx, t, database, foreignFixture.offlineFamilyID)
	if foreignFamilyRevoked || foreignFamilyReason != "" {
		t.Fatalf("foreign-user family revoked=%v reason=%q, batch cascade crossed user binding", foreignFamilyRevoked, foreignFamilyReason)
	}
	foreignAccessRevoked, foreignAccessReason := projectReviewAccessState(ctx, t, database, foreignFixture.offlineAccessID)
	if foreignAccessRevoked || foreignAccessReason != "" {
		t.Fatalf("foreign-user Access revoked=%v reason=%q, batch cascade crossed user binding", foreignAccessRevoked, foreignAccessReason)
	}
}

func testProjectReviewConcurrentRevocation(ctx context.Context, t *testing.T, services phaseTwoServices, database *sql.DB) {
	t.Helper()
	base := time.Now().UTC().Truncate(time.Microsecond)
	current, user, _ := projectReviewRegister(ctx, t, services, "lock-order", base, "")
	currentFixture := projectReviewInsertAuthority(ctx, t, database, services, user, current, "lock-order", base, false)

	peerID := uuid.New()
	for peerID == current.Record.ID {
		peerID = uuid.New()
	}
	peer := projectReviewInsertIndependentSession(ctx, t, database, user.ID, "lock-order-peer", base.Add(time.Second), peerID)
	familyOrder := uuid.New()
	sessionOrder := projectReviewUUIDCompare(current.Record.ID, peer.Record.ID)
	for projectReviewUUIDCompare(currentFixture.offlineFamilyID, familyOrder) == sessionOrder {
		familyOrder = uuid.New()
	}
	peerAuthority := projectReviewInsertBindingAuthority(ctx, t, database, user.ID, peer, currentFixture.clientID, currentFixture.grantID, "lock-order-peer", base.Add(2*time.Second), familyOrder)
	if projectReviewUUIDCompare(current.Record.ID, peer.Record.ID) == projectReviewUUIDCompare(currentFixture.offlineFamilyID, peerAuthority.familyID) {
		t.Fatalf("fixture did not reverse Session and family order: sessions=%s/%s families=%s/%s", current.Record.ID, peer.Record.ID, currentFixture.offlineFamilyID, peerAuthority.familyID)
	}
	t.Logf("lock-order fixture reverses Session row order (%s,%s) and family UUID order (%s,%s)", current.Record.ID, peer.Record.ID, currentFixture.offlineFamilyID, peerAuthority.familyID)

	principal, err := services.sessions.Authenticate(ctx, current.Token, base.Add(3*time.Second))
	if err != nil {
		t.Fatalf("authenticate current session for lock-order race: %v", err)
	}
	barrierName := "oneissuer_project_review_lock_barrier_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:12]
	triggerName := barrierName + "_trigger"
	blocker, err := database.Conn(ctx)
	if err != nil {
		t.Fatalf("reserve advisory barrier connection: %v", err)
	}
	barrierHeld := false
	if _, err := blocker.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, projectReviewLockBarrierKey); err != nil {
		_ = blocker.Close()
		t.Fatalf("acquire advisory barrier: %v", err)
	}
	barrierHeld = true
	functionSQL := fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger
	LANGUAGE plpgsql AS $$
	BEGIN
		IF NEW.id IN ('%s'::uuid, '%s'::uuid) THEN
			PERFORM pg_advisory_xact_lock(%d);
		END IF;
		RETURN NEW;
	END
	$$`, barrierName, currentFixture.offlineFamilyID, peerAuthority.familyID, projectReviewLockBarrierKey)
	if _, err := database.ExecContext(ctx, functionSQL); err != nil {
		_, _ = blocker.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, projectReviewLockBarrierKey)
		_ = blocker.Close()
		t.Fatalf("create family update advisory barrier: %v", err)
	}
	triggerSQL := fmt.Sprintf(`CREATE TRIGGER %s
	BEFORE UPDATE OF revoked_at ON refresh_token_families
	FOR EACH ROW EXECUTE FUNCTION %s()`, triggerName, barrierName)
	if _, err := database.ExecContext(ctx, triggerSQL); err != nil {
		_, _ = blocker.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, projectReviewLockBarrierKey)
		_ = blocker.Close()
		_, _ = database.ExecContext(context.Background(), fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, barrierName))
		t.Fatalf("install family update advisory barrier: %v", err)
	}
	cleanupBarrier := func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if barrierHeld {
			_, _ = blocker.ExecContext(cleanupCtx, `SELECT pg_advisory_unlock($1)`, projectReviewLockBarrierKey)
		}
		_ = blocker.Close()
		_, _ = database.ExecContext(cleanupCtx, fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON refresh_token_families`, triggerName))
		_, _ = database.ExecContext(cleanupCtx, fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, barrierName))
	}
	t.Cleanup(cleanupBarrier)

	raceCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	start := make(chan struct{})
	results := make(chan projectReviewRaceResult, 2)
	var raceWG sync.WaitGroup
	raceWG.Add(2)
	go func() {
		defer raceWG.Done()
		<-start
		count, revokeErr := services.sessions.RevokeOthers(raceCtx, principal, "project-review-lock-revoke-others", base.Add(4*time.Second))
		results <- projectReviewRaceResult{name: "RevokeOthers", count: count, err: revokeErr}
	}()
	go func() {
		defer raceWG.Done()
		<-start
		disabled := clientdomain.StatusDisabled
		updated, _, updateErr := services.clients.Update(raceCtx, user.ID, currentFixture.clientID, clientdomain.UpdateInput{Status: &disabled}, "project-review-lock-client-disable", base.Add(5*time.Second))
		results <- projectReviewRaceResult{name: "ClientDisable", status: updated.Status, err: updateErr}
	}()
	close(start)

	waitCtx, waitCancel := context.WithTimeout(raceCtx, 5*time.Second)
	waitErr := projectReviewWaitForAdvisoryWaiter(waitCtx, database)
	waitCancel()
	waiting, granted, lockQueryErr := projectReviewAdvisoryLockCounts(ctx, database)
	t.Logf("lock-order barrier observed waiting=%d granted=%d query_error=%v; pg_locks proves overlap at the barrier only", waiting, granted, lockQueryErr)
	if waitErr != nil {
		_, _ = blocker.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, projectReviewLockBarrierKey)
		barrierHeld = false
		raceWG.Wait()
		t.Fatalf("concurrent revocation did not reach PostgreSQL advisory barrier: %v", waitErr)
	}
	if waiting < 1 {
		_, _ = blocker.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, projectReviewLockBarrierKey)
		barrierHeld = false
		raceWG.Wait()
		t.Fatalf("pg_locks reported no advisory waiter while race was expected")
	}
	unlockCtx, unlockCancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, unlockErr := blocker.ExecContext(unlockCtx, `SELECT pg_advisory_unlock($1)`, projectReviewLockBarrierKey)
	unlockCancel()
	barrierHeld = false
	if unlockErr != nil {
		raceWG.Wait()
		t.Fatalf("release advisory barrier: %v", unlockErr)
	}
	raceWG.Wait()
	close(results)
	var raceErrs []string
	for result := range results {
		if result.err != nil {
			if projectReviewIsDeadlock(result.err) {
				raceErrs = append(raceErrs, result.name+" returned PostgreSQL deadlock")
			} else {
				raceErrs = append(raceErrs, result.name+" error: "+result.err.Error())
			}
			continue
		}
		if result.name == "ClientDisable" && result.status != clientdomain.StatusDisabled {
			raceErrs = append(raceErrs, fmt.Sprintf("ClientDisable status=%q, want disabled", result.status))
		}
	}
	if len(raceErrs) != 0 {
		t.Fatalf("concurrent session/client revocation failures: %s", strings.Join(raceErrs, "; "))
	}

	_, currentRevoked, currentReason := projectReviewSessionState(ctx, t, database, current.Record.ID)
	if currentRevoked || currentReason != "" {
		t.Fatalf("race current session revoked=%v reason=%q, RevokeOthers must retain current Session row", currentRevoked, currentReason)
	}
	_, peerRevoked, peerReason := projectReviewSessionState(ctx, t, database, peer.Record.ID)
	if !peerRevoked || peerReason != "others" {
		t.Fatalf("race peer session revoked=%v reason=%q, want final revoked peer", peerRevoked, peerReason)
	}
	for _, familyID := range []uuid.UUID{currentFixture.offlineFamilyID, peerAuthority.familyID} {
		revoked, reason := projectReviewFamilyState(ctx, t, database, familyID)
		if !revoked || (reason != "session_revoked" && reason != "client_disabled") {
			t.Fatalf("race family %s revoked=%v reason=%q, want final revoked state", familyID, revoked, reason)
		}
	}
	for _, accessID := range []uuid.UUID{currentFixture.offlineAccessID, peerAuthority.accessID} {
		revoked, reason := projectReviewAccessState(ctx, t, database, accessID)
		if !revoked || (reason != "session_revoked" && reason != "client_disabled") {
			t.Fatalf("race Access %s revoked=%v reason=%q, want final revoked state", accessID, revoked, reason)
		}
	}
}

type projectReviewRaceResult struct {
	name   string
	count  int64
	status clientdomain.Status
	err    error
}

func projectReviewInsertIndependentSession(ctx context.Context, t *testing.T, database *sql.DB, userID uuid.UUID, label string, at time.Time, id uuid.UUID) session.Issued {
	t.Helper()
	if id == uuid.Nil {
		id = uuid.New()
	}
	token := "project-review-independent-session-" + label
	csrf := "project-review-independent-csrf-" + label
	tokenHash := session.HashToken(token)
	csrfHash := session.HashCSRF(csrf)
	userAgentHash := projectReviewDigest("independent-user-agent:" + label)
	if _, err := database.ExecContext(ctx, `INSERT INTO login_sessions (
		id, user_id, token_hash, csrf_hash, csrf_expires_at, created_at,
		last_seen_at, authenticated_at, expires_at, idle_expires_at,
		user_agent_hash, ip_prefix, session_binding_id
	) VALUES ($1, $2, $3, $4, $5, $6, $6, $6, $7, $8, $9, $10, $1)`,
		id, userID, tokenHash, csrfHash, at.Add(time.Hour), at, at.Add(24*time.Hour), at.Add(2*time.Hour), userAgentHash[:], "192.0.2.0/24"); err != nil {
		t.Fatalf("insert independent session %s: %v", label, err)
	}
	return session.Issued{
		Token: token, CSRFToken: csrf,
		Record: session.Record{
			ID: id, UserID: userID, SessionBindingID: id, TokenHash: tokenHash, CSRFHash: csrfHash,
			CSRFExpiresAt: at.Add(time.Hour), CreatedAt: at, LastSeenAt: at, AuthenticatedAt: at,
			ExpiresAt: at.Add(24 * time.Hour), IdleExpiresAt: at.Add(2 * time.Hour), UserAgentHash: userAgentHash[:], IPPrefix: "192.0.2.0/24",
		},
	}
}

func projectReviewInsertBindingAuthority(ctx context.Context, t *testing.T, database *sql.DB, userID uuid.UUID, issued session.Issued, clientID, grantID uuid.UUID, label string, at time.Time, familyID uuid.UUID) projectReviewBindingAuthority {
	t.Helper()
	if familyID == uuid.Nil {
		familyID = uuid.New()
	}
	refreshID := uuid.New()
	accessID := uuid.New()
	refreshHash := projectReviewDigest("independent-refresh:" + label)
	accessHash := projectReviewDigest("independent-access:" + label)
	scopes := "ARRAY['offline_access','openid','profile']::text[]"
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin independent authority %s: %v", label, err)
	}
	defer func() { _ = tx.Rollback() }()
	run := func(statement string, args ...any) {
		t.Helper()
		if _, execErr := tx.ExecContext(ctx, statement, args...); execErr != nil {
			t.Fatalf("insert independent authority %s: %v", label, execErr)
		}
	}
	run(`INSERT INTO refresh_token_families (
		id, origin_authorization_code_id, consent_grant_id, user_id, client_id,
		origin_session_id, session_binding_id, scopes, created_at, absolute_expires_at
	) VALUES ($1, NULL, $2, $3, $4, $5, $6, `+scopes+`, $7, $8)`,
		familyID, grantID, userID, clientID, issued.Record.ID, issued.Record.SessionBindingID, at, at.Add(24*time.Hour))
	run(`INSERT INTO refresh_tokens (id, family_id, token_hash, generation, issued_at, expires_at)
		VALUES ($1, $2, $3, 0, $4, $5)`, refreshID, familyID, refreshHash[:], at, at.Add(23*time.Hour))
	run(`INSERT INTO access_tokens (
		id, jti_hash, authorization_code_id, consent_grant_id, user_id, client_id,
		scopes, issued_at, expires_at, issuance_source, source_refresh_token_id,
		refresh_family_id, origin_session_id, session_binding_id
	) VALUES ($1, $2, NULL, $3, $4, $5, `+scopes+`, $6, $7, 'refresh_token', $8, $9, $10, $11)`,
		accessID, accessHash[:], grantID, userID, clientID, at, at.Add(10*time.Minute), refreshID, familyID, issued.Record.ID, issued.Record.SessionBindingID)
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit independent authority %s: %v", label, err)
	}
	return projectReviewBindingAuthority{familyID: familyID, accessID: accessID}
}

func projectReviewUUIDCompare(left, right uuid.UUID) int {
	return bytes.Compare(left[:], right[:])
}

func projectReviewWaitForAdvisoryWaiter(ctx context.Context, database *sql.DB) error {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		waiting, _, err := projectReviewAdvisoryLockCounts(ctx, database)
		if err != nil {
			return err
		}
		if waiting > 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func projectReviewAdvisoryLockCounts(ctx context.Context, database *sql.DB) (waiting, granted int, err error) {
	err = database.QueryRowContext(ctx, `SELECT
		count(*) FILTER (WHERE NOT granted)::int,
		count(*) FILTER (WHERE granted)::int
	FROM pg_locks
	WHERE locktype='advisory' AND objid::bigint=$1`, projectReviewLockBarrierKey).Scan(&waiting, &granted)
	return waiting, granted, err
}

func projectReviewIsDeadlock(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40P01" || strings.Contains(strings.ToLower(err.Error()), "deadlock detected")
}
