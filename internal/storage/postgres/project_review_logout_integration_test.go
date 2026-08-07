package postgres_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	logoutdomain "github.com/oneissuer/oneissuer/internal/logout"
	"github.com/oneissuer/oneissuer/internal/session"
	"github.com/oneissuer/oneissuer/internal/storage/postgres"
	productionmigrations "github.com/oneissuer/oneissuer/migrations"
	"github.com/testcontainers/testcontainers-go"
)

type projectReviewLogoutPGFixture struct {
	userID       uuid.UUID
	sessionID    uuid.UUID
	bindingID    uuid.UUID
	clientID     uuid.UUID
	grantID      uuid.UUID
	familyID     uuid.UUID
	refreshID    uuid.UUID
	accessID     uuid.UUID
	now          time.Time
	lookupToken  string
	csrfProofA   string
	csrfProofB   string
	sessionToken string
}

type projectReviewLogoutPGBindResult struct {
	transaction logoutdomain.Transaction
	err         error
}

type projectReviewLogoutPGCompleteResult struct {
	candidate logoutdomain.CompletionCandidate
	err       error
}

func TestProjectReviewLogoutPostgresAtomicity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PostgreSQL logout integration test in short mode")
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

	t.Run("pre-confirm completion cannot bind authority", func(t *testing.T) {
		fixture := projectReviewLogoutPGInsertFixture(ctx, t, database, false)
		lookupHash, err := logoutdomain.DigestLookupToken(fixture.lookupToken)
		if err != nil {
			t.Fatal(err)
		}
		csrfHash, err := logoutdomain.DigestCSRFProof(fixture.csrfProofA)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.CreateLogoutTransaction(ctx, projectReviewLogoutPGTransaction(fixture, lookupHash)); err != nil {
			t.Fatalf("create pre-confirm transaction: %v", err)
		}
		_, err = store.CompleteLogoutTransaction(ctx, logoutdomain.CompleteInput{
			LookupHash: lookupHash, CSRFHash: csrfHash, Decision: logoutdomain.DecisionConfirm,
			UserID: fixture.userID, SessionID: fixture.sessionID, SessionBindingID: fixture.bindingID,
			Now: fixture.now, RequestID: "project-review-preconfirm", MaxAttempts: 10,
		})
		if !errors.Is(err, logoutdomain.ErrNotFound) {
			t.Fatalf("pre-confirm completion error = %v, want ErrNotFound", err)
		}
		projectReviewLogoutPGAssertTransaction(ctx, t, database, lookupHash, "pre_confirm", false)
	})

	t.Run("concurrent bind enforces reject-current capacity and retry", func(t *testing.T) {
		fixture := projectReviewLogoutPGInsertFixture(ctx, t, database, false)
		inputs := make([]logoutdomain.BindInput, 2)
		for index, proof := range []string{fixture.csrfProofA, fixture.csrfProofB} {
			lookupToken := projectReviewLogoutPGToken("lt1_", "lookup-capacity", index)
			lookupHash, err := logoutdomain.DigestLookupToken(lookupToken)
			if err != nil {
				t.Fatal(err)
			}
			csrfHash, err := logoutdomain.DigestCSRFProof(proof)
			if err != nil {
				t.Fatal(err)
			}
			value := fixture
			value.lookupToken = lookupToken
			if err := store.CreateLogoutTransaction(ctx, projectReviewLogoutPGTransaction(value, lookupHash)); err != nil {
				t.Fatalf("create capacity transaction %d: %v", index, err)
			}
			inputs[index] = logoutdomain.BindInput{
				LookupHash: lookupHash, CSRFHash: csrfHash, UserID: fixture.userID,
				SessionID: fixture.sessionID, SessionBindingID: fixture.bindingID,
				Subject: "project-review-capacity-subject", Now: fixture.now,
				MaxActive: 1, MaxAttempts: 10,
			}
		}

		start := make(chan struct{})
		results := make(chan projectReviewLogoutPGBindResult, len(inputs))
		var wait sync.WaitGroup
		for _, input := range inputs {
			input := input
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				transaction, bindErr := store.BindLogoutTransaction(ctx, input)
				results <- projectReviewLogoutPGBindResult{transaction: transaction, err: bindErr}
			}()
		}
		close(start)
		wait.Wait()
		close(results)

		var winner projectReviewLogoutPGBindResult
		successes, capacities := 0, 0
		for result := range results {
			switch {
			case result.err == nil:
				winner = result
				successes++
			case errors.Is(result.err, logoutdomain.ErrCapacity):
				capacities++
			default:
				t.Fatalf("concurrent bind error = %v", result.err)
			}
		}
		if successes != 1 || capacities != 1 {
			t.Fatalf("concurrent bind successes=%d capacity_rejections=%d, want one each", successes, capacities)
		}

		if _, err := store.CompleteLogoutTransaction(ctx, logoutdomain.CompleteInput{
			LookupHash: winner.transaction.LookupHash, CSRFHash: winner.transaction.CSRFHash,
			Decision: logoutdomain.DecisionCancel, UserID: fixture.userID, SessionID: fixture.sessionID,
			SessionBindingID: fixture.bindingID, Now: fixture.now, RequestID: "project-review-capacity-cancel", MaxAttempts: 10,
		}); err != nil {
			t.Fatalf("cancel capacity winner: %v", err)
		}

		var retryInput logoutdomain.BindInput
		for _, input := range inputs {
			if !sameProjectReviewLogoutDigest(input.LookupHash, winner.transaction.LookupHash) {
				retryInput = input
			}
		}
		retryInput.CSRFHash, _ = logoutdomain.DigestCSRFProof(projectReviewLogoutPGToken("lc1_", "capacity-retry-proof", 0))
		retried, err := store.BindLogoutTransaction(ctx, retryInput)
		if err != nil {
			t.Fatalf("capacity rejection was not retryable after winner cancel: %v", err)
		}
		if retried.Stage != logoutdomain.StageBoundConfirm {
			t.Fatalf("retried stage = %q, want bound_confirmable", retried.Stage)
		}
	})

	t.Run("confirm and cancel have one transaction winner", func(t *testing.T) {
		fixture := projectReviewLogoutPGInsertFixture(ctx, t, database, false)
		lookupHash, _ := logoutdomain.DigestLookupToken(fixture.lookupToken)
		csrfHash, _ := logoutdomain.DigestCSRFProof(fixture.csrfProofA)
		if err := store.CreateLogoutTransaction(ctx, projectReviewLogoutPGTransaction(fixture, lookupHash)); err != nil {
			t.Fatal(err)
		}
		bound, err := store.BindLogoutTransaction(ctx, logoutdomain.BindInput{
			LookupHash: lookupHash, CSRFHash: csrfHash, UserID: fixture.userID, SessionID: fixture.sessionID,
			SessionBindingID: fixture.bindingID, Subject: "project-review-single-winner", Now: fixture.now, MaxActive: 1, MaxAttempts: 10,
		})
		if err != nil {
			t.Fatalf("bind single winner transaction: %v", err)
		}

		start := make(chan struct{})
		results := make(chan projectReviewLogoutPGCompleteResult, 2)
		var wait sync.WaitGroup
		for _, decision := range []logoutdomain.Decision{logoutdomain.DecisionConfirm, logoutdomain.DecisionCancel} {
			decision := decision
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				candidate, completeErr := store.CompleteLogoutTransaction(ctx, logoutdomain.CompleteInput{
					LookupHash: lookupHash, CSRFHash: bound.CSRFHash, Decision: decision,
					UserID: fixture.userID, SessionID: fixture.sessionID, SessionBindingID: fixture.bindingID,
					Now: fixture.now, RequestID: "project-review-single-winner", MaxAttempts: 10,
				})
				results <- projectReviewLogoutPGCompleteResult{candidate: candidate, err: completeErr}
			}()
		}
		close(start)
		wait.Wait()
		close(results)

		successes := 0
		var winner projectReviewLogoutPGCompleteResult
		for result := range results {
			if result.err == nil {
				successes++
				winner = result
			} else if !errors.Is(result.err, logoutdomain.ErrNotFound) {
				t.Fatalf("losing completion error = %v, want ErrNotFound", result.err)
			}
		}
		if successes != 1 {
			t.Fatalf("completion successes = %d, want exactly one", successes)
		}
		var stage string
		var revoked sql.NullTime
		if err := database.QueryRowContext(ctx, `SELECT stage FROM logout_transactions WHERE lookup_hash=$1`, lookupHash).Scan(&stage); err != nil {
			t.Fatal(err)
		}
		if winner.candidate.Confirmed {
			if stage != string(logoutdomain.StageConfirmed) {
				t.Fatalf("winning confirm stage = %q", stage)
			}
		} else if stage != string(logoutdomain.StageCanceled) {
			t.Fatalf("winning cancel stage = %q", stage)
		}
		if err := database.QueryRowContext(ctx, `SELECT revoked_at FROM login_sessions WHERE id=$1`, fixture.sessionID).Scan(&revoked); err != nil {
			t.Fatal(err)
		}
		if revoked.Valid != winner.candidate.Confirmed {
			t.Fatalf("session revoked=%v, confirmed=%v", revoked.Valid, winner.candidate.Confirmed)
		}
	})

	t.Run("stale CSRF proof is rejected after rotation", func(t *testing.T) {
		fixture := projectReviewLogoutPGInsertFixture(ctx, t, database, false)
		lookupHash, _ := logoutdomain.DigestLookupToken(fixture.lookupToken)
		proofA, _ := logoutdomain.DigestCSRFProof(fixture.csrfProofA)
		proofB, _ := logoutdomain.DigestCSRFProof(fixture.csrfProofB)
		if err := store.CreateLogoutTransaction(ctx, projectReviewLogoutPGTransaction(fixture, lookupHash)); err != nil {
			t.Fatal(err)
		}
		input := logoutdomain.BindInput{LookupHash: lookupHash, CSRFHash: proofA, UserID: fixture.userID, SessionID: fixture.sessionID, SessionBindingID: fixture.bindingID, Subject: "project-review-stale-proof", Now: fixture.now, MaxActive: 1, MaxAttempts: 10}
		if _, err := store.BindLogoutTransaction(ctx, input); err != nil {
			t.Fatalf("initial bind: %v", err)
		}
		input.CSRFHash = proofB
		rotated, err := store.BindLogoutTransaction(ctx, input)
		if err != nil {
			t.Fatalf("proof rotation bind: %v", err)
		}
		_, err = store.CompleteLogoutTransaction(ctx, logoutdomain.CompleteInput{
			LookupHash: lookupHash, CSRFHash: proofA, Decision: logoutdomain.DecisionConfirm,
			UserID: fixture.userID, SessionID: fixture.sessionID, SessionBindingID: fixture.bindingID,
			Now: fixture.now, RequestID: "project-review-stale-proof", MaxAttempts: 10,
		})
		if !errors.Is(err, logoutdomain.ErrCSRF) {
			t.Fatalf("stale proof error = %v, want ErrCSRF", err)
		}
		if _, err := store.CompleteLogoutTransaction(ctx, logoutdomain.CompleteInput{
			LookupHash: lookupHash, CSRFHash: rotated.CSRFHash, Decision: logoutdomain.DecisionCancel,
			UserID: fixture.userID, SessionID: fixture.sessionID, SessionBindingID: fixture.bindingID,
			Now: fixture.now, RequestID: "project-review-stale-proof-retry", MaxAttempts: 10,
		}); err != nil {
			t.Fatalf("fresh proof retry: %v", err)
		}
	})

	t.Run("confirm cascades binding authority", func(t *testing.T) {
		fixture := projectReviewLogoutPGInsertFixture(ctx, t, database, true)
		lookupHash, _ := logoutdomain.DigestLookupToken(fixture.lookupToken)
		csrfHash, _ := logoutdomain.DigestCSRFProof(fixture.csrfProofA)
		if err := store.CreateLogoutTransaction(ctx, projectReviewLogoutPGTransaction(fixture, lookupHash)); err != nil {
			t.Fatal(err)
		}
		bound, err := store.BindLogoutTransaction(ctx, logoutdomain.BindInput{LookupHash: lookupHash, CSRFHash: csrfHash, UserID: fixture.userID, SessionID: fixture.sessionID, SessionBindingID: fixture.bindingID, Subject: "project-review-cascade", Now: fixture.now, MaxActive: 1, MaxAttempts: 10})
		if err != nil {
			t.Fatalf("bind cascade transaction: %v", err)
		}
		candidate, err := store.CompleteLogoutTransaction(ctx, logoutdomain.CompleteInput{LookupHash: lookupHash, CSRFHash: bound.CSRFHash, Decision: logoutdomain.DecisionConfirm, UserID: fixture.userID, SessionID: fixture.sessionID, SessionBindingID: fixture.bindingID, Now: fixture.now, RequestID: "project-review-cascade", MaxAttempts: 10})
		if err != nil || !candidate.Confirmed {
			t.Fatalf("confirm candidate=%+v err=%v", candidate, err)
		}
		var sessionRevoked, familyRevoked, accessRevoked sql.NullTime
		var familyReason, accessReason string
		if err := database.QueryRowContext(ctx, `SELECT revoked_at FROM login_sessions WHERE id=$1`, fixture.sessionID).Scan(&sessionRevoked); err != nil {
			t.Fatal(err)
		}
		if err := database.QueryRowContext(ctx, `SELECT revoked_at,revoke_reason FROM refresh_token_families WHERE id=$1`, fixture.familyID).Scan(&familyRevoked, &familyReason); err != nil {
			t.Fatal(err)
		}
		if err := database.QueryRowContext(ctx, `SELECT revoked_at,revoke_reason FROM access_tokens WHERE id=$1`, fixture.accessID).Scan(&accessRevoked, &accessReason); err != nil {
			t.Fatal(err)
		}
		if !sessionRevoked.Valid || !familyRevoked.Valid || !accessRevoked.Valid || familyReason != "session_revoked" || accessReason != "session_revoked" {
			t.Fatalf("cascade session=%v family=%v/%q access=%v/%q", sessionRevoked.Valid, familyRevoked.Valid, familyReason, accessRevoked.Valid, accessReason)
		}
	})

	t.Run("audit failure rolls back and permits proof retry", func(t *testing.T) {
		fixture := projectReviewLogoutPGInsertFixture(ctx, t, database, false)
		lookupHash, _ := logoutdomain.DigestLookupToken(fixture.lookupToken)
		csrfHash, _ := logoutdomain.DigestCSRFProof(fixture.csrfProofA)
		transaction := projectReviewLogoutPGTransaction(fixture, lookupHash)
		if err := store.CreateLogoutTransaction(ctx, transaction); err != nil {
			t.Fatal(err)
		}
		bound, err := store.BindLogoutTransaction(ctx, logoutdomain.BindInput{LookupHash: lookupHash, CSRFHash: csrfHash, UserID: fixture.userID, SessionID: fixture.sessionID, SessionBindingID: fixture.bindingID, Subject: "project-review-audit-rollback", Now: fixture.now, MaxActive: 1, MaxAttempts: 10})
		if err != nil {
			t.Fatalf("bind audit rollback transaction: %v", err)
		}
		if _, err := database.ExecContext(ctx, `
CREATE OR REPLACE FUNCTION project_review_logout_fail_audit() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'project review audit failure'; END; $$;
CREATE TRIGGER project_review_logout_fail_audit_trigger
BEFORE INSERT ON audit_events FOR EACH ROW
WHEN (NEW.event_type = 'rp_logout_completed')
EXECUTE FUNCTION project_review_logout_fail_audit()`); err != nil {
			t.Fatalf("install audit failure trigger: %v", err)
		}
		_, err = store.CompleteLogoutTransaction(ctx, logoutdomain.CompleteInput{LookupHash: lookupHash, CSRFHash: bound.CSRFHash, Decision: logoutdomain.DecisionConfirm, UserID: fixture.userID, SessionID: fixture.sessionID, SessionBindingID: fixture.bindingID, Now: fixture.now, RequestID: "project-review-audit-rollback", MaxAttempts: 10})
		if err == nil {
			t.Fatal("audit failure unexpectedly committed logout")
		}
		if _, err := database.ExecContext(ctx, `DROP TRIGGER project_review_logout_fail_audit_trigger ON audit_events; DROP FUNCTION project_review_logout_fail_audit()`); err != nil {
			t.Fatalf("remove audit failure trigger: %v", err)
		}
		projectReviewLogoutPGAssertTransaction(ctx, t, database, lookupHash, "bound_confirmable", false)
		var revoked sql.NullTime
		if err := database.QueryRowContext(ctx, `SELECT revoked_at FROM login_sessions WHERE id=$1`, fixture.sessionID).Scan(&revoked); err != nil {
			t.Fatal(err)
		}
		if revoked.Valid {
			t.Fatal("session authority was not rolled back after audit failure")
		}
		var auditCount int
		if err := database.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE target_type='logout_transaction' AND target_id=$1`, transaction.ID).Scan(&auditCount); err != nil {
			t.Fatal(err)
		}
		if auditCount != 0 {
			t.Fatalf("logout audit rows after rollback = %d, want 0", auditCount)
		}
		if _, err := store.CompleteLogoutTransaction(ctx, logoutdomain.CompleteInput{LookupHash: lookupHash, CSRFHash: bound.CSRFHash, Decision: logoutdomain.DecisionConfirm, UserID: fixture.userID, SessionID: fixture.sessionID, SessionBindingID: fixture.bindingID, Now: fixture.now, RequestID: "project-review-audit-retry", MaxAttempts: 10}); err != nil {
			t.Fatalf("retry after audit failure: %v", err)
		}
		projectReviewLogoutPGAssertTransaction(ctx, t, database, lookupHash, "confirmed", true)
		if err := database.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE target_type='logout_transaction' AND target_id=$1`, transaction.ID).Scan(&auditCount); err != nil {
			t.Fatal(err)
		}
		if auditCount != 1 {
			t.Fatalf("logout audit rows after retry = %d, want 1", auditCount)
		}
	})
}

func projectReviewLogoutPGInsertFixture(ctx context.Context, t *testing.T, database *sql.DB, withCascade bool) projectReviewLogoutPGFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	fixture := projectReviewLogoutPGFixture{
		userID: uuid.New(), sessionID: uuid.New(), bindingID: uuid.New(), clientID: uuid.New(), grantID: uuid.New(),
		familyID: uuid.New(), refreshID: uuid.New(), accessID: uuid.New(), now: now,
	}
	fixture.lookupToken = projectReviewLogoutPGToken("lt1_", "lookup:"+fixture.userID.String(), 0)
	fixture.csrfProofA = projectReviewLogoutPGToken("lc1_", "proof-a:"+fixture.userID.String(), 0)
	fixture.csrfProofB = projectReviewLogoutPGToken("lc1_", "proof-b:"+fixture.userID.String(), 0)
	fixture.sessionToken = projectReviewLogoutPGToken("s1_", "session:"+fixture.userID.String(), 0)
	_, err := database.ExecContext(ctx, `INSERT INTO users (id,subject,username,username_normalized,display_name,email,email_normalized,status,role,created_at,updated_at) VALUES ($1,$2,$3,$3,$4,$5,$5,'active','user',$6,$6)`, fixture.userID, "project-review-logout-subject-"+fixture.userID.String(), "project_review_"+fixture.userID.String()[:8], "Project Review", "project-review-"+fixture.userID.String()[:8]+"@example.invalid", now)
	if err != nil {
		t.Fatalf("insert logout user: %v", err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO login_sessions (id,user_id,token_hash,csrf_hash,csrf_expires_at,created_at,last_seen_at,authenticated_at,expires_at,idle_expires_at,user_agent_hash,ip_prefix,session_binding_id) VALUES ($1,$2,$3,$4,$5,$6,$6,$6,$7,$8,$9,$10,$11)`, fixture.sessionID, fixture.userID, session.HashToken(fixture.sessionToken), session.HashCSRF(projectReviewLogoutPGToken("c1_", "session-csrf", 0)), now.Add(time.Hour), now, now.Add(time.Hour), now.Add(30*time.Minute), sha256BytesProjectReviewLogout("user-agent"), "127.0.0.0/24", fixture.bindingID); err != nil {
		t.Fatalf("insert logout session: %v", err)
	}
	if withCascade {
		clientPublicID := "ois_cli_" + strings.ReplaceAll(fixture.clientID.String(), "-", "")
		if _, err := database.ExecContext(ctx, `INSERT INTO oidc_clients (id,client_id,client_type,token_endpoint_auth_method,name,created_at,updated_at) VALUES ($1,$2,'public','none','Project Review Client',$3,$3)`, fixture.clientID, clientPublicID, now); err != nil {
			t.Fatalf("insert logout client: %v", err)
		}
		if _, err := database.ExecContext(ctx, `INSERT INTO consent_grants (id,user_id,client_id,scopes,created_at,updated_at) VALUES ($1,$2,$3,ARRAY['offline_access','openid']::text[],$4,$4)`, fixture.grantID, fixture.userID, fixture.clientID, now); err != nil {
			t.Fatalf("insert logout grant: %v", err)
		}
		if _, err := database.ExecContext(ctx, `INSERT INTO refresh_token_families (id,consent_grant_id,user_id,client_id,origin_session_id,session_binding_id,scopes,created_at,absolute_expires_at) VALUES ($1,$2,$3,$4,$5,$6,ARRAY['offline_access','openid']::text[],$7,$8)`, fixture.familyID, fixture.grantID, fixture.userID, fixture.clientID, fixture.sessionID, fixture.bindingID, now, now.Add(24*time.Hour)); err != nil {
			t.Fatalf("insert logout refresh family: %v", err)
		}
		if _, err := database.ExecContext(ctx, `INSERT INTO refresh_tokens (id,family_id,token_hash,generation,issued_at,expires_at) VALUES ($1,$2,$3,0,$4,$5)`, fixture.refreshID, fixture.familyID, sha256BytesProjectReviewLogout("refresh:"+fixture.refreshID.String()), now, now.Add(time.Hour)); err != nil {
			t.Fatalf("insert logout refresh token: %v", err)
		}
		if _, err := database.ExecContext(ctx, `INSERT INTO access_tokens (id,jti_hash,authorization_code_id,consent_grant_id,user_id,client_id,scopes,issued_at,expires_at,issuance_source,source_refresh_token_id,refresh_family_id,origin_session_id,session_binding_id) VALUES ($1,$2,NULL,$3,$4,$5,ARRAY['offline_access','openid']::text[],$6,$7,'refresh_token',$8,$9,$10,$11)`, fixture.accessID, sha256BytesProjectReviewLogout("access:"+fixture.accessID.String()), fixture.grantID, fixture.userID, fixture.clientID, now, now.Add(10*time.Minute), fixture.refreshID, fixture.familyID, fixture.sessionID, fixture.bindingID); err != nil {
			t.Fatalf("insert logout access token: %v", err)
		}
	}
	return fixture
}

func projectReviewLogoutPGTransaction(fixture projectReviewLogoutPGFixture, lookupHash []byte) logoutdomain.Transaction {
	return logoutdomain.Transaction{ID: uuid.New(), LookupHash: lookupHash, Stage: logoutdomain.StagePreConfirm, CreatedAt: fixture.now, ExpiresAt: fixture.now.Add(5 * time.Minute)}
}

func projectReviewLogoutPGAssertTransaction(ctx context.Context, t *testing.T, database *sql.DB, lookupHash []byte, wantStage string, wantConsumed bool) {
	t.Helper()
	var stage string
	var consumed sql.NullTime
	if err := database.QueryRowContext(ctx, `SELECT stage,consumed_at FROM logout_transactions WHERE lookup_hash=$1`, lookupHash).Scan(&stage, &consumed); err != nil {
		t.Fatalf("query logout transaction: %v", err)
	}
	if stage != wantStage || consumed.Valid != wantConsumed {
		t.Fatalf("transaction stage=%q consumed=%v, want %q/%v", stage, consumed.Valid, wantStage, wantConsumed)
	}
}

func projectReviewLogoutPGToken(prefix, label string, index int) string {
	digest := sha256.Sum256([]byte(label + ":" + string(rune(index)) + ":project-review"))
	return prefix + base64.RawURLEncoding.EncodeToString(digest[:])
}

func sha256BytesProjectReviewLogout(value string) []byte {
	digest := sha256.Sum256([]byte(value))
	return digest[:]
}

func sameProjectReviewLogoutDigest(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
