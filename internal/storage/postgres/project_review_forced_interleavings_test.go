package postgres_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/admin"
	"github.com/oneissuer/oneissuer/internal/audit"
	"github.com/oneissuer/oneissuer/internal/authflow"
	"github.com/oneissuer/oneissuer/internal/authorization"
	"github.com/oneissuer/oneissuer/internal/identity"
	"github.com/oneissuer/oneissuer/internal/storage/postgres"
	tokendomain "github.com/oneissuer/oneissuer/internal/token"
	"github.com/testcontainers/testcontainers-go"
)

var forcedInterleavingLockSequence int64 = 730000000

type forcedInterleavingBarrier struct {
	database   *sql.DB
	blocker    *sql.Conn
	key        int64
	table      string
	function   string
	trigger    string
	held       bool
	returnExpr string
}

// TestProjectReviewForcedInterleavings runs each cross-authority race against a
// fresh real PostgreSQL container. Every operation is allowed to reach a
// database trigger waiter before the test releases the next lock interval.
func TestProjectReviewForcedInterleavingsIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PostgreSQL integration test in short mode")
	}
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	container, databaseURL := startPostgres(ctx, t)
	defer func() {
		terminateCtx, terminateCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer terminateCancel()
		if err := testcontainers.TerminateContainer(container, testcontainers.StopContext(terminateCtx)); err != nil {
			t.Errorf("terminate PostgreSQL container: %v", err)
		}
	}()

	if err := postgres.RunMigrationCommand(ctx, databaseURL, postgres.MigrationUp, io.Discard); err != nil {
		t.Fatalf("run production migrations: %v", err)
	}
	database := openSQLDatabase(ctx, t, databaseURL)
	defer func() {
		if err := database.Close(); err != nil && !t.Failed() {
			t.Errorf("close PostgreSQL database: %v", err)
		}
	}()
	store, err := postgres.Open(ctx, databaseURL, 16)
	if err != nil {
		t.Fatalf("open PostgreSQL store: %v", err)
	}
	defer store.Close()
	services := newPhaseTwoServices(ctx, t, store)

	t.Run("refresh rotation and reuse versus user disable", func(t *testing.T) {
		testForcedRefreshDisableInterleaving(ctx, t, store, database, services)
	})
	t.Run("authorization code commit versus grant revoke", func(t *testing.T) {
		testForcedAuthorizationGrantInterleaving(ctx, t, store, database, services)
	})
	t.Run("protocol and refresh cleanup versus consumed refresh reuse", func(t *testing.T) {
		testForcedCleanupReuseInterleaving(ctx, t, store, database, services)
	})
}

func testForcedRefreshDisableInterleaving(ctx context.Context, t *testing.T, store *postgres.Store, database *sql.DB, services phaseTwoServices) {
	t.Helper()
	base := time.Now().UTC().Truncate(time.Microsecond)
	issued, user, _ := projectReviewRegister(ctx, t, services, "forced-refresh-disable", base, "")
	fixture := projectReviewInsertAuthority(ctx, t, database, services, user, issued, "forced-refresh-disable", base, false)
	clientValue, err := store.GetClient(ctx, fixture.clientID)
	if err != nil {
		t.Fatalf("load refresh fixture client: %v", err)
	}
	refreshDigest := projectReviewDigest("refresh-forced-refresh-disable")

	// The fixture has one deterministic generation, so the rotation barrier can
	// target the production ConsumeRefreshToken UPDATE directly.
	var generationID uuid.UUID
	if err := database.QueryRowContext(ctx, `SELECT id FROM refresh_tokens WHERE token_hash=$1`, refreshDigest[:]).Scan(&generationID); err != nil {
		t.Fatalf("load refresh generation id: %v", err)
	}
	rotationBarrier := installForcedInterleavingBarrier(ctx, t, database, "refresh_tokens", "UPDATE OF consumed_at", "NEW.id = '"+generationID.String()+"'::uuid", "NEW", "rotation")
	disableBarrier := installForcedInterleavingBarrier(ctx, t, database, "refresh_token_families", "UPDATE OF revoked_at", "NEW.id = '"+fixture.offlineFamilyID.String()+"'::uuid", "NEW", "disable")

	disableAt := base.Add(5 * time.Second)
	disabled := identity.StatusDisabled
	currentUser, err := store.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("reload user before disable update: %v", err)
	}
	updated, changed, err := services.identities.PrepareUpdate(currentUser, identity.UpdateInput{Status: &disabled}, disableAt)
	if err != nil {
		t.Fatalf("prepare user disable: %v", err)
	}
	statusEvent, err := audit.New(audit.UserStatusChanged, audit.ResultSuccess, &user.ID, audit.TargetUser, &user.ID, "forced-refresh-disable-user", changed, disableAt)
	if err != nil {
		t.Fatalf("create user disable audit: %v", err)
	}
	sessionEvent, err := audit.New(audit.SessionsRevokedAll, audit.ResultSuccess, &user.ID, audit.TargetUser, &user.ID, "forced-refresh-disable-user", []string{"revoked"}, disableAt)
	if err != nil {
		t.Fatalf("create session disable audit: %v", err)
	}
	disableCommit := admin.UpdateUserCommit{
		Actor: user.ID, Updated: updated, Changed: changed, RevokeSessions: true,
		Event: statusEvent, SessionEvent: &sessionEvent,
	}

	raceCtx, raceCancel := context.WithTimeout(ctx, 20*time.Second)
	defer raceCancel()
	type rotationResult struct {
		response tokendomain.Response
		err      error
	}
	rotationResults := make(chan rotationResult, 1)
	disableResults := make(chan error, 1)
	reuseResults := make(chan error, 1)
	reuseMintCalled := false
	var raceWG sync.WaitGroup
	mint := forcedRefreshMint
	raceWG.Add(1)
	go func() {
		defer raceWG.Done()
		response, exchangeErr := store.ExchangeRefreshToken(raceCtx, tokendomain.RefreshInput{
			TokenHash: refreshDigest[:], Client: clientValue, RequestID: "forced-refresh-rotation", Now: base.Add(time.Second),
		}, mint)
		rotationResults <- rotationResult{response: response, err: exchangeErr}
	}()
	if err := rotationBarrier.wait(raceCtx); err != nil {
		_ = rotationBarrier.release(context.Background())
		raceCancel()
		raceWG.Wait()
		t.Fatalf("rotation did not enter generation critical section: %v", err)
	}

	raceWG.Add(1)
	go func() {
		defer raceWG.Done()
		_, disableErr := store.UpdateManagedUser(raceCtx, disableCommit)
		disableResults <- disableErr
	}()
	if err := waitForForcedSQLWaiter(raceCtx, database, "FROM users"); err != nil {
		_ = rotationBarrier.release(context.Background())
		_ = disableBarrier.release(context.Background())
		raceCancel()
		raceWG.Wait()
		t.Fatalf("disable did not enter user lock interval: %v", err)
	}
	rotationBarrier.releaseOrFatal(t)
	if err := disableBarrier.wait(raceCtx); err != nil {
		_ = disableBarrier.release(context.Background())
		raceCancel()
		raceWG.Wait()
		t.Fatalf("disable did not enter family revocation critical section: %v", err)
	}
	// While disable owns the User row and is paused at its family update, a
	// reuse attempt must enter its own transaction and wait on that User lock.
	raceWG.Add(1)
	go func() {
		defer raceWG.Done()
		_, reuseErr := store.ExchangeRefreshToken(raceCtx, tokendomain.RefreshInput{
			TokenHash: refreshDigest[:], Client: clientValue, RequestID: "forced-refresh-reuse-after-disable", Now: disableAt.Add(time.Second),
		}, func(context.Context, tokendomain.RefreshAuthority) (tokendomain.RefreshMinted, error) {
			reuseMintCalled = true
			return tokendomain.RefreshMinted{}, errors.New("refresh reuse invoked mint callback after user disable")
		})
		reuseResults <- reuseErr
	}()
	if err := waitForForcedSQLWaiter(raceCtx, database, "FROM users"); err != nil {
		_ = disableBarrier.release(context.Background())
		_ = rotationBarrier.release(context.Background())
		raceCancel()
		raceWG.Wait()
		t.Fatalf("refresh reuse did not enter User lock interval: %v", err)
	}
	disableBarrier.releaseOrFatal(t)
	raceWG.Wait()
	rotation := <-rotationResults
	disableErr := <-disableResults
	reuseErr := <-reuseResults
	if rotation.err != nil {
		t.Fatalf("forced refresh rotation error: %v", rotation.err)
	}
	if rotation.response.RefreshToken == "" {
		t.Fatal("forced refresh rotation returned no replacement token")
	}
	if disableErr != nil {
		t.Fatalf("forced user disable error: %v", disableErr)
	}
	if !errors.Is(reuseErr, tokendomain.ErrInvalidGrant) || reuseMintCalled {
		t.Fatalf("refresh reuse after disable error=%v mint_called=%v, want invalid grant without mint", reuseErr, reuseMintCalled)
	}

	var userStatus, familyReason string
	var familyRevoked bool
	var liveAccess, replacementCount int
	if err := database.QueryRowContext(ctx, `SELECT users.status, families.revoked_at IS NOT NULL,
		families.revoke_reason, (SELECT count(*) FROM access_tokens WHERE refresh_family_id=families.id AND revoked_at IS NULL),
		(SELECT count(*) FROM refresh_tokens WHERE family_id=families.id)
		FROM users JOIN refresh_token_families AS families ON families.user_id=users.id WHERE users.id=$1 AND families.id=$2`, user.ID, fixture.offlineFamilyID).
		Scan(&userStatus, &familyRevoked, &familyReason, &liveAccess, &replacementCount); err != nil {
		t.Fatalf("inspect refresh/disable terminal state: %v", err)
	}
	if userStatus != string(identity.StatusDisabled) || !familyRevoked || familyReason != "user_disabled" || liveAccess != 0 || replacementCount != 2 {
		t.Fatalf("refresh/disable terminal state user=%q family=%v/%q live_access=%d generations=%d", userStatus, familyRevoked, familyReason, liveAccess, replacementCount)
	}
	var rotatedAudits, statusAudits, reuseAudits int
	if err := database.QueryRowContext(ctx, `SELECT
		count(*) FILTER (WHERE event_type='refresh_token_rotated' AND request_id='forced-refresh-rotation'),
		count(*) FILTER (WHERE event_type='user_status_changed' AND request_id='forced-refresh-disable-user'),
		count(*) FILTER (WHERE event_type='refresh_token_reuse_detected' AND request_id='forced-refresh-reuse-after-disable')
		FROM audit_events`).Scan(&rotatedAudits, &statusAudits, &reuseAudits); err != nil {
		t.Fatalf("inspect refresh/disable audit: %v", err)
	}
	if rotatedAudits != 1 || statusAudits != 1 || reuseAudits != 0 {
		t.Fatalf("refresh/disable audits rotated=%d status=%d reuse=%d", rotatedAudits, statusAudits, reuseAudits)
	}
	disableAccessHash := projectReviewDigest("access-forced-refresh-disable-offline")
	if _, err := store.GetAccessTokenAuthority(ctx, disableAccessHash[:], disableAt); !errors.Is(err, tokendomain.ErrInvalidToken) {
		t.Fatalf("disabled user's original Access authority error=%v, want invalid token", err)
	}
}

func testForcedAuthorizationGrantInterleaving(ctx context.Context, t *testing.T, store *postgres.Store, database *sql.DB, services phaseTwoServices) {
	t.Helper()
	base := time.Now().UTC().Truncate(time.Microsecond)
	issued, user, _ := projectReviewRegister(ctx, t, services, "forced-code-grant", base, "")
	fixture := projectReviewInsertAuthority(ctx, t, database, services, user, issued, "forced-code-grant", base, false)
	clientValue, err := store.GetClient(ctx, fixture.clientID)
	if err != nil {
		t.Fatalf("load authorization fixture client: %v", err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE consent_grants SET scopes=ARRAY['offline_access','openid']::text[] WHERE id=$1`, fixture.grantID); err != nil {
		t.Fatalf("narrow authorization fixture grant: %v", err)
	}
	verifier := strings.Repeat("v", 43)
	challengeDigest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeDigest[:])
	_, transaction, err := services.transactions.CreateVerified(ctx, authflow.VerifiedInput{
		ClientID: fixture.clientID, RedirectURI: "https://project-review-forced-code-grant.example/callback",
		Scopes: []string{"offline_access", "openid", "profile"}, PKCEChallenge: challenge,
		State: "forced-state", Nonce: "forced-nonce", ResponseType: "code", ResponseMode: "query",
	}, "forced-code-transaction", base)
	if err != nil {
		t.Fatalf("create authorization transaction fixture: %v", err)
	}
	issueBarrier := installForcedInterleavingBarrier(ctx, t, database, "consent_grants", "UPDATE OF scopes", "NEW.id = '"+fixture.grantID.String()+"'::uuid", "NEW", "issue")
	revokeBarrier := installForcedInterleavingBarrier(ctx, t, database, "consent_grants", "UPDATE OF revoked_at", "NEW.id = '"+fixture.grantID.String()+"'::uuid", "NEW", "revoke")
	revokeCtx, revokeCancel := context.WithTimeout(ctx, 20*time.Second)
	defer revokeCancel()
	type issueResult struct {
		issued authorization.Issued
		err    error
	}
	issueResults := make(chan issueResult, 1)
	revokeResults := make(chan error, 1)
	var raceWG sync.WaitGroup
	raceWG.Add(1)
	go func() {
		defer raceWG.Done()
		code, issueErr := services.authorization.Issue(revokeCtx, transaction, user.ID, issued.Record.ID, issued.Record.SessionBindingID, issued.Record.CreatedAt, true, "forced-code-issue", base.Add(time.Second))
		issueResults <- issueResult{issued: code, err: issueErr}
	}()
	if err := issueBarrier.wait(revokeCtx); err != nil {
		_ = issueBarrier.release(context.Background())
		revokeCancel()
		raceWG.Wait()
		t.Fatalf("authorization issue did not enter grant update critical section: %v", err)
	}

	raceWG.Add(1)
	go func() {
		defer raceWG.Done()
		_, revokeErr := services.consents.RevokeMine(revokeCtx, user.ID, clientValue.ClientID, "forced-code-revoke", base.Add(2*time.Second))
		revokeResults <- revokeErr
	}()
	if err := waitForForcedSQLWaiter(revokeCtx, database, "FROM users"); err != nil {
		_ = issueBarrier.release(context.Background())
		_ = revokeBarrier.release(context.Background())
		revokeCancel()
		raceWG.Wait()
		t.Fatalf("grant revoke did not enter grant lock interval: %v", err)
	}
	issueBarrier.releaseOrFatal(t)
	if err := revokeBarrier.wait(revokeCtx); err != nil {
		_ = revokeBarrier.release(context.Background())
		revokeCancel()
		raceWG.Wait()
		t.Fatalf("grant revoke did not enter grant update critical section: %v", err)
	}
	revokeBarrier.releaseOrFatal(t)
	raceWG.Wait()
	issue := <-issueResults
	revokeErr := <-revokeResults
	if issue.err != nil {
		t.Fatalf("forced authorization issue error: %v", issue.err)
	}
	if revokeErr != nil {
		t.Fatalf("forced grant revoke error: %v", revokeErr)
	}

	// The Code was committed before the revoke, but the current Grant authority
	// must still reject exchange and must not leave an Access half-commit.
	mintCalled := false
	exchangeResponse, exchangeErr := store.ExchangeAuthorizationCode(ctx, tokendomain.ExchangeInput{
		CodeHash: authorization.HashCode(issue.issued.Code), Client: clientValue,
		RedirectURI: transaction.RedirectURI, CodeVerifier: verifier,
		RequestID: "forced-code-exchange-after-revoke", Now: base.Add(3 * time.Second),
	}, func(context.Context, tokendomain.Authority) (tokendomain.Minted, error) {
		mintCalled = true
		return tokendomain.Minted{}, errors.New("mint must not run after grant revoke")
	})
	if !errors.Is(exchangeErr, tokendomain.ErrInvalidGrant) || exchangeResponse != (tokendomain.Response{}) || mintCalled {
		t.Fatalf("exchange after grant revoke response=%+v error=%v mint_called=%v", exchangeResponse, exchangeErr, mintCalled)
	}
	var grantRevoked, codeConsumed, familyRevoked bool
	var codeCount, codeAccessCount, familyLiveAccess int
	if err := database.QueryRowContext(ctx, `SELECT grants.revoked_at IS NOT NULL,
		codes.consumed_at IS NOT NULL, count_codes.value, count_access.value,
		(SELECT revoked_at IS NOT NULL FROM refresh_token_families WHERE id=$3),
		(SELECT count(*)::int FROM access_tokens WHERE refresh_family_id=$3 AND revoked_at IS NULL)
		FROM consent_grants AS grants
		JOIN authorization_codes AS codes ON codes.id=$2
		CROSS JOIN (SELECT count(*)::int AS value FROM authorization_codes WHERE id=$2) AS count_codes
		CROSS JOIN (SELECT count(*)::int AS value FROM access_tokens WHERE authorization_code_id=$2) AS count_access
		WHERE grants.id=$1`, fixture.grantID, issue.issued.CodeID, fixture.offlineFamilyID).Scan(&grantRevoked, &codeConsumed, &codeCount, &codeAccessCount, &familyRevoked, &familyLiveAccess); err != nil {
		t.Fatalf("inspect code/grant terminal state: %v", err)
	}
	if !grantRevoked || codeConsumed || codeCount != 1 || codeAccessCount != 0 || !familyRevoked || familyLiveAccess != 0 {
		t.Fatalf("code/grant terminal state grant_revoked=%v code_consumed=%v code_rows=%d access_rows=%d family_revoked=%v family_live_access=%d", grantRevoked, codeConsumed, codeCount, codeAccessCount, familyRevoked, familyLiveAccess)
	}
	var issuedAudits, revokeAudits, exchangeRejectAudits int
	if err := database.QueryRowContext(ctx, `SELECT
		count(*) FILTER (WHERE event_type='authorization_code_issued' AND request_id='forced-code-issue'),
		count(*) FILTER (WHERE event_type='consent_grant_revoked' AND request_id='forced-code-revoke'),
		count(*) FILTER (WHERE event_type='authorization_code_exchange_rejected' AND request_id='forced-code-exchange-after-revoke')
		FROM audit_events`).Scan(&issuedAudits, &revokeAudits, &exchangeRejectAudits); err != nil {
		t.Fatalf("inspect code/grant audit: %v", err)
	}
	// A revoked Grant is rejected before Code replay handling, so this
	// fail-closed exchange intentionally emits no replay audit.
	if issuedAudits != 1 || revokeAudits != 1 || exchangeRejectAudits != 0 {
		t.Fatalf("code/grant audits issued=%d revoked=%d exchange_rejected=%d", issuedAudits, revokeAudits, exchangeRejectAudits)
	}
}

func testForcedCleanupReuseInterleaving(ctx context.Context, t *testing.T, store *postgres.Store, database *sql.DB, services phaseTwoServices) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	fixtureAt := now.Add(-3 * time.Hour)
	issued, user, _ := projectReviewRegister(ctx, t, services, "forced-cleanup-reuse", fixtureAt, "")
	fixture := projectReviewInsertAuthority(ctx, t, database, services, user, issued, "forced-cleanup-reuse", fixtureAt, false)
	refreshDigest := projectReviewDigest("refresh-forced-cleanup-reuse")
	cleanupClient, err := store.GetClient(ctx, fixture.clientID)
	if err != nil {
		t.Fatalf("load cleanup/reuse fixture client: %v", err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE refresh_tokens SET consumed_at=$2 WHERE token_hash=$1`, refreshDigest[:], fixtureAt.Add(time.Hour)); err != nil {
		t.Fatalf("consume cleanup/reuse fixture generation: %v", err)
	}
	// Protocol cleanup deletes the old origin Code first. Detaching that
	// optional FK keeps the cleanup transaction from holding the family row
	// while the reuse transaction reaches its own family UPDATE barrier.
	if _, err := database.ExecContext(ctx, `UPDATE refresh_token_families SET origin_authorization_code_id=NULL WHERE id=$1`, fixture.offlineFamilyID); err != nil {
		t.Fatalf("detach cleanup/reuse family origin code: %v", err)
	}
	staleFamilyID, staleTokenID := uuid.New(), uuid.New()
	staleCreated := now.Add(-72 * time.Hour)
	staleAbsolute := now.Add(-2 * time.Hour)
	staleRevoked := staleCreated.Add(time.Minute)
	staleHash := projectReviewDigest("stale-refresh-forced-cleanup-reuse")
	if _, err := database.ExecContext(ctx, `INSERT INTO refresh_token_families (
		id, consent_grant_id, user_id, client_id, session_binding_id, scopes,
		created_at, absolute_expires_at, revoked_at, revoke_reason
	) VALUES ($1,$2,$3,$4,$5,ARRAY['offline_access','openid']::text[],$6,$7,$8,'reuse')`, staleFamilyID, fixture.grantID, user.ID, fixture.clientID, issued.Record.SessionBindingID, staleCreated, staleAbsolute, staleRevoked); err != nil {
		t.Fatalf("insert stale cleanup family: %v", err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO refresh_tokens (
		id, family_id, token_hash, generation, issued_at, expires_at, consumed_at
	) VALUES ($1,$2,$3,0,$4,$5,$6)`, staleTokenID, staleFamilyID, staleHash[:], staleCreated, staleAbsolute.Add(-time.Hour), staleAbsolute.Add(-90*time.Minute)); err != nil {
		t.Fatalf("insert stale cleanup generation: %v", err)
	}

	protocolBarrier := installForcedInterleavingBarrier(ctx, t, database, "access_tokens", "DELETE", "OLD.id = '"+fixture.offlineAccessID.String()+"'::uuid", "OLD", "protocol-cleanup")
	refreshBarrier := installForcedInterleavingBarrier(ctx, t, database, "refresh_tokens", "DELETE", "OLD.id = '"+staleTokenID.String()+"'::uuid", "OLD", "refresh-cleanup")
	reuseBarrier := installForcedInterleavingBarrier(ctx, t, database, "refresh_token_families", "UPDATE OF revoked_at", "NEW.id = '"+fixture.offlineFamilyID.String()+"'::uuid", "NEW", "reuse")
	raceCtx, raceCancel := context.WithTimeout(ctx, 20*time.Second)
	defer raceCancel()
	type cleanupResult struct {
		name    string
		deleted int64
		err     error
	}
	cleanupResults := make(chan cleanupResult, 2)
	reuseResults := make(chan error, 1)
	var raceWG sync.WaitGroup
	raceWG.Add(1)
	go func() {
		defer raceWG.Done()
		deleted, cleanupErr := store.CleanupProtocolArtifacts(raceCtx, now.Add(-30*time.Minute))
		cleanupResults <- cleanupResult{name: "protocol", deleted: deleted, err: cleanupErr}
	}()
	if err := protocolBarrier.wait(raceCtx); err != nil {
		_ = protocolBarrier.release(context.Background())
		raceCancel()
		raceWG.Wait()
		t.Fatalf("protocol cleanup did not enter Access deletion critical section: %v", err)
	}

	raceWG.Add(1)
	go func() {
		defer raceWG.Done()
		deleted, cleanupErr := store.CleanupRefreshArtifacts(raceCtx, now.Add(-time.Hour))
		cleanupResults <- cleanupResult{name: "refresh", deleted: deleted, err: cleanupErr}
	}()
	if err := refreshBarrier.wait(raceCtx); err != nil {
		_ = protocolBarrier.release(context.Background())
		_ = refreshBarrier.release(context.Background())
		raceCancel()
		raceWG.Wait()
		t.Fatalf("refresh cleanup did not enter generation deletion critical section: %v", err)
	}

	raceWG.Add(1)
	go func() {
		defer raceWG.Done()
		_, reuseErr := store.ExchangeRefreshToken(raceCtx, tokendomain.RefreshInput{
			TokenHash: refreshDigest[:], Client: cleanupClient,
			RequestID: "forced-cleanup-reuse", Now: now,
		}, func(context.Context, tokendomain.RefreshAuthority) (tokendomain.RefreshMinted, error) {
			return tokendomain.RefreshMinted{}, errors.New("consumed refresh reuse invoked mint callback")
		})
		reuseResults <- reuseErr
	}()
	if err := reuseBarrier.wait(raceCtx); err != nil {
		_ = protocolBarrier.release(context.Background())
		_ = refreshBarrier.release(context.Background())
		_ = reuseBarrier.release(context.Background())
		raceCancel()
		raceWG.Wait()
		t.Fatalf("consumed refresh reuse did not enter family revocation critical section: %v", err)
	}
	// Reuse has locked and is revoking the family; protocol cleanup owns the
	// Access row lock until its trigger is released. Releasing in this order
	// proves the two transactions serialize without a deadlock.
	reuseBarrier.releaseOrFatal(t)
	protocolBarrier.releaseOrFatal(t)
	refreshBarrier.releaseOrFatal(t)
	raceWG.Wait()
	reuseErr := <-reuseResults
	if !errors.Is(reuseErr, tokendomain.ErrInvalidGrant) {
		t.Fatalf("consumed refresh reuse error=%v, want invalid grant", reuseErr)
	}
	results := make(map[string]cleanupResult, 2)
	for range 2 {
		result := <-cleanupResults
		results[result.name] = result
	}
	if results["protocol"].err != nil || results["protocol"].deleted == 0 {
		t.Fatalf("protocol cleanup result=%+v, want committed deletion", results["protocol"])
	}
	if results["refresh"].err != nil || results["refresh"].deleted < 2 {
		t.Fatalf("refresh cleanup result=%+v, want generation and family deletion", results["refresh"])
	}

	var familyRevoked bool
	var liveAccess, generationCount, staleFamilyCount, staleTokenCount int
	var familyReason string
	if err := database.QueryRowContext(ctx, `SELECT families.revoked_at IS NOT NULL, families.revoke_reason,
		(SELECT count(*) FROM access_tokens WHERE refresh_family_id=families.id AND revoked_at IS NULL),
		(SELECT count(*) FROM refresh_tokens WHERE family_id=families.id),
		(SELECT count(*) FROM refresh_token_families WHERE id=$2),
		(SELECT count(*) FROM refresh_tokens WHERE id=$3)
		FROM refresh_token_families AS families WHERE families.id=$1`, fixture.offlineFamilyID, staleFamilyID, staleTokenID).
		Scan(&familyRevoked, &familyReason, &liveAccess, &generationCount, &staleFamilyCount, &staleTokenCount); err != nil {
		t.Fatalf("inspect cleanup/reuse terminal state: %v", err)
	}
	if !familyRevoked || familyReason != "reuse" || liveAccess != 0 || generationCount != 1 || staleFamilyCount != 0 || staleTokenCount != 0 {
		t.Fatalf("cleanup/reuse terminal state family=%v/%q live_access=%d generations=%d stale_family=%d stale_token=%d", familyRevoked, familyReason, liveAccess, generationCount, staleFamilyCount, staleTokenCount)
	}
	var reuseAudits, familyAudits int
	if err := database.QueryRowContext(ctx, `SELECT
		count(*) FILTER (WHERE event_type='refresh_token_reuse_detected' AND request_id='forced-cleanup-reuse'),
		count(*) FILTER (WHERE event_type='refresh_token_family_revoked' AND request_id='forced-cleanup-reuse')
		FROM audit_events`).Scan(&reuseAudits, &familyAudits); err != nil {
		t.Fatalf("inspect cleanup/reuse audit: %v", err)
	}
	if reuseAudits != 1 || familyAudits != 1 {
		t.Fatalf("cleanup/reuse audits reuse=%d family_revoked=%d", reuseAudits, familyAudits)
	}
	cleanupAccessHash := projectReviewDigest("access-forced-cleanup-reuse-offline")
	if _, err := store.GetAccessTokenAuthority(ctx, cleanupAccessHash[:], now); !errors.Is(err, tokendomain.ErrInvalidToken) {
		t.Fatalf("cleaned/revoked Access authority error=%v, want invalid token", err)
	}
}

func forcedRefreshMint(_ context.Context, authority tokendomain.RefreshAuthority) (tokendomain.RefreshMinted, error) {
	clearToken, digest, err := tokendomain.GenerateRefreshToken(rand.Reader)
	if err != nil {
		return tokendomain.RefreshMinted{}, err
	}
	issuedAt := authority.IssuedAt.UTC()
	jtiHash := projectReviewDigest("forced-refresh-replacement-jti")
	return tokendomain.RefreshMinted{
		AccessTokenID: uuid.New(), JTIHash: jtiHash[:],
		AccessToken: "forced-access-token", IssuedAt: issuedAt, AccessExpiresAt: issuedAt.Add(10 * time.Minute),
		ReplacementTokenID: uuid.New(), ReplacementTokenHash: digest, ReplacementClearToken: clearToken,
		ReplacementExpiresAt: issuedAt.Add(time.Hour),
	}, nil
}

func installForcedInterleavingBarrier(ctx context.Context, t *testing.T, database *sql.DB, table, operation, condition, returnExpr, label string) *forcedInterleavingBarrier {
	t.Helper()
	key := atomic.AddInt64(&forcedInterleavingLockSequence, 1)
	suffix := strings.ReplaceAll(uuid.New().String(), "-", "")[:16]
	safeLabel := strings.NewReplacer("-", "_", " ", "_").Replace(label)
	functionName := "oneissuer_forced_" + safeLabel + "_fn_" + suffix
	triggerName := "oneissuer_forced_" + safeLabel + "_trg_" + suffix
	blocker, err := database.Conn(ctx)
	if err != nil {
		t.Fatalf("reserve %s barrier connection: %v", label, err)
	}
	barrier := &forcedInterleavingBarrier{database: database, blocker: blocker, key: key, table: table, function: functionName, trigger: triggerName, held: true, returnExpr: returnExpr}
	if _, err := blocker.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, key); err != nil {
		_ = blocker.Close()
		t.Fatalf("acquire %s barrier lock: %v", label, err)
	}
	functionSQL := fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	IF %s THEN
		PERFORM pg_advisory_xact_lock(%d);
	END IF;
	RETURN %s;
END
$$`, functionName, condition, key, returnExpr)
	if _, err := database.ExecContext(ctx, functionSQL); err != nil {
		_, _ = blocker.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, key)
		_ = blocker.Close()
		t.Fatalf("create %s barrier function: %v", label, err)
	}
	triggerSQL := fmt.Sprintf("CREATE TRIGGER %s BEFORE %s ON %s FOR EACH ROW EXECUTE FUNCTION %s()", triggerName, operation, table, functionName)
	if _, err := database.ExecContext(ctx, triggerSQL); err != nil {
		_, _ = blocker.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, key)
		_ = blocker.Close()
		_, _ = database.ExecContext(context.Background(), fmt.Sprintf("DROP FUNCTION IF EXISTS %s()", functionName))
		t.Fatalf("create %s barrier trigger: %v", label, err)
	}
	t.Cleanup(func() { barrier.cleanup() })
	return barrier
}

func (barrier *forcedInterleavingBarrier) wait(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting int
		err := barrier.database.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE NOT granted)::int
			FROM pg_locks WHERE locktype='advisory' AND objid::bigint=$1`, barrier.key).Scan(&waiting)
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

func (barrier *forcedInterleavingBarrier) release(ctx context.Context) error {
	if barrier == nil || !barrier.held || barrier.blocker == nil {
		return nil
	}
	_, err := barrier.blocker.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, barrier.key)
	if err == nil {
		barrier.held = false
	}
	return err
}

func (barrier *forcedInterleavingBarrier) releaseOrFatal(t *testing.T) {
	t.Helper()
	if err := barrier.release(context.Background()); err != nil {
		t.Fatalf("release barrier %s: %v", barrier.trigger, err)
	}
}

func (barrier *forcedInterleavingBarrier) cleanup() {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = barrier.release(cleanupCtx)
	if barrier.blocker != nil {
		_ = barrier.blocker.Close()
	}
	if barrier.database != nil {
		_, _ = barrier.database.ExecContext(cleanupCtx, fmt.Sprintf("DROP TRIGGER IF EXISTS %s ON %s", barrier.trigger, barrier.table))
		_, _ = barrier.database.ExecContext(cleanupCtx, fmt.Sprintf("DROP FUNCTION IF EXISTS %s()", barrier.function))
	}
}

func waitForForcedSQLWaiter(ctx context.Context, database *sql.DB, queryFragment string) error {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		err := database.QueryRowContext(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_stat_activity
			WHERE datname=current_database() AND state='active' AND wait_event_type='Lock'
			AND query LIKE '%' || $1 || '%'
		)`, queryFragment).Scan(&waiting)
		if err != nil {
			return err
		}
		if waiting {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
