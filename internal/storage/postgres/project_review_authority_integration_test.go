package postgres_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/authn"
	"github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/identity"
	"github.com/oneissuer/oneissuer/internal/session"
	"github.com/oneissuer/oneissuer/internal/storage/postgres"
)

// projectReviewAuthorityFixture is intentionally assembled from the same
// digest-only rows that production protocol exchange writes. It lets the
// authentication transactions exercise their real PostgreSQL cascade without
// coupling these tests to JWT signing or a clear refresh token.
type projectReviewAuthorityFixture struct {
	clientID         uuid.UUID
	grantID          uuid.UUID
	offlineFamilyID  uuid.UUID
	offlineAccessID  uuid.UUID
	ordinaryAccessID uuid.UUID
}

// testProjectReviewAuthorityLifecycle is called by the shared integration
// harness after production migrations are applied. Keeping the helper here
// avoids starting a second PostgreSQL container for the project-review cases.
func testProjectReviewAuthorityLifecycle(ctx context.Context, t *testing.T, store *postgres.Store, databaseURL string) {
	t.Helper()
	database := openSQLDatabase(ctx, t, databaseURL)
	defer func() { _ = database.Close() }()
	services := newPhaseTwoServices(ctx, t, store)

	t.Run("ProjectReview account switch revokes old binding authority", func(t *testing.T) {
		at := time.Now().UTC().Truncate(time.Microsecond)
		oldSession, oldUser, _ := projectReviewRegister(ctx, t, services, "switch-a", at, "")
		fixture := projectReviewInsertAuthority(ctx, t, database, services, oldUser, oldSession, "switch-a", at, false)
		_, newUser, newPassword := projectReviewRegister(ctx, t, services, "switch-b", at.Add(2*time.Minute), "")
		newSession := projectReviewLogin(ctx, t, services, "switch-b", newUser, newPassword, oldSession.Token, at.Add(3*time.Minute))

		if newSession.Record.SessionBindingID == oldSession.Record.SessionBindingID {
			t.Fatalf("account-switch binding = %s, unexpectedly inherited old binding %s", newSession.Record.SessionBindingID, oldSession.Record.SessionBindingID)
		}
		_, revoked, reason := projectReviewSessionState(ctx, t, database, oldSession.Record.ID)
		if !revoked || reason != "account_switch" {
			t.Fatalf("old session revoked=%v reason=%q, want account_switch", revoked, reason)
		}
		assertProjectReviewSessionRevokeAudit(ctx, t, database, "project-review-login-switch-b", oldUser.ID, oldSession.Record.ID)
		familyRevoked, familyReason := projectReviewFamilyState(ctx, t, database, fixture.offlineFamilyID)
		if !familyRevoked || familyReason != "account_switch" {
			t.Fatalf("old family revoked=%v reason=%q, want account_switch", familyRevoked, familyReason)
		}
		accessRevoked, accessReason := projectReviewAccessState(ctx, t, database, fixture.offlineAccessID)
		if !accessRevoked || accessReason != "account_switch" {
			t.Fatalf("old binding Access revoked=%v reason=%q, want account_switch", accessRevoked, accessReason)
		}
		newBinding, newRevoked, newReason := projectReviewSessionState(ctx, t, database, newSession.Record.ID)
		if newBinding != newSession.Record.SessionBindingID || newRevoked || newReason != "" {
			t.Fatalf("new session binding=%s revoked=%v reason=%q, want fresh live session", newBinding, newRevoked, newReason)
		}
	})

	t.Run("ProjectReview same-user rotation preserves family binding", func(t *testing.T) {
		at := time.Now().UTC().Truncate(time.Microsecond).Add(10 * time.Minute)
		oldSession, user, password := projectReviewRegister(ctx, t, services, "rotation", at, "")
		fixture := projectReviewInsertAuthority(ctx, t, database, services, user, oldSession, "rotation", at, false)
		rotated := projectReviewLogin(ctx, t, services, "rotation", user, password, oldSession.Token, at.Add(2*time.Minute))

		if rotated.Record.SessionBindingID != oldSession.Record.SessionBindingID {
			t.Fatalf("same-user rotation binding=%s, want inherited %s", rotated.Record.SessionBindingID, oldSession.Record.SessionBindingID)
		}
		_, revoked, reason := projectReviewSessionState(ctx, t, database, oldSession.Record.ID)
		if !revoked || reason != "rotation" {
			t.Fatalf("rotated session revoked=%v reason=%q, want rotation", revoked, reason)
		}
		assertProjectReviewSessionRevokeAudit(ctx, t, database, "project-review-login-rotation", user.ID, oldSession.Record.ID)
		familyRevoked, familyReason := projectReviewFamilyState(ctx, t, database, fixture.offlineFamilyID)
		if familyRevoked || familyReason != "" {
			t.Fatalf("same-user family revoked=%v reason=%q, want live family", familyRevoked, familyReason)
		}
		accessRevoked, accessReason := projectReviewAccessState(ctx, t, database, fixture.offlineAccessID)
		if accessRevoked || accessReason != "" {
			t.Fatalf("same-user Access revoked=%v reason=%q, want live Access", accessRevoked, accessReason)
		}
	})

	t.Run("ProjectReview expired session neither inherits nor cascades", func(t *testing.T) {
		at := time.Now().UTC().Truncate(time.Microsecond).Add(20 * time.Minute)
		oldSession, user, password := projectReviewRegister(ctx, t, services, "expired", at, "")
		fixture := projectReviewInsertAuthority(ctx, t, database, services, user, oldSession, "expired", at, false)
		expires := oldSession.Record.CreatedAt.Add(5 * time.Second)
		if _, err := database.ExecContext(ctx, `UPDATE login_sessions SET expires_at=$2, idle_expires_at=$2 WHERE id=$1`, oldSession.Record.ID, expires); err != nil {
			t.Fatalf("expire old session fixture: %v", err)
		}
		fresh := projectReviewLogin(ctx, t, services, "expired", user, password, oldSession.Token, at.Add(2*time.Minute))
		if fresh.Record.SessionBindingID == oldSession.Record.SessionBindingID {
			t.Fatalf("expired candidate inherited binding %s", oldSession.Record.SessionBindingID)
		}
		_, revoked, reason := projectReviewSessionState(ctx, t, database, oldSession.Record.ID)
		if revoked || reason != "" {
			t.Fatalf("expired old session revoked=%v reason=%q, want untouched", revoked, reason)
		}
		familyRevoked, familyReason := projectReviewFamilyState(ctx, t, database, fixture.offlineFamilyID)
		if familyRevoked || familyReason != "" {
			t.Fatalf("expired candidate family revoked=%v reason=%q, want live family", familyRevoked, familyReason)
		}
		accessRevoked, accessReason := projectReviewAccessState(ctx, t, database, fixture.offlineAccessID)
		if accessRevoked || accessReason != "" {
			t.Fatalf("expired candidate Access revoked=%v reason=%q, want live Access", accessRevoked, accessReason)
		}
	})

	t.Run("ProjectReview registration switch atomically cascades old authority", func(t *testing.T) {
		at := time.Now().UTC().Truncate(time.Microsecond).Add(30 * time.Minute)
		oldSession, oldUser, _ := projectReviewRegister(ctx, t, services, "registration-a", at, "")
		fixture := projectReviewInsertAuthority(ctx, t, database, services, oldUser, oldSession, "registration-a", at, false)
		newSession, newUser, _ := projectReviewRegister(ctx, t, services, "registration-b", at.Add(2*time.Minute), oldSession.Token)
		if newUser.ID == oldUser.ID || newSession.Record.SessionBindingID == oldSession.Record.SessionBindingID {
			t.Fatalf("registration switch user=%s binding=%s unexpectedly reused old identity/binding", newUser.ID, newSession.Record.SessionBindingID)
		}
		_, revoked, reason := projectReviewSessionState(ctx, t, database, oldSession.Record.ID)
		if !revoked || reason != "account_switch" {
			t.Fatalf("registration old session revoked=%v reason=%q, want account_switch", revoked, reason)
		}
		assertProjectReviewSessionRevokeAudit(ctx, t, database, "project-review-register-registration-b", oldUser.ID, oldSession.Record.ID)
		familyRevoked, familyReason := projectReviewFamilyState(ctx, t, database, fixture.offlineFamilyID)
		if !familyRevoked || familyReason != "account_switch" {
			t.Fatalf("registration old family revoked=%v reason=%q, want account_switch", familyRevoked, familyReason)
		}
		accessRevoked, accessReason := projectReviewAccessState(ctx, t, database, fixture.offlineAccessID)
		if !accessRevoked || accessReason != "account_switch" {
			t.Fatalf("registration old Access revoked=%v reason=%q, want account_switch", accessRevoked, accessReason)
		}
	})

	t.Run("ProjectReview offline scope removal leaves code-only Access live", func(t *testing.T) {
		at := time.Now().UTC().Truncate(time.Microsecond).Add(40 * time.Minute)
		sessionValue, user, _ := projectReviewRegister(ctx, t, services, "scope-removal", at, "")
		fixture := projectReviewInsertAuthority(ctx, t, database, services, user, sessionValue, "scope-removal", at, true)
		updated, _, err := services.clients.Update(ctx, user.ID, fixture.clientID, client.UpdateInput{
			Scopes: projectReviewStringSlice([]string{"openid", "profile"}),
		}, "project-review-offline-scope-removal", at.Add(2*time.Minute))
		if err != nil {
			t.Fatalf("remove offline_access scope: %v", err)
		}
		if updated.Status != client.StatusActive {
			t.Fatalf("scope-removal client status=%q, want active", updated.Status)
		}
		familyRevoked, familyReason := projectReviewFamilyState(ctx, t, database, fixture.offlineFamilyID)
		if !familyRevoked || familyReason != "offline_scope_removed" {
			t.Fatalf("offline family revoked=%v reason=%q, want offline_scope_removed", familyRevoked, familyReason)
		}
		offlineAccessRevoked, offlineAccessReason := projectReviewAccessState(ctx, t, database, fixture.offlineAccessID)
		if !offlineAccessRevoked || offlineAccessReason != "offline_scope_removed" {
			t.Fatalf("family-linked Access revoked=%v reason=%q, want offline_scope_removed", offlineAccessRevoked, offlineAccessReason)
		}
		ordinaryAccessRevoked, ordinaryAccessReason := projectReviewAccessState(ctx, t, database, fixture.ordinaryAccessID)
		if ordinaryAccessRevoked || ordinaryAccessReason != "" {
			t.Fatalf("code-only Access revoked=%v reason=%q, want live after scope removal", ordinaryAccessRevoked, ordinaryAccessReason)
		}

		status := client.StatusDisabled
		if _, _, err := services.clients.Update(ctx, user.ID, fixture.clientID, client.UpdateInput{Status: &status}, "project-review-client-disable", at.Add(3*time.Minute)); err != nil {
			t.Fatalf("disable client after scope removal: %v", err)
		}
		ordinaryAccessRevoked, ordinaryAccessReason = projectReviewAccessState(ctx, t, database, fixture.ordinaryAccessID)
		if !ordinaryAccessRevoked || ordinaryAccessReason != "client_disabled" {
			t.Fatalf("client-disabled code-only Access revoked=%v reason=%q, want client_disabled", ordinaryAccessRevoked, ordinaryAccessReason)
		}
	})

	t.Run("ProjectReview registration audit failure rolls back identity and cascade", func(t *testing.T) {
		at := time.Now().UTC().Truncate(time.Microsecond).Add(50 * time.Minute)
		oldSession, oldUser, _ := projectReviewRegister(ctx, t, services, "rollback-a", at, "")
		fixture := projectReviewInsertAuthority(ctx, t, database, services, oldUser, oldSession, "rollback-a", at, false)
		projectReviewInstallRegistrationAuditFailure(ctx, t, database)
		const requestID = "project-review-registration-rollback"
		_, _, _, err := projectReviewRegisterResult(ctx, services, "rollback-b", at.Add(2*time.Minute), oldSession.Token, requestID)
		if err == nil {
			t.Fatal("registration unexpectedly succeeded with audit failure trigger")
		}
		var users, sessions int
		if queryErr := database.QueryRowContext(ctx, `SELECT count(*)::int FROM users WHERE username_normalized=$1`, "project-review-rollback-b").Scan(&users); queryErr != nil {
			t.Fatalf("count rolled-back user: %v", queryErr)
		}
		if queryErr := database.QueryRowContext(ctx, `SELECT count(*)::int FROM login_sessions WHERE user_id IN (SELECT id FROM users WHERE username_normalized=$1)`, "project-review-rollback-b").Scan(&sessions); queryErr != nil {
			t.Fatalf("count rolled-back user sessions: %v", queryErr)
		}
		if users != 0 || sessions != 0 {
			t.Fatalf("failed registration left users=%d sessions=%d", users, sessions)
		}
		_, revoked, reason := projectReviewSessionState(ctx, t, database, oldSession.Record.ID)
		if revoked || reason != "" {
			t.Fatalf("failed registration changed old session revoked=%v reason=%q", revoked, reason)
		}
		familyRevoked, familyReason := projectReviewFamilyState(ctx, t, database, fixture.offlineFamilyID)
		if familyRevoked || familyReason != "" {
			t.Fatalf("failed registration changed old family revoked=%v reason=%q", familyRevoked, familyReason)
		}
		accessRevoked, accessReason := projectReviewAccessState(ctx, t, database, fixture.offlineAccessID)
		if accessRevoked || accessReason != "" {
			t.Fatalf("failed registration changed old Access revoked=%v reason=%q", accessRevoked, accessReason)
		}
	})

	t.Run("ProjectReview batch cascade preserves current and foreign bindings", func(t *testing.T) {
		testProjectReviewBatchCascadeBoundaries(ctx, t, services, database)
	})

	t.Run("ProjectReview concurrent session and client revocation follows lock order", func(t *testing.T) {
		testProjectReviewConcurrentRevocation(ctx, t, services, database)
	})
}

func projectReviewStringSlice(value []string) *[]string { return &value }

func projectReviewRegister(ctx context.Context, t *testing.T, services phaseTwoServices, label string, at time.Time, existingSessionToken string, requestIDs ...string) (session.Issued, identity.User, string) {
	t.Helper()
	requestID := "project-review-register-" + label
	if len(requestIDs) > 0 {
		requestID = requestIDs[0]
	}
	issued, user, password, err := projectReviewRegisterResult(ctx, services, label, at, existingSessionToken, requestID)
	if err != nil {
		t.Fatalf("Register(%s): %v", label, err)
	}
	return issued, user, password
}

func projectReviewRegisterResult(ctx context.Context, services phaseTwoServices, label string, at time.Time, existingSessionToken, requestID string) (session.Issued, identity.User, string, error) {
	password := "project-review-" + label + "-password"
	begin, err := services.authn.Begin(ctx, authn.BeginRegister, "", requestID, at)
	if err != nil {
		return session.Issued{}, identity.User{}, password, err
	}
	issued, err := services.authn.Register(ctx, authn.RegisterInput{
		PreAuthToken: begin.PreAuth.Token, CSRFToken: begin.PreAuth.CSRFToken,
		TransactionToken: begin.TransactionToken,
		Account: identity.CreateInput{
			Username:    "project-review-" + label,
			DisplayName: "Project Review " + label,
			Email:       "project-review-" + label + "@example.invalid", Password: password,
		},
		ExistingSessionToken: existingSessionToken,
		RequestID:            requestID,
	}, at.Add(time.Second))
	if err != nil {
		return session.Issued{}, identity.User{}, password, err
	}
	principal, err := services.sessions.Authenticate(ctx, issued.Token, at.Add(1500*time.Millisecond))
	if err != nil {
		return session.Issued{}, identity.User{}, password, err
	}
	return issued, principal.User, password, nil
}

func projectReviewLogin(ctx context.Context, t *testing.T, services phaseTwoServices, label string, user identity.User, password, existingSessionToken string, at time.Time) session.Issued {
	t.Helper()
	requestID := "project-review-login-" + label
	begin, err := services.authn.Begin(ctx, authn.BeginLogin, "", requestID, at)
	if err != nil {
		t.Fatalf("Begin(login %s): %v", label, err)
	}
	issued, loggedIn, err := services.authn.Login(ctx, authn.LoginInput{
		PreAuthToken: begin.PreAuth.Token, CSRFToken: begin.PreAuth.CSRFToken,
		TransactionToken: begin.TransactionToken, Identifier: user.Username, Password: password,
		ExistingSessionToken: existingSessionToken, RequestID: requestID,
	}, at.Add(time.Second))
	if err != nil {
		t.Fatalf("Login(%s): %v", label, err)
	}
	if loggedIn.ID != user.ID {
		t.Fatalf("Login(%s) user=%s, want %s", label, loggedIn.ID, user.ID)
	}
	return issued
}

func projectReviewInsertAuthority(ctx context.Context, t *testing.T, database *sql.DB, services phaseTwoServices, user identity.User, issued session.Issued, label string, at time.Time, includeOrdinary bool) projectReviewAuthorityFixture {
	t.Helper()
	redirectURI := "https://project-review-" + label + ".example/callback"
	created, err := services.clients.Create(ctx, user.ID, client.CreateInput{
		Type: client.TypePublic, Name: "Project Review " + label, RegistrationEnabled: true,
		RedirectURIs: []string{redirectURI}, Scopes: []string{"offline_access", "openid", "profile"},
	}, "project-review-client-"+label, at)
	if err != nil {
		t.Fatalf("create authority fixture client %s: %v", label, err)
	}
	fixture := projectReviewAuthorityFixture{
		clientID: created.Client.ID, grantID: uuid.New(), offlineFamilyID: uuid.New(),
		offlineAccessID: uuid.New(), ordinaryAccessID: uuid.New(),
	}
	offlineTransactionID := uuid.New()
	offlineCodeID := uuid.New()
	offlineTokenHash := projectReviewDigest("transaction-" + label + "-offline")
	offlineCodeHash := projectReviewDigest("code-" + label + "-offline")
	offlineFamilyTokenID := uuid.New()
	offlineFamilyTokenHash := projectReviewDigest("refresh-" + label)
	offlineAccessJTIHash := projectReviewDigest("access-" + label + "-offline")
	ordinaryTransactionID := uuid.New()
	ordinaryCodeID := uuid.New()
	ordinaryTokenHash := projectReviewDigest("transaction-" + label + "-ordinary")
	ordinaryCodeHash := projectReviewDigest("code-" + label + "-ordinary")
	ordinaryAccessJTIHash := projectReviewDigest("access-" + label + "-ordinary")
	exec, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin authority fixture %s: %v", label, err)
	}
	defer func() { _ = exec.Rollback() }()
	run := func(statement string, args ...any) {
		t.Helper()
		if _, execErr := exec.ExecContext(ctx, statement, args...); execErr != nil {
			t.Fatalf("insert authority fixture %s: %v", label, execErr)
		}
	}
	scopes := "ARRAY['offline_access','openid','profile']::text[]"
	run(`INSERT INTO consent_grants (id, user_id, client_id, scopes, created_at, updated_at)
		VALUES ($1, $2, $3, `+scopes+`, $4, $4)`, fixture.grantID, user.ID, fixture.clientID, at)
	run(`INSERT INTO auth_transactions (
		id, token_hash, transaction_kind, client_id, redirect_uri, scopes,
		pkce_challenge, pkce_method, state_value, nonce_value, prompt_create,
		response_type, response_mode, prompt_values, created_at, expires_at
	) VALUES ($1, $2, 'authorization', $3, $4, `+scopes+`, repeat('A', 43), 'S256', $5, $6,
		false, 'code', 'query', ARRAY[]::text[], $7, $8)`, offlineTransactionID, offlineTokenHash[:], fixture.clientID, redirectURI,
		"state-"+label+"-offline", "nonce-"+label+"-offline", at, at.Add(4*time.Minute))
	run(`INSERT INTO authorization_codes (
		id, code_hash, auth_transaction_id, consent_grant_id, user_id, client_id,
		redirect_uri, scopes, pkce_challenge, pkce_method, nonce_value,
		auth_time, created_at, expires_at, consent_grant_version,
		origin_session_id, session_binding_id
	) VALUES ($1, $2, $3, $4, $5, $6, $7, `+scopes+`, repeat('A', 43), 'S256', $8,
		$9, $9, $10, 1, $11, $12)`, offlineCodeID, offlineCodeHash[:], offlineTransactionID, fixture.grantID,
		user.ID, fixture.clientID, redirectURI, "nonce-"+label+"-offline", at, at.Add(2*time.Minute), issued.Record.ID, issued.Record.SessionBindingID)
	run(`INSERT INTO refresh_token_families (
		id, origin_authorization_code_id, consent_grant_id, user_id, client_id,
		origin_session_id, session_binding_id, scopes, created_at, absolute_expires_at
	) VALUES ($1, $2, $3, $4, $5, $6, $7, `+scopes+`, $8, $9)`, fixture.offlineFamilyID, offlineCodeID,
		fixture.grantID, user.ID, fixture.clientID, issued.Record.ID, issued.Record.SessionBindingID, at, at.Add(24*time.Hour))
	run(`INSERT INTO refresh_tokens (id, family_id, token_hash, generation, issued_at, expires_at)
		VALUES ($1, $2, $3, 0, $4, $5)`, offlineFamilyTokenID, fixture.offlineFamilyID, offlineFamilyTokenHash[:], at, at.Add(23*time.Hour))
	run(`INSERT INTO access_tokens (
		id, jti_hash, authorization_code_id, consent_grant_id, user_id, client_id,
		scopes, issued_at, expires_at, issuance_source, refresh_family_id,
		origin_session_id, session_binding_id
	) VALUES ($1, $2, $3, $4, $5, $6, `+scopes+`, $7, $8, 'authorization_code', $9, $10, $11)`, fixture.offlineAccessID,
		offlineAccessJTIHash[:], offlineCodeID, fixture.grantID, user.ID, fixture.clientID,
		at, at.Add(10*time.Minute), fixture.offlineFamilyID, issued.Record.ID, issued.Record.SessionBindingID)
	if includeOrdinary {
		ordinaryScopes := "ARRAY['openid']::text[]"
		run(`INSERT INTO auth_transactions (
			id, token_hash, transaction_kind, client_id, redirect_uri, scopes,
			pkce_challenge, pkce_method, state_value, nonce_value, prompt_create,
			response_type, response_mode, prompt_values, created_at, expires_at
		) VALUES ($1, $2, 'authorization', $3, $4, `+ordinaryScopes+`, repeat('B', 43), 'S256', $5, $6,
			false, 'code', 'query', ARRAY[]::text[], $7, $8)`, ordinaryTransactionID, ordinaryTokenHash[:], fixture.clientID, redirectURI,
			"state-"+label+"-ordinary", "nonce-"+label+"-ordinary", at, at.Add(4*time.Minute))
		run(`INSERT INTO authorization_codes (
			id, code_hash, auth_transaction_id, consent_grant_id, user_id, client_id,
			redirect_uri, scopes, pkce_challenge, pkce_method, nonce_value,
			auth_time, created_at, expires_at, consent_grant_version,
			origin_session_id, session_binding_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, `+ordinaryScopes+`, repeat('B', 43), 'S256', $8,
			$9, $9, $10, 1, NULL, NULL)`, ordinaryCodeID, ordinaryCodeHash[:], ordinaryTransactionID, fixture.grantID,
			user.ID, fixture.clientID, redirectURI, "nonce-"+label+"-ordinary", at, at.Add(2*time.Minute))
		run(`INSERT INTO access_tokens (
			id, jti_hash, authorization_code_id, consent_grant_id, user_id, client_id,
			scopes, issued_at, expires_at, issuance_source, refresh_family_id,
			origin_session_id, session_binding_id
		) VALUES ($1, $2, $3, $4, $5, $6, `+ordinaryScopes+`, $7, $8, 'authorization_code', NULL, NULL, NULL)`, fixture.ordinaryAccessID,
			ordinaryAccessJTIHash[:], ordinaryCodeID, fixture.grantID, user.ID, fixture.clientID,
			at, at.Add(10*time.Minute))
	}
	if err := exec.Commit(); err != nil {
		t.Fatalf("commit authority fixture %s: %v", label, err)
	}
	return fixture
}

func projectReviewDigest(value string) [32]byte {
	return sha256.Sum256([]byte("project-review:" + value))
}

func projectReviewSessionState(ctx context.Context, t *testing.T, database *sql.DB, id uuid.UUID) (uuid.UUID, bool, string) {
	t.Helper()
	var binding uuid.UUID
	var revoked sql.NullTime
	var reason sql.NullString
	if err := database.QueryRowContext(ctx, `SELECT session_binding_id, revoked_at, revoke_reason FROM login_sessions WHERE id=$1`, id).Scan(&binding, &revoked, &reason); err != nil {
		t.Fatalf("read session %s: %v", id, err)
	}
	return binding, revoked.Valid, reason.String
}

func projectReviewFamilyState(ctx context.Context, t *testing.T, database *sql.DB, id uuid.UUID) (bool, string) {
	t.Helper()
	var revoked sql.NullTime
	var reason sql.NullString
	if err := database.QueryRowContext(ctx, `SELECT revoked_at, revoke_reason FROM refresh_token_families WHERE id=$1`, id).Scan(&revoked, &reason); err != nil {
		t.Fatalf("read refresh family %s: %v", id, err)
	}
	return revoked.Valid, reason.String
}

func projectReviewAccessState(ctx context.Context, t *testing.T, database *sql.DB, id uuid.UUID) (bool, string) {
	t.Helper()
	var revoked sql.NullTime
	var reason sql.NullString
	if err := database.QueryRowContext(ctx, `SELECT revoked_at, revoke_reason FROM access_tokens WHERE id=$1`, id).Scan(&revoked, &reason); err != nil {
		t.Fatalf("read Access metadata %s: %v", id, err)
	}
	return revoked.Valid, reason.String
}

func assertProjectReviewSessionRevokeAudit(ctx context.Context, t *testing.T, database *sql.DB, requestID string, actorID, targetID uuid.UUID) {
	t.Helper()
	var count int
	if err := database.QueryRowContext(ctx, `SELECT count(*)::int
		FROM audit_events
		WHERE event_type='session_revoked' AND result='success' AND request_id=$1
		  AND target_type='session' AND target_id=$2`, requestID, targetID).Scan(&count); err != nil {
		t.Fatalf("count account-switch audit request %q: %v", requestID, err)
	}
	if count != 1 {
		t.Fatalf("session-revoked audit request %q count=%d, want one", requestID, count)
	}
	var persistedActor, persistedTarget uuid.UUID
	var targetType string
	if err := database.QueryRowContext(ctx, `SELECT actor_user_id, target_type, target_id
		FROM audit_events
		WHERE event_type='session_revoked' AND result='success' AND request_id=$1
		  AND target_type='session' AND target_id=$2`, requestID, targetID).Scan(&persistedActor, &targetType, &persistedTarget); err != nil {
		t.Fatalf("read account-switch audit request %q: %v", requestID, err)
	}
	if persistedActor != actorID || targetType != "session" || persistedTarget != targetID {
		t.Fatalf("session-revoked audit request %q actor=%s target=%s/%s, want actor=%s target=session/%s", requestID, persistedActor, targetType, persistedTarget, actorID, targetID)
	}
}

func projectReviewInstallRegistrationAuditFailure(ctx context.Context, t *testing.T, database *sql.DB) {
	t.Helper()
	if _, err := database.ExecContext(ctx, `
		CREATE FUNCTION oneissuer_project_review_reject_registration_audit() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.event_type = 'session_revoked' AND NEW.request_id = 'project-review-registration-rollback' THEN
				RAISE EXCEPTION 'project-review registration audit failure' USING ERRCODE = '55000';
			END IF;
			RETURN NEW;
		END
		$$`); err != nil {
		t.Fatalf("create registration audit failure function: %v", err)
	}
	if _, err := database.ExecContext(ctx, `
		CREATE TRIGGER oneissuer_project_review_reject_registration_audit
		BEFORE INSERT ON audit_events
		FOR EACH ROW EXECUTE FUNCTION oneissuer_project_review_reject_registration_audit()`); err != nil {
		t.Fatalf("create registration audit failure trigger: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = database.ExecContext(cleanupCtx, `DROP TRIGGER IF EXISTS oneissuer_project_review_reject_registration_audit ON audit_events`)
		_, _ = database.ExecContext(cleanupCtx, `DROP FUNCTION IF EXISTS oneissuer_project_review_reject_registration_audit()`)
	})
}
