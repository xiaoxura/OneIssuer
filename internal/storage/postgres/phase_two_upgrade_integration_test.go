package postgres_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"io/fs"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/authflow"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/session"
	"github.com/oneissuer/oneissuer/internal/storage/postgres"
	productionmigrations "github.com/oneissuer/oneissuer/migrations"
)

const (
	phaseTwoUpgradeDatabase = "oneissuer_phase_two_upgrade"
	phaseTwoPasswordHash    = "$argon2id$v=19$m=65536,t=3,p=2$YWJjZGVmZ2hpamtsbW5vcA$YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo"
	phaseTwoClientID        = "ois_cli_0123456789abcdefghijklmnopqrstuv"
	phaseTwoRedirectURI     = "https://phase-two-rp.example/callback"
	phaseTwoLogoutURI       = "https://phase-two-rp.example/logout"
)

var phaseTwoMigrationNames = []string{
	"00001_users_credentials.sql",
	"00002_oidc_clients.sql",
	"00003_login_sessions.sql",
	"00004_audit_events.sql",
	"00005_auth_transactions.sql",
}

type phaseTwoUpgradeFixture struct {
	userID           uuid.UUID
	clientID         uuid.UUID
	sessionID        uuid.UUID
	transactionID    uuid.UUID
	preAuthID        uuid.UUID
	auditID          uuid.UUID
	base             time.Time
	sessionToken     string
	transactionToken string
	sessionHash      []byte
	csrfHash         []byte
	transactionHash  []byte
	preAuthHash      []byte
}

func testPhaseTwoUpgrade(ctx context.Context, t *testing.T, adminDatabaseURL string) {
	t.Helper()
	upgradeURL := createPhaseTwoUpgradeDatabase(ctx, t, adminDatabaseURL)
	database := openSQLDatabase(ctx, t, upgradeURL)
	defer func() { _ = database.Close() }()

	if err := postgres.MigrateUp(ctx, database, phaseTwoMigrationFS(t), "."); err != nil {
		t.Fatalf("apply phase-two production migrations: %v", err)
	}
	assertMigrationVersion(ctx, t, database, 5)

	fixture := newPhaseTwoUpgradeFixture()
	insertPhaseTwoUpgradeFixture(ctx, t, database, fixture)
	assertPhaseTwoFixturePreserved(ctx, t, database, fixture)

	phaseTwoStore, err := postgres.Open(ctx, upgradeURL, 2)
	if err != nil {
		t.Fatalf("open phase-two store: %v", err)
	}
	if checkErr := phaseTwoStore.CheckMigrations(ctx); checkErr == nil || !strings.Contains(checkErr.Error(), "pending") {
		phaseTwoStore.Close()
		t.Fatalf("CheckMigrations() at phase two = %v, want pending", checkErr)
	}
	phaseTwoStore.Close()

	if err := postgres.MigrateUp(ctx, database, productionmigrations.FS, "."); err != nil {
		t.Fatalf("upgrade phase-two database to phase three: %v", err)
	}
	if err := postgres.MigrateUp(ctx, database, productionmigrations.FS, "."); err != nil {
		t.Fatalf("repeat phase-three migration after upgrade: %v", err)
	}
	assertMigrationVersion(ctx, t, database, 15)
	assertPhaseTwoFixturePreserved(ctx, t, database, fixture)
	assertPhaseTwoUpgradeIntroducesNoNewAuthority(ctx, t, database)
	assertPhaseTwoAuthorizationTerminal(ctx, t, database, fixture)
	assertPhaseThreeSchemaInstalled(ctx, t, database)

	upgradedStore, err := postgres.Open(ctx, upgradeURL, 4)
	if err != nil {
		t.Fatalf("open upgraded store: %v", err)
	}
	defer upgradedStore.Close()
	if err := upgradedStore.CheckMigrations(ctx); err != nil {
		t.Fatalf("CheckMigrations() after phase-two upgrade: %v", err)
	}
	assertPhaseTwoAuthorityUsable(ctx, t, upgradedStore, fixture)

	var status strings.Builder
	if err := postgres.RunMigrationCommand(ctx, upgradeURL, postgres.MigrationStatus, &status); err != nil {
		t.Fatalf("migration status after phase-two upgrade: %v", err)
	}
	if got := status.String(); !strings.Contains(got, "current_version=15 expected_version=15 status=current") {
		t.Fatalf("migration status after phase-two upgrade = %q", got)
	}
}

func createPhaseTwoUpgradeDatabase(ctx context.Context, t *testing.T, adminDatabaseURL string) string {
	t.Helper()
	admin := openSQLDatabase(ctx, t, adminDatabaseURL)
	defer func() { _ = admin.Close() }()
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE oneissuer_phase_two_upgrade`); err != nil {
		t.Fatalf("create isolated phase-two database: %v", err)
	}
	parsed, err := url.Parse(adminDatabaseURL)
	if err != nil {
		t.Fatalf("parse integration database URL: %v", err)
	}
	parsed.Path = "/" + phaseTwoUpgradeDatabase
	parsed.RawPath = ""
	return parsed.String()
}

func phaseTwoMigrationFS(t *testing.T) fs.FS {
	t.Helper()
	result := make(fstest.MapFS, len(phaseTwoMigrationNames))
	for _, name := range phaseTwoMigrationNames {
		data, err := fs.ReadFile(productionmigrations.FS, name)
		if err != nil {
			t.Fatalf("read embedded phase-two migration %s: %v", name, err)
		}
		result[name] = &fstest.MapFile{Data: data, Mode: 0o444}
	}
	return result
}

func newPhaseTwoUpgradeFixture() phaseTwoUpgradeFixture {
	base := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
	sessionToken := opaqueUpgradeToken("s1_", 0x31)
	transactionToken := opaqueUpgradeToken("t1_", 0x41)
	return phaseTwoUpgradeFixture{
		userID:           uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		clientID:         uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		sessionID:        uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		transactionID:    uuid.MustParse("44444444-4444-4444-8444-444444444444"),
		preAuthID:        uuid.MustParse("55555555-5555-4555-8555-555555555555"),
		auditID:          uuid.MustParse("66666666-6666-4666-8666-666666666666"),
		base:             base,
		sessionToken:     sessionToken,
		transactionToken: transactionToken,
		sessionHash:      session.HashToken(sessionToken),
		csrfHash:         session.HashCSRF(opaqueUpgradeToken("c1_", 0x32)),
		transactionHash:  authflow.HashToken(transactionToken),
		preAuthHash:      session.HashToken(opaqueUpgradeToken("p1_", 0x51)),
	}
}

func opaqueUpgradeToken(prefix string, fill byte) string {
	return prefix + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func insertPhaseTwoUpgradeFixture(ctx context.Context, t *testing.T, database *sql.DB, fixture phaseTwoUpgradeFixture) {
	t.Helper()
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin phase-two fixture transaction: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	exec := func(statement string, arguments ...any) {
		t.Helper()
		if _, execErr := tx.ExecContext(ctx, statement, arguments...); execErr != nil {
			t.Fatalf("insert phase-two fixture: %v", execErr)
		}
	}

	exec(`INSERT INTO users (
		id, subject, username, username_normalized, display_name, email, email_normalized,
		email_verified, status, role, created_at, updated_at, last_login_at
	) VALUES ($1, 'phase-two-subject-0001', 'phase-two-user', 'phase-two-user',
		'Phase Two User', 'Phase-Two@example.invalid', 'phase-two@example.invalid', true,
		'active', 'user', $2, $3, $4)`,
		fixture.userID, fixture.base, fixture.base.Add(time.Second), fixture.base.Add(2*time.Second))
	exec(`INSERT INTO credentials (user_id, credential_type, password_hash, created_at, updated_at)
		VALUES ($1, 'password', $2, $3, $4)`,
		fixture.userID, phaseTwoPasswordHash, fixture.base, fixture.base.Add(time.Second))
	exec(`INSERT INTO oidc_clients (
		id, client_id, client_type, token_endpoint_auth_method, name, description, logo_uri,
		status, registration_enabled, created_at, updated_at
	) VALUES ($1, $2, 'public', 'none', 'Phase Two RP', 'preserved description',
		'https://phase-two-rp.example/logo.png', 'active', true, $3, $4)`,
		fixture.clientID, phaseTwoClientID, fixture.base, fixture.base.Add(time.Second))
	exec(`INSERT INTO oidc_client_redirect_uris (client_id, uri, created_at) VALUES ($1, $2, $3)`,
		fixture.clientID, phaseTwoRedirectURI, fixture.base)
	exec(`INSERT INTO oidc_client_logout_uris (client_id, uri, created_at) VALUES ($1, $2, $3)`,
		fixture.clientID, phaseTwoLogoutURI, fixture.base)
	exec(`INSERT INTO oidc_client_scopes (client_id, scope, created_at)
		VALUES ($1, 'openid', $2), ($1, 'profile', $2)`, fixture.clientID, fixture.base)
	exec(`INSERT INTO login_sessions (
		id, user_id, token_hash, csrf_hash, csrf_expires_at, created_at, last_seen_at,
		authenticated_at, expires_at, idle_expires_at, user_agent_hash, ip_prefix
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, '192.0.2.0/24')`,
		fixture.sessionID, fixture.userID, fixture.sessionHash, fixture.csrfHash,
		fixture.base.Add(20*time.Minute), fixture.base.Add(3*time.Second), fixture.base.Add(4*time.Second),
		fixture.base.Add(3*time.Second), fixture.base.Add(24*time.Hour), fixture.base.Add(2*time.Hour), bytes.Repeat([]byte{0x33}, 32))
	exec(`INSERT INTO auth_transactions (
		id, token_hash, transaction_kind, client_id, redirect_uri, scopes,
		pkce_challenge, pkce_method, state_value, nonce_value, prompt_create, created_at, expires_at
	) VALUES ($1, $2, 'authorization', $3, $4, ARRAY['openid', 'profile']::text[],
		'legacy-phase-two-challenge', 'S256', '', '', true, $5, $6)`,
		fixture.transactionID, fixture.transactionHash, fixture.clientID, phaseTwoRedirectURI,
		fixture.base.Add(5*time.Second), fixture.base.Add(15*time.Minute))
	exec(`INSERT INTO preauth_sessions (
		id, token_hash, csrf_hash, auth_transaction_id, created_at, expires_at
	) VALUES ($1, $2, $3, $4, $5, $6)`,
		fixture.preAuthID, fixture.preAuthHash, fixture.csrfHash, fixture.transactionID,
		fixture.base.Add(6*time.Second), fixture.base.Add(10*time.Minute))
	exec(`INSERT INTO audit_events (
		id, event_type, result, actor_user_id, target_type, target_id,
		request_id, changed_fields, occurred_at
	) VALUES ($1, 'authorization_transaction_created', 'success', $2,
		'auth_transaction', $3, 'phase-two-upgrade', ARRAY[]::text[], $4)`,
		fixture.auditID, fixture.userID, fixture.transactionID, fixture.base.Add(5*time.Second))

	if err := tx.Commit(); err != nil {
		t.Fatalf("commit phase-two fixture: %v", err)
	}
}

func assertPhaseTwoFixturePreserved(ctx context.Context, t *testing.T, database *sql.DB, fixture phaseTwoUpgradeFixture) {
	t.Helper()
	var hardened bool
	if err := database.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema='public' AND table_name='users' AND column_name='version'
	)`).Scan(&hardened); err != nil {
		t.Fatalf("detect security-hardening schema: %v", err)
	}
	userVersionClause := ""
	clientVersionClause := ""
	preAuthAttemptClause := ""
	sessionBindingClause := ""
	if hardened {
		userVersionClause = " AND u.version=1"
		clientVersionClause = " AND version=1"
		preAuthAttemptClause = " AND attempt_count=0"
		sessionBindingClause = " AND session_binding_id=id"
	}

	assertUpgradeRow(ctx, t, database, "user and credential", `SELECT EXISTS (
		SELECT 1 FROM users u JOIN credentials c ON c.user_id=u.id
		WHERE u.id=$1 AND u.subject='phase-two-subject-0001'
		  AND u.username='phase-two-user' AND u.username_normalized='phase-two-user'
		  AND u.display_name='Phase Two User' AND u.email='Phase-Two@example.invalid'
		  AND u.email_normalized='phase-two@example.invalid' AND u.email_verified
		  AND u.status='active' AND u.role='user' AND u.created_at=$2
		  AND u.updated_at=$3 AND u.last_login_at=$4`+userVersionClause+`
		  AND c.credential_type='password' AND c.password_hash=$5
		  AND c.created_at=$2 AND c.updated_at=$3
	)`, fixture.userID, fixture.base, fixture.base.Add(time.Second), fixture.base.Add(2*time.Second), phaseTwoPasswordHash)
	assertUpgradeRow(ctx, t, database, "client", `SELECT EXISTS (
		SELECT 1 FROM oidc_clients
		WHERE id=$1 AND client_id=$2 AND client_type='public' AND token_endpoint_auth_method='none'
		  AND name='Phase Two RP' AND description='preserved description'
		  AND logo_uri='https://phase-two-rp.example/logo.png' AND status='active'
		  AND registration_enabled AND created_at=$3 AND updated_at=$4`+clientVersionClause+`
	)`, fixture.clientID, phaseTwoClientID, fixture.base, fixture.base.Add(time.Second))
	assertUpgradeRow(ctx, t, database, "client redirect URI", `SELECT
		count(*)=1 AND bool_and(uri=$2 AND created_at=$3)
		FROM oidc_client_redirect_uris WHERE client_id=$1`, fixture.clientID, phaseTwoRedirectURI, fixture.base)
	assertUpgradeRow(ctx, t, database, "client logout URI", `SELECT
		count(*)=1 AND bool_and(uri=$2 AND created_at=$3)
		FROM oidc_client_logout_uris WHERE client_id=$1`, fixture.clientID, phaseTwoLogoutURI, fixture.base)
	assertUpgradeRow(ctx, t, database, "client scopes", `SELECT
		count(*)=2 AND array_agg(scope ORDER BY scope)=ARRAY['openid','profile']::text[]
		  AND bool_and(created_at=$2)
		FROM oidc_client_scopes WHERE client_id=$1`, fixture.clientID, fixture.base)
	assertUpgradeRow(ctx, t, database, "login session", `SELECT EXISTS (
		SELECT 1 FROM login_sessions WHERE id=$1 AND user_id=$2 AND token_hash=$3 AND csrf_hash=$4
		  AND csrf_expires_at=$5 AND created_at=$6 AND last_seen_at=$7 AND authenticated_at=$6
		  AND expires_at=$8 AND idle_expires_at=$9 AND revoked_at IS NULL AND revoke_reason IS NULL
		  AND user_agent_hash=$10 AND ip_prefix='192.0.2.0/24'`+sessionBindingClause+`
	)`, fixture.sessionID, fixture.userID, fixture.sessionHash, fixture.csrfHash,
		fixture.base.Add(20*time.Minute), fixture.base.Add(3*time.Second), fixture.base.Add(4*time.Second),
		fixture.base.Add(24*time.Hour), fixture.base.Add(2*time.Hour), bytes.Repeat([]byte{0x33}, 32))
	assertUpgradeRow(ctx, t, database, "pre-auth session", `SELECT EXISTS (
		SELECT 1 FROM preauth_sessions WHERE id=$1 AND token_hash=$2 AND csrf_hash=$3
		  AND auth_transaction_id=$4 AND created_at=$5 AND expires_at=$6 AND consumed_at IS NULL`+preAuthAttemptClause+`
	)`, fixture.preAuthID, fixture.preAuthHash, fixture.csrfHash, fixture.transactionID,
		fixture.base.Add(6*time.Second), fixture.base.Add(10*time.Minute))
	assertUpgradeRow(ctx, t, database, "audit event", `SELECT EXISTS (
		SELECT 1 FROM audit_events WHERE id=$1 AND event_type='authorization_transaction_created'
		  AND result='success' AND actor_user_id=$2 AND target_type='auth_transaction'
		  AND target_id=$3 AND request_id='phase-two-upgrade' AND changed_fields=ARRAY[]::text[]
		  AND occurred_at=$4
	)`, fixture.auditID, fixture.userID, fixture.transactionID, fixture.base.Add(5*time.Second))
}

func assertPhaseTwoUpgradeIntroducesNoNewAuthority(ctx context.Context, t *testing.T, database *sql.DB) {
	t.Helper()
	assertUpgradeRow(ctx, t, database, "no fabricated phase-four authority", `SELECT
		NOT EXISTS (SELECT 1 FROM consent_grants)
		AND NOT EXISTS (SELECT 1 FROM authorization_codes)
		AND NOT EXISTS (SELECT 1 FROM access_tokens)
		AND NOT EXISTS (SELECT 1 FROM refresh_token_families)
		AND NOT EXISTS (SELECT 1 FROM refresh_tokens)
		AND NOT EXISTS (SELECT 1 FROM logout_transactions)`)
}

func assertPhaseTwoAuthorizationTerminal(ctx context.Context, t *testing.T, database *sql.DB, fixture phaseTwoUpgradeFixture) {
	t.Helper()
	assertUpgradeRow(ctx, t, database, "terminal phase-two authorization transaction", `SELECT EXISTS (
		SELECT 1 FROM auth_transactions
		WHERE id=$1 AND token_hash=$2 AND transaction_kind='authorization' AND client_id=$3
		  AND redirect_uri=$4 AND scopes=ARRAY['openid','profile']::text[]
		  AND pkce_challenge=repeat('A',43) AND pkce_method='S256'
		  AND state_value IS NULL AND nonce_value IS NULL AND prompt_create
		  AND response_type='code' AND response_mode='query'
		  AND prompt_values=ARRAY['create']::text[] AND max_age_seconds IS NULL
		  AND created_at=$5 AND expires_at=$6 AND consumed_at IS NOT NULL
		  AND consumed_at>=created_at AND failure_reason='invalid'
	)`, fixture.transactionID, fixture.transactionHash, fixture.clientID, phaseTwoRedirectURI,
		fixture.base.Add(5*time.Second), fixture.base.Add(15*time.Minute))
}

func assertPhaseThreeSchemaInstalled(ctx context.Context, t *testing.T, database *sql.DB) {
	t.Helper()
	assertUpgradeRow(ctx, t, database, "phase-three tables and constraints", `SELECT
		to_regclass('public.consent_grants') IS NOT NULL
		AND to_regclass('public.authorization_codes') IS NOT NULL
		AND to_regclass('public.access_tokens') IS NOT NULL
			AND (SELECT count(*) FROM information_schema.columns
				 WHERE table_schema='public' AND table_name='auth_transactions'
				   AND column_name IN ('response_type','response_mode','prompt_values','max_age_seconds'))=4
			AND (SELECT count(*) FROM information_schema.columns
				 WHERE table_schema='public' AND (
				   (table_name='users' AND column_name='version') OR
				   (table_name='oidc_clients' AND column_name='version') OR
				   (table_name='preauth_sessions' AND column_name='attempt_count')))=3
			AND (SELECT count(*) FROM pg_constraint WHERE conname IN (
				'auth_transactions_prompt_valid', 'auth_transactions_authorization_context',
				'consent_grants_scopes_valid', 'authorization_codes_pkce_valid',
				'access_tokens_scopes_valid', 'users_version_valid', 'oidc_clients_version_valid',
				'preauth_sessions_attempt_count_valid'))=8
			AND to_regclass('public.audit_events_code_exchange_rejection_target_idx') IS NOT NULL
			AND to_regclass('public.preauth_sessions_consumed_retirement_idx') IS NOT NULL
			AND to_regclass('public.login_sessions_revoked_retirement_idx') IS NOT NULL
			AND to_regclass('public.login_sessions_expiry_retirement_idx') IS NOT NULL
			AND to_regclass('public.login_sessions_idle_retirement_idx') IS NOT NULL
			AND to_regclass('public.auth_transactions_consumed_retirement_idx') IS NOT NULL
			AND to_regclass('public.authorization_codes_retirement_idx') IS NOT NULL
				AND (SELECT indisunique FROM pg_index
					 WHERE indexrelid='public.audit_events_code_exchange_rejection_target_idx'::regclass)`)
	assertUpgradeRow(ctx, t, database, "phase-four lifecycle tables and authority guards", `SELECT
		to_regclass('public.refresh_token_families') IS NOT NULL
		AND to_regclass('public.refresh_tokens') IS NOT NULL
		AND to_regclass('public.logout_transactions') IS NOT NULL
		AND to_regclass('public.refresh_token_families_terminal_retirement_idx') IS NOT NULL
		AND to_regclass('public.access_tokens_authorization_code_source_idx') IS NOT NULL
		AND to_regclass('public.audit_events_refresh_reuse_target_idx') IS NOT NULL
		AND EXISTS (SELECT 1 FROM pg_constraint WHERE conname='refresh_token_families_scopes_valid')
		AND EXISTS (SELECT 1 FROM pg_constraint WHERE conname='refresh_tokens_lifetime_valid')
		AND EXISTS (SELECT 1 FROM pg_constraint WHERE conname='access_tokens_source_valid')
		AND EXISTS (SELECT 1 FROM pg_constraint WHERE conname='logout_transactions_authority_stage_valid')
		AND EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='refresh_token_families_origin_guard' AND NOT tgisinternal)
		AND EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='refresh_tokens_lifetime_guard' AND NOT tgisinternal)
		AND EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='access_tokens_authority_guard' AND NOT tgisinternal)
		AND EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='access_tokens_immutable_source' AND NOT tgisinternal)`)
}

func assertPhaseTwoAuthorityUsable(ctx context.Context, t *testing.T, store *postgres.Store, fixture phaseTwoUpgradeFixture) {
	t.Helper()
	login, err := store.FindLoginRecord(ctx, "phase-two-user")
	if err != nil || login.User.ID != fixture.userID || login.User.Subject != "phase-two-subject-0001" ||
		login.User.DisplayName != "Phase Two User" || login.PasswordHash != phaseTwoPasswordHash {
		t.Fatalf("phase-two login authority after upgrade = %+v, error = %v", login, err)
	}
	clients := clientdomain.NewService(store, nil, false, nil)
	clientValue, err := clients.ResolveActive(ctx, phaseTwoClientID)
	if err != nil || clientValue.ID != fixture.clientID || clientValue.ClientID != phaseTwoClientID ||
		len(clientValue.RedirectURIs) != 1 || clientValue.RedirectURIs[0] != phaseTwoRedirectURI ||
		len(clientValue.Scopes) != 2 || clientValue.Scopes[0] != "openid" || clientValue.Scopes[1] != "profile" {
		t.Fatalf("phase-two client authority after upgrade = %+v, error = %v", clientValue, err)
	}
	tokens, err := session.NewTokenManager(nil, 24*time.Hour, 2*time.Hour, 15*time.Minute)
	if err != nil {
		t.Fatalf("create session token manager: %v", err)
	}
	principal, err := session.NewService(store, tokens).Authenticate(ctx, fixture.sessionToken, fixture.base.Add(2*time.Minute))
	if err != nil || principal.SessionID != fixture.sessionID || principal.User.ID != fixture.userID {
		t.Fatalf("phase-two session authority after upgrade = %+v, error = %v", principal, err)
	}
	transactions, err := authflow.NewService(store, nil, 10*time.Minute, nil)
	if err != nil {
		t.Fatalf("create authorization transaction service: %v", err)
	}
	if _, err := transactions.Resolve(ctx, fixture.transactionToken, fixture.base.Add(2*time.Minute)); !errors.Is(err, authflow.ErrConsumed) {
		t.Fatalf("Resolve() phase-two authorization after upgrade = %v, want ErrConsumed", err)
	}
}

func assertMigrationVersion(ctx context.Context, t *testing.T, database *sql.DB, want int64) {
	t.Helper()
	var got int64
	if err := database.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(version_id) FILTER (WHERE is_applied), 0)
		FROM (
			SELECT DISTINCT ON (version_id) version_id, is_applied
			FROM goose_db_version ORDER BY version_id, id DESC
		) AS latest`).Scan(&got); err != nil {
		t.Fatalf("read migration version: %v", err)
	}
	if got != want {
		t.Fatalf("migration version = %d, want %d", got, want)
	}
}

func assertUpgradeRow(ctx context.Context, t *testing.T, database *sql.DB, label, query string, arguments ...any) {
	t.Helper()
	var matched bool
	if err := database.QueryRowContext(ctx, query, arguments...).Scan(&matched); err != nil {
		t.Fatalf("verify %s: %v", label, err)
	}
	if !matched {
		t.Fatalf("phase-two %s was not preserved by the phase-three upgrade", label)
	}
}
