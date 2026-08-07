package postgres_test

import (
	"bytes"
	"context"
	"database/sql"
	"io/fs"
	"net/url"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/storage/postgres"
	productionmigrations "github.com/oneissuer/oneissuer/migrations"
)

const projectReviewSchemaDatabase = "oneissuer_project_review_schema"

var projectReviewSchema11MigrationNames = []string{
	"00001_users_credentials.sql",
	"00002_oidc_clients.sql",
	"00003_login_sessions.sql",
	"00004_audit_events.sql",
	"00005_auth_transactions.sql",
	"00006_phase_three_protocol_events.sql",
	"00007_auth_transaction_protocol_context.sql",
	"00008_consent_grants.sql",
	"00009_authorization_codes.sql",
	"00010_access_tokens.sql",
	"00011_security_hardening.sql",
}

type projectReviewSchemaFixture struct {
	activeUserID       uuid.UUID
	expiredUserID      uuid.UUID
	clientID           uuid.UUID
	activeSessionID    uuid.UUID
	expiredSessionID   uuid.UUID
	activeGrantID      uuid.UUID
	expiredGrantID     uuid.UUID
	activeTransaction  uuid.UUID
	expiredTransaction uuid.UUID
	activeCodeID       uuid.UUID
	expiredCodeID      uuid.UUID
	activeAccessID     uuid.UUID
	expiredAccessID    uuid.UUID
	base               time.Time
}

// testProjectReviewSchema exercises the populated upgrade boundary separately
// from the phase-two fixture. It starts at schema 11 so every row that existed
// before Phase Four is present while migrations 12-15 run.
func testProjectReviewSchema(ctx context.Context, t *testing.T, adminDatabaseURL string) {
	t.Helper()
	upgradeURL := createProjectReviewSchemaDatabase(ctx, t, adminDatabaseURL)
	database := openSQLDatabase(ctx, t, upgradeURL)
	defer func() { _ = database.Close() }()

	if err := postgres.MigrateUp(ctx, database, projectReviewSchema11MigrationFS(t), "."); err != nil {
		t.Fatalf("apply schema-11 migrations: %v", err)
	}
	assertMigrationVersion(ctx, t, database, 11)

	fixture := newProjectReviewSchemaFixture()
	insertProjectReviewSchemaFixture(ctx, t, database, fixture)
	assertProjectReviewSchema11Fixture(ctx, t, database, fixture)

	if err := postgres.MigrateUp(ctx, database, productionmigrations.FS, "."); err != nil {
		t.Fatalf("upgrade populated schema 11 to schema 15: %v", err)
	}
	if err := postgres.MigrateUp(ctx, database, productionmigrations.FS, "."); err != nil {
		t.Fatalf("repeat schema-15 migration: %v", err)
	}
	assertMigrationVersion(ctx, t, database, 15)
	assertProjectReviewSchema15Upgrade(ctx, t, database, fixture)

	testProjectReviewMigration15(ctx, t, database, fixture)
	testProjectReviewProtocolCleanup(ctx, t, database, upgradeURL, fixture)
}

func createProjectReviewSchemaDatabase(ctx context.Context, t *testing.T, adminDatabaseURL string) string {
	t.Helper()
	admin := openSQLDatabase(ctx, t, adminDatabaseURL)
	defer func() { _ = admin.Close() }()
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+projectReviewSchemaDatabase); err != nil {
		t.Fatalf("create isolated project-review database: %v", err)
	}
	parsed, err := url.Parse(adminDatabaseURL)
	if err != nil {
		t.Fatalf("parse integration database URL: %v", err)
	}
	parsed.Path = "/" + projectReviewSchemaDatabase
	parsed.RawPath = ""
	return parsed.String()
}

func projectReviewSchema11MigrationFS(t *testing.T) fs.FS {
	t.Helper()
	result := make(fstest.MapFS, len(projectReviewSchema11MigrationNames))
	for _, name := range projectReviewSchema11MigrationNames {
		data, err := fs.ReadFile(productionmigrations.FS, name)
		if err != nil {
			t.Fatalf("read schema-11 migration %s: %v", name, err)
		}
		result[name] = &fstest.MapFile{Data: data, Mode: 0o444}
	}
	return result
}

func newProjectReviewSchemaFixture() projectReviewSchemaFixture {
	base := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
	return projectReviewSchemaFixture{
		activeUserID:       uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		expiredUserID:      uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		clientID:           uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		activeSessionID:    uuid.MustParse("44444444-4444-4444-8444-444444444444"),
		expiredSessionID:   uuid.MustParse("55555555-5555-4555-8555-555555555555"),
		activeGrantID:      uuid.MustParse("66666666-6666-4666-8666-666666666666"),
		expiredGrantID:     uuid.MustParse("77777777-7777-4777-8777-777777777777"),
		activeTransaction:  uuid.MustParse("88888888-8888-4888-8888-888888888888"),
		expiredTransaction: uuid.MustParse("99999999-9999-4999-8999-999999999999"),
		activeCodeID:       uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
		expiredCodeID:      uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
		activeAccessID:     uuid.MustParse("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
		expiredAccessID:    uuid.MustParse("dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
		base:               base,
	}
}

func insertProjectReviewSchemaFixture(ctx context.Context, t *testing.T, database *sql.DB, fixture projectReviewSchemaFixture) {
	t.Helper()
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin schema-11 fixture transaction: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	exec := func(statement string, arguments ...any) {
		t.Helper()
		if _, execErr := tx.ExecContext(ctx, statement, arguments...); execErr != nil {
			t.Fatalf("insert schema-11 fixture: %v", execErr)
		}
	}

	activeUserCreated := fixture.base.Add(-2 * time.Hour)
	expiredUserCreated := fixture.base.Add(-4 * time.Hour)
	exec(`INSERT INTO users (
		id, subject, username, username_normalized, display_name, email, email_normalized,
		email_verified, status, role, created_at, updated_at, last_login_at
	) VALUES ($1, $2, $3, $3, $4, $5, $6, true, 'active', 'user', $7, $8, $9),
	         ($10, $11, $12, $12, $13, $14, $15, true, 'active', 'user', $16, $17, $18)`,
		fixture.activeUserID, "project-review-active-subject", "project-review-active", "Active Review User",
		"active-review@example.invalid", "active-review@example.invalid", activeUserCreated,
		activeUserCreated.Add(time.Second), activeUserCreated.Add(2*time.Second),
		fixture.expiredUserID, "project-review-expired-subject", "project-review-expired", "Expired Review User",
		"expired-review@example.invalid", "expired-review@example.invalid", expiredUserCreated,
		expiredUserCreated.Add(time.Second), expiredUserCreated.Add(2*time.Second))
	exec(`INSERT INTO oidc_clients (
		id, client_id, client_type, token_endpoint_auth_method, name, description, logo_uri,
		status, registration_enabled, created_at, updated_at
	) VALUES ($1, 'ois_cli_0123456789abcdefghijklmnopqrstuv', 'public', 'none',
		'Project Review RP', 'schema-11 authority fixture', NULL, 'active', true, $2, $3)`,
		fixture.clientID, fixture.base.Add(-4*time.Hour), fixture.base.Add(-3*time.Hour))
	exec(`INSERT INTO oidc_client_scopes (client_id, scope, created_at)
		VALUES ($1, 'openid', $2), ($1, 'profile', $2)`, fixture.clientID, fixture.base.Add(-4*time.Hour))

	exec(`INSERT INTO login_sessions (
		id, user_id, token_hash, csrf_hash, csrf_expires_at, created_at, last_seen_at,
		authenticated_at, expires_at, idle_expires_at, user_agent_hash, ip_prefix
	) VALUES
		($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, '192.0.2.0/24'),
		($12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, '198.51.100.0/24')`,
		fixture.activeSessionID, fixture.activeUserID, projectReviewHash(0x41), projectReviewHash(0x42),
		fixture.base.Add(20*time.Minute), fixture.base.Add(-2*time.Hour), fixture.base.Add(-time.Hour),
		fixture.base.Add(-time.Hour), fixture.base.Add(time.Hour), fixture.base.Add(30*time.Minute), projectReviewHash(0x43),
		fixture.expiredSessionID, fixture.expiredUserID, projectReviewHash(0x51), projectReviewHash(0x52),
		fixture.base.Add(-3*time.Hour), fixture.base.Add(-4*time.Hour), fixture.base.Add(-3*time.Hour),
		fixture.base.Add(-3*time.Hour), fixture.base.Add(-2*time.Hour), fixture.base.Add(-3*time.Hour), projectReviewHash(0x53))

	exec(`INSERT INTO auth_transactions (
		id, token_hash, transaction_kind, client_id, redirect_uri, scopes,
		pkce_challenge, pkce_method, state_value, nonce_value, prompt_create, created_at, expires_at
	) VALUES
		($1, $2, 'authorization', $3, 'https://project-review.example/callback', ARRAY['openid','profile']::text[], repeat('A', 43), 'S256', 'active-state', 'active-nonce', false, $4, $5),
		($6, $7, 'authorization', $3, 'https://project-review.example/callback', ARRAY['openid','profile']::text[], repeat('B', 43), 'S256', 'expired-state', 'expired-nonce', false, $8, $9)`,
		fixture.activeTransaction, projectReviewHash(0x61), fixture.clientID, fixture.base.Add(-20*time.Minute), fixture.base.Add(10*time.Minute),
		fixture.expiredTransaction, projectReviewHash(0x62), fixture.base.Add(-3*time.Hour), fixture.base.Add(-2*time.Hour))

	exec(`INSERT INTO consent_grants (
		id, user_id, client_id, scopes, created_at, updated_at
	) VALUES
		($1, $2, $3, ARRAY['openid','profile']::text[], $4, $5),
		($6, $7, $3, ARRAY['openid','profile']::text[], $8, $9)`,
		fixture.activeGrantID, fixture.activeUserID, fixture.clientID, fixture.base.Add(-2*time.Hour), fixture.base.Add(-time.Hour),
		fixture.expiredGrantID, fixture.expiredUserID, fixture.base.Add(-4*time.Hour), fixture.base.Add(-3*time.Hour))

	exec(`INSERT INTO authorization_codes (
		id, code_hash, auth_transaction_id, consent_grant_id, user_id, client_id,
		redirect_uri, scopes, pkce_challenge, pkce_method, nonce_value, auth_time,
		created_at, expires_at
	) VALUES
		($1, $2, $3, $4, $5, $6, 'https://project-review.example/callback', ARRAY['openid','profile']::text[], repeat('A', 43), 'S256', 'active-nonce', $7, $8, $9),
		($10, $11, $12, $13, $14, $6, 'https://project-review.example/callback', ARRAY['openid','profile']::text[], repeat('B', 43), 'S256', 'expired-nonce', $15, $16, $17)`,
		fixture.activeCodeID, projectReviewHash(0x71), fixture.activeTransaction, fixture.activeGrantID, fixture.activeUserID, fixture.clientID,
		fixture.base.Add(-15*time.Minute), fixture.base, fixture.base.Add(4*time.Minute),
		fixture.expiredCodeID, projectReviewHash(0x72), fixture.expiredTransaction, fixture.expiredGrantID, fixture.expiredUserID,
		fixture.base.Add(-2*time.Hour), fixture.base.Add(-2*time.Hour+time.Minute), fixture.base.Add(-2*time.Hour+5*time.Minute))

	exec(`INSERT INTO access_tokens (
		id, jti_hash, authorization_code_id, consent_grant_id, user_id, client_id,
		scopes, issued_at, expires_at
	) VALUES
		($1, $2, $3, $4, $5, $6, ARRAY['openid','profile']::text[], $7, $8),
		($9, $10, $11, $12, $13, $6, ARRAY['openid','profile']::text[], $14, $15)`,
		fixture.activeAccessID, projectReviewHash(0x81), fixture.activeCodeID, fixture.activeGrantID, fixture.activeUserID, fixture.clientID,
		fixture.base.Add(-5*time.Minute), fixture.base.Add(20*time.Minute),
		fixture.expiredAccessID, projectReviewHash(0x82), fixture.expiredCodeID, fixture.expiredGrantID, fixture.expiredUserID,
		fixture.base.Add(-2*time.Hour+5*time.Minute), fixture.base.Add(-2*time.Hour+20*time.Minute))

	if err := tx.Commit(); err != nil {
		t.Fatalf("commit schema-11 fixture: %v", err)
	}
}

func projectReviewHash(fill byte) []byte {
	return bytes.Repeat([]byte{fill}, 32)
}

func assertProjectReviewSchema11Fixture(ctx context.Context, t *testing.T, database *sql.DB, fixture projectReviewSchemaFixture) {
	t.Helper()
	assertProjectReviewRow(ctx, t, database, "active schema-11 Session", `SELECT EXISTS (
		SELECT 1 FROM login_sessions
		WHERE id=$1 AND user_id=$2 AND token_hash=$3 AND csrf_hash=$4
		  AND expires_at=$5 AND idle_expires_at=$6 AND revoked_at IS NULL AND revoke_reason IS NULL
	)`, fixture.activeSessionID, fixture.activeUserID, projectReviewHash(0x41), projectReviewHash(0x42),
		fixture.base.Add(time.Hour), fixture.base.Add(30*time.Minute))
	assertProjectReviewRow(ctx, t, database, "expired schema-11 Session", `SELECT EXISTS (
		SELECT 1 FROM login_sessions
		WHERE id=$1 AND user_id=$2 AND token_hash=$3 AND csrf_hash=$4
		  AND expires_at=$5 AND idle_expires_at=$6 AND revoked_at IS NULL AND revoke_reason IS NULL
	)`, fixture.expiredSessionID, fixture.expiredUserID, projectReviewHash(0x51), projectReviewHash(0x52),
		fixture.base.Add(-2*time.Hour), fixture.base.Add(-3*time.Hour))
	assertProjectReviewRow(ctx, t, database, "active schema-11 Grant", `SELECT EXISTS (
		SELECT 1 FROM consent_grants
		WHERE id=$1 AND user_id=$2 AND client_id=$3
		  AND scopes=ARRAY['openid','profile']::text[] AND created_at=$4 AND updated_at=$5
	)`, fixture.activeGrantID, fixture.activeUserID, fixture.clientID, fixture.base.Add(-2*time.Hour), fixture.base.Add(-time.Hour))
	assertProjectReviewRow(ctx, t, database, "expired schema-11 Grant", `SELECT EXISTS (
		SELECT 1 FROM consent_grants
		WHERE id=$1 AND user_id=$2 AND client_id=$3
		  AND scopes=ARRAY['openid','profile']::text[] AND created_at=$4 AND updated_at=$5
	)`, fixture.expiredGrantID, fixture.expiredUserID, fixture.clientID, fixture.base.Add(-4*time.Hour), fixture.base.Add(-3*time.Hour))
	assertProjectReviewRow(ctx, t, database, "active schema-11 Code", `SELECT EXISTS (
		SELECT 1 FROM authorization_codes
		WHERE id=$1 AND code_hash=$2 AND auth_transaction_id=$3 AND consent_grant_id=$4
		  AND user_id=$5 AND client_id=$6 AND auth_time=$7 AND created_at=$8 AND expires_at=$9 AND consumed_at IS NULL
	)`, fixture.activeCodeID, projectReviewHash(0x71), fixture.activeTransaction, fixture.activeGrantID,
		fixture.activeUserID, fixture.clientID, fixture.base.Add(-15*time.Minute), fixture.base, fixture.base.Add(4*time.Minute))
	assertProjectReviewRow(ctx, t, database, "expired schema-11 Code", `SELECT EXISTS (
		SELECT 1 FROM authorization_codes
		WHERE id=$1 AND code_hash=$2 AND auth_transaction_id=$3 AND consent_grant_id=$4
		  AND user_id=$5 AND client_id=$6 AND auth_time=$7 AND created_at=$8 AND expires_at=$9 AND consumed_at IS NULL
	)`, fixture.expiredCodeID, projectReviewHash(0x72), fixture.expiredTransaction, fixture.expiredGrantID,
		fixture.expiredUserID, fixture.clientID, fixture.base.Add(-2*time.Hour), fixture.base.Add(-2*time.Hour+time.Minute), fixture.base.Add(-2*time.Hour+5*time.Minute))
	assertProjectReviewRow(ctx, t, database, "active schema-11 Access", `SELECT EXISTS (
		SELECT 1 FROM access_tokens
		WHERE id=$1 AND jti_hash=$2 AND authorization_code_id=$3 AND consent_grant_id=$4
		  AND user_id=$5 AND client_id=$6 AND issued_at=$7 AND expires_at=$8
	)`, fixture.activeAccessID, projectReviewHash(0x81), fixture.activeCodeID, fixture.activeGrantID,
		fixture.activeUserID, fixture.clientID, fixture.base.Add(-5*time.Minute), fixture.base.Add(20*time.Minute))
	assertProjectReviewRow(ctx, t, database, "expired schema-11 Access", `SELECT EXISTS (
		SELECT 1 FROM access_tokens
		WHERE id=$1 AND jti_hash=$2 AND authorization_code_id=$3 AND consent_grant_id=$4
		  AND user_id=$5 AND client_id=$6 AND issued_at=$7 AND expires_at=$8
	)`, fixture.expiredAccessID, projectReviewHash(0x82), fixture.expiredCodeID, fixture.expiredGrantID,
		fixture.expiredUserID, fixture.clientID, fixture.base.Add(-2*time.Hour+5*time.Minute), fixture.base.Add(-2*time.Hour+20*time.Minute))
}

func assertProjectReviewSchema15Upgrade(ctx context.Context, t *testing.T, database *sql.DB, fixture projectReviewSchemaFixture) {
	t.Helper()
	assertProjectReviewRow(ctx, t, database, "active Session after schema-15 upgrade", `SELECT EXISTS (
		SELECT 1 FROM login_sessions
		WHERE id=$1 AND user_id=$2 AND token_hash=$3 AND csrf_hash=$4
		  AND expires_at=$5 AND idle_expires_at=$6 AND session_binding_id=id
	)`, fixture.activeSessionID, fixture.activeUserID, projectReviewHash(0x41), projectReviewHash(0x42),
		fixture.base.Add(time.Hour), fixture.base.Add(30*time.Minute))
	assertProjectReviewRow(ctx, t, database, "expired Session after schema-15 upgrade", `SELECT EXISTS (
		SELECT 1 FROM login_sessions
		WHERE id=$1 AND user_id=$2 AND token_hash=$3 AND csrf_hash=$4
		  AND expires_at=$5 AND idle_expires_at=$6 AND session_binding_id=id
	)`, fixture.expiredSessionID, fixture.expiredUserID, projectReviewHash(0x51), projectReviewHash(0x52),
		fixture.base.Add(-2*time.Hour), fixture.base.Add(-3*time.Hour))
	assertProjectReviewRow(ctx, t, database, "active Grant after schema-15 upgrade", `SELECT EXISTS (
		SELECT 1 FROM consent_grants
		WHERE id=$1 AND user_id=$2 AND client_id=$3 AND scopes=ARRAY['openid','profile']::text[]
		  AND created_at=$4 AND updated_at=$5 AND revoked_at IS NULL AND version=1
	)`, fixture.activeGrantID, fixture.activeUserID, fixture.clientID, fixture.base.Add(-2*time.Hour), fixture.base.Add(-time.Hour))
	assertProjectReviewRow(ctx, t, database, "expired Grant after schema-15 upgrade", `SELECT EXISTS (
		SELECT 1 FROM consent_grants
		WHERE id=$1 AND user_id=$2 AND client_id=$3 AND scopes=ARRAY['openid','profile']::text[]
		  AND created_at=$4 AND updated_at=$5 AND revoked_at IS NULL AND version=1
	)`, fixture.expiredGrantID, fixture.expiredUserID, fixture.clientID, fixture.base.Add(-4*time.Hour), fixture.base.Add(-3*time.Hour))
	assertProjectReviewRow(ctx, t, database, "active Code after schema-15 upgrade", `SELECT EXISTS (
		SELECT 1 FROM authorization_codes
		WHERE id=$1 AND code_hash=$2 AND auth_transaction_id=$3 AND consent_grant_id=$4
		  AND user_id=$5 AND client_id=$6 AND auth_time=$7 AND created_at=$8 AND expires_at=$9 AND consumed_at IS NULL
		  AND consent_grant_version=1 AND origin_session_id IS NULL AND session_binding_id IS NULL
	)`, fixture.activeCodeID, projectReviewHash(0x71), fixture.activeTransaction, fixture.activeGrantID,
		fixture.activeUserID, fixture.clientID, fixture.base.Add(-15*time.Minute), fixture.base, fixture.base.Add(4*time.Minute))
	assertProjectReviewRow(ctx, t, database, "expired Code after schema-15 upgrade", `SELECT EXISTS (
		SELECT 1 FROM authorization_codes
		WHERE id=$1 AND code_hash=$2 AND auth_transaction_id=$3 AND consent_grant_id=$4
		  AND user_id=$5 AND client_id=$6 AND auth_time=$7 AND created_at=$8 AND expires_at=$9 AND consumed_at IS NULL
		  AND consent_grant_version=1 AND origin_session_id IS NULL AND session_binding_id IS NULL
	)`, fixture.expiredCodeID, projectReviewHash(0x72), fixture.expiredTransaction, fixture.expiredGrantID,
		fixture.expiredUserID, fixture.clientID, fixture.base.Add(-2*time.Hour), fixture.base.Add(-2*time.Hour+time.Minute), fixture.base.Add(-2*time.Hour+5*time.Minute))
	assertProjectReviewRow(ctx, t, database, "active Access after schema-15 upgrade", `SELECT EXISTS (
		SELECT 1 FROM access_tokens
		WHERE id=$1 AND jti_hash=$2 AND authorization_code_id=$3 AND consent_grant_id=$4
		  AND user_id=$5 AND client_id=$6 AND issued_at=$7 AND expires_at=$8 AND issuance_source='authorization_code'
		  AND source_refresh_token_id IS NULL AND refresh_family_id IS NULL
		  AND origin_session_id IS NULL AND session_binding_id IS NULL AND revoked_at IS NULL
	)`, fixture.activeAccessID, projectReviewHash(0x81), fixture.activeCodeID, fixture.activeGrantID,
		fixture.activeUserID, fixture.clientID, fixture.base.Add(-5*time.Minute), fixture.base.Add(20*time.Minute))
	assertProjectReviewRow(ctx, t, database, "expired Access after schema-15 upgrade", `SELECT EXISTS (
		SELECT 1 FROM access_tokens
		WHERE id=$1 AND jti_hash=$2 AND authorization_code_id=$3 AND consent_grant_id=$4
		  AND user_id=$5 AND client_id=$6 AND issued_at=$7 AND expires_at=$8 AND issuance_source='authorization_code'
		  AND source_refresh_token_id IS NULL AND refresh_family_id IS NULL
		  AND origin_session_id IS NULL AND session_binding_id IS NULL AND revoked_at IS NULL
	)`, fixture.expiredAccessID, projectReviewHash(0x82), fixture.expiredCodeID, fixture.expiredGrantID,
		fixture.expiredUserID, fixture.clientID, fixture.base.Add(-2*time.Hour+5*time.Minute), fixture.base.Add(-2*time.Hour+20*time.Minute))
	assertProjectReviewRow(ctx, t, database, "no fabricated Phase-Four authority", `SELECT
		(SELECT count(*) FROM consent_grants)=2
		AND NOT EXISTS (SELECT 1 FROM consent_grants WHERE 'offline_access'=ANY(scopes))
		AND NOT EXISTS (SELECT 1 FROM refresh_token_families)
		AND NOT EXISTS (SELECT 1 FROM refresh_tokens)
		AND (SELECT count(*) FROM login_sessions WHERE session_binding_id=id)=2
		AND NOT EXISTS (SELECT 1 FROM authorization_codes WHERE origin_session_id IS NOT NULL OR session_binding_id IS NOT NULL)
		AND NOT EXISTS (SELECT 1 FROM access_tokens WHERE refresh_family_id IS NOT NULL OR origin_session_id IS NOT NULL OR session_binding_id IS NOT NULL)`)
}

func testProjectReviewMigration15(ctx context.Context, t *testing.T, database *sql.DB, fixture projectReviewSchemaFixture) {
	t.Helper()
	codeID := uuid.MustParse("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
	transactionID := uuid.MustParse("ffffffff-ffff-4fff-8fff-ffffffffffff")
	accessID := uuid.MustParse("10101010-1010-4010-8010-101010101010")
	insertProjectReviewLatestCode(ctx, t, database, transactionID, codeID, fixture.activeGrantID, fixture.activeUserID, fixture.clientID,
		fixture.base, fixture.base.Add(4*time.Minute), projectReviewHash(0x91), projectReviewHash(0x92))
	insertProjectReviewLatestAccess(ctx, t, database, accessID, projectReviewHash(0x93), codeID, fixture.activeGrantID,
		fixture.activeUserID, fixture.clientID, fixture.base, fixture.base.Add(10*time.Minute))

	assertProjectReviewRow(ctx, t, database, "legal Code-sourced Access", `SELECT EXISTS (
		SELECT 1 FROM access_tokens
		WHERE id=$1 AND authorization_code_id=$2 AND issuance_source='authorization_code'
	)`, accessID, codeID)

	assertProjectReviewRejected(ctx, t, database, "Code-sourced Access without Code", `INSERT INTO access_tokens (
		id, jti_hash, authorization_code_id, consent_grant_id, user_id, client_id, scopes,
		issued_at, expires_at, issuance_source
	) VALUES ($1, $2, NULL, $3, $4, $5, ARRAY['openid','profile']::text[], $6, $7, 'authorization_code')`,
		uuid.MustParse("12121212-1212-4012-8012-121212121212"), projectReviewHash(0x94), fixture.activeGrantID,
		fixture.activeUserID, fixture.clientID, fixture.base, fixture.base.Add(10*time.Minute))
	assertProjectReviewRejected(ctx, t, database, "manual Code detach", `UPDATE access_tokens SET authorization_code_id=NULL WHERE id=$1`, accessID)
	assertProjectReviewRejected(ctx, t, database, "issuance source mutation", `UPDATE access_tokens SET issuance_source='refresh_token' WHERE id=$1`, accessID)
	assertProjectReviewRejected(ctx, t, database, "mismatched Code-sourced Access insert", `INSERT INTO access_tokens (
		id, jti_hash, authorization_code_id, consent_grant_id, user_id, client_id, scopes,
		issued_at, expires_at, issuance_source
	) VALUES ($1, $2, $3, $4, $5, $6, ARRAY['openid','profile']::text[], $7, $8, 'authorization_code')`,
		uuid.MustParse("13131313-1313-4013-8013-131313131313"), projectReviewHash(0x95), codeID,
		fixture.activeGrantID, fixture.expiredUserID, fixture.clientID, fixture.base, fixture.base.Add(10*time.Minute))

	if _, err := database.ExecContext(ctx, `DELETE FROM authorization_codes WHERE id=$1`, codeID); err != nil {
		t.Fatalf("delete Code for controlled detach: %v", err)
	}
	assertProjectReviewRow(ctx, t, database, "detached retained Access", `SELECT EXISTS (
		SELECT 1 FROM access_tokens
		WHERE id=$1 AND issuance_source='authorization_code' AND authorization_code_id IS NULL
		  AND expires_at=$2 AND consent_grant_id=$3 AND user_id=$4 AND client_id=$5
	)`, accessID, fixture.base.Add(10*time.Minute), fixture.activeGrantID, fixture.activeUserID, fixture.clientID)

	reattachCodeID := uuid.MustParse("14141414-1414-4014-8014-141414141414")
	reatachTransactionID := uuid.MustParse("15151515-1515-4015-8015-151515151515")
	insertProjectReviewLatestCode(ctx, t, database, reatachTransactionID, reattachCodeID, fixture.activeGrantID, fixture.activeUserID,
		fixture.clientID, fixture.base, fixture.base.Add(4*time.Minute), projectReviewHash(0x96), projectReviewHash(0x97))
	assertProjectReviewRejected(ctx, t, database, "reattach detached Access", `UPDATE access_tokens SET authorization_code_id=$2 WHERE id=$1`, accessID, reattachCodeID)
}

func insertProjectReviewLatestCode(ctx context.Context, t *testing.T, database *sql.DB, transactionID, codeID, grantID, userID, clientID uuid.UUID,
	createdAt, expiresAt time.Time, transactionHash, codeHash []byte) {
	t.Helper()
	exec := func(statement string, arguments ...any) {
		t.Helper()
		if _, err := database.ExecContext(ctx, statement, arguments...); err != nil {
			t.Fatalf("insert schema-15 Code fixture: %v", err)
		}
	}
	exec(`INSERT INTO auth_transactions (
		id, token_hash, transaction_kind, client_id, redirect_uri, scopes, pkce_challenge, pkce_method,
		state_value, nonce_value, prompt_create, response_type, response_mode, prompt_values,
		max_age_seconds, created_at, expires_at
	) VALUES ($1, $2, 'authorization', $3, 'https://project-review.example/callback', ARRAY['openid','profile']::text[],
		repeat('C',43), 'S256', NULL, NULL, false, 'code', 'query', ARRAY[]::text[], NULL, $4, $5)`,
		transactionID, transactionHash, clientID, createdAt, expiresAt)
	exec(`INSERT INTO authorization_codes (
		id, code_hash, auth_transaction_id, consent_grant_id, user_id, client_id,
		redirect_uri, scopes, pkce_challenge, pkce_method, nonce_value, auth_time,
		created_at, expires_at, consent_grant_version, origin_session_id, session_binding_id
	) VALUES ($1, $2, $3, $4, $5, $6, 'https://project-review.example/callback',
		ARRAY['openid','profile']::text[], repeat('C',43), 'S256', NULL, $7, $8, $9, 1, NULL, NULL)`,
		codeID, codeHash, transactionID, grantID, userID, clientID, createdAt, createdAt, expiresAt)
}

func insertProjectReviewLatestAccess(ctx context.Context, t *testing.T, database *sql.DB, accessID uuid.UUID, jtiHash []byte,
	codeID, grantID, userID, clientID uuid.UUID, issuedAt, expiresAt time.Time) {
	t.Helper()
	if _, err := database.ExecContext(ctx, `INSERT INTO access_tokens (
		id, jti_hash, authorization_code_id, consent_grant_id, user_id, client_id,
		scopes, issued_at, expires_at, issuance_source, source_refresh_token_id,
		refresh_family_id, origin_session_id, session_binding_id
	) VALUES ($1, $2, $3, $4, $5, $6, ARRAY['openid','profile']::text[], $7, $8,
		'authorization_code', NULL, NULL, NULL, NULL)`,
		accessID, jtiHash, codeID, grantID, userID, clientID, issuedAt, expiresAt); err != nil {
		t.Fatalf("insert schema-15 Access fixture: %v", err)
	}
}

func testProjectReviewProtocolCleanup(ctx context.Context, t *testing.T, database *sql.DB, databaseURL string, fixture projectReviewSchemaFixture) {
	t.Helper()
	codeID := uuid.MustParse("16161616-1616-4016-8016-161616161616")
	transactionID := uuid.MustParse("17171717-1717-4017-8017-171717171717")
	accessID := uuid.MustParse("18181818-1818-4018-8018-181818181818")
	codeCreated := fixture.base.Add(-3*time.Hour - 4*time.Minute)
	codeExpires := fixture.base.Add(-3 * time.Hour)
	accessIssued := fixture.base.Add(-2 * time.Hour)
	accessExpires := fixture.base.Add(-90 * time.Minute)
	cleanupCutoff := fixture.base.Add(-2 * time.Hour)
	insertProjectReviewLatestCode(ctx, t, database, transactionID, codeID, fixture.activeGrantID, fixture.activeUserID, fixture.clientID,
		codeCreated, codeExpires, projectReviewHash(0xa1), projectReviewHash(0xa2))
	insertProjectReviewLatestAccess(ctx, t, database, accessID, projectReviewHash(0xa3), codeID, fixture.activeGrantID,
		fixture.activeUserID, fixture.clientID, accessIssued, accessExpires)

	store, err := postgres.Open(ctx, databaseURL, 2)
	if err != nil {
		t.Fatalf("open store for protocol cleanup: %v", err)
	}
	defer store.Close()
	deleted, err := store.CleanupProtocolArtifacts(ctx, cleanupCutoff)
	if err != nil {
		t.Fatalf("cleanup expired Code with retained Access: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("cleanup deleted %d rows at Code-only cutoff, want 1", deleted)
	}
	assertProjectReviewRow(ctx, t, database, "cleanup-detached Access retained through retention window", `SELECT EXISTS (
		SELECT 1 FROM access_tokens
		WHERE id=$1 AND issuance_source='authorization_code' AND authorization_code_id IS NULL
		  AND expires_at=$2 AND expires_at < now()
	)`, accessID, accessExpires)
	assertProjectReviewRow(ctx, t, database, "cleanup-detached Code removed", `SELECT NOT EXISTS (
		SELECT 1 FROM authorization_codes WHERE id=$1
	)`, codeID)

	if _, err := store.CleanupProtocolArtifacts(ctx, fixture.base); err != nil {
		t.Fatalf("cleanup expired retained Access: %v", err)
	}
	assertProjectReviewRow(ctx, t, database, "retained Access eventually retired", `SELECT NOT EXISTS (
		SELECT 1 FROM access_tokens WHERE id=$1
	)`, accessID)
}

func assertProjectReviewRejected(ctx context.Context, t *testing.T, database *sql.DB, label, statement string, arguments ...any) {
	t.Helper()
	if _, err := database.ExecContext(ctx, statement, arguments...); err == nil {
		t.Fatalf("%s unexpectedly succeeded", label)
	}
}

func assertProjectReviewRow(ctx context.Context, t *testing.T, database *sql.DB, label, query string, arguments ...any) {
	t.Helper()
	var matched bool
	if err := database.QueryRowContext(ctx, query, arguments...).Scan(&matched); err != nil {
		t.Fatalf("verify %s: %v", label, err)
	}
	if !matched {
		t.Fatalf("%s did not hold", label)
	}
}
