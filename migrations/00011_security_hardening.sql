-- +goose Up
-- +goose StatementBegin
ALTER TABLE users
    ADD COLUMN version bigint NOT NULL DEFAULT 1,
    ADD CONSTRAINT users_version_valid CHECK (version > 0);

ALTER TABLE oidc_clients
    ADD COLUMN version bigint NOT NULL DEFAULT 1,
    ADD CONSTRAINT oidc_clients_version_valid CHECK (version > 0);

ALTER TABLE preauth_sessions
    ADD COLUMN attempt_count smallint NOT NULL DEFAULT 0,
    ADD CONSTRAINT preauth_sessions_attempt_count_valid CHECK (attempt_count BETWEEN 0 AND 10);

CREATE UNIQUE INDEX audit_events_code_exchange_rejection_target_idx
    ON audit_events (target_id)
    WHERE event_type = 'authorization_code_exchange_rejected'
      AND target_type = 'authorization_code';

CREATE INDEX preauth_sessions_consumed_retirement_idx
    ON preauth_sessions (consumed_at, id)
    WHERE consumed_at IS NOT NULL;
CREATE INDEX login_sessions_revoked_retirement_idx
    ON login_sessions (revoked_at, id)
    WHERE revoked_at IS NOT NULL;
CREATE INDEX login_sessions_expiry_retirement_idx
    ON login_sessions (expires_at, id);
CREATE INDEX login_sessions_idle_retirement_idx
    ON login_sessions (idle_expires_at, id);
CREATE INDEX auth_transactions_consumed_retirement_idx
    ON auth_transactions (consumed_at, id)
    WHERE consumed_at IS NOT NULL;
CREATE INDEX authorization_codes_retirement_idx
    ON authorization_codes (expires_at, id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX authorization_codes_retirement_idx;
DROP INDEX auth_transactions_consumed_retirement_idx;
DROP INDEX login_sessions_idle_retirement_idx;
DROP INDEX login_sessions_expiry_retirement_idx;
DROP INDEX login_sessions_revoked_retirement_idx;
DROP INDEX preauth_sessions_consumed_retirement_idx;
DROP INDEX audit_events_code_exchange_rejection_target_idx;

ALTER TABLE preauth_sessions
    DROP CONSTRAINT preauth_sessions_attempt_count_valid,
    DROP COLUMN attempt_count;
ALTER TABLE oidc_clients
    DROP CONSTRAINT oidc_clients_version_valid,
    DROP COLUMN version;
ALTER TABLE users
    DROP CONSTRAINT users_version_valid,
    DROP COLUMN version;
-- +goose StatementEnd
