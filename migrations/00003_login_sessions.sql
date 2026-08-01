-- +goose Up
-- +goose StatementBegin
CREATE TABLE login_sessions (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    token_hash bytea NOT NULL UNIQUE,
    csrf_hash bytea NOT NULL,
    csrf_expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    authenticated_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revoke_reason text,
    user_agent_hash bytea,
    ip_prefix text,
    CONSTRAINT login_sessions_token_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT login_sessions_csrf_hash_length CHECK (octet_length(csrf_hash) = 32),
    CONSTRAINT login_sessions_user_agent_hash_length CHECK (
        user_agent_hash IS NULL OR octet_length(user_agent_hash) = 32
    ),
    CONSTRAINT login_sessions_ip_prefix_bounds CHECK (
        ip_prefix IS NULL OR length(ip_prefix) BETWEEN 3 AND 64
    ),
    CONSTRAINT login_sessions_expiry_valid CHECK (
        last_seen_at >= created_at
        AND authenticated_at >= created_at
        AND expires_at > created_at
        AND idle_expires_at > created_at
        AND idle_expires_at <= expires_at
        AND csrf_expires_at > created_at
        AND (revoked_at IS NULL OR revoked_at >= created_at)
    ),
    CONSTRAINT login_sessions_revoke_reason_valid CHECK (
        (revoked_at IS NULL AND revoke_reason IS NULL)
        OR
        (revoked_at IS NOT NULL AND revoke_reason IN (
            'logout', 'user', 'others', 'admin', 'user_disabled',
            'role_changed', 'rotation', 'expired'
        ))
    )
);

CREATE TABLE preauth_sessions (
    id uuid PRIMARY KEY,
    token_hash bytea NOT NULL UNIQUE,
    csrf_hash bytea NOT NULL,
    auth_transaction_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CONSTRAINT preauth_sessions_token_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT preauth_sessions_csrf_hash_length CHECK (octet_length(csrf_hash) = 32),
    CONSTRAINT preauth_sessions_expiry_valid CHECK (
        expires_at > created_at
        AND (consumed_at IS NULL OR consumed_at >= created_at)
    )
);

CREATE INDEX login_sessions_user_cursor_idx
    ON login_sessions (user_id, created_at DESC, id DESC);
CREATE INDEX login_sessions_active_expiry_idx
    ON login_sessions (expires_at, idle_expires_at)
    WHERE revoked_at IS NULL;
CREATE INDEX login_sessions_admin_cursor_idx
    ON login_sessions (created_at DESC, id DESC);
CREATE INDEX preauth_sessions_expiry_idx
    ON preauth_sessions (expires_at)
    WHERE consumed_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE preauth_sessions;
DROP TABLE login_sessions;
-- +goose StatementEnd
