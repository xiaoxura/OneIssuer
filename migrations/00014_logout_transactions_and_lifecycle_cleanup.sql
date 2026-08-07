-- +goose Up
-- +goose StatementBegin
CREATE TABLE logout_transactions (
    id uuid PRIMARY KEY,
    lookup_hash bytea NOT NULL UNIQUE,
    stage text NOT NULL DEFAULT 'pre_confirm',
    csrf_hash bytea,
    verified_client_id uuid REFERENCES oidc_clients(id) ON DELETE RESTRICT,
    post_logout_redirect_uri text,
    state_value text,
    hint_subject text,
    user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    session_id uuid REFERENCES login_sessions(id) ON DELETE RESTRICT,
    session_binding_id uuid,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    bound_at timestamptz,
    consumed_at timestamptz,
    attempt_count smallint NOT NULL DEFAULT 0,
    CONSTRAINT logout_transactions_lookup_hash_length CHECK (
        octet_length(lookup_hash) = 32
    ),
    CONSTRAINT logout_transactions_csrf_hash_length CHECK (
        csrf_hash IS NULL OR octet_length(csrf_hash) = 32
    ),
    CONSTRAINT logout_transactions_stage_valid CHECK (
        stage IN ('pre_confirm', 'bound_confirmable', 'confirmed', 'canceled')
    ),
    CONSTRAINT logout_transactions_verified_redirect_valid CHECK (
        (post_logout_redirect_uri IS NULL OR (
            verified_client_id IS NOT NULL
            AND octet_length(post_logout_redirect_uri) BETWEEN 8 AND 2048
        ))
        AND (state_value IS NULL OR (
            post_logout_redirect_uri IS NOT NULL
            AND octet_length(state_value) BETWEEN 1 AND 1024
        ))
        AND (hint_subject IS NULL OR octet_length(hint_subject) BETWEEN 1 AND 255)
    ),
    CONSTRAINT logout_transactions_authority_stage_valid CHECK (
        (
            stage = 'pre_confirm'
            AND csrf_hash IS NULL
            AND user_id IS NULL
            AND session_id IS NULL
            AND session_binding_id IS NULL
            AND bound_at IS NULL
            AND consumed_at IS NULL
        )
        OR
        (
            stage = 'bound_confirmable'
            AND csrf_hash IS NOT NULL
            AND user_id IS NOT NULL
            AND session_id IS NOT NULL
            AND session_binding_id IS NOT NULL
            AND bound_at IS NOT NULL
            AND consumed_at IS NULL
        )
        OR
        (
            stage IN ('confirmed', 'canceled')
            AND csrf_hash IS NULL
            AND user_id IS NOT NULL
            AND session_id IS NOT NULL
            AND session_binding_id IS NOT NULL
            AND bound_at IS NOT NULL
            AND consumed_at IS NOT NULL
        )
    ),
    CONSTRAINT logout_transactions_time_valid CHECK (
        expires_at > created_at
        AND expires_at <= created_at + interval '15 minutes'
        AND (bound_at IS NULL OR bound_at >= created_at)
        AND (consumed_at IS NULL OR consumed_at >= COALESCE(bound_at, created_at))
    ),
    CONSTRAINT logout_transactions_attempt_count_valid CHECK (
        attempt_count BETWEEN 0 AND 10
    )
);

CREATE INDEX logout_transactions_live_expiry_idx
    ON logout_transactions (expires_at, id)
    WHERE consumed_at IS NULL;
CREATE INDEX logout_transactions_session_live_idx
    ON logout_transactions (session_id, expires_at, id)
    WHERE stage = 'bound_confirmable' AND consumed_at IS NULL;
CREATE INDEX logout_transactions_terminal_retirement_idx
    ON logout_transactions (consumed_at, id)
    WHERE consumed_at IS NOT NULL;

CREATE UNIQUE INDEX audit_events_refresh_exchange_rejection_target_idx
    ON audit_events (target_id)
    WHERE event_type = 'refresh_token_exchange_rejected'
      AND target_type = 'refresh_token';
CREATE UNIQUE INDEX audit_events_refresh_reuse_target_idx
    ON audit_events (target_id)
    WHERE event_type = 'refresh_token_reuse_detected'
      AND target_type = 'refresh_token';

CREATE INDEX refresh_token_families_terminal_retirement_idx
    ON refresh_token_families (
        GREATEST(absolute_expires_at, COALESCE(revoked_at, absolute_expires_at)), id
    );
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX refresh_token_families_terminal_retirement_idx;
DROP INDEX audit_events_refresh_reuse_target_idx;
DROP INDEX audit_events_refresh_exchange_rejection_target_idx;
DROP TABLE logout_transactions;
-- +goose StatementEnd
