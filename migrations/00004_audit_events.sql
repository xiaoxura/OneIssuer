-- +goose Up
-- +goose StatementBegin
CREATE TABLE audit_events (
    id uuid PRIMARY KEY,
    event_type text NOT NULL,
    result text NOT NULL,
    actor_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    target_type text,
    target_id uuid,
    request_id text,
    changed_fields text[] NOT NULL DEFAULT '{}',
    occurred_at timestamptz NOT NULL,
    CONSTRAINT audit_events_type_valid CHECK (event_type IN (
        'admin_bootstrap_succeeded', 'admin_bootstrap_rejected',
        'user_registered', 'user_registration_rejected',
        'user_created', 'user_updated', 'user_status_changed', 'user_role_changed',
        'login_succeeded', 'login_failed', 'login_disabled_user',
        'session_created', 'session_revoked', 'sessions_revoked_all',
        'client_created', 'client_updated', 'client_disabled',
        'client_secret_rotated',
        'authorization_transaction_created', 'authorization_transaction_consumed',
        'authorization_transaction_expired', 'authorization_transaction_rejected'
    )),
    CONSTRAINT audit_events_result_valid CHECK (result IN ('success', 'rejected', 'failure')),
    CONSTRAINT audit_events_target_valid CHECK (
        (target_type IS NULL AND target_id IS NULL)
        OR
        (target_type IN ('user', 'client', 'session', 'auth_transaction') AND target_id IS NOT NULL)
    ),
    CONSTRAINT audit_events_request_id_safe CHECK (
        request_id IS NULL OR (
            length(request_id) BETWEEN 1 AND 128
            AND request_id ~ '^[A-Za-z0-9._:-]+$'
        )
    ),
    CONSTRAINT audit_events_changed_fields_whitelist CHECK (
        changed_fields <@ ARRAY[
            'status', 'role', 'username', 'display_name', 'email',
            'name', 'description', 'logo_uri', 'registration_enabled',
            'redirect_uris', 'logout_uris', 'scopes', 'secret',
            'revoked', 'created'
        ]::text[]
    )
);

CREATE INDEX audit_events_cursor_idx ON audit_events (occurred_at DESC, id DESC);
CREATE INDEX audit_events_type_cursor_idx ON audit_events (event_type, occurred_at DESC, id DESC);
CREATE INDEX audit_events_actor_cursor_idx ON audit_events (actor_user_id, occurred_at DESC, id DESC);

CREATE FUNCTION oneissuer_prevent_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit events are append-only' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER audit_events_append_only
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION oneissuer_prevent_audit_mutation();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER audit_events_append_only ON audit_events;
DROP FUNCTION oneissuer_prevent_audit_mutation();
DROP TABLE audit_events;
-- +goose StatementEnd
