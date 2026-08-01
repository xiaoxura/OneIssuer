-- +goose Up
-- +goose StatementBegin
ALTER TABLE audit_events DROP CONSTRAINT audit_events_type_valid;
ALTER TABLE audit_events DROP CONSTRAINT audit_events_target_valid;
ALTER TABLE audit_events DROP CONSTRAINT audit_events_changed_fields_whitelist;

ALTER TABLE audit_events
    ADD CONSTRAINT audit_events_type_valid CHECK (event_type IN (
        'admin_bootstrap_succeeded', 'admin_bootstrap_rejected',
        'user_registered', 'user_registration_rejected',
        'user_created', 'user_updated', 'user_status_changed', 'user_role_changed',
        'login_succeeded', 'login_failed', 'login_disabled_user',
        'session_created', 'session_revoked', 'sessions_revoked_all',
        'client_created', 'client_updated', 'client_disabled',
        'client_secret_rotated',
        'authorization_transaction_created', 'authorization_transaction_consumed',
        'authorization_transaction_expired', 'authorization_transaction_rejected',
        'authorization_granted', 'authorization_denied',
        'authorization_code_issued', 'authorization_code_exchange_succeeded',
        'authorization_code_exchange_rejected',
        'consent_grant_created', 'consent_grant_expanded',
        'access_token_issued', 'signing_key_loaded'
    )),
    ADD CONSTRAINT audit_events_target_valid CHECK (
        (target_type IS NULL AND target_id IS NULL)
        OR
        (target_type IN (
            'user', 'client', 'session', 'auth_transaction',
            'consent_grant', 'authorization_code', 'access_token'
        ) AND target_id IS NOT NULL)
    ),
    ADD CONSTRAINT audit_events_changed_fields_whitelist CHECK (
        changed_fields <@ ARRAY[
            'status', 'role', 'username', 'display_name', 'email',
            'name', 'description', 'logo_uri', 'registration_enabled',
            'redirect_uris', 'logout_uris', 'scopes', 'secret',
            'revoked', 'created', 'expanded', 'issued', 'consumed'
        ]::text[]
    );
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE audit_events DROP CONSTRAINT audit_events_type_valid;
ALTER TABLE audit_events DROP CONSTRAINT audit_events_target_valid;
ALTER TABLE audit_events DROP CONSTRAINT audit_events_changed_fields_whitelist;

ALTER TABLE audit_events
    ADD CONSTRAINT audit_events_type_valid CHECK (event_type IN (
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
    ADD CONSTRAINT audit_events_target_valid CHECK (
        (target_type IS NULL AND target_id IS NULL)
        OR
        (target_type IN ('user', 'client', 'session', 'auth_transaction') AND target_id IS NOT NULL)
    ),
    ADD CONSTRAINT audit_events_changed_fields_whitelist CHECK (
        changed_fields <@ ARRAY[
            'status', 'role', 'username', 'display_name', 'email',
            'name', 'description', 'logo_uri', 'registration_enabled',
            'redirect_uris', 'logout_uris', 'scopes', 'secret',
            'revoked', 'created'
        ]::text[]
    );
-- +goose StatementEnd
