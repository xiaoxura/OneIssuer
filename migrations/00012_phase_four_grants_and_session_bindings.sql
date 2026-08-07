-- +goose Up
-- +goose StatementBegin
-- Expand only the reviewed protocol Scope vocabulary. Client registry rows could
-- already contain offline_access, but phase-three authority rows could not.
ALTER TABLE auth_transactions DROP CONSTRAINT auth_transactions_authorization_context;
ALTER TABLE auth_transactions
    ADD CONSTRAINT auth_transactions_authorization_context CHECK (
        transaction_kind <> 'authorization'
        OR (
            client_id IS NOT NULL
            AND redirect_uri IS NOT NULL
            AND response_type = 'code'
            AND response_mode = 'query'
            AND pkce_challenge ~ '^[A-Za-z0-9_-]{43}$'
            AND pkce_method = 'S256'
            AND cardinality(scopes) BETWEEN 1 AND 4
            AND scopes <@ ARRAY['email', 'offline_access', 'openid', 'profile']::text[]
            AND 'openid' = ANY(scopes)
            AND oneissuer_text_array_is_sorted_unique(scopes)
        )
    );

ALTER TABLE consent_grants DROP CONSTRAINT consent_grants_scopes_valid;
ALTER TABLE consent_grants DROP CONSTRAINT consent_grants_timestamps_valid;
ALTER TABLE consent_grants
    ADD COLUMN revoked_at timestamptz,
    ADD COLUMN version bigint NOT NULL DEFAULT 1,
    ADD CONSTRAINT consent_grants_scopes_valid CHECK (
        cardinality(scopes) BETWEEN 1 AND 4
        AND scopes <@ ARRAY['email', 'offline_access', 'openid', 'profile']::text[]
        AND 'openid' = ANY(scopes)
        AND oneissuer_text_array_is_sorted_unique(scopes)
    ),
    ADD CONSTRAINT consent_grants_version_valid CHECK (version > 0),
    ADD CONSTRAINT consent_grants_timestamps_valid CHECK (
        updated_at >= created_at
        AND (revoked_at IS NULL OR revoked_at >= created_at)
    );

CREATE INDEX consent_grants_user_updated_idx
    ON consent_grants (user_id, updated_at DESC, client_id);
CREATE INDEX consent_grants_active_client_idx
    ON consent_grants (client_id, user_id)
    WHERE revoked_at IS NULL;

ALTER TABLE login_sessions DROP CONSTRAINT login_sessions_revoke_reason_valid;
ALTER TABLE login_sessions
    ADD COLUMN session_binding_id uuid;
UPDATE login_sessions SET session_binding_id = id;
ALTER TABLE login_sessions
    ALTER COLUMN session_binding_id SET NOT NULL,
    ADD CONSTRAINT login_sessions_revoke_reason_valid CHECK (
        (revoked_at IS NULL AND revoke_reason IS NULL)
        OR
        (revoked_at IS NOT NULL AND revoke_reason IN (
            'logout', 'user', 'others', 'admin', 'user_disabled',
            'role_changed', 'rotation', 'expired', 'account_switch'
        ))
    );
CREATE INDEX login_sessions_binding_idx
    ON login_sessions (session_binding_id, id);

ALTER TABLE authorization_codes DROP CONSTRAINT authorization_codes_scopes_valid;
ALTER TABLE authorization_codes
    ADD COLUMN consent_grant_version bigint,
    ADD COLUMN origin_session_id uuid REFERENCES login_sessions(id) ON DELETE SET NULL,
    ADD COLUMN session_binding_id uuid;

UPDATE authorization_codes AS codes
SET consent_grant_version = grants.version
FROM consent_grants AS grants
WHERE grants.id = codes.consent_grant_id;

ALTER TABLE authorization_codes
    ALTER COLUMN consent_grant_version SET NOT NULL,
    ADD CONSTRAINT authorization_codes_consent_grant_version_valid CHECK (
        consent_grant_version > 0
    ),
    ADD CONSTRAINT authorization_codes_scopes_valid CHECK (
        cardinality(scopes) BETWEEN 1 AND 4
        AND scopes <@ ARRAY['email', 'offline_access', 'openid', 'profile']::text[]
        AND 'openid' = ANY(scopes)
        AND oneissuer_text_array_is_sorted_unique(scopes)
    ),
    ADD CONSTRAINT authorization_codes_offline_binding_valid CHECK (
        NOT ('offline_access' = ANY(scopes)) OR session_binding_id IS NOT NULL
    );

CREATE INDEX authorization_codes_session_binding_idx
    ON authorization_codes (session_binding_id, created_at DESC)
    WHERE session_binding_id IS NOT NULL;

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
        'access_token_issued', 'signing_key_loaded',
        'refresh_token_issued', 'refresh_token_rotated',
        'refresh_token_exchange_rejected', 'refresh_token_reuse_detected',
        'refresh_token_family_revoked', 'access_token_revoked',
        'consent_grant_revoked', 'consent_grant_reactivated',
        'rp_logout_completed', 'logout_transaction_rejected'
    )),
    ADD CONSTRAINT audit_events_target_valid CHECK (
        (target_type IS NULL AND target_id IS NULL)
        OR
        (target_type IN (
            'user', 'client', 'session', 'auth_transaction',
            'consent_grant', 'authorization_code', 'access_token',
            'refresh_token', 'refresh_token_family', 'logout_transaction'
        ) AND target_id IS NOT NULL)
    ),
    ADD CONSTRAINT audit_events_changed_fields_whitelist CHECK (
        changed_fields <@ ARRAY[
            'status', 'role', 'username', 'display_name', 'email',
            'name', 'description', 'logo_uri', 'registration_enabled',
            'redirect_uris', 'logout_uris', 'scopes', 'secret',
            'revoked', 'created', 'expanded', 'issued', 'consumed',
            'rotated', 'reused', 'reactivated'
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

DROP INDEX authorization_codes_session_binding_idx;
ALTER TABLE authorization_codes DROP CONSTRAINT authorization_codes_offline_binding_valid;
ALTER TABLE authorization_codes DROP CONSTRAINT authorization_codes_scopes_valid;
ALTER TABLE authorization_codes DROP CONSTRAINT authorization_codes_consent_grant_version_valid;
ALTER TABLE authorization_codes
    DROP COLUMN session_binding_id,
    DROP COLUMN origin_session_id,
    DROP COLUMN consent_grant_version;
ALTER TABLE authorization_codes
    ADD CONSTRAINT authorization_codes_scopes_valid CHECK (
        cardinality(scopes) BETWEEN 1 AND 3
        AND scopes <@ ARRAY['email', 'openid', 'profile']::text[]
        AND 'openid' = ANY(scopes)
        AND oneissuer_text_array_is_sorted_unique(scopes)
    );

DROP INDEX login_sessions_binding_idx;
ALTER TABLE login_sessions DROP CONSTRAINT login_sessions_revoke_reason_valid;
ALTER TABLE login_sessions DROP COLUMN session_binding_id;
ALTER TABLE login_sessions
    ADD CONSTRAINT login_sessions_revoke_reason_valid CHECK (
        (revoked_at IS NULL AND revoke_reason IS NULL)
        OR
        (revoked_at IS NOT NULL AND revoke_reason IN (
            'logout', 'user', 'others', 'admin', 'user_disabled',
            'role_changed', 'rotation', 'expired'
        ))
    );

DROP INDEX consent_grants_active_client_idx;
DROP INDEX consent_grants_user_updated_idx;
ALTER TABLE consent_grants DROP CONSTRAINT consent_grants_timestamps_valid;
ALTER TABLE consent_grants DROP CONSTRAINT consent_grants_version_valid;
ALTER TABLE consent_grants DROP CONSTRAINT consent_grants_scopes_valid;
ALTER TABLE consent_grants
    DROP COLUMN version,
    DROP COLUMN revoked_at;
ALTER TABLE consent_grants
    ADD CONSTRAINT consent_grants_scopes_valid CHECK (
        cardinality(scopes) BETWEEN 1 AND 3
        AND scopes <@ ARRAY['email', 'openid', 'profile']::text[]
        AND 'openid' = ANY(scopes)
        AND oneissuer_text_array_is_sorted_unique(scopes)
    ),
    ADD CONSTRAINT consent_grants_timestamps_valid CHECK (updated_at >= created_at);

ALTER TABLE auth_transactions DROP CONSTRAINT auth_transactions_authorization_context;
ALTER TABLE auth_transactions
    ADD CONSTRAINT auth_transactions_authorization_context CHECK (
        transaction_kind <> 'authorization'
        OR (
            client_id IS NOT NULL
            AND redirect_uri IS NOT NULL
            AND response_type = 'code'
            AND response_mode = 'query'
            AND pkce_challenge ~ '^[A-Za-z0-9_-]{43}$'
            AND pkce_method = 'S256'
            AND cardinality(scopes) BETWEEN 1 AND 3
            AND scopes <@ ARRAY['email', 'openid', 'profile']::text[]
            AND 'openid' = ANY(scopes)
            AND oneissuer_text_array_is_sorted_unique(scopes)
        )
    );
-- +goose StatementEnd
