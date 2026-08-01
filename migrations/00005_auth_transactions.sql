-- +goose Up
-- +goose StatementBegin
CREATE TABLE auth_transactions (
    id uuid PRIMARY KEY,
    token_hash bytea NOT NULL UNIQUE,
    transaction_kind text NOT NULL,
    client_id uuid REFERENCES oidc_clients(id) ON DELETE RESTRICT,
    redirect_uri text,
    scopes text[] NOT NULL DEFAULT '{}',
    pkce_challenge text,
    pkce_method text,
    state_value text,
    nonce_value text,
    prompt_create boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    failure_reason text,
    CONSTRAINT auth_transactions_token_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT auth_transactions_kind_valid CHECK (transaction_kind IN ('local', 'authorization')),
    CONSTRAINT auth_transactions_expiry_valid CHECK (
        expires_at > created_at
        AND (consumed_at IS NULL OR consumed_at >= created_at)
    ),
    CONSTRAINT auth_transactions_scope_bounds CHECK (cardinality(scopes) <= 32),
    CONSTRAINT auth_transactions_context_bounds CHECK (
        (redirect_uri IS NULL OR length(redirect_uri) <= 2048)
        AND (pkce_challenge IS NULL OR length(pkce_challenge) <= 256)
        AND (state_value IS NULL OR length(state_value) <= 1024)
        AND (nonce_value IS NULL OR length(nonce_value) <= 1024)
    ),
    CONSTRAINT auth_transactions_pkce_valid CHECK (
        (pkce_challenge IS NULL AND pkce_method IS NULL)
        OR
        (pkce_challenge IS NOT NULL AND pkce_method = 'S256')
    ),
    CONSTRAINT auth_transactions_local_context CHECK (
        transaction_kind <> 'local'
        OR (
            client_id IS NULL AND redirect_uri IS NULL AND cardinality(scopes) = 0
            AND pkce_challenge IS NULL AND pkce_method IS NULL
            AND state_value IS NULL AND nonce_value IS NULL AND prompt_create = false
        )
    ),
    CONSTRAINT auth_transactions_authorization_context CHECK (
        transaction_kind <> 'authorization'
        OR (client_id IS NOT NULL AND redirect_uri IS NOT NULL AND cardinality(scopes) > 0)
    ),
    CONSTRAINT auth_transactions_failure_reason_valid CHECK (
        failure_reason IS NULL OR failure_reason IN (
            'expired', 'consumed', 'invalid', 'client_disabled',
            'registration_disabled', 'canceled'
        )
    )
);

ALTER TABLE preauth_sessions
    ADD CONSTRAINT preauth_sessions_auth_transaction_fk
    FOREIGN KEY (auth_transaction_id)
    REFERENCES auth_transactions(id)
    ON DELETE RESTRICT;

CREATE INDEX auth_transactions_expiry_idx
    ON auth_transactions (expires_at)
    WHERE consumed_at IS NULL;
CREATE INDEX auth_transactions_client_idx
    ON auth_transactions (client_id, created_at DESC)
    WHERE client_id IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE preauth_sessions DROP CONSTRAINT preauth_sessions_auth_transaction_fk;
DROP TABLE auth_transactions;
-- +goose StatementEnd
