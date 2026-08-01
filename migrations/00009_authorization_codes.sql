-- +goose Up
-- +goose StatementBegin
CREATE TABLE authorization_codes (
    id uuid PRIMARY KEY,
    code_hash bytea NOT NULL UNIQUE,
    auth_transaction_id uuid NOT NULL UNIQUE REFERENCES auth_transactions(id) ON DELETE RESTRICT,
    consent_grant_id uuid NOT NULL REFERENCES consent_grants(id) ON DELETE RESTRICT,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    client_id uuid NOT NULL REFERENCES oidc_clients(id) ON DELETE RESTRICT,
    redirect_uri text NOT NULL,
    scopes text[] NOT NULL,
    pkce_challenge text NOT NULL,
    pkce_method text NOT NULL,
    nonce_value text,
    auth_time timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CONSTRAINT authorization_codes_hash_length CHECK (octet_length(code_hash) = 32),
    CONSTRAINT authorization_codes_redirect_bounds CHECK (octet_length(redirect_uri) BETWEEN 1 AND 2048),
    CONSTRAINT authorization_codes_scopes_valid CHECK (
        cardinality(scopes) BETWEEN 1 AND 3
        AND scopes <@ ARRAY['email', 'openid', 'profile']::text[]
        AND 'openid' = ANY(scopes)
        AND oneissuer_text_array_is_sorted_unique(scopes)
    ),
    CONSTRAINT authorization_codes_pkce_valid CHECK (
        pkce_challenge ~ '^[A-Za-z0-9_-]{43}$' AND pkce_method = 'S256'
    ),
    CONSTRAINT authorization_codes_nonce_bounds CHECK (
        nonce_value IS NULL OR octet_length(nonce_value) BETWEEN 1 AND 1024
    ),
    CONSTRAINT authorization_codes_lifetime_valid CHECK (
        auth_time <= created_at
        AND expires_at > created_at
        AND expires_at <= created_at + interval '5 minutes'
        AND (consumed_at IS NULL OR consumed_at >= created_at)
    )
);

CREATE INDEX authorization_codes_live_expiry_idx
    ON authorization_codes (expires_at)
    WHERE consumed_at IS NULL;
CREATE INDEX authorization_codes_client_created_idx
    ON authorization_codes (client_id, created_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE authorization_codes;
-- +goose StatementEnd
