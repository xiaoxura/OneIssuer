-- +goose Up
-- +goose StatementBegin
CREATE TABLE access_tokens (
    id uuid PRIMARY KEY,
    jti_hash bytea NOT NULL UNIQUE,
    authorization_code_id uuid NOT NULL UNIQUE REFERENCES authorization_codes(id) ON DELETE RESTRICT,
    consent_grant_id uuid NOT NULL REFERENCES consent_grants(id) ON DELETE RESTRICT,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    client_id uuid NOT NULL REFERENCES oidc_clients(id) ON DELETE RESTRICT,
    scopes text[] NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT access_tokens_jti_hash_length CHECK (octet_length(jti_hash) = 32),
    CONSTRAINT access_tokens_scopes_valid CHECK (
        cardinality(scopes) BETWEEN 1 AND 3
        AND scopes <@ ARRAY['email', 'openid', 'profile']::text[]
        AND 'openid' = ANY(scopes)
        AND oneissuer_text_array_is_sorted_unique(scopes)
    ),
    CONSTRAINT access_tokens_lifetime_valid CHECK (
        expires_at > issued_at
        AND expires_at <= issued_at + interval '30 minutes'
    )
);

CREATE INDEX access_tokens_live_expiry_idx ON access_tokens (expires_at);
CREATE INDEX access_tokens_user_client_idx ON access_tokens (user_id, client_id, issued_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE access_tokens;
-- +goose StatementEnd
