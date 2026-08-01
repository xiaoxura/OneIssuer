-- +goose Up
-- +goose StatementBegin
CREATE TABLE consent_grants (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    client_id uuid NOT NULL REFERENCES oidc_clients(id) ON DELETE RESTRICT,
    scopes text[] NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT consent_grants_user_client_unique UNIQUE (user_id, client_id),
    CONSTRAINT consent_grants_scopes_valid CHECK (
        cardinality(scopes) BETWEEN 1 AND 3
        AND scopes <@ ARRAY['email', 'openid', 'profile']::text[]
        AND 'openid' = ANY(scopes)
        AND oneissuer_text_array_is_sorted_unique(scopes)
    ),
    CONSTRAINT consent_grants_timestamps_valid CHECK (updated_at >= created_at)
);

CREATE INDEX consent_grants_client_idx ON consent_grants (client_id, updated_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE consent_grants;
-- +goose StatementEnd
