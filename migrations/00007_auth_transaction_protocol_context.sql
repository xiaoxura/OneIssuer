-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION oneissuer_text_array_is_sorted_unique(input_array text[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
    SELECT input_array = COALESCE(
        (SELECT array_agg(item ORDER BY item)
         FROM (SELECT DISTINCT unnest(input_array) AS item) AS distinct_items),
        ARRAY[]::text[]
    );
$$;

ALTER TABLE auth_transactions
    ADD COLUMN response_type text,
    ADD COLUMN response_mode text,
    ADD COLUMN prompt_values text[] NOT NULL DEFAULT '{}',
    ADD COLUMN max_age_seconds bigint;

-- Phase-two authorization transactions cannot safely resume across the protocol
-- schema upgrade. Preserve them for retention/audit, but make them terminal and
-- backfill structurally valid context so the stronger invariant applies to every row.
UPDATE auth_transactions
SET consumed_at = COALESCE(consumed_at, clock_timestamp()),
    failure_reason = COALESCE(failure_reason, 'invalid'),
    response_type = 'code',
    response_mode = 'query',
    prompt_values = CASE WHEN prompt_create THEN ARRAY['create']::text[] ELSE ARRAY[]::text[] END,
    pkce_challenge = CASE
        WHEN pkce_challenge ~ '^[A-Za-z0-9_-]{43}$' AND pkce_method = 'S256' THEN pkce_challenge
        ELSE repeat('A', 43)
    END,
    pkce_method = 'S256',
    state_value = NULLIF(state_value, ''),
    nonce_value = NULLIF(nonce_value, '')
WHERE transaction_kind = 'authorization';

ALTER TABLE auth_transactions DROP CONSTRAINT auth_transactions_local_context;
ALTER TABLE auth_transactions DROP CONSTRAINT auth_transactions_authorization_context;
ALTER TABLE auth_transactions DROP CONSTRAINT auth_transactions_pkce_valid;
ALTER TABLE auth_transactions DROP CONSTRAINT auth_transactions_context_bounds;
ALTER TABLE auth_transactions DROP CONSTRAINT auth_transactions_failure_reason_valid;

ALTER TABLE auth_transactions
    ADD CONSTRAINT auth_transactions_context_bounds CHECK (
        (redirect_uri IS NULL OR octet_length(redirect_uri) BETWEEN 1 AND 2048)
        AND (pkce_challenge IS NULL OR octet_length(pkce_challenge) = 43)
        AND (state_value IS NULL OR octet_length(state_value) BETWEEN 1 AND 1024)
        AND (nonce_value IS NULL OR octet_length(nonce_value) BETWEEN 1 AND 1024)
        AND cardinality(prompt_values) <= 4
        AND (max_age_seconds IS NULL OR max_age_seconds BETWEEN 0 AND 2592000)
    ),
    ADD CONSTRAINT auth_transactions_pkce_valid CHECK (
        (pkce_challenge IS NULL AND pkce_method IS NULL)
        OR
        (pkce_challenge ~ '^[A-Za-z0-9_-]{43}$' AND pkce_method = 'S256')
    ),
    ADD CONSTRAINT auth_transactions_prompt_valid CHECK (
        oneissuer_text_array_is_sorted_unique(prompt_values)
        AND prompt_values <@ ARRAY['consent', 'create', 'login', 'none']::text[]
        AND (NOT ('none' = ANY(prompt_values)) OR cardinality(prompt_values) = 1)
        AND NOT ('create' = ANY(prompt_values) AND 'login' = ANY(prompt_values))
        AND prompt_create = ('create' = ANY(prompt_values))
    ),
    ADD CONSTRAINT auth_transactions_local_context CHECK (
        transaction_kind <> 'local'
        OR (
            client_id IS NULL AND redirect_uri IS NULL AND cardinality(scopes) = 0
            AND pkce_challenge IS NULL AND pkce_method IS NULL
            AND state_value IS NULL AND nonce_value IS NULL AND prompt_create = false
            AND response_type IS NULL AND response_mode IS NULL
            AND cardinality(prompt_values) = 0 AND max_age_seconds IS NULL
        )
    ),
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
    ),
    ADD CONSTRAINT auth_transactions_failure_reason_valid CHECK (
        failure_reason IS NULL OR failure_reason IN (
            'expired', 'consumed', 'invalid', 'client_disabled',
            'registration_disabled', 'canceled', 'login_required',
            'consent_required', 'interaction_required', 'access_denied',
            'server_error'
        )
    );
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE auth_transactions DROP CONSTRAINT auth_transactions_local_context;
ALTER TABLE auth_transactions DROP CONSTRAINT auth_transactions_authorization_context;
ALTER TABLE auth_transactions DROP CONSTRAINT auth_transactions_pkce_valid;
ALTER TABLE auth_transactions DROP CONSTRAINT auth_transactions_prompt_valid;
ALTER TABLE auth_transactions DROP CONSTRAINT auth_transactions_context_bounds;
ALTER TABLE auth_transactions DROP CONSTRAINT auth_transactions_failure_reason_valid;

ALTER TABLE auth_transactions
    ADD CONSTRAINT auth_transactions_context_bounds CHECK (
        (redirect_uri IS NULL OR length(redirect_uri) <= 2048)
        AND (pkce_challenge IS NULL OR length(pkce_challenge) <= 256)
        AND (state_value IS NULL OR length(state_value) <= 1024)
        AND (nonce_value IS NULL OR length(nonce_value) <= 1024)
    ),
    ADD CONSTRAINT auth_transactions_pkce_valid CHECK (
        (pkce_challenge IS NULL AND pkce_method IS NULL)
        OR
        (pkce_challenge IS NOT NULL AND pkce_method = 'S256')
    ),
    ADD CONSTRAINT auth_transactions_local_context CHECK (
        transaction_kind <> 'local'
        OR (
            client_id IS NULL AND redirect_uri IS NULL AND cardinality(scopes) = 0
            AND pkce_challenge IS NULL AND pkce_method IS NULL
            AND state_value IS NULL AND nonce_value IS NULL AND prompt_create = false
        )
    ),
    ADD CONSTRAINT auth_transactions_authorization_context CHECK (
        transaction_kind <> 'authorization'
        OR (client_id IS NOT NULL AND redirect_uri IS NOT NULL AND cardinality(scopes) > 0)
    ),
    ADD CONSTRAINT auth_transactions_failure_reason_valid CHECK (
        failure_reason IS NULL OR failure_reason IN (
            'expired', 'consumed', 'invalid', 'client_disabled',
            'registration_disabled', 'canceled'
        )
    );

ALTER TABLE auth_transactions
    DROP COLUMN max_age_seconds,
    DROP COLUMN prompt_values,
    DROP COLUMN response_mode,
    DROP COLUMN response_type;
DROP FUNCTION oneissuer_text_array_is_sorted_unique(text[]);
-- +goose StatementEnd
