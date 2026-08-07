-- +goose Up
-- +goose StatementBegin
CREATE TABLE refresh_token_families (
    id uuid PRIMARY KEY,
    origin_authorization_code_id uuid REFERENCES authorization_codes(id) ON DELETE SET NULL,
    consent_grant_id uuid NOT NULL REFERENCES consent_grants(id) ON DELETE RESTRICT,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    client_id uuid NOT NULL REFERENCES oidc_clients(id) ON DELETE RESTRICT,
    origin_session_id uuid REFERENCES login_sessions(id) ON DELETE SET NULL,
    session_binding_id uuid NOT NULL,
    scopes text[] NOT NULL,
    created_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revoke_reason text,
    CONSTRAINT refresh_token_families_scopes_valid CHECK (
        cardinality(scopes) BETWEEN 2 AND 4
        AND scopes <@ ARRAY['email', 'offline_access', 'openid', 'profile']::text[]
        AND 'openid' = ANY(scopes)
        AND 'offline_access' = ANY(scopes)
        AND oneissuer_text_array_is_sorted_unique(scopes)
    ),
    CONSTRAINT refresh_token_families_lifetime_valid CHECK (
        absolute_expires_at > created_at
        AND absolute_expires_at <= created_at + interval '365 days'
        AND (revoked_at IS NULL OR revoked_at >= created_at)
    ),
    CONSTRAINT refresh_token_families_revoke_reason_valid CHECK (
        (revoked_at IS NULL AND revoke_reason IS NULL)
        OR
        (revoked_at IS NOT NULL AND revoke_reason IN (
            'reuse', 'client_revocation', 'grant_revoked', 'session_revoked',
            'user_disabled', 'client_disabled', 'offline_scope_removed',
            'account_switch'
        ))
    )
);

CREATE UNIQUE INDEX refresh_token_families_origin_code_idx
    ON refresh_token_families (origin_authorization_code_id)
    WHERE origin_authorization_code_id IS NOT NULL;
CREATE INDEX refresh_token_families_grant_active_idx
    ON refresh_token_families (consent_grant_id, id)
    WHERE revoked_at IS NULL;
CREATE INDEX refresh_token_families_client_active_idx
    ON refresh_token_families (client_id, id)
    WHERE revoked_at IS NULL;
CREATE INDEX refresh_token_families_user_active_idx
    ON refresh_token_families (user_id, id)
    WHERE revoked_at IS NULL;
CREATE INDEX refresh_token_families_binding_active_idx
    ON refresh_token_families (session_binding_id, id)
    WHERE revoked_at IS NULL;
CREATE INDEX refresh_token_families_absolute_expiry_idx
    ON refresh_token_families (absolute_expires_at, id);

CREATE TABLE refresh_tokens (
    id uuid PRIMARY KEY,
    family_id uuid NOT NULL REFERENCES refresh_token_families(id) ON DELETE RESTRICT,
    token_hash bytea NOT NULL UNIQUE,
    generation bigint NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CONSTRAINT refresh_tokens_family_generation_unique UNIQUE (family_id, generation),
    CONSTRAINT refresh_tokens_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT refresh_tokens_generation_valid CHECK (generation >= 0),
    CONSTRAINT refresh_tokens_lifetime_valid CHECK (
        expires_at > issued_at
        AND expires_at <= issued_at + interval '30 days'
        AND (consumed_at IS NULL OR consumed_at >= issued_at)
    )
);

CREATE INDEX refresh_tokens_family_issued_idx
    ON refresh_tokens (family_id, generation DESC);
CREATE INDEX refresh_tokens_expiry_idx
    ON refresh_tokens (expires_at, id);
CREATE INDEX refresh_tokens_consumed_idx
    ON refresh_tokens (consumed_at, id)
    WHERE consumed_at IS NOT NULL;

CREATE FUNCTION oneissuer_validate_refresh_family_origin()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    origin authorization_codes%ROWTYPE;
BEGIN
    IF NEW.origin_authorization_code_id IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT * INTO origin
    FROM authorization_codes
    WHERE id = NEW.origin_authorization_code_id;
    IF NOT FOUND
       OR origin.user_id <> NEW.user_id
       OR origin.client_id <> NEW.client_id
       OR origin.consent_grant_id <> NEW.consent_grant_id
       OR NOT ('offline_access' = ANY(origin.scopes))
       OR origin.session_binding_id IS NULL
       OR origin.session_binding_id <> NEW.session_binding_id THEN
        RAISE EXCEPTION 'refresh family origin is inconsistent'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER refresh_token_families_origin_guard
BEFORE INSERT OR UPDATE OF origin_authorization_code_id, consent_grant_id,
    user_id, client_id, session_binding_id
ON refresh_token_families
FOR EACH ROW EXECUTE FUNCTION oneissuer_validate_refresh_family_origin();

CREATE FUNCTION oneissuer_validate_refresh_token_lifetime()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    family_created timestamptz;
    family_absolute timestamptz;
BEGIN
    SELECT created_at, absolute_expires_at
    INTO family_created, family_absolute
    FROM refresh_token_families
    WHERE id = NEW.family_id;
    IF NOT FOUND
       OR NEW.issued_at < family_created
       OR NEW.expires_at > family_absolute THEN
        RAISE EXCEPTION 'refresh token lifetime exceeds family authority'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER refresh_tokens_lifetime_guard
BEFORE INSERT OR UPDATE OF family_id, issued_at, expires_at
ON refresh_tokens
FOR EACH ROW EXECUTE FUNCTION oneissuer_validate_refresh_token_lifetime();

ALTER TABLE access_tokens DROP CONSTRAINT access_tokens_authorization_code_id_fkey;
ALTER TABLE access_tokens DROP CONSTRAINT access_tokens_authorization_code_id_key;
ALTER TABLE access_tokens DROP CONSTRAINT access_tokens_scopes_valid;
ALTER TABLE access_tokens DROP CONSTRAINT access_tokens_lifetime_valid;
ALTER TABLE access_tokens ALTER COLUMN authorization_code_id DROP NOT NULL;
ALTER TABLE access_tokens
    ADD CONSTRAINT access_tokens_authorization_code_id_fkey
        FOREIGN KEY (authorization_code_id) REFERENCES authorization_codes(id) ON DELETE SET NULL,
    ADD COLUMN issuance_source text NOT NULL DEFAULT 'authorization_code',
    ADD COLUMN source_refresh_token_id uuid UNIQUE REFERENCES refresh_tokens(id) ON DELETE RESTRICT,
    ADD COLUMN refresh_family_id uuid REFERENCES refresh_token_families(id) ON DELETE RESTRICT,
    ADD COLUMN origin_session_id uuid REFERENCES login_sessions(id) ON DELETE SET NULL,
    ADD COLUMN session_binding_id uuid,
    ADD COLUMN revoked_at timestamptz,
    ADD COLUMN revoke_reason text,
    ADD CONSTRAINT access_tokens_issuance_source_valid CHECK (
        issuance_source IN ('authorization_code', 'refresh_token')
    ),
    ADD CONSTRAINT access_tokens_source_valid CHECK (
        (
            issuance_source = 'authorization_code'
            AND authorization_code_id IS NOT NULL
            AND source_refresh_token_id IS NULL
        )
        OR
        (
            issuance_source = 'refresh_token'
            AND authorization_code_id IS NULL
            AND source_refresh_token_id IS NOT NULL
            AND refresh_family_id IS NOT NULL
            AND session_binding_id IS NOT NULL
        )
    ),
    ADD CONSTRAINT access_tokens_offline_source_valid CHECK (
        NOT ('offline_access' = ANY(scopes))
        OR (refresh_family_id IS NOT NULL AND session_binding_id IS NOT NULL)
    ),
    ADD CONSTRAINT access_tokens_scopes_valid CHECK (
        cardinality(scopes) BETWEEN 1 AND 4
        AND scopes <@ ARRAY['email', 'offline_access', 'openid', 'profile']::text[]
        AND 'openid' = ANY(scopes)
        AND oneissuer_text_array_is_sorted_unique(scopes)
    ),
    ADD CONSTRAINT access_tokens_lifetime_valid CHECK (
        expires_at > issued_at
        AND expires_at <= issued_at + interval '30 minutes'
        AND (revoked_at IS NULL OR revoked_at >= issued_at)
    ),
    ADD CONSTRAINT access_tokens_revoke_reason_valid CHECK (
        (revoked_at IS NULL AND revoke_reason IS NULL)
        OR
        (revoked_at IS NOT NULL AND revoke_reason IN (
            'client_revocation', 'family_revoked', 'grant_revoked',
            'session_revoked', 'user_disabled', 'client_disabled',
            'offline_scope_removed', 'account_switch'
        ))
    );
ALTER TABLE access_tokens ALTER COLUMN issuance_source DROP DEFAULT;

CREATE FUNCTION oneissuer_validate_access_token_authority()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    family refresh_token_families%ROWTYPE;
    generation refresh_tokens%ROWTYPE;
    code authorization_codes%ROWTYPE;
BEGIN
    IF NEW.issuance_source = 'authorization_code' THEN
        SELECT * INTO code
        FROM authorization_codes
        WHERE id = NEW.authorization_code_id;
        IF NOT FOUND
           OR code.consent_grant_id <> NEW.consent_grant_id
           OR code.user_id <> NEW.user_id
           OR code.client_id <> NEW.client_id
           OR code.scopes IS DISTINCT FROM NEW.scopes
           OR code.origin_session_id IS DISTINCT FROM NEW.origin_session_id
           OR code.session_binding_id IS DISTINCT FROM NEW.session_binding_id
           OR NEW.source_refresh_token_id IS NOT NULL THEN
            RAISE EXCEPTION 'authorization-code Access authority is inconsistent'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.refresh_family_id IS NOT NULL THEN
            SELECT * INTO family
            FROM refresh_token_families
            WHERE id = NEW.refresh_family_id;
            IF NOT FOUND
               OR family.origin_authorization_code_id IS DISTINCT FROM NEW.authorization_code_id
               OR family.consent_grant_id <> NEW.consent_grant_id
               OR family.user_id <> NEW.user_id
               OR family.client_id <> NEW.client_id
               OR family.origin_session_id IS DISTINCT FROM NEW.origin_session_id
               OR family.session_binding_id IS DISTINCT FROM NEW.session_binding_id
               OR family.scopes IS DISTINCT FROM code.scopes
               OR NEW.scopes IS DISTINCT FROM code.scopes
               OR NOT ('offline_access' = ANY(NEW.scopes)) THEN
                RAISE EXCEPTION 'authorization-code Refresh family authority is inconsistent'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
        RETURN NEW;
    END IF;

    SELECT * INTO generation
    FROM refresh_tokens
    WHERE id = NEW.source_refresh_token_id;
    SELECT * INTO family
    FROM refresh_token_families
    WHERE id = NEW.refresh_family_id;
    IF generation.id IS NULL
       OR family.id IS NULL
       OR generation.family_id <> NEW.refresh_family_id
       OR family.id <> NEW.refresh_family_id
       OR family.consent_grant_id <> NEW.consent_grant_id
       OR family.user_id <> NEW.user_id
       OR family.client_id <> NEW.client_id
       OR family.origin_session_id IS DISTINCT FROM NEW.origin_session_id
       OR family.session_binding_id IS DISTINCT FROM NEW.session_binding_id
       OR NOT (NEW.scopes <@ family.scopes)
       OR NEW.authorization_code_id IS NOT NULL THEN
        RAISE EXCEPTION 'refresh-sourced Access authority is inconsistent'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER access_tokens_authority_guard
BEFORE INSERT OR UPDATE OF authorization_code_id, source_refresh_token_id,
    refresh_family_id, origin_session_id, session_binding_id, consent_grant_id,
    user_id, client_id, scopes, issuance_source
ON access_tokens
FOR EACH ROW EXECUTE FUNCTION oneissuer_validate_access_token_authority();

CREATE UNIQUE INDEX access_tokens_authorization_code_source_idx
    ON access_tokens (authorization_code_id)
    WHERE authorization_code_id IS NOT NULL;
CREATE INDEX access_tokens_family_live_idx
    ON access_tokens (refresh_family_id, id)
    WHERE refresh_family_id IS NOT NULL AND revoked_at IS NULL;
CREATE INDEX access_tokens_binding_live_idx
    ON access_tokens (session_binding_id, id)
    WHERE session_binding_id IS NOT NULL AND revoked_at IS NULL;
CREATE INDEX access_tokens_grant_live_idx
    ON access_tokens (consent_grant_id, id)
    WHERE revoked_at IS NULL;
CREATE INDEX access_tokens_revoked_retirement_idx
    ON access_tokens (revoked_at, id)
    WHERE revoked_at IS NOT NULL;

CREATE FUNCTION oneissuer_prevent_access_source_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.issuance_source IS DISTINCT FROM OLD.issuance_source
       OR NEW.source_refresh_token_id IS DISTINCT FROM OLD.source_refresh_token_id
       OR NEW.refresh_family_id IS DISTINCT FROM OLD.refresh_family_id
       OR NEW.consent_grant_id IS DISTINCT FROM OLD.consent_grant_id
       OR NEW.user_id IS DISTINCT FROM OLD.user_id
       OR NEW.client_id IS DISTINCT FROM OLD.client_id
       OR NEW.session_binding_id IS DISTINCT FROM OLD.session_binding_id THEN
        RAISE EXCEPTION 'access token issuance authority is immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER access_tokens_immutable_source
BEFORE UPDATE ON access_tokens
FOR EACH ROW EXECUTE FUNCTION oneissuer_prevent_access_source_mutation();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- A populated Phase 4 database cannot be losslessly represented by the
-- pre-Phase 4 access_tokens shape. Refuse before any DDL so an operator gets a
-- bounded, atomic failure instead of a partially downgraded schema.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM access_tokens
        WHERE authorization_code_id IS NULL
           OR issuance_source <> 'authorization_code'
    ) THEN
        RAISE EXCEPTION
            'cannot downgrade schema 13 with refresh-sourced or detached access tokens'
            USING ERRCODE = '55000';
    END IF;
END;
$$;

DROP TRIGGER access_tokens_authority_guard ON access_tokens;
DROP FUNCTION oneissuer_validate_access_token_authority();
DROP TRIGGER access_tokens_immutable_source ON access_tokens;
DROP FUNCTION oneissuer_prevent_access_source_mutation();

DROP INDEX access_tokens_revoked_retirement_idx;
DROP INDEX access_tokens_grant_live_idx;
DROP INDEX access_tokens_binding_live_idx;
DROP INDEX access_tokens_family_live_idx;
DROP INDEX access_tokens_authorization_code_source_idx;

ALTER TABLE access_tokens DROP CONSTRAINT access_tokens_revoke_reason_valid;
ALTER TABLE access_tokens DROP CONSTRAINT access_tokens_lifetime_valid;
ALTER TABLE access_tokens DROP CONSTRAINT access_tokens_scopes_valid;
ALTER TABLE access_tokens DROP CONSTRAINT access_tokens_offline_source_valid;
ALTER TABLE access_tokens DROP CONSTRAINT access_tokens_source_valid;
ALTER TABLE access_tokens DROP CONSTRAINT access_tokens_issuance_source_valid;
ALTER TABLE access_tokens DROP CONSTRAINT access_tokens_authorization_code_id_fkey;
ALTER TABLE access_tokens
    DROP COLUMN revoke_reason,
    DROP COLUMN revoked_at,
    DROP COLUMN session_binding_id,
    DROP COLUMN origin_session_id,
    DROP COLUMN refresh_family_id,
    DROP COLUMN source_refresh_token_id,
    DROP COLUMN issuance_source;
ALTER TABLE access_tokens ALTER COLUMN authorization_code_id SET NOT NULL;
ALTER TABLE access_tokens
    ADD CONSTRAINT access_tokens_authorization_code_id_fkey
        FOREIGN KEY (authorization_code_id) REFERENCES authorization_codes(id) ON DELETE RESTRICT,
    ADD CONSTRAINT access_tokens_authorization_code_id_key UNIQUE (authorization_code_id),
    ADD CONSTRAINT access_tokens_scopes_valid CHECK (
        cardinality(scopes) BETWEEN 1 AND 3
        AND scopes <@ ARRAY['email', 'openid', 'profile']::text[]
        AND 'openid' = ANY(scopes)
        AND oneissuer_text_array_is_sorted_unique(scopes)
    ),
    ADD CONSTRAINT access_tokens_lifetime_valid CHECK (
        expires_at > issued_at
        AND expires_at <= issued_at + interval '30 minutes'
    );

DROP TRIGGER refresh_tokens_lifetime_guard ON refresh_tokens;
DROP FUNCTION oneissuer_validate_refresh_token_lifetime();
DROP TRIGGER refresh_token_families_origin_guard ON refresh_token_families;
DROP FUNCTION oneissuer_validate_refresh_family_origin();

DROP TABLE refresh_tokens;
DROP TABLE refresh_token_families;
-- +goose StatementEnd
