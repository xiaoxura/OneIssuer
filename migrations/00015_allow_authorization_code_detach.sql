-- +goose Up
-- +goose StatementBegin
ALTER TABLE access_tokens DROP CONSTRAINT access_tokens_source_valid;
ALTER TABLE access_tokens
    ADD CONSTRAINT access_tokens_source_valid CHECK (
        (
            issuance_source = 'authorization_code'
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
    );

CREATE OR REPLACE FUNCTION oneissuer_validate_access_token_authority()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    family refresh_token_families%ROWTYPE;
    generation refresh_tokens%ROWTYPE;
    code authorization_codes%ROWTYPE;
BEGIN
    IF NEW.issuance_source = 'authorization_code' THEN
        IF NEW.authorization_code_id IS NULL THEN
            -- The FK's ON DELETE SET NULL action runs after its parent Code is
            -- gone. Only that exact authority-preserving transition may detach
            -- a Code-sourced Access row.
            IF TG_OP = 'UPDATE' THEN
                IF OLD.issuance_source = 'authorization_code'
                   AND OLD.authorization_code_id IS NOT NULL
                   AND NEW.source_refresh_token_id IS NOT DISTINCT FROM OLD.source_refresh_token_id
                   AND NEW.refresh_family_id IS NOT DISTINCT FROM OLD.refresh_family_id
                   AND NEW.origin_session_id IS NOT DISTINCT FROM OLD.origin_session_id
                   AND NEW.session_binding_id IS NOT DISTINCT FROM OLD.session_binding_id
                   AND NEW.consent_grant_id IS NOT DISTINCT FROM OLD.consent_grant_id
                   AND NEW.user_id IS NOT DISTINCT FROM OLD.user_id
                   AND NEW.client_id IS NOT DISTINCT FROM OLD.client_id
                   AND NEW.scopes IS NOT DISTINCT FROM OLD.scopes
                   AND NOT EXISTS (
                       SELECT 1 FROM authorization_codes
                       WHERE id = OLD.authorization_code_id
                   ) THEN
                    RETURN NEW;
                END IF;
            END IF;
            RAISE EXCEPTION 'authorization-code Access authority is inconsistent'
                USING ERRCODE = '23514';
        END IF;

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

CREATE OR REPLACE FUNCTION oneissuer_prevent_access_source_mutation()
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

    IF NEW.authorization_code_id IS DISTINCT FROM OLD.authorization_code_id THEN
        IF OLD.issuance_source IS DISTINCT FROM 'authorization_code'
           OR OLD.authorization_code_id IS NULL
           OR NEW.authorization_code_id IS NOT NULL
           OR EXISTS (
               SELECT 1 FROM authorization_codes
               WHERE id = OLD.authorization_code_id
           ) THEN
            RAISE EXCEPTION 'access token issuance authority is immutable'
                USING ERRCODE = '55000';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM access_tokens
        WHERE issuance_source = 'authorization_code'
          AND authorization_code_id IS NULL
    ) THEN
        RAISE EXCEPTION 'cannot restore schema 14 constraints with detached access tokens'
            USING ERRCODE = '55000';
    END IF;
END;
$$;

ALTER TABLE access_tokens DROP CONSTRAINT access_tokens_source_valid;
ALTER TABLE access_tokens
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
    );

CREATE OR REPLACE FUNCTION oneissuer_validate_access_token_authority()
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

CREATE OR REPLACE FUNCTION oneissuer_prevent_access_source_mutation()
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
-- +goose StatementEnd
