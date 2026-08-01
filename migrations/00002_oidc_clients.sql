-- +goose Up
-- +goose StatementBegin
CREATE TABLE oidc_clients (
    id uuid PRIMARY KEY,
    client_id text NOT NULL UNIQUE,
    client_type text NOT NULL,
    token_endpoint_auth_method text NOT NULL,
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    logo_uri text,
    status text NOT NULL DEFAULT 'active',
    registration_enabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT oidc_clients_id_format CHECK (
        client_id LIKE 'ois_cli_%' AND length(client_id) BETWEEN 40 AND 128
    ),
    CONSTRAINT oidc_clients_type_valid CHECK (client_type IN ('public', 'confidential')),
    CONSTRAINT oidc_clients_auth_method_valid CHECK (
        (client_type = 'public' AND token_endpoint_auth_method = 'none')
        OR
        (client_type = 'confidential' AND token_endpoint_auth_method = 'client_secret_basic')
    ),
    CONSTRAINT oidc_clients_name_bounds CHECK (length(name) BETWEEN 1 AND 256),
    CONSTRAINT oidc_clients_description_bounds CHECK (length(description) <= 2048),
    CONSTRAINT oidc_clients_logo_uri_bounds CHECK (logo_uri IS NULL OR length(logo_uri) <= 2048),
    CONSTRAINT oidc_clients_status_valid CHECK (status IN ('active', 'disabled')),
    CONSTRAINT oidc_clients_timestamps_valid CHECK (updated_at >= created_at)
);

CREATE TABLE oidc_client_redirect_uris (
    client_id uuid NOT NULL REFERENCES oidc_clients(id) ON DELETE RESTRICT,
    uri text NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (client_id, uri),
    CONSTRAINT oidc_client_redirect_uri_bounds CHECK (length(uri) BETWEEN 8 AND 2048)
);

CREATE TABLE oidc_client_logout_uris (
    client_id uuid NOT NULL REFERENCES oidc_clients(id) ON DELETE RESTRICT,
    uri text NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (client_id, uri),
    CONSTRAINT oidc_client_logout_uri_bounds CHECK (length(uri) BETWEEN 8 AND 2048)
);

CREATE TABLE oidc_client_scopes (
    client_id uuid NOT NULL REFERENCES oidc_clients(id) ON DELETE RESTRICT,
    scope text NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (client_id, scope),
    CONSTRAINT oidc_client_scope_format CHECK (
        scope ~ '^[a-z][a-z0-9:_-]{0,63}$'
    )
);

CREATE TABLE oidc_client_secrets (
    id uuid PRIMARY KEY,
    client_id uuid NOT NULL REFERENCES oidc_clients(id) ON DELETE RESTRICT,
    secret_hash bytea NOT NULL UNIQUE,
    version smallint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CONSTRAINT oidc_client_secret_hash_length CHECK (octet_length(secret_hash) = 32),
    CONSTRAINT oidc_client_secret_version_valid CHECK (version = 1),
    CONSTRAINT oidc_client_secret_timestamps_valid CHECK (
        revoked_at IS NULL OR revoked_at >= created_at
    )
);

CREATE INDEX oidc_clients_created_cursor_idx ON oidc_clients (created_at DESC, id DESC);
CREATE INDEX oidc_client_secrets_active_idx
    ON oidc_client_secrets (client_id, created_at DESC)
    WHERE revoked_at IS NULL;

CREATE FUNCTION oneissuer_enforce_confidential_secret()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM oidc_clients
        WHERE id = NEW.client_id
          AND client_type = 'confidential'
          AND token_endpoint_auth_method = 'client_secret_basic'
    ) THEN
        RAISE EXCEPTION 'client secrets require a confidential client'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER oidc_client_secrets_confidential_only
BEFORE INSERT OR UPDATE OF client_id ON oidc_client_secrets
FOR EACH ROW EXECUTE FUNCTION oneissuer_enforce_confidential_secret();

CREATE FUNCTION oneissuer_prevent_public_client_with_secrets()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.client_type = 'public' AND EXISTS (
        SELECT 1 FROM oidc_client_secrets WHERE client_id = NEW.id
    ) THEN
        RAISE EXCEPTION 'a client with secret history cannot become public'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER oidc_clients_public_secret_guard
BEFORE UPDATE OF client_type, token_endpoint_auth_method ON oidc_clients
FOR EACH ROW EXECUTE FUNCTION oneissuer_prevent_public_client_with_secrets();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER oidc_clients_public_secret_guard ON oidc_clients;
DROP FUNCTION oneissuer_prevent_public_client_with_secrets();
DROP TRIGGER oidc_client_secrets_confidential_only ON oidc_client_secrets;
DROP FUNCTION oneissuer_enforce_confidential_secret();
DROP TABLE oidc_client_secrets;
DROP TABLE oidc_client_scopes;
DROP TABLE oidc_client_logout_uris;
DROP TABLE oidc_client_redirect_uris;
DROP TABLE oidc_clients;
-- +goose StatementEnd
