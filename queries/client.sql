-- name: CreateOIDCClient :one
INSERT INTO oidc_clients (
    id, client_id, client_type, token_endpoint_auth_method,
    name, description, logo_uri, status, registration_enabled,
    created_at, updated_at
) VALUES (
    sqlc.arg(id), sqlc.arg(client_id), sqlc.arg(client_type),
    sqlc.arg(token_endpoint_auth_method), sqlc.arg(name), sqlc.arg(description),
    sqlc.arg(logo_uri), sqlc.arg(status), sqlc.arg(registration_enabled),
    sqlc.arg(created_at), sqlc.arg(updated_at)
)
RETURNING *;

-- name: CreateOIDCClientRedirectURI :exec
INSERT INTO oidc_client_redirect_uris (client_id, uri, created_at)
VALUES (sqlc.arg(client_id), sqlc.arg(uri), sqlc.arg(created_at));

-- name: CreateOIDCClientLogoutURI :exec
INSERT INTO oidc_client_logout_uris (client_id, uri, created_at)
VALUES (sqlc.arg(client_id), sqlc.arg(uri), sqlc.arg(created_at));

-- name: CreateOIDCClientScope :exec
INSERT INTO oidc_client_scopes (client_id, scope, created_at)
VALUES (sqlc.arg(client_id), sqlc.arg(scope), sqlc.arg(created_at));

-- name: CreateOIDCClientSecret :exec
INSERT INTO oidc_client_secrets (
    id, client_id, secret_hash, version, created_at
) VALUES (
    sqlc.arg(id), sqlc.arg(client_id), sqlc.arg(secret_hash), 1, sqlc.arg(created_at)
);

-- name: GetOIDCClientByID :one
SELECT * FROM oidc_clients WHERE id = sqlc.arg(id);

-- name: GetOIDCClientByClientID :one
SELECT * FROM oidc_clients WHERE client_id = sqlc.arg(client_id);

-- name: LockOIDCClientByID :one
SELECT * FROM oidc_clients WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ListOIDCClients :many
SELECT *
FROM oidc_clients
WHERE (
        sqlc.arg(cursor_time)::timestamptz IS NULL
        OR (created_at, id) < (sqlc.arg(cursor_time)::timestamptz, sqlc.arg(cursor_id)::uuid)
      )
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(page_limit);

-- name: ListOIDCClientRedirectURIs :many
SELECT uri FROM oidc_client_redirect_uris
WHERE client_id = sqlc.arg(client_id)
ORDER BY uri;

-- name: ListOIDCClientLogoutURIs :many
SELECT uri FROM oidc_client_logout_uris
WHERE client_id = sqlc.arg(client_id)
ORDER BY uri;

-- name: ListOIDCClientScopes :many
SELECT scope FROM oidc_client_scopes
WHERE client_id = sqlc.arg(client_id)
ORDER BY scope;

-- name: UpdateOIDCClient :one
UPDATE oidc_clients SET
    name = sqlc.arg(name),
    description = sqlc.arg(description),
    logo_uri = sqlc.arg(logo_uri),
    status = sqlc.arg(status),
    registration_enabled = sqlc.arg(registration_enabled),
    updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id) AND updated_at = sqlc.arg(expected_updated_at)
RETURNING *;

-- name: DeleteOIDCClientRedirectURIs :exec
DELETE FROM oidc_client_redirect_uris WHERE client_id = sqlc.arg(client_id);

-- name: DeleteOIDCClientLogoutURIs :exec
DELETE FROM oidc_client_logout_uris WHERE client_id = sqlc.arg(client_id);

-- name: DeleteOIDCClientScopes :exec
DELETE FROM oidc_client_scopes WHERE client_id = sqlc.arg(client_id);

-- name: RevokeActiveOIDCClientSecrets :many
UPDATE oidc_client_secrets
SET revoked_at = sqlc.arg(revoked_at)
WHERE client_id = sqlc.arg(client_id) AND revoked_at IS NULL
RETURNING id;

-- name: ListActiveOIDCClientSecretHashes :many
SELECT secret_hash
FROM oidc_client_secrets
WHERE client_id = sqlc.arg(client_id) AND revoked_at IS NULL
ORDER BY created_at DESC;
