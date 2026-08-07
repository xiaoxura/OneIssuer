-- name: GetConsentGrantByUserClient :one
SELECT * FROM consent_grants
WHERE user_id = sqlc.arg(user_id) AND client_id = sqlc.arg(client_id);

-- name: LockConsentGrantByUserClient :one
SELECT * FROM consent_grants
WHERE user_id = sqlc.arg(user_id) AND client_id = sqlc.arg(client_id)
FOR UPDATE;

-- name: CreateConsentGrant :one
INSERT INTO consent_grants (id, user_id, client_id, scopes, created_at, updated_at)
VALUES (sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(client_id), sqlc.arg(scopes), sqlc.arg(created_at), sqlc.arg(updated_at))
RETURNING *;

-- name: UpdateConsentGrantScopes :one
UPDATE consent_grants
SET scopes = sqlc.arg(scopes),
    updated_at = sqlc.arg(updated_at),
    version = version + 1
WHERE id = sqlc.arg(id) AND revoked_at IS NULL
RETURNING *;

-- name: ReactivateConsentGrant :one
UPDATE consent_grants
SET scopes = sqlc.arg(scopes),
    revoked_at = NULL,
    updated_at = sqlc.arg(updated_at),
    version = version + 1
WHERE id = sqlc.arg(id) AND revoked_at IS NOT NULL
RETURNING *;

-- name: ListCurrentUserConsentGrants :many
SELECT grants.id, grants.user_id, grants.client_id, grants.scopes,
       grants.created_at, grants.updated_at, grants.revoked_at, grants.version,
       clients.client_id AS public_client_id, clients.name AS client_name,
       clients.status AS client_status,
       EXISTS (
           SELECT 1 FROM refresh_token_families AS families
           WHERE families.consent_grant_id = grants.id
             AND families.revoked_at IS NULL
             AND families.absolute_expires_at > sqlc.arg(now)
       ) AS has_active_offline_family
FROM consent_grants AS grants
JOIN oidc_clients AS clients ON clients.id = grants.client_id
WHERE grants.user_id = sqlc.arg(user_id)
  AND (
      sqlc.arg(cursor_time)::timestamptz IS NULL
      OR (grants.updated_at, clients.client_id) <
         (sqlc.arg(cursor_time)::timestamptz, sqlc.arg(cursor_client_id)::text)
  )
ORDER BY grants.updated_at DESC, clients.client_id DESC
LIMIT sqlc.arg(page_limit);

-- name: RevokeConsentGrant :one
UPDATE consent_grants
SET revoked_at = sqlc.arg(revoked_at),
    updated_at = sqlc.arg(revoked_at),
    version = version + 1
WHERE id = sqlc.arg(id) AND revoked_at IS NULL
RETURNING *;
