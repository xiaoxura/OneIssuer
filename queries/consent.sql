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
SET scopes = sqlc.arg(scopes), updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id)
RETURNING *;
