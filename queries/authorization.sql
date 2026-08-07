-- name: CreateAuthorizationCode :exec
INSERT INTO authorization_codes (
    id, code_hash, auth_transaction_id, consent_grant_id, user_id, client_id,
    redirect_uri, scopes, pkce_challenge, pkce_method, nonce_value,
    auth_time, created_at, expires_at, consent_grant_version,
    origin_session_id, session_binding_id
) VALUES (
    sqlc.arg(id), sqlc.arg(code_hash), sqlc.arg(auth_transaction_id),
    sqlc.arg(consent_grant_id), sqlc.arg(user_id), sqlc.arg(client_id),
    sqlc.arg(redirect_uri), sqlc.arg(scopes), sqlc.arg(pkce_challenge),
    sqlc.arg(pkce_method), sqlc.arg(nonce_value), sqlc.arg(auth_time),
    sqlc.arg(created_at), sqlc.arg(expires_at), sqlc.arg(consent_grant_version),
    sqlc.arg(origin_session_id), sqlc.arg(session_binding_id)
);

-- name: GetAuthorizationCodeByHash :one
SELECT * FROM authorization_codes WHERE code_hash = sqlc.arg(code_hash);

-- name: LockAuthorizationCodeByHash :one
SELECT * FROM authorization_codes WHERE code_hash = sqlc.arg(code_hash) FOR UPDATE;

-- name: ConsumeAuthorizationCode :one
UPDATE authorization_codes
SET consumed_at = sqlc.arg(consumed_at)
WHERE id = sqlc.arg(id)
  AND consumed_at IS NULL
  AND expires_at > sqlc.arg(consumed_at)
RETURNING *;

-- name: DeleteRetiredAuthorizationCodes :execrows
WITH candidates AS (
    SELECT codes.id
    FROM authorization_codes AS codes
    WHERE codes.expires_at <= sqlc.arg(cutoff)
    ORDER BY codes.expires_at, codes.id
    LIMIT sqlc.arg(batch_limit)
    FOR UPDATE OF codes SKIP LOCKED
)
DELETE FROM authorization_codes AS codes
USING candidates
WHERE codes.id = candidates.id;
