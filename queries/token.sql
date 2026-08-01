-- name: CreateAccessToken :exec
INSERT INTO access_tokens (
    id, jti_hash, authorization_code_id, consent_grant_id,
    user_id, client_id, scopes, issued_at, expires_at
) VALUES (
    sqlc.arg(id), sqlc.arg(jti_hash), sqlc.arg(authorization_code_id),
    sqlc.arg(consent_grant_id), sqlc.arg(user_id), sqlc.arg(client_id),
    sqlc.arg(scopes), sqlc.arg(issued_at), sqlc.arg(expires_at)
);

-- name: GetAccessTokenByJTIHash :one
SELECT * FROM access_tokens WHERE jti_hash = sqlc.arg(jti_hash);

-- name: HasAuthorizationCodeExchangeRejection :one
SELECT EXISTS (
    SELECT 1
    FROM audit_events
    WHERE event_type = 'authorization_code_exchange_rejected'
      AND target_type = 'authorization_code'
      AND target_id = sqlc.arg(authorization_code_id)
);

-- name: DeleteRetiredAccessTokens :execrows
DELETE FROM access_tokens WHERE expires_at <= sqlc.arg(cutoff);
