-- name: CreateAuthTransaction :exec
INSERT INTO auth_transactions (
    id, token_hash, transaction_kind, client_id, redirect_uri, scopes,
    pkce_challenge, pkce_method, state_value, nonce_value, prompt_create,
    response_type, response_mode, prompt_values, max_age_seconds,
    created_at, expires_at
) VALUES (
    sqlc.arg(id), sqlc.arg(token_hash), sqlc.arg(transaction_kind),
    sqlc.arg(client_id), sqlc.arg(redirect_uri), sqlc.arg(scopes),
    sqlc.arg(pkce_challenge), sqlc.arg(pkce_method), sqlc.arg(state_value),
    sqlc.arg(nonce_value), sqlc.arg(prompt_create), sqlc.arg(response_type),
    sqlc.arg(response_mode), sqlc.arg(prompt_values), sqlc.arg(max_age_seconds), sqlc.arg(created_at),
    sqlc.arg(expires_at)
);

-- name: GetAuthTransactionByTokenHash :one
SELECT * FROM auth_transactions WHERE token_hash = sqlc.arg(token_hash);

-- name: GetAuthTransactionByID :one
SELECT * FROM auth_transactions WHERE id = sqlc.arg(id);

-- name: LockAuthTransactionByID :one
SELECT * FROM auth_transactions WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ConsumeAuthTransaction :one
UPDATE auth_transactions
SET consumed_at = sqlc.arg(consumed_at)
WHERE id = sqlc.arg(id)
  AND consumed_at IS NULL
  AND expires_at > sqlc.arg(consumed_at)
RETURNING *;

-- name: RejectAuthTransaction :one
UPDATE auth_transactions
SET consumed_at = sqlc.arg(consumed_at), failure_reason = sqlc.arg(failure_reason)
WHERE id = sqlc.arg(id)
  AND consumed_at IS NULL
  AND expires_at > sqlc.arg(consumed_at)
RETURNING *;

-- name: ExpireAuthTransactions :many
UPDATE auth_transactions
SET consumed_at = sqlc.arg(now), failure_reason = 'expired'
WHERE consumed_at IS NULL AND expires_at <= sqlc.arg(now)
RETURNING id;

-- name: DeleteRetiredAuthTransactions :execrows
DELETE FROM auth_transactions
WHERE consumed_at IS NOT NULL AND consumed_at <= sqlc.arg(cutoff);
