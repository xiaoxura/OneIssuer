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
WITH candidates AS (
    SELECT id
    FROM auth_transactions
    WHERE consumed_at IS NULL AND expires_at <= sqlc.arg(now)
    ORDER BY expires_at, id
    LIMIT sqlc.arg(batch_limit)
    FOR UPDATE SKIP LOCKED
)
UPDATE auth_transactions AS transactions
SET consumed_at = sqlc.arg(now), failure_reason = 'expired'
FROM candidates
WHERE transactions.id = candidates.id
RETURNING transactions.id;

-- name: DeleteRetiredAuthTransactions :execrows
WITH candidates AS (
    SELECT transactions.id
    FROM auth_transactions AS transactions
    WHERE transactions.consumed_at IS NOT NULL
      AND transactions.consumed_at <= sqlc.arg(cutoff)
      AND NOT EXISTS (
          SELECT 1 FROM preauth_sessions AS preauth
          WHERE preauth.auth_transaction_id = transactions.id
      )
      AND NOT EXISTS (
          SELECT 1 FROM authorization_codes AS codes
          WHERE codes.auth_transaction_id = transactions.id
      )
    ORDER BY transactions.consumed_at, transactions.id
    LIMIT sqlc.arg(batch_limit)
    FOR UPDATE OF transactions SKIP LOCKED
)
DELETE FROM auth_transactions AS transactions
USING candidates
WHERE transactions.id = candidates.id;
