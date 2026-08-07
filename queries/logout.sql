-- name: CreateLogoutTransaction :exec
INSERT INTO logout_transactions (
    id, lookup_hash, stage, verified_client_id, post_logout_redirect_uri,
    state_value, hint_subject, created_at, expires_at
) VALUES (
    sqlc.arg(id), sqlc.arg(lookup_hash), 'pre_confirm', sqlc.arg(verified_client_id),
    sqlc.arg(post_logout_redirect_uri), sqlc.arg(state_value), sqlc.arg(hint_subject),
    sqlc.arg(created_at), sqlc.arg(expires_at)
);

-- name: GetLogoutTransactionByLookupHash :one
SELECT * FROM logout_transactions
WHERE lookup_hash = sqlc.arg(lookup_hash);

-- name: LockLogoutTransactionByLookupHash :one
SELECT * FROM logout_transactions
WHERE lookup_hash = sqlc.arg(lookup_hash)
FOR UPDATE;

-- name: CountLiveBoundLogoutTransactionsBySession :one
SELECT count(*)::bigint
FROM logout_transactions
WHERE session_id = sqlc.arg(session_id)
  AND stage = 'bound_confirmable'
  AND consumed_at IS NULL
  AND expires_at > sqlc.arg(now);

-- name: BindPreConfirmLogoutTransaction :one
UPDATE logout_transactions
SET stage = 'bound_confirmable',
    csrf_hash = sqlc.arg(csrf_hash),
    user_id = sqlc.arg(user_id),
    session_id = sqlc.arg(session_id),
    session_binding_id = sqlc.arg(session_binding_id),
    bound_at = sqlc.arg(bound_at),
    post_logout_redirect_uri = CASE
        WHEN hint_subject IS NULL OR hint_subject = sqlc.arg(subject) THEN post_logout_redirect_uri
        ELSE NULL
    END,
    state_value = CASE
        WHEN hint_subject IS NULL OR hint_subject = sqlc.arg(subject) THEN state_value
        ELSE NULL
    END
WHERE id = sqlc.arg(id)
  AND stage = 'pre_confirm'
  AND consumed_at IS NULL
  AND expires_at > sqlc.arg(bound_at)
RETURNING *;

-- name: RotateBoundLogoutTransactionCSRF :one
UPDATE logout_transactions
SET csrf_hash = sqlc.arg(csrf_hash)
WHERE id = sqlc.arg(id)
  AND stage = 'bound_confirmable'
  AND consumed_at IS NULL
  AND expires_at > sqlc.arg(now)
  AND user_id = sqlc.arg(user_id)
  AND session_id = sqlc.arg(session_id)
  AND session_binding_id = sqlc.arg(session_binding_id)
RETURNING *;

-- name: IncrementLogoutTransactionAttempt :one
UPDATE logout_transactions
SET attempt_count = attempt_count + 1
WHERE id = sqlc.arg(id)
  AND consumed_at IS NULL
  AND attempt_count < sqlc.arg(max_attempts)
RETURNING *;

-- name: LockLoginSessionByID :one
SELECT * FROM login_sessions
WHERE id = sqlc.arg(id)
FOR UPDATE;

-- name: LockUnrevokedRefreshTokenFamiliesByBinding :many
SELECT id
FROM refresh_token_families
WHERE session_binding_id = sqlc.arg(session_binding_id)
  AND revoked_at IS NULL
ORDER BY id
FOR UPDATE;

-- name: LockUnrevokedRefreshTokenFamiliesByBindings :many
SELECT id
FROM refresh_token_families
WHERE session_binding_id = ANY(sqlc.arg(session_binding_ids)::uuid[])
  AND revoked_at IS NULL
ORDER BY id
FOR UPDATE;

-- name: LockLiveAccessTokensByBinding :many
SELECT id
FROM access_tokens
WHERE session_binding_id = sqlc.arg(session_binding_id)
  AND revoked_at IS NULL
  AND expires_at > sqlc.arg(now)
ORDER BY id
FOR UPDATE;

-- name: LockLiveAccessTokensByBindings :many
SELECT id
FROM access_tokens
WHERE session_binding_id = ANY(sqlc.arg(session_binding_ids)::uuid[])
  AND revoked_at IS NULL
  AND expires_at > sqlc.arg(now)
ORDER BY id
FOR UPDATE;

-- name: RevokeRefreshTokenFamiliesByBinding :execrows
UPDATE refresh_token_families
SET revoked_at = sqlc.arg(revoked_at), revoke_reason = sqlc.arg(revoke_reason)
WHERE session_binding_id = sqlc.arg(session_binding_id)
  AND revoked_at IS NULL;

-- name: RevokeRefreshTokenFamiliesByBindings :execrows
UPDATE refresh_token_families
SET revoked_at = sqlc.arg(revoked_at), revoke_reason = sqlc.arg(revoke_reason)
WHERE session_binding_id = ANY(sqlc.arg(session_binding_ids)::uuid[])
  AND revoked_at IS NULL;

-- name: RevokeLiveAccessTokensByBinding :execrows
UPDATE access_tokens
SET revoked_at = sqlc.arg(revoked_at), revoke_reason = sqlc.arg(revoke_reason)
WHERE session_binding_id = sqlc.arg(session_binding_id)
  AND revoked_at IS NULL
  AND expires_at > sqlc.arg(revoked_at);

-- name: RevokeLiveAccessTokensByBindings :execrows
UPDATE access_tokens
SET revoked_at = sqlc.arg(revoked_at), revoke_reason = sqlc.arg(revoke_reason)
WHERE session_binding_id = ANY(sqlc.arg(session_binding_ids)::uuid[])
  AND revoked_at IS NULL
  AND expires_at > sqlc.arg(revoked_at);

-- name: RevokeLoginSessionBindingByID :one
UPDATE login_sessions
SET revoked_at = sqlc.arg(revoked_at), revoke_reason = sqlc.arg(revoke_reason)
WHERE id = sqlc.arg(id)
  AND revoked_at IS NULL
RETURNING *;

-- name: ConfirmLogoutTransaction :one
UPDATE logout_transactions
SET stage = 'confirmed', csrf_hash = NULL, consumed_at = sqlc.arg(consumed_at)
WHERE id = sqlc.arg(id)
  AND stage = 'bound_confirmable'
  AND consumed_at IS NULL
RETURNING *;

-- name: CancelLogoutTransaction :one
UPDATE logout_transactions
SET stage = 'canceled', csrf_hash = NULL, consumed_at = sqlc.arg(consumed_at)
WHERE id = sqlc.arg(id)
  AND stage = 'bound_confirmable'
  AND consumed_at IS NULL
RETURNING *;

-- name: DeleteRetiredLogoutTransactions :execrows
WITH candidates AS (
    SELECT transactions.id
    FROM logout_transactions AS transactions
    WHERE (transactions.consumed_at IS NULL AND transactions.expires_at <= sqlc.arg(now))
       OR (transactions.consumed_at IS NOT NULL AND transactions.consumed_at <= sqlc.arg(cutoff))
    ORDER BY COALESCE(transactions.consumed_at, transactions.expires_at), transactions.id
    LIMIT sqlc.arg(batch_limit)
    FOR UPDATE SKIP LOCKED
)
DELETE FROM logout_transactions AS transactions
USING candidates
WHERE transactions.id = candidates.id;
