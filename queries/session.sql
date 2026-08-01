-- name: CreateLoginSession :exec
INSERT INTO login_sessions (
    id, user_id, token_hash, csrf_hash, csrf_expires_at,
    created_at, last_seen_at, authenticated_at, expires_at, idle_expires_at,
    user_agent_hash, ip_prefix
) VALUES (
    sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(token_hash), sqlc.arg(csrf_hash),
    sqlc.arg(csrf_expires_at), sqlc.arg(created_at), sqlc.arg(last_seen_at),
    sqlc.arg(authenticated_at), sqlc.arg(expires_at), sqlc.arg(idle_expires_at),
    sqlc.arg(user_agent_hash), sqlc.arg(ip_prefix)
);

-- name: CreatePreAuthSession :exec
INSERT INTO preauth_sessions (
    id, token_hash, csrf_hash, auth_transaction_id, created_at, expires_at
) VALUES (
    sqlc.arg(id), sqlc.arg(token_hash), sqlc.arg(csrf_hash),
    sqlc.arg(auth_transaction_id), sqlc.arg(created_at), sqlc.arg(expires_at)
);

-- name: GetPreAuthSessionByTokenHash :one
SELECT * FROM preauth_sessions WHERE token_hash = sqlc.arg(token_hash);

-- name: ConsumePreAuthSession :one
UPDATE preauth_sessions
SET consumed_at = sqlc.arg(consumed_at)
WHERE id = sqlc.arg(id)
  AND consumed_at IS NULL
  AND expires_at > sqlc.arg(consumed_at)
RETURNING id;

-- name: GetLoginSessionByTokenHash :one
SELECT
    s.id, s.user_id, s.token_hash, s.csrf_hash, s.csrf_expires_at,
    s.created_at, s.last_seen_at, s.authenticated_at, s.expires_at,
    s.idle_expires_at, s.revoked_at, s.revoke_reason,
    s.user_agent_hash, s.ip_prefix,
    u.subject, u.username, u.display_name, u.email, u.email_verified,
    u.status AS user_status, u.role AS user_role, u.created_at AS user_created_at,
    u.updated_at AS user_updated_at, u.last_login_at AS user_last_login_at
FROM login_sessions AS s
JOIN users AS u ON u.id = s.user_id
WHERE s.token_hash = sqlc.arg(token_hash);

-- name: TouchLoginSession :exec
UPDATE login_sessions
SET last_seen_at = sqlc.arg(last_seen_at),
    idle_expires_at = LEAST(expires_at, sqlc.arg(idle_expires_at))
WHERE id = sqlc.arg(id)
  AND revoked_at IS NULL
  AND expires_at > sqlc.arg(last_seen_at)
  AND idle_expires_at > sqlc.arg(last_seen_at);

-- name: RotateLoginSessionCSRF :exec
UPDATE login_sessions
SET csrf_hash = sqlc.arg(csrf_hash), csrf_expires_at = sqlc.arg(csrf_expires_at)
WHERE id = sqlc.arg(id) AND revoked_at IS NULL;

-- name: RevokeLoginSessionByHash :one
UPDATE login_sessions
SET revoked_at = sqlc.arg(revoked_at), revoke_reason = sqlc.arg(revoke_reason)
WHERE token_hash = sqlc.arg(token_hash) AND revoked_at IS NULL
RETURNING id, user_id;

-- name: RevokeLoginSessionForUser :one
UPDATE login_sessions
SET revoked_at = sqlc.arg(revoked_at), revoke_reason = sqlc.arg(revoke_reason)
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND revoked_at IS NULL
RETURNING id, user_id;

-- name: RevokeLoginSessionAdmin :one
UPDATE login_sessions
SET revoked_at = sqlc.arg(revoked_at), revoke_reason = sqlc.arg(revoke_reason)
WHERE id = sqlc.arg(id) AND revoked_at IS NULL
RETURNING id, user_id;

-- name: RevokeOtherLoginSessions :many
UPDATE login_sessions
SET revoked_at = sqlc.arg(revoked_at), revoke_reason = 'others'
WHERE user_id = sqlc.arg(user_id)
  AND id <> sqlc.arg(current_session_id)
  AND revoked_at IS NULL
RETURNING id;

-- name: RevokeAllUserLoginSessions :many
UPDATE login_sessions
SET revoked_at = sqlc.arg(revoked_at), revoke_reason = sqlc.arg(revoke_reason)
WHERE user_id = sqlc.arg(user_id) AND revoked_at IS NULL
RETURNING id;

-- name: ListUserLoginSessions :many
SELECT id, user_id, created_at, last_seen_at, authenticated_at, expires_at,
       idle_expires_at, revoked_at, revoke_reason, ip_prefix
FROM login_sessions
WHERE user_id = sqlc.arg(user_id)
  AND (
        sqlc.arg(cursor_time)::timestamptz IS NULL
        OR (created_at, id) < (sqlc.arg(cursor_time)::timestamptz, sqlc.arg(cursor_id)::uuid)
      )
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(page_limit);

-- name: ListLoginSessionsAdmin :many
SELECT s.id, s.user_id, s.created_at, s.last_seen_at, s.authenticated_at,
       s.expires_at, s.idle_expires_at, s.revoked_at, s.revoke_reason,
       s.ip_prefix, u.username, u.status AS user_status
FROM login_sessions AS s
JOIN users AS u ON u.id = s.user_id
WHERE (
        sqlc.arg(cursor_time)::timestamptz IS NULL
        OR (s.created_at, s.id) < (sqlc.arg(cursor_time)::timestamptz, sqlc.arg(cursor_id)::uuid)
      )
ORDER BY s.created_at DESC, s.id DESC
LIMIT sqlc.arg(page_limit);

-- name: CountActiveLoginSessions :one
SELECT count(*)::bigint
FROM login_sessions
WHERE revoked_at IS NULL
  AND expires_at > sqlc.arg(now)
  AND idle_expires_at > sqlc.arg(now);

-- name: DeleteExpiredPreAuthSessions :execrows
DELETE FROM preauth_sessions
WHERE expires_at <= sqlc.arg(cutoff)
   OR (consumed_at IS NOT NULL AND consumed_at <= sqlc.arg(cutoff));

-- name: DeleteRetiredLoginSessions :execrows
DELETE FROM login_sessions
WHERE (revoked_at IS NOT NULL AND revoked_at <= sqlc.arg(cutoff))
   OR expires_at <= sqlc.arg(cutoff)
   OR idle_expires_at <= sqlc.arg(cutoff);
