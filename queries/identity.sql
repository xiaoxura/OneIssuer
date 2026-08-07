-- name: LockLoginIdentifier :exec
SELECT pg_advisory_xact_lock(hashtextextended(sqlc.arg(identifier)::text, 780665709));

-- name: LoginIdentifierExists :one
SELECT EXISTS (
    SELECT 1
    FROM users
    WHERE username_normalized = sqlc.arg(identifier)
       OR email_normalized = sqlc.arg(identifier)
)::boolean;

-- name: CreateUser :one
INSERT INTO users (
    id, subject, username, username_normalized, display_name,
    email, email_normalized, email_verified, status, role,
    created_at, updated_at
) VALUES (
    sqlc.arg(id), sqlc.arg(subject), sqlc.arg(username), sqlc.arg(username_normalized),
    sqlc.arg(display_name), sqlc.arg(email), sqlc.arg(email_normalized),
    sqlc.arg(email_verified), sqlc.arg(status), sqlc.arg(role),
    sqlc.arg(created_at), sqlc.arg(updated_at)
)
RETURNING *;

-- name: CreateCredential :exec
INSERT INTO credentials (
    user_id, credential_type, password_hash, created_at, updated_at
) VALUES (
    sqlc.arg(user_id), 'password', sqlc.arg(password_hash),
    sqlc.arg(created_at), sqlc.arg(updated_at)
);

-- name: HasAdmin :one
SELECT EXISTS (SELECT 1 FROM users WHERE role = 'admin')::boolean;

-- name: CountActiveAdmins :one
SELECT count(*)::bigint FROM users WHERE role = 'admin' AND status = 'active';

-- name: LockAdminSet :exec
SELECT pg_advisory_xact_lock(780665710);

-- name: LoginIdentifierOwnedByOther :one
SELECT EXISTS (
    SELECT 1 FROM users
    WHERE id <> sqlc.arg(id)
      AND (username_normalized = sqlc.arg(identifier) OR email_normalized = sqlc.arg(identifier))
)::boolean;

-- name: FindCredentialForLogin :one
SELECT
    u.id, u.subject, u.username, u.username_normalized, u.display_name,
    u.email, u.email_normalized, u.email_verified, u.status, u.role,
    u.created_at, u.updated_at, u.last_login_at, u.version,
    c.password_hash, c.updated_at AS credential_updated_at
FROM users AS u
JOIN credentials AS c ON c.user_id = u.id AND c.credential_type = 'password'
WHERE u.username_normalized = sqlc.arg(identifier)
   OR u.email_normalized = sqlc.arg(identifier)
ORDER BY (u.username_normalized = sqlc.arg(identifier)) DESC
LIMIT 1;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = sqlc.arg(id);

-- name: LockUserByID :one
SELECT * FROM users WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: UpdateUser :one
UPDATE users SET
    username = sqlc.arg(username),
    username_normalized = sqlc.arg(username_normalized),
    display_name = sqlc.arg(display_name),
    email = sqlc.arg(email),
    email_normalized = sqlc.arg(email_normalized),
    status = sqlc.arg(status),
    role = sqlc.arg(role),
    updated_at = sqlc.arg(updated_at),
    version = version + 1
WHERE id = sqlc.arg(id) AND version = sqlc.arg(expected_version)
RETURNING *;

-- name: UpdateCredentialHash :exec
UPDATE credentials
SET password_hash = sqlc.arg(password_hash), updated_at = sqlc.arg(updated_at)
WHERE user_id = sqlc.arg(user_id) AND credential_type = 'password';

-- name: UpdateLastLogin :exec
UPDATE users
SET last_login_at = sqlc.arg(last_login_at), updated_at = GREATEST(updated_at, sqlc.arg(last_login_at))
WHERE id = sqlc.arg(id);

-- name: ListUsers :many
SELECT *
FROM users
WHERE (
        sqlc.arg(search)::text = ''
        OR username_normalized LIKE sqlc.arg(search)::text || '%'
        OR email_normalized LIKE sqlc.arg(search)::text || '%'
    )
  AND (
        sqlc.arg(cursor_time)::timestamptz IS NULL
        OR (created_at, id) < (sqlc.arg(cursor_time)::timestamptz, sqlc.arg(cursor_id)::uuid)
    )
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(page_limit);
