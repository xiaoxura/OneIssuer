-- name: CreateAccessToken :exec
INSERT INTO access_tokens (
    id, jti_hash, authorization_code_id, consent_grant_id,
    user_id, client_id, scopes, issued_at, expires_at,
    issuance_source, refresh_family_id, origin_session_id, session_binding_id
) VALUES (
    sqlc.arg(id), sqlc.arg(jti_hash), sqlc.arg(authorization_code_id),
    sqlc.arg(consent_grant_id), sqlc.arg(user_id), sqlc.arg(client_id),
    sqlc.arg(scopes), sqlc.arg(issued_at), sqlc.arg(expires_at),
    'authorization_code', sqlc.arg(refresh_family_id),
    sqlc.arg(origin_session_id), sqlc.arg(session_binding_id)
);

-- name: CreateRefreshAccessToken :exec
INSERT INTO access_tokens (
    id, jti_hash, authorization_code_id, consent_grant_id,
    user_id, client_id, scopes, issued_at, expires_at,
    issuance_source, source_refresh_token_id, refresh_family_id,
    origin_session_id, session_binding_id
) VALUES (
    sqlc.arg(id), sqlc.arg(jti_hash), NULL, sqlc.arg(consent_grant_id),
    sqlc.arg(user_id), sqlc.arg(client_id), sqlc.arg(scopes),
    sqlc.arg(issued_at), sqlc.arg(expires_at), 'refresh_token',
    sqlc.arg(source_refresh_token_id), sqlc.arg(refresh_family_id),
    sqlc.arg(origin_session_id), sqlc.arg(session_binding_id)
);

-- name: CreateRefreshTokenFamily :one
INSERT INTO refresh_token_families (
    id, origin_authorization_code_id, consent_grant_id, user_id, client_id,
    origin_session_id, session_binding_id, scopes, created_at, absolute_expires_at
) VALUES (
    sqlc.arg(id), sqlc.arg(origin_authorization_code_id), sqlc.arg(consent_grant_id),
    sqlc.arg(user_id), sqlc.arg(client_id), sqlc.arg(origin_session_id),
    sqlc.arg(session_binding_id), sqlc.arg(scopes), sqlc.arg(created_at),
    sqlc.arg(absolute_expires_at)
)
RETURNING *;

-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (
    id, family_id, token_hash, generation, issued_at, expires_at
) VALUES (
    sqlc.arg(id), sqlc.arg(family_id), sqlc.arg(token_hash),
    sqlc.arg(generation), sqlc.arg(issued_at), sqlc.arg(expires_at)
)
RETURNING *;

-- name: GetRefreshTokenByHash :one
SELECT * FROM refresh_tokens WHERE token_hash = sqlc.arg(token_hash);

-- name: LockRefreshTokenByID :one
SELECT * FROM refresh_tokens WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: GetRefreshTokenFamilyByID :one
SELECT * FROM refresh_token_families WHERE id = sqlc.arg(id);

-- name: LockRefreshTokenFamilyByID :one
SELECT * FROM refresh_token_families WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ConsumeRefreshToken :one
UPDATE refresh_tokens
SET consumed_at = sqlc.arg(consumed_at)
WHERE id = sqlc.arg(id) AND consumed_at IS NULL
RETURNING *;

-- name: RevokeRefreshTokenFamily :one
UPDATE refresh_token_families
SET revoked_at = sqlc.arg(revoked_at), revoke_reason = sqlc.arg(revoke_reason)
WHERE id = sqlc.arg(id) AND revoked_at IS NULL
RETURNING *;

-- name: RevokeAccessToken :one
UPDATE access_tokens
SET revoked_at = sqlc.arg(revoked_at), revoke_reason = sqlc.arg(revoke_reason)
WHERE id = sqlc.arg(id) AND revoked_at IS NULL
RETURNING *;

-- name: RevokeLiveAccessTokensByFamily :execrows
UPDATE access_tokens
SET revoked_at = sqlc.arg(revoked_at), revoke_reason = 'family_revoked'
WHERE refresh_family_id = sqlc.arg(refresh_family_id)
  AND revoked_at IS NULL
  AND expires_at > sqlc.arg(revoked_at);

-- name: GetAccessTokenByJTIHash :one
SELECT * FROM access_tokens WHERE jti_hash = sqlc.arg(jti_hash);

-- name: LockAccessTokenByID :one
SELECT * FROM access_tokens WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: HasAuthorizationCodeExchangeRejection :one
SELECT EXISTS (
    SELECT 1
    FROM audit_events
    WHERE event_type = 'authorization_code_exchange_rejected'
      AND target_type = 'authorization_code'
      AND target_id = sqlc.arg(authorization_code_id)
);

-- name: DeleteRetiredAccessTokens :execrows
WITH candidates AS (
    SELECT tokens.id
    FROM access_tokens AS tokens
    WHERE tokens.expires_at <= sqlc.arg(cutoff)
    ORDER BY tokens.expires_at, tokens.id
    LIMIT sqlc.arg(batch_limit)
    FOR UPDATE SKIP LOCKED
)
DELETE FROM access_tokens AS tokens
USING candidates
WHERE tokens.id = candidates.id;

-- name: DeleteRetiredRefreshTokens :execrows
WITH candidates AS (
    SELECT tokens.id
    FROM refresh_tokens AS tokens
    JOIN refresh_token_families AS families ON families.id = tokens.family_id
    WHERE GREATEST(
        families.absolute_expires_at,
        COALESCE(families.revoked_at, families.absolute_expires_at)
    ) <= sqlc.arg(cutoff)
      AND NOT EXISTS (
          SELECT 1 FROM access_tokens AS accesses
          WHERE accesses.source_refresh_token_id = tokens.id
      )
    ORDER BY GREATEST(
        families.absolute_expires_at,
        COALESCE(families.revoked_at, families.absolute_expires_at)
    ), tokens.id
    LIMIT sqlc.arg(batch_limit)
    FOR UPDATE OF tokens SKIP LOCKED
)
DELETE FROM refresh_tokens AS tokens
USING candidates
WHERE tokens.id = candidates.id;

-- name: DeleteRetiredRefreshTokenFamilies :execrows
WITH candidates AS (
    SELECT families.id
    FROM refresh_token_families AS families
    WHERE GREATEST(
        families.absolute_expires_at,
        COALESCE(families.revoked_at, families.absolute_expires_at)
    ) <= sqlc.arg(cutoff)
      AND NOT EXISTS (
          SELECT 1 FROM refresh_tokens AS tokens
          WHERE tokens.family_id = families.id
      )
      AND NOT EXISTS (
          SELECT 1 FROM access_tokens AS accesses
          WHERE accesses.refresh_family_id = families.id
      )
    ORDER BY GREATEST(
        families.absolute_expires_at,
        COALESCE(families.revoked_at, families.absolute_expires_at)
    ), families.id
    LIMIT sqlc.arg(batch_limit)
    FOR UPDATE OF families SKIP LOCKED
)
DELETE FROM refresh_token_families AS families
USING candidates
WHERE families.id = candidates.id;

-- name: RevokeRefreshTokenFamiliesByGrant :many
UPDATE refresh_token_families
SET revoked_at = sqlc.arg(revoked_at), revoke_reason = 'grant_revoked'
WHERE consent_grant_id = sqlc.arg(consent_grant_id)
  AND revoked_at IS NULL
RETURNING id;

-- name: LockUnrevokedRefreshTokenFamiliesByGrant :many
SELECT id
FROM refresh_token_families
WHERE consent_grant_id = sqlc.arg(consent_grant_id)
  AND revoked_at IS NULL
ORDER BY id
FOR UPDATE;

-- name: LockLiveAccessTokensByGrant :many
SELECT id
FROM access_tokens
WHERE consent_grant_id = sqlc.arg(consent_grant_id)
  AND revoked_at IS NULL
  AND expires_at > sqlc.arg(now)
ORDER BY id
FOR UPDATE;

-- name: RevokeLiveAccessTokensByGrant :execrows
UPDATE access_tokens
SET revoked_at = sqlc.arg(revoked_at), revoke_reason = 'grant_revoked'
WHERE consent_grant_id = sqlc.arg(consent_grant_id)
  AND revoked_at IS NULL
  AND expires_at > sqlc.arg(revoked_at);

-- name: RevokeRefreshTokenFamiliesByUser :execrows
UPDATE refresh_token_families
SET revoked_at = sqlc.arg(revoked_at), revoke_reason = sqlc.arg(revoke_reason)
WHERE user_id = sqlc.arg(user_id)
  AND revoked_at IS NULL;

-- name: LockUnrevokedRefreshTokenFamiliesByUser :many
SELECT id
FROM refresh_token_families
WHERE user_id = sqlc.arg(user_id)
  AND revoked_at IS NULL
ORDER BY id
FOR UPDATE;

-- name: LockLiveAccessTokensByUser :many
SELECT id
FROM access_tokens
WHERE user_id = sqlc.arg(user_id)
  AND revoked_at IS NULL
  AND expires_at > sqlc.arg(now)
ORDER BY id
FOR UPDATE;

-- name: RevokeLiveAccessTokensByUser :execrows
UPDATE access_tokens
SET revoked_at = sqlc.arg(revoked_at), revoke_reason = sqlc.arg(revoke_reason)
WHERE user_id = sqlc.arg(user_id)
  AND revoked_at IS NULL
  AND expires_at > sqlc.arg(revoked_at);

-- name: RevokeRefreshTokenFamiliesByClient :execrows
UPDATE refresh_token_families
SET revoked_at = sqlc.arg(revoked_at), revoke_reason = sqlc.arg(revoke_reason)
WHERE client_id = sqlc.arg(client_id)
  AND revoked_at IS NULL;

-- name: LockUnrevokedRefreshTokenFamiliesByClient :many
SELECT id
FROM refresh_token_families
WHERE client_id = sqlc.arg(client_id)
  AND revoked_at IS NULL
ORDER BY id
FOR UPDATE;

-- name: LockLiveAccessTokensByClient :many
SELECT id
FROM access_tokens
WHERE client_id = sqlc.arg(client_id)
  AND revoked_at IS NULL
  AND expires_at > sqlc.arg(now)
ORDER BY id
FOR UPDATE;

-- name: LockLiveRefreshAccessTokensByClient :many
SELECT id
FROM access_tokens
WHERE client_id = sqlc.arg(client_id)
  AND refresh_family_id IS NOT NULL
  AND revoked_at IS NULL
  AND expires_at > sqlc.arg(now)
ORDER BY id
FOR UPDATE;

-- name: RevokeLiveAccessTokensByClient :execrows
UPDATE access_tokens
SET revoked_at = sqlc.arg(revoked_at), revoke_reason = sqlc.arg(revoke_reason)
WHERE client_id = sqlc.arg(client_id)
  AND revoked_at IS NULL
  AND expires_at > sqlc.arg(revoked_at);

-- name: RevokeLiveRefreshAccessTokensByClient :execrows
UPDATE access_tokens
SET revoked_at = sqlc.arg(revoked_at), revoke_reason = sqlc.arg(revoke_reason)
WHERE client_id = sqlc.arg(client_id)
  AND refresh_family_id IS NOT NULL
  AND revoked_at IS NULL
  AND expires_at > sqlc.arg(revoked_at);
