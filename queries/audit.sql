-- name: CreateAuditEvent :exec
INSERT INTO audit_events (
    id, event_type, result, actor_user_id, target_type, target_id,
    request_id, changed_fields, occurred_at
) VALUES (
    sqlc.arg(id), sqlc.arg(event_type), sqlc.arg(result), sqlc.arg(actor_user_id),
    sqlc.arg(target_type), sqlc.arg(target_id), sqlc.arg(request_id),
    sqlc.arg(changed_fields), sqlc.arg(occurred_at)
);

-- name: ListAuditEvents :many
SELECT *
FROM audit_events
WHERE (sqlc.arg(event_type)::text = '' OR event_type = sqlc.arg(event_type)::text)
  AND (
        sqlc.arg(cursor_time)::timestamptz IS NULL
        OR (occurred_at, id) < (sqlc.arg(cursor_time)::timestamptz, sqlc.arg(cursor_id)::uuid)
      )
ORDER BY occurred_at DESC, id DESC
LIMIT sqlc.arg(page_limit);
