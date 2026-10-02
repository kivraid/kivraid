-- name: InsertAudit :exec
INSERT INTO audit_log (ts, actor, action, object, detail, ip)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: ListAudit :many
SELECT * FROM audit_log ORDER BY id DESC LIMIT $1;

-- name: ListAuditPage :many
SELECT * FROM audit_log ORDER BY id DESC LIMIT $1 OFFSET $2;

-- name: CountAudit :one
SELECT COUNT(*) FROM audit_log;

-- name: DeleteAuditBefore :exec
DELETE FROM audit_log WHERE ts < $1;

-- Filtered variants for the activity view. An empty action or IP matches
-- everything; the actor pattern is lowercased and wildcard-escaped by the
-- caller ('%' for no filter), matching the users-search convention. The
-- caller always passes a time window (wide open when unfiltered).
-- name: CountAuditFiltered :one
SELECT COUNT(*) FROM audit_log
WHERE (sqlc.arg(action) = '' OR action = sqlc.arg(action))
  AND lower(actor) LIKE CAST(sqlc.arg(actor_pattern) AS TEXT) ESCAPE '\'
  AND (CAST(sqlc.arg(ip) AS TEXT) = '' OR ip = CAST(sqlc.arg(ip) AS TEXT))
  AND ts >= sqlc.arg(since) AND ts < sqlc.arg(until);

-- name: ListAuditFilteredPage :many
SELECT * FROM audit_log
WHERE (sqlc.arg(action) = '' OR action = sqlc.arg(action))
  AND lower(actor) LIKE CAST(sqlc.arg(actor_pattern) AS TEXT) ESCAPE '\'
  AND (CAST(sqlc.arg(ip) AS TEXT) = '' OR ip = CAST(sqlc.arg(ip) AS TEXT))
  AND ts >= sqlc.arg(since) AND ts < sqlc.arg(until)
ORDER BY id DESC
LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);

-- name: ListAuditFiltered :many
SELECT * FROM audit_log
WHERE (sqlc.arg(action) = '' OR action = sqlc.arg(action))
  AND lower(actor) LIKE CAST(sqlc.arg(actor_pattern) AS TEXT) ESCAPE '\'
  AND (CAST(sqlc.arg(ip) AS TEXT) = '' OR ip = CAST(sqlc.arg(ip) AS TEXT))
  AND ts >= sqlc.arg(since) AND ts < sqlc.arg(until)
ORDER BY id DESC;

-- name: ListSignInEventsSince :many
-- Sign-in outcomes for the dashboard chart, bucketed by the caller. Every
-- successful sign-in (password, passkey, federated) records 'login'.
SELECT ts, action FROM audit_log
WHERE action IN ('login', 'login.failed') AND ts >= sqlc.arg(since);
