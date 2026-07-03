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
