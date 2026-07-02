-- name: InsertAudit :exec
INSERT INTO audit_log (ts, actor, action, object, detail, ip)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: ListAudit :many
SELECT * FROM audit_log ORDER BY id DESC LIMIT $1;

-- name: DeleteAuditBefore :exec
DELETE FROM audit_log WHERE ts < $1;
