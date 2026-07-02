-- name: InsertAudit :exec
INSERT INTO audit_log (ts, actor, action, object, detail, ip)
VALUES (?, ?, ?, ?, ?, ?);

-- name: ListAudit :many
SELECT * FROM audit_log ORDER BY id DESC LIMIT ?;

-- name: DeleteAuditBefore :exec
DELETE FROM audit_log WHERE ts < ?;
