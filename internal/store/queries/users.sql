-- name: CreateUser :one
INSERT INTO users (id, username, email, name, password_hash, source, ldap_source_id, ldap_dn, is_admin, active, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = ?;

-- name: GetUserByUsername :one
SELECT * FROM users WHERE username = ?;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = ?;

-- name: UpdateUserPassword :exec
UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?;

-- name: CountUsers :one
SELECT COUNT(*) FROM users;

-- name: ListUserGroups :many
SELECT g.*
FROM groups g
JOIN user_groups ug ON ug.group_id = g.id
WHERE ug.user_id = ?
ORDER BY g.name;
