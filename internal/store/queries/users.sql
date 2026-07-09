-- name: CreateUser :one
INSERT INTO users (id, username, email, name, password_hash, source, ldap_source_id, ldap_dn, is_admin, active, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: GetUserByUsername :one
SELECT * FROM users WHERE username = $1;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: UpdateUserPassword :exec
UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3;

-- name: SetUserLastLogin :exec
UPDATE users SET last_login_at = $1 WHERE id = $2;

-- name: CountUsers :one
SELECT COUNT(*) FROM users;

-- name: ListUserGroups :many
SELECT g.*
FROM groups g
JOIN user_groups ug ON ug.group_id = g.id
WHERE ug.user_id = $1
ORDER BY g.name;
