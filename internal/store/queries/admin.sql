-- name: ListUsers :many
SELECT * FROM users ORDER BY username;

-- name: CountUsersSearch :one
-- The pattern is lowercased and wildcard-escaped by the caller ('%' for
-- no filter). lower() keeps the match case-insensitive on both engines.
-- An empty source / status means "any"; admins_only also counts members of
-- an administrator-granting group.
SELECT COUNT(*) FROM users
WHERE (lower(username) LIKE CAST(sqlc.arg(pattern) AS TEXT) ESCAPE '\'
    OR lower(email) LIKE CAST(sqlc.arg(pattern) AS TEXT) ESCAPE '\'
    OR lower(name) LIKE CAST(sqlc.arg(pattern) AS TEXT) ESCAPE '\')
  AND (CAST(sqlc.arg(source) AS TEXT) = '' OR source = CAST(sqlc.arg(source) AS TEXT))
  AND (CAST(sqlc.arg(status) AS TEXT) = ''
    OR (CAST(sqlc.arg(status) AS TEXT) = 'active' AND active)
    OR (CAST(sqlc.arg(status) AS TEXT) = 'inactive' AND NOT active))
  AND (NOT CAST(sqlc.arg(admins_only) AS BOOLEAN) OR is_admin
    OR id IN (SELECT ug.user_id FROM user_groups ug JOIN groups g ON g.id = ug.group_id WHERE g.grants_admin));

-- name: ListUsersPage :many
SELECT * FROM users
WHERE (lower(username) LIKE CAST(sqlc.arg(pattern) AS TEXT) ESCAPE '\'
    OR lower(email) LIKE CAST(sqlc.arg(pattern) AS TEXT) ESCAPE '\'
    OR lower(name) LIKE CAST(sqlc.arg(pattern) AS TEXT) ESCAPE '\')
  AND (CAST(sqlc.arg(source) AS TEXT) = '' OR source = CAST(sqlc.arg(source) AS TEXT))
  AND (CAST(sqlc.arg(status) AS TEXT) = ''
    OR (CAST(sqlc.arg(status) AS TEXT) = 'active' AND active)
    OR (CAST(sqlc.arg(status) AS TEXT) = 'inactive' AND NOT active))
  AND (NOT CAST(sqlc.arg(admins_only) AS BOOLEAN) OR is_admin
    OR id IN (SELECT ug.user_id FROM user_groups ug JOIN groups g ON g.id = ug.group_id WHERE g.grants_admin))
ORDER BY username
LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);

-- name: UpdateUserIdentity :exec
UPDATE users SET name = $1, email = $2, updated_at = $3 WHERE id = $4;

-- name: UpdateUserFlags :exec
UPDATE users SET is_admin = $1, active = $2, updated_at = $3 WHERE id = $4;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1;

-- name: CountActiveAdmins :one
SELECT COUNT(*) FROM users WHERE is_admin = TRUE AND active = TRUE;

-- name: CountActiveUsers :one
SELECT COUNT(*) FROM users WHERE active = TRUE;

-- name: CountApplications :one
SELECT COUNT(*) FROM applications;

-- name: CountGroups :one
SELECT COUNT(*) FROM groups;

-- name: UpdateUserPhoto :exec
UPDATE users SET photo = $1, photo_mime = $2, updated_at = $3 WHERE id = $4;

-- name: GetUserPhoto :one
SELECT photo, photo_mime FROM users WHERE id = $1;

-- name: DeleteAccessTokensByUser :exec
DELETE FROM access_tokens WHERE user_id = $1;

-- name: DeleteRefreshTokensByUser :exec
DELETE FROM refresh_tokens WHERE user_id = $1;

-- name: ListGroupsWithCounts :many
SELECT g.*, COUNT(ug.user_id) AS member_count
FROM groups g
LEFT JOIN user_groups ug ON ug.group_id = g.id
GROUP BY g.id
ORDER BY g.name;

-- name: GetGroup :one
SELECT * FROM groups WHERE id = $1;

-- name: RenameGroup :exec
UPDATE groups SET name = $1 WHERE id = $2;

-- name: DeleteGroup :exec
DELETE FROM groups WHERE id = $1;

-- name: ListGroupMembers :many
SELECT u.*
FROM users u
JOIN user_groups ug ON ug.user_id = u.id
WHERE ug.group_id = $1
ORDER BY u.username;

-- name: RemoveUserGroup :exec
DELETE FROM user_groups WHERE user_id = $1 AND group_id = $2;

-- name: UpdateGroupGrantsAdmin :exec
UPDATE groups SET grants_admin = $1 WHERE id = $2;

-- name: CountAdminGroupMemberships :one
SELECT COUNT(*)
FROM user_groups ug
JOIN groups g ON g.id = ug.group_id
WHERE ug.user_id = $1 AND g.grants_admin = TRUE;

-- name: ListUserAdminGroups :many
SELECT g.*
FROM groups g
JOIN user_groups ug ON ug.group_id = g.id
WHERE ug.user_id = $1 AND g.grants_admin = TRUE
ORDER BY g.name;

-- name: ListAdminGroupMemberIDs :many
SELECT DISTINCT ug.user_id
FROM user_groups ug
JOIN groups g ON g.id = ug.group_id
WHERE g.grants_admin = TRUE;
