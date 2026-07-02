-- name: CreateLdapSource :one
INSERT INTO ldap_sources (id, name, url, start_tls, skip_tls_verify, bind_dn, bind_password_enc,
                          base_dn, user_filter, username_attr, email_attr, name_attr,
                          group_filter, group_name_attr, password_writeback, enabled, position,
                          created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetLdapSource :one
SELECT * FROM ldap_sources WHERE id = ?;

-- name: ListLdapSources :many
SELECT * FROM ldap_sources ORDER BY position, name;

-- name: ListEnabledLdapSources :many
SELECT * FROM ldap_sources WHERE enabled = TRUE ORDER BY position, name;

-- name: UpdateLdapSource :exec
UPDATE ldap_sources
SET name = ?, url = ?, start_tls = ?, skip_tls_verify = ?, bind_dn = ?, base_dn = ?,
    user_filter = ?, username_attr = ?, email_attr = ?, name_attr = ?,
    group_filter = ?, group_name_attr = ?, password_writeback = ?, enabled = ?, updated_at = ?
WHERE id = ?;

-- name: UpdateLdapSourceBindPassword :exec
UPDATE ldap_sources SET bind_password_enc = ?, updated_at = ? WHERE id = ?;

-- name: DeleteLdapSource :exec
DELETE FROM ldap_sources WHERE id = ?;

-- name: UpdateUserLdapProfile :exec
UPDATE users SET email = ?, name = ?, ldap_dn = ?, updated_at = ? WHERE id = ?;

-- name: GetGroupByName :one
SELECT * FROM groups WHERE name = ?;

-- name: CreateGroup :one
INSERT INTO groups (id, name, created_at) VALUES (?, ?, ?) RETURNING *;

-- name: DeleteUserGroups :exec
DELETE FROM user_groups WHERE user_id = ?;

-- name: AddUserGroup :exec
INSERT INTO user_groups (user_id, group_id) VALUES (?, ?);
