-- name: CreateLdapSource :one
INSERT INTO ldap_sources (id, name, url, start_tls, skip_tls_verify, bind_dn, bind_password_enc,
                          base_dn, user_filter, username_attr, email_attr, name_attr,
                          group_filter, group_name_attr, password_writeback, enabled, position,
                          created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
RETURNING *;

-- name: GetLdapSource :one
SELECT * FROM ldap_sources WHERE id = $1;

-- name: ListLdapSources :many
SELECT * FROM ldap_sources ORDER BY position, name;

-- name: ListEnabledLdapSources :many
SELECT * FROM ldap_sources WHERE enabled = TRUE ORDER BY position, name;

-- name: UpdateLdapSource :exec
UPDATE ldap_sources
SET name = $1, url = $2, start_tls = $3, skip_tls_verify = $4, bind_dn = $5, base_dn = $6,
    user_filter = $7, username_attr = $8, email_attr = $9, name_attr = $10,
    group_filter = $11, group_name_attr = $12, password_writeback = $13, enabled = $14, updated_at = $15
WHERE id = $16;

-- name: UpdateLdapSourceBindPassword :exec
UPDATE ldap_sources SET bind_password_enc = $1, updated_at = $2 WHERE id = $3;

-- name: DeleteLdapSource :exec
DELETE FROM ldap_sources WHERE id = $1;

-- name: UpdateUserLdapProfile :exec
UPDATE users SET email = $1, name = $2, ldap_dn = $3, updated_at = $4 WHERE id = $5;

-- name: GetGroupByName :one
SELECT * FROM groups WHERE name = $1;

-- name: CreateGroup :one
INSERT INTO groups (id, name, created_at) VALUES ($1, $2, $3) RETURNING *;

-- name: DeleteUserGroups :exec
DELETE FROM user_groups WHERE user_id = $1;

-- name: AddUserGroup :exec
INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2);
