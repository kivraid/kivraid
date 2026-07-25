-- name: CreateUpstreamProvider :one
INSERT INTO upstream_providers (id, name, issuer, client_id, client_secret_enc, scopes,
                                claim_email, claim_name, claim_groups, allow_signup, enabled,
                                position, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
RETURNING *;

-- name: GetUpstreamProvider :one
SELECT * FROM upstream_providers WHERE id = $1;

-- name: ListUpstreamProviders :many
SELECT * FROM upstream_providers ORDER BY position, name;

-- name: ListEnabledUpstreamProviders :many
SELECT * FROM upstream_providers WHERE enabled = TRUE ORDER BY position, name;

-- name: UpdateUpstreamProvider :exec
UPDATE upstream_providers
SET name = $1, issuer = $2, client_id = $3, scopes = $4,
    claim_email = $5, claim_name = $6, claim_groups = $7, allow_signup = $8,
    enabled = $9, updated_at = $10
WHERE id = $11;

-- name: UpdateUpstreamProviderSecret :exec
UPDATE upstream_providers SET client_secret_enc = $1, updated_at = $2 WHERE id = $3;

-- name: DeleteUpstreamProvider :exec
DELETE FROM upstream_providers WHERE id = $1;

-- --- Login routes (home-realm discovery) --------------------------------

-- name: ListLoginRoutes :many
SELECT * FROM login_routes ORDER BY kind, match_value;

-- name: GetLoginRoute :one
SELECT * FROM login_routes WHERE kind = $1 AND match_value = $2;

-- name: CreateLoginRoute :one
INSERT INTO login_routes (id, kind, match_value, target, position, created_at)
VALUES ($1, $2, $3, $4, 0, $5)
RETURNING *;

-- name: DeleteLoginRoute :exec
DELETE FROM login_routes WHERE id = $1;

-- name: SetDefaultRoute :exec
INSERT INTO login_routes (id, kind, match_value, target, position, created_at)
VALUES ($1, 'default', '', $2, 0, $3)
ON CONFLICT (kind, match_value) DO UPDATE SET target = excluded.target;

-- --- Federated identity on users ----------------------------------------

-- name: GetUserByExternalID :one
SELECT * FROM users WHERE upstream_source_id = $1 AND external_id = $2;

-- name: SetUserUpstreamIdentity :exec
UPDATE users SET upstream_source_id = $1, external_id = $2, updated_at = $3 WHERE id = $4;

-- name: CreateUpstreamUser :one
INSERT INTO users (id, username, email, name, source, upstream_source_id, external_id,
                   email_verified, is_admin, active, created_at, updated_at)
VALUES ($1, $2, $3, $4, 'upstream', $5, $6, $7, FALSE, TRUE, $8, $9)
RETURNING *;
