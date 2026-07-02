-- name: CreateApplication :one
INSERT INTO applications (id, name, slug, launch_url, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: CreateProvider :one
INSERT INTO providers (id, application_id, client_id, client_secret_hash, redirect_uris,
                       post_logout_redirect_uris, public, access_token_ttl_seconds,
                       refresh_token_ttl_seconds, id_token_ttl_seconds, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING *;

-- name: GetApplication :one
SELECT * FROM applications WHERE id = $1;

-- name: GetProviderByApplication :one
SELECT * FROM providers WHERE application_id = $1;

-- name: GetProviderByClientID :one
SELECT * FROM providers WHERE client_id = $1;

-- name: ListApplicationsWithProviders :many
SELECT sqlc.embed(applications), sqlc.embed(providers)
FROM applications
JOIN providers ON providers.application_id = applications.id
ORDER BY applications.name;

-- name: UpdateApplication :exec
UPDATE applications SET name = $1, slug = $2, launch_url = $3, updated_at = $4 WHERE id = $5;

-- name: UpdateProviderRedirects :exec
UPDATE providers SET redirect_uris = $1, post_logout_redirect_uris = $2, updated_at = $3 WHERE id = $4;

-- name: UpdateProviderSecret :exec
UPDATE providers SET client_secret_hash = $1, updated_at = $2 WHERE id = $3;

-- name: DeleteApplication :exec
DELETE FROM applications WHERE id = $1;
