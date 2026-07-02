-- name: CreateApplication :one
INSERT INTO applications (id, name, slug, launch_url, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: CreateProvider :one
INSERT INTO providers (id, application_id, client_id, client_secret_hash, redirect_uris,
                       post_logout_redirect_uris, public, access_token_ttl_seconds,
                       refresh_token_ttl_seconds, id_token_ttl_seconds, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetApplication :one
SELECT * FROM applications WHERE id = ?;

-- name: GetProviderByApplication :one
SELECT * FROM providers WHERE application_id = ?;

-- name: GetProviderByClientID :one
SELECT * FROM providers WHERE client_id = ?;

-- name: ListApplicationsWithProviders :many
SELECT sqlc.embed(applications), sqlc.embed(providers)
FROM applications
JOIN providers ON providers.application_id = applications.id
ORDER BY applications.name;

-- name: UpdateApplication :exec
UPDATE applications SET name = ?, slug = ?, launch_url = ?, updated_at = ? WHERE id = ?;

-- name: UpdateProviderRedirects :exec
UPDATE providers SET redirect_uris = ?, post_logout_redirect_uris = ?, updated_at = ? WHERE id = ?;

-- name: UpdateProviderSecret :exec
UPDATE providers SET client_secret_hash = ?, updated_at = ? WHERE id = ?;

-- name: DeleteApplication :exec
DELETE FROM applications WHERE id = ?;
