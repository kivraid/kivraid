-- name: CreateApplication :one
INSERT INTO applications (id, name, slug, kind, description, launch_url, proxy_hosts, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: CreateProvider :one
INSERT INTO providers (id, application_id, client_id, client_secret_hash, client_secret_enc,
                       redirect_uris, post_logout_redirect_uris, public, access_token_ttl_seconds,
                       refresh_token_ttl_seconds, id_token_ttl_seconds, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
RETURNING *;

-- name: GetApplication :one
SELECT * FROM applications WHERE id = $1;

-- name: GetProviderByApplication :one
SELECT * FROM providers WHERE application_id = $1;

-- name: GetProviderByClientID :one
SELECT * FROM providers WHERE client_id = $1;

-- name: ListApplicationsAdmin :many
SELECT sqlc.embed(a), p.client_id, p.public, p.redirect_uris
FROM applications a
LEFT JOIN providers p ON p.application_id = a.id
ORDER BY a.name;

-- name: ListProxyApplications :many
SELECT * FROM applications WHERE kind = 'proxy' ORDER BY name;

-- name: UpdateApplication :exec
UPDATE applications
SET name = $1, slug = $2, description = $3, launch_url = $4, proxy_hosts = $5, updated_at = $6
WHERE id = $7;

-- name: UpdateApplicationIcon :exec
UPDATE applications SET icon = $1, icon_mime = $2, updated_at = $3 WHERE id = $4;

-- name: GetApplicationIcon :one
SELECT icon, icon_mime FROM applications WHERE id = $1;

-- name: UpdateProviderRedirects :exec
UPDATE providers
SET redirect_uris = $1, post_logout_redirect_uris = $2,
    access_token_ttl_seconds = $3, refresh_token_ttl_seconds = $4, id_token_ttl_seconds = $5,
    updated_at = $6
WHERE id = $7;

-- name: UpdateProviderSecret :exec
UPDATE providers SET client_secret_hash = $1, client_secret_enc = $2, updated_at = $3 WHERE id = $4;

-- name: UpdateProviderType :exec
UPDATE providers SET public = $1, client_secret_hash = $2, client_secret_enc = $3, updated_at = $4 WHERE id = $5;

-- name: DeleteApplication :exec
DELETE FROM applications WHERE id = $1;
