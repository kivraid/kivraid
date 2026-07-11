-- name: GetInstanceSettings :one
SELECT * FROM instance_settings WHERE id = 1;

-- name: SetBrandName :exec
UPDATE instance_settings SET brand_name = $1, updated_at = $2 WHERE id = 1;

-- name: SetBrandLogo :exec
UPDATE instance_settings SET logo = $1, logo_mime = $2, updated_at = $3 WHERE id = 1;

-- name: ClearBrandLogo :exec
UPDATE instance_settings SET logo = NULL, logo_mime = NULL, updated_at = $1 WHERE id = 1;
