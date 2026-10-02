-- name: GetInstanceSettings :one
SELECT * FROM instance_settings WHERE id = 1;

-- name: SetBrandName :exec
UPDATE instance_settings SET brand_name = $1, updated_at = $2 WHERE id = 1;

-- name: SetBrandLogo :exec
UPDATE instance_settings SET logo = $1, logo_mime = $2, updated_at = $3 WHERE id = 1;

-- name: ClearBrandLogo :exec
UPDATE instance_settings SET logo = NULL, logo_mime = NULL, updated_at = $1 WHERE id = 1;

-- name: SetLoginBackground :exec
UPDATE instance_settings SET login_background = $1, login_background_mime = $2, updated_at = $3 WHERE id = 1;

-- name: ClearLoginBackground :exec
UPDATE instance_settings SET login_background = NULL, login_background_mime = NULL, updated_at = $1 WHERE id = 1;

-- name: SetMFAPolicy :exec
UPDATE instance_settings SET mfa_policy = $1, updated_at = $2 WHERE id = 1;

-- name: SetNewDeviceAlerts :exec
UPDATE instance_settings SET new_device_alerts = $1, updated_at = $2 WHERE id = 1;
