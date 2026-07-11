-- name: GetSMTPSettings :one
SELECT * FROM smtp_settings WHERE id = 1;

-- name: UpdateSMTPSettings :exec
UPDATE smtp_settings
SET enabled = $1, host = $2, port = $3, username = $4,
    from_address = $5, from_name = $6, encryption = $7, updated_at = $8
WHERE id = 1;

-- name: UpdateSMTPPassword :exec
UPDATE smtp_settings SET password_enc = $1, updated_at = $2 WHERE id = 1;
