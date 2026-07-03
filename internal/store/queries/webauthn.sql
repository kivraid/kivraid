-- name: CreateWebauthnCredential :exec
INSERT INTO webauthn_credentials (id, user_id, credential_id, name, data, created_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: ListWebauthnCredentials :many
SELECT * FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at;

-- name: CountWebauthnCredentials :one
SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = $1;

-- name: UpdateWebauthnCredential :exec
UPDATE webauthn_credentials SET data = $1, last_used_at = $2 WHERE credential_id = $3;

-- name: DeleteWebauthnCredential :exec
DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2;
