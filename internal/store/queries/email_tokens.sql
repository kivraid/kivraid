-- name: CreateEmailToken :exec
INSERT INTO email_tokens (token_hash, purpose, user_id, email, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetEmailToken :one
SELECT * FROM email_tokens WHERE token_hash = $1;

-- name: DeleteEmailToken :exec
DELETE FROM email_tokens WHERE token_hash = $1;

-- name: DeleteEmailTokensByUserPurpose :exec
DELETE FROM email_tokens WHERE user_id = $1 AND purpose = $2;

-- name: DeleteExpiredEmailTokens :exec
DELETE FROM email_tokens WHERE expires_at < $1;
