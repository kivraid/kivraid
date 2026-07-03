-- name: SetUserTOTP :exec
UPDATE users SET totp_secret_enc = $1, totp_enabled = $2, updated_at = $3 WHERE id = $4;

-- name: DisableUserTOTP :exec
UPDATE users SET totp_secret_enc = NULL, totp_enabled = FALSE, updated_at = $1 WHERE id = $2;

-- name: CreateRecoveryCode :exec
INSERT INTO mfa_recovery_codes (id, user_id, code_hash, created_at) VALUES ($1, $2, $3, $4);

-- name: ListUnusedRecoveryCodes :many
SELECT * FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL;

-- name: CountUnusedRecoveryCodes :one
SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL;

-- name: MarkRecoveryCodeUsed :exec
UPDATE mfa_recovery_codes SET used_at = $1 WHERE id = $2;

-- name: DeleteRecoveryCodes :exec
DELETE FROM mfa_recovery_codes WHERE user_id = $1;
