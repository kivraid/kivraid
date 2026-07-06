-- name: SetUserTOTP :exec
UPDATE users SET totp_secret_enc = $1, totp_enabled = $2, totp_last_counter = $3, updated_at = $4 WHERE id = $5;

-- name: ClaimUserTOTPCounter :execrows
-- Atomically advances the last accepted TOTP counter. Zero rows means
-- this time step (or a later one) was already consumed: a replay.
UPDATE users SET totp_last_counter = $1, updated_at = $2
WHERE id = $3 AND totp_last_counter < $1;

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
