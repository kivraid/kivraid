-- TOTP two-factor authentication. The secret is encrypted at rest; MFA
-- sits on top of the user's source, so both local and directory users
-- can enable it.
ALTER TABLE users ADD COLUMN totp_secret_enc BYTEA;
ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT FALSE;

-- Single-use recovery codes (SHA-256 hashed, high entropy).
CREATE TABLE mfa_recovery_codes (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX mfa_recovery_user_idx ON mfa_recovery_codes (user_id);
