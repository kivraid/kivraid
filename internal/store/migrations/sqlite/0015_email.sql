-- Email verification state per user. Existing accounts are grandfathered as
-- verified so an upgrade never regresses a working install; new accounts
-- created through the admin UI start unverified and confirm via a link.
ALTER TABLE users ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE users SET email_verified = TRUE;

-- SMTP delivery settings, admin-editable and held in the database like LDAP
-- sources. Single pinned row; the password is encrypted at rest.
CREATE TABLE smtp_settings (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    enabled      BOOLEAN NOT NULL DEFAULT FALSE,
    host         TEXT NOT NULL DEFAULT '',
    port         INTEGER NOT NULL DEFAULT 587,
    username     TEXT NOT NULL DEFAULT '',
    password_enc BLOB,
    from_address TEXT NOT NULL DEFAULT '',
    from_name    TEXT NOT NULL DEFAULT '',
    encryption   TEXT NOT NULL DEFAULT 'starttls',
    updated_at   TIMESTAMP NOT NULL
);
INSERT INTO smtp_settings (id, updated_at) VALUES (1, CURRENT_TIMESTAMP);

-- Single-use, expiring tokens for password reset and email verification.
-- The raw token travels in the emailed link; only its hash is stored.
CREATE TABLE email_tokens (
    token_hash TEXT PRIMARY KEY,
    purpose    TEXT NOT NULL,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email      TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL
);
CREATE INDEX email_tokens_user_idx ON email_tokens (user_id);
