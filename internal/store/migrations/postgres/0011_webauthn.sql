-- WebAuthn / passkey credentials. Each row stores one authenticator's
-- credential (public key, sign count, transports…) as JSON, keyed by the
-- base64url credential ID. Passkeys are a passwordless, phishing-resistant
-- login path in addition to password (+TOTP).
CREATE TABLE webauthn_credentials (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL DEFAULT '',
    data          TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    last_used_at  TIMESTAMPTZ
);

CREATE INDEX webauthn_user_idx ON webauthn_credentials (user_id);
