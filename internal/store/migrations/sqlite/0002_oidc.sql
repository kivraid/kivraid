CREATE TABLE applications (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    slug       TEXT NOT NULL UNIQUE,
    launch_url TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE providers (
    id                        TEXT PRIMARY KEY,
    application_id            TEXT NOT NULL UNIQUE REFERENCES applications(id) ON DELETE CASCADE,
    client_id                 TEXT NOT NULL UNIQUE,
    client_secret_hash        TEXT,
    redirect_uris             TEXT NOT NULL DEFAULT '[]',
    post_logout_redirect_uris TEXT NOT NULL DEFAULT '[]',
    public                    BOOLEAN NOT NULL DEFAULT FALSE,
    access_token_ttl_seconds  INTEGER NOT NULL DEFAULT 300,
    refresh_token_ttl_seconds INTEGER NOT NULL DEFAULT 2592000,
    id_token_ttl_seconds      INTEGER NOT NULL DEFAULT 3600,
    created_at                TIMESTAMP NOT NULL,
    updated_at                TIMESTAMP NOT NULL
);

CREATE TABLE signing_keys (
    id              TEXT PRIMARY KEY,
    alg             TEXT NOT NULL,
    private_key_enc BLOB NOT NULL,
    public_key_der  BLOB NOT NULL,
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMP NOT NULL
);

-- Pending authorization requests; the request column holds the JSON-encoded
-- request state (including user binding once the login completes).
CREATE TABLE auth_requests (
    id         TEXT PRIMARY KEY,
    code       TEXT UNIQUE,
    request    TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE access_tokens (
    id               TEXT PRIMARY KEY,
    user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id        TEXT NOT NULL,
    scopes           TEXT NOT NULL DEFAULT '[]',
    audience         TEXT NOT NULL DEFAULT '[]',
    refresh_token_id TEXT,
    expires_at       TIMESTAMP NOT NULL,
    created_at       TIMESTAMP NOT NULL
);

CREATE INDEX access_tokens_user_client_idx ON access_tokens (user_id, client_id);
CREATE INDEX access_tokens_refresh_idx ON access_tokens (refresh_token_id);

-- The id is the SHA-256 hex of the opaque token value handed to the client;
-- the raw value is never stored.
CREATE TABLE refresh_tokens (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id  TEXT NOT NULL,
    scopes     TEXT NOT NULL DEFAULT '[]',
    audience   TEXT NOT NULL DEFAULT '[]',
    amr        TEXT NOT NULL DEFAULT '[]',
    auth_time  TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX refresh_tokens_user_client_idx ON refresh_tokens (user_id, client_id);
