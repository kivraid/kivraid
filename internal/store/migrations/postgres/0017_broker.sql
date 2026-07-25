-- Identity brokering: Kivraid acts as an OIDC client (RP) to upstream
-- providers and federates their users. Generic OIDC only for now.
CREATE TABLE upstream_providers (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL UNIQUE,
    issuer            TEXT NOT NULL,
    client_id         TEXT NOT NULL,
    client_secret_enc BYTEA,
    scopes            TEXT NOT NULL DEFAULT 'openid profile email',
    claim_email       TEXT NOT NULL DEFAULT 'email',
    claim_name        TEXT NOT NULL DEFAULT 'name',
    claim_groups      TEXT NOT NULL DEFAULT 'groups',
    allow_signup      BOOLEAN NOT NULL DEFAULT TRUE,
    enabled           BOOLEAN NOT NULL DEFAULT TRUE,
    position          INTEGER NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL,
    updated_at        TIMESTAMPTZ NOT NULL
);

-- Home-realm-discovery rules. An entered identifier is matched most-specific
-- first: exact identifier, then email domain, then the single 'default' row.
-- target is 'local' or an upstream_providers.id.
CREATE TABLE login_routes (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,               -- 'identifier' | 'domain' | 'default'
    match_value TEXT NOT NULL DEFAULT '',    -- the identifier or domain ('' for default)
    target      TEXT NOT NULL,               -- 'local' | <upstream_providers.id>
    position    INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL
);
-- One rule per (kind, value); a single 'default' row (its value is '').
CREATE UNIQUE INDEX login_routes_kind_match_idx ON login_routes (kind, match_value);

-- Federated shadow users: which upstream owns them and the stable subject
-- (sub) claim used to re-link on later logins. NULL for local/LDAP users.
ALTER TABLE users ADD COLUMN upstream_source_id TEXT REFERENCES upstream_providers(id) ON DELETE SET NULL;
ALTER TABLE users ADD COLUMN external_id TEXT;
-- NULLs are distinct in a unique index, so local/LDAP rows never collide.
CREATE UNIQUE INDEX users_upstream_identity_idx ON users (upstream_source_id, external_id);
