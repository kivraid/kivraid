CREATE TABLE ldap_sources (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL UNIQUE,
    url               TEXT NOT NULL,
    start_tls         BOOLEAN NOT NULL DEFAULT FALSE,
    skip_tls_verify   BOOLEAN NOT NULL DEFAULT FALSE,
    bind_dn           TEXT NOT NULL,
    bind_password_enc BYTEA NOT NULL,
    base_dn           TEXT NOT NULL,
    user_filter       TEXT NOT NULL,
    username_attr     TEXT NOT NULL DEFAULT 'uid',
    email_attr        TEXT NOT NULL DEFAULT 'mail',
    name_attr         TEXT NOT NULL DEFAULT 'cn',
    group_filter      TEXT NOT NULL DEFAULT '',
    group_name_attr   TEXT NOT NULL DEFAULT 'cn',
    enabled           BOOLEAN NOT NULL DEFAULT TRUE,
    position          BIGINT NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL,
    updated_at        TIMESTAMPTZ NOT NULL
);

ALTER TABLE users ADD COLUMN ldap_source_id TEXT REFERENCES ldap_sources(id) ON DELETE SET NULL;
ALTER TABLE users ADD COLUMN ldap_dn TEXT;
