CREATE TABLE ldap_sources (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL UNIQUE,
    url               TEXT NOT NULL,
    start_tls         BOOLEAN NOT NULL DEFAULT FALSE,
    skip_tls_verify   BOOLEAN NOT NULL DEFAULT FALSE,
    bind_dn           TEXT NOT NULL,
    bind_password_enc BLOB NOT NULL,
    base_dn           TEXT NOT NULL,
    -- Search filter with a {username} placeholder (LDAP-escaped at query
    -- time), e.g. (&(objectClass=person)(|(uid={username})(mail={username})))
    user_filter       TEXT NOT NULL,
    username_attr     TEXT NOT NULL DEFAULT 'uid',
    email_attr        TEXT NOT NULL DEFAULT 'mail',
    name_attr         TEXT NOT NULL DEFAULT 'cn',
    -- Group filter with a {dn} placeholder for the user's DN; empty
    -- disables group sync.
    group_filter      TEXT NOT NULL DEFAULT '',
    group_name_attr   TEXT NOT NULL DEFAULT 'cn',
    enabled           BOOLEAN NOT NULL DEFAULT TRUE,
    position          INTEGER NOT NULL DEFAULT 0,
    created_at        TIMESTAMP NOT NULL,
    updated_at        TIMESTAMP NOT NULL
);

ALTER TABLE users ADD COLUMN ldap_source_id TEXT REFERENCES ldap_sources(id) ON DELETE SET NULL;
ALTER TABLE users ADD COLUMN ldap_dn TEXT;
