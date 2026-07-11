-- Instance-level settings held in the database rather than the config file:
-- the first mutable, admin-editable configuration surface (branding). A
-- single pinned row (id = 1) keeps the columns strongly typed and leaves
-- room to grow without a key/value free-for-all.
CREATE TABLE instance_settings (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    brand_name TEXT NOT NULL DEFAULT '',
    logo       BYTEA,
    logo_mime  TEXT,
    updated_at TIMESTAMPTZ NOT NULL
);

INSERT INTO instance_settings (id, brand_name, updated_at) VALUES (1, '', CURRENT_TIMESTAMP);
