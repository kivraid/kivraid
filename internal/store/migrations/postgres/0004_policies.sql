-- Group-based access policies: an application with no policy rows is
-- open to every authenticated user; otherwise the user must belong to
-- at least one of the bound groups.
CREATE TABLE app_policies (
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    group_id       TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (application_id, group_id)
);

ALTER TABLE ldap_sources ADD COLUMN password_writeback BOOLEAN NOT NULL DEFAULT TRUE;
