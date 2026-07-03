-- Profile photos: mirrored from the directory for LDAP users, uploaded
-- from the portal for local users.
ALTER TABLE users ADD COLUMN photo BLOB;
ALTER TABLE users ADD COLUMN photo_mime TEXT;

-- Group provenance: local groups are managed in the admin, ldap groups
-- are mirrored from their directory and read-only in Kivraid.
ALTER TABLE groups ADD COLUMN source TEXT NOT NULL DEFAULT 'local';
ALTER TABLE groups ADD COLUMN ldap_source_id TEXT REFERENCES ldap_sources(id) ON DELETE SET NULL;

ALTER TABLE ldap_sources ADD COLUMN photo_attr TEXT NOT NULL DEFAULT 'jpegPhoto';
