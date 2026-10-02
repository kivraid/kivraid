-- Automatic rotation of the OIDC signing key: a fresh key replaces the
-- signer once it is this many days old. 0 keeps rotation manual.
ALTER TABLE instance_settings ADD COLUMN key_rotation_days INTEGER NOT NULL DEFAULT 0;
