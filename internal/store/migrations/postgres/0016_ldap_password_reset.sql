-- Whether Kivraid may reset a directory user's password using the service
-- (bind) account — an admin-style force-set that powers email-based
-- password reset and admin-initiated resets for this source's users. This
-- is more privileged than self-service write-back (which binds as the user),
-- so it defaults off and must be opted into per directory.
ALTER TABLE ldap_sources ADD COLUMN password_reset BOOLEAN NOT NULL DEFAULT FALSE;
