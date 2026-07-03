-- Groups can grant the Kivraid administrator role: a user is an
-- administrator if their personal flag is set OR they belong to at
-- least one granting group. Works for local and directory groups —
-- flag a synced LDAP group to manage administrators from the directory.
ALTER TABLE groups ADD COLUMN grants_admin BOOLEAN NOT NULL DEFAULT FALSE;
