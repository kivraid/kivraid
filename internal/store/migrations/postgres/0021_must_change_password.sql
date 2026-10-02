-- Set when an administrator chose the password (account creation or reset)
-- and wants the user to replace it: the next sign-in asks for a new one
-- before anything else. Cleared whenever the password changes.
ALTER TABLE users ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE;
