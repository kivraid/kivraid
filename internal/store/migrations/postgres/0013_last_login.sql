-- Records the most recent successful login so the admin can see when an
-- account was last used. NULL until the user next signs in.
ALTER TABLE users ADD COLUMN last_login_at TIMESTAMPTZ;
