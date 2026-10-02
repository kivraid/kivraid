-- Optional custom background image for the sign-in pages, replacing the
-- built-in mesh gradient (branding, alongside the logo).
ALTER TABLE instance_settings ADD COLUMN login_background BLOB;
ALTER TABLE instance_settings ADD COLUMN login_background_mime TEXT;
