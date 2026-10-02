-- Email users when their account signs in from a browser that has never
-- signed in as them before. Off by default: right after it is turned on,
-- every browser's next sign-in looks new.
ALTER TABLE instance_settings ADD COLUMN new_device_alerts BOOLEAN NOT NULL DEFAULT FALSE;
