-- The user's preferred UI language ("" = follow the browser), also used for
-- the emails Kivraid sends them.
ALTER TABLE users ADD COLUMN locale TEXT NOT NULL DEFAULT '';
