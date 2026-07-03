-- Applications gain a kind (OIDC provider vs forward-auth proxy),
-- presentation metadata (description, icon) and, for proxy apps, the
-- protected hosts matched by the forward-auth endpoint.
ALTER TABLE applications ADD COLUMN kind TEXT NOT NULL DEFAULT 'oidc';
ALTER TABLE applications ADD COLUMN description TEXT NOT NULL DEFAULT '';
ALTER TABLE applications ADD COLUMN icon BLOB;
ALTER TABLE applications ADD COLUMN icon_mime TEXT;
ALTER TABLE applications ADD COLUMN proxy_hosts TEXT NOT NULL DEFAULT '[]';
