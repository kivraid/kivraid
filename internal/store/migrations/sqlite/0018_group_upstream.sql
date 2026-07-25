-- Groups mirrored from an upstream OIDC provider's groups claim, tagged with
-- the provider so a user's federated memberships can be refreshed on each
-- login (mirrors ldap_source_id for directory groups). NULL for local/LDAP.
ALTER TABLE groups ADD COLUMN upstream_source_id TEXT REFERENCES upstream_providers(id) ON DELETE SET NULL;
