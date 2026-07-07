# Coolify

Coolify has an OAuth/SSO login for its own dashboard, but **it cannot be
pointed at Kivraid**: it only speaks to a fixed list of built-in providers
whose endpoints are hardcoded, and there is no generic OpenID Connect option
(no discovery URL, no custom endpoints) in any released version. The
recommended way to put Coolify behind Kivraid is **forward auth** at the
reverse proxy. Replace `sso.example.com` (your Kivraid base URL) and
`coolify.example.com` (your Coolify host) with your own.

## Why not native OIDC

Coolify's built-in SSO (**Settings → OAuth**) is a closed set of named
providers — Azure, Bitbucket, GitHub, GitLab, Google, Discord, and the
identity providers Authentik, Clerk, and Zitadel. Each one supplies only a
client ID, client secret, and (for the self-hosted ones) a base URL; Coolify
appends that provider's own fixed endpoint paths.

The closest match, the **Authentik** provider, is built on
`SocialiteProviders/Authentik`, which builds its URLs as
`{base_url}/application/o/authorize/`, `{base_url}/application/o/token/`, and
`{base_url}/application/o/userinfo/`. Kivraid serves OIDC at `/authorize`,
`/oauth/token`, and `/userinfo`, so pointing Coolify's Authentik provider at
`https://sso.example.com` sends every request to a path Kivraid does not
have, and login fails. There is no field to override those paths, and no
"discovery URL" / generic-OIDC provider to enter Kivraid's issuer into.

A community pull request to add a true generic OIDC provider
([coollabsio/coolify#6696](https://github.com/coollabsio/coolify/pull/6696))
has been open since 2025 and is **not merged** as of mid-2026. Until it
ships, there is no Kivraid client to register and no OIDC config to set in
Coolify.

## Protect it with forward auth

Follow [../forward-auth.md](../forward-auth.md) and route the Coolify host
through the Kivraid forward-auth middleware. Every request then requires a
valid Kivraid session before it reaches Coolify, and Kivraid sets
`Remote-User`, `Remote-Email`, `Remote-Name`, and `Remote-Groups` headers
upstream. Coolify does not consume those headers, so they are harmless — the
protection comes from Kivraid gating access to the host.

Register a **forward-auth application** in Kivraid (Admin → Applications →
Forward auth), list `coolify.example.com` as a protected host, and bind the
groups allowed to reach the dashboard.

## Coolify's own login

Coolify keeps its own email/password login behind the proxy, so users hit
two prompts: Kivraid first, then Coolify. There is no supported way to
disable Coolify's local login, so treat forward auth as an outer gate
(defense in depth) rather than single sign-on — Coolify accounts still exist
locally and are not provisioned from Kivraid groups. Access is all-or-nothing
at the proxy; per-user roles and team membership are managed inside Coolify.

Note that Coolify runs its own reverse proxy (Traefik or Caddy) in front of
your services. Forward auth here means adding the Kivraid middleware to the
route that serves the Coolify dashboard itself, not to a deployed app.

## Notes

- Third-party "Coolify + Authentik" guides describe **Traefik forward-auth
  middleware**, not the built-in OAuth provider — the same proxy-level
  approach described here.
- If Coolify ships a generic OIDC provider (a discovery URL or editable
  endpoints), replace this guide with a real OIDC configuration using
  Kivraid's issuer `https://sso.example.com`, client type **Confidential**,
  and redirect URI `https://coolify.example.com/auth/oidc/callback` (Coolify's
  callback pattern is `/auth/<provider>/callback`) — verify the exact provider
  slug against that release.
</content>
</invoke>
