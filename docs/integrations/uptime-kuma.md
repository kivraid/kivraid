# Uptime Kuma

Uptime Kuma has **no native OpenID Connect (or SAML) support** — its web UI
authenticates against a single local account only, and the maintainer has
declined requests to add SSO
([issue #553](https://github.com/louislam/uptime-kuma/issues/553),
[issue #5589](https://github.com/louislam/uptime-kuma/issues/5589)). There is
no client to register in Kivraid and no OIDC config to set in Uptime Kuma.
The recommended way to put it behind Kivraid is **forward auth** at the
reverse proxy. Replace `sso.example.com` (your Kivraid base URL) and
`status.example.com` (your Uptime Kuma host) with your own.

## Protect it with forward auth

Follow [../forward-auth.md](../forward-auth.md) and route the whole Uptime
Kuma host through the Kivraid forward-auth middleware. Every request then
requires a valid Kivraid session before it reaches Uptime Kuma, and Kivraid
sets `Remote-User`, `Remote-Email`, `Remote-Name`, and `Remote-Groups`
headers upstream. Uptime Kuma does not consume those headers, so they are
harmless — the protection comes from Kivraid gating access to the host.

Register a **forward-auth application** in Kivraid (Admin → Applications →
Forward auth), list `status.example.com` as a protected host, and bind the
groups allowed to see the status dashboard.

## Uptime Kuma's own login

Uptime Kuma keeps its own single-user login screen behind the proxy, so by
default users hit two prompts: Kivraid, then Uptime Kuma. Two ways to handle
this:

- **Disable Uptime Kuma's built-in auth** so Kivraid is the only gate. In
  Uptime Kuma go to Settings → Security → *Disable Auth* and confirm. Only do
  this once the whole host is behind forward auth — otherwise the dashboard is
  exposed to anyone. This is the usual choice for a fully SSO-gated instance.
- **Keep the local login** as a second factor. Leave auth enabled; users log
  in to Kivraid and then to Uptime Kuma with the shared local credentials.

Because there is no OIDC, Uptime Kuma accounts are not provisioned from
Kivraid groups — access is all-or-nothing at the proxy, and any per-user
distinction inside Uptime Kuma does not exist (it is single-user).

## Notes

- Third-party "Uptime Kuma SSO" guides (Authelia, authentik) are all
  forward/reverse-proxy setups, not native OIDC — they confirm the same
  approach described here.
- Native OIDC has been discussed upstream but is not part of a released
  version; if a future release adds it, replace this guide with a real OIDC
  configuration.
