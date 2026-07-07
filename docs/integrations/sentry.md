# Sentry

Self-hosted Sentry has **no native OpenID Connect support**, so this guide
recommends protecting it with Kivraid **forward auth** instead of an OIDC
client. Replace `sso.example.com` with your Kivraid `base_url` and
`sentry.example.com` with your Sentry URL throughout.

## Why not OIDC

Self-hosted Sentry's built-in SSO is **SAML2** (bundled since Sentry
20.6.0), plus dedicated Google and GitHub providers. There is no generic
OpenID Connect provider in the box, and Kivraid speaks OIDC, not SAML2 —
so the two do not connect directly.

A generic OIDC provider only exists as a **third-party, community-maintained
plugin** (`sentry-auth-oidc`), not shipped or supported by Sentry. If you
prefer that route, see [OIDC via the community plugin](#oidc-via-the-community-plugin)
below; otherwise use forward auth, which needs nothing installed inside
Sentry.

## Forward auth (recommended)

Put Sentry behind your reverse proxy and require a valid Kivraid session
before any request reaches it. See [../forward-auth.md](../forward-auth.md)
for the full Traefik / nginx / Caddy configuration.

### In Kivraid

Register a **forward-auth application** (Admin → Applications → New
application → Forward auth) and list `sentry.example.com` as a protected
host. Bind the groups allowed to reach Sentry under the application's
**Access** section; anyone outside them gets `403` before Sentry sees the
request. Add `sentry.example.com` (or a wildcard covering it) to
`forward_auth.domains` in `kivraid.yaml` so the post-login redirect is
allowed.

### In Sentry

Kivraid injects the identity headers `Remote-User`, `Remote-Email`,
`Remote-Name` and `Remote-Groups` on authenticated requests. Sentry does
**not** read these headers to log a user in — it manages its own accounts —
so forward auth acts as a gate in front of Sentry, not as an identity
source. Keep a Sentry account (local or SAML) for each user, or let them
register once Kivraid has let them through.

## OIDC via the community plugin

Only if you specifically want OIDC login inside Sentry. `sentry-auth-oidc`
is community software; verify it against your Sentry version before relying
on it.

### In Kivraid

Register an OpenID Connect application (see
[the generic reference](README.md#register-an-application-in-kivraid)):

- **Redirect URI:** `https://sentry.example.com/auth/sso/`
- **Client type:** Confidential

Copy the client ID and secret.

### In Sentry

Install the plugin (`pip install sentry-auth-oidc`, or add it to
`sentry/requirements.txt` before running the self-hosted install script),
then set these in `sentry.conf.py`:

```python
OIDC_CLIENT_ID = "<client id from Kivraid>"
OIDC_CLIENT_SECRET = "<client secret from Kivraid>"
OIDC_SCOPE = "openid email profile"
OIDC_DOMAIN = "https://sso.example.com"   # discovery is read from /.well-known/openid-configuration
OIDC_ISSUER = "Kivraid"                    # name shown on the login button
```

`OIDC_DOMAIN` points at the Kivraid issuer; the plugin appends
`/.well-known/openid-configuration` to discover the `/authorize`,
`/oauth/token` and `/userinfo` endpoints automatically. If discovery is
unreachable, set the endpoints explicitly instead:

```python
OIDC_AUTHORIZATION_ENDPOINT = "https://sso.example.com/authorize"
OIDC_TOKEN_ENDPOINT = "https://sso.example.com/oauth/token"
OIDC_USERINFO_ENDPOINT = "https://sso.example.com/userinfo"
OIDC_ISSUER = "https://sso.example.com"
```

The display name comes from the `name` claim by default
(`OIDC_USERINFO_NAME_CLAIM` overrides it). Sentry keys accounts on the
`email` claim, not on `preferred_username`, so email is what identifies the
user here.

## Notes

- Redirect URIs are matched exactly in Kivraid: the value must equal what
  Sentry sends (`https://sentry.example.com/auth/sso/`, with the trailing
  slash), including the scheme and host as seen behind your proxy.
- The forward-auth identity headers are only trustworthy when set by the
  proxy — ensure Sentry cannot receive `Remote-*` headers straight from
  clients.
- Plugin config keys and behaviour are from the community `sentry-auth-oidc`
  README and are not guaranteed by Sentry; confirm them for the version you
  install.
