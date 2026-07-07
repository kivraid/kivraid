# Integrations

Recipes for connecting common applications to Kivraid over OpenID Connect.
Each guide has two halves: what to enter **in Kivraid** (register the
application) and what to enter **in the app**.

For anything not listed, follow the generic reference below — most OIDC
clients need the same handful of values.

### Native OpenID Connect

Configured directly in the app:

- [Grafana](grafana.md)
- [Gitea](gitea.md) · [Forgejo](forgejo.md)
- [GitLab](gitlab.md)
- [Nextcloud](nextcloud.md)
- [BookStack](bookstack.md) — requires the instance on RS256 (see below)
- [Outline](outline.md)
- [Opengist](opengist.md)
- [Weblate](weblate.md)
- [NetBox](netbox.md)
- [Paperless-ngx](paperless-ngx.md)
- [Portainer](portainer.md)
- [Rancher](rancher.md)
- [Harbor](harbor.md)
- [Immich](immich.md)
- [Wazuh](wazuh.md)
- [Wallos](wallos.md)
- [Proxmox VE](proxmox.md)

### OIDC via a plugin or add-on

- [Jenkins](jenkins.md) — official OpenID Connect Authentication plugin
- [Jellyfin](jellyfin.md) — community SSO-Auth plugin
- [SonarQube](sonarqube.md) — community `sonar-auth-oidc` plugin

### No usable OIDC — use forward auth

These have no OIDC path that works with Kivraid today; protect them
through your reverse proxy with [forward auth](../forward-auth.md) instead:

- [Home Assistant](home-assistant.md) — no native OIDC
- [Uptime Kuma](uptime-kuma.md) — no SSO support
- [Coolify](coolify.md) — no generic OIDC provider
- [Sentry](sentry.md) — only an unofficial community plugin

## Register an application in Kivraid

**Admin → Applications → New application → OpenID Connect.**

- **Redirect URIs** — one per line, matched **exactly** (scheme, host,
  path, no trailing slash unless the app sends one). Each app's guide
  gives the exact value.
- **Client type**:
  - **Confidential** — server-side apps that can keep a secret (the
    common case; almost every app below).
  - **Public** — apps that cannot hold a secret (SPAs, CLIs); PKCE is
    required and no secret is issued.
- On save Kivraid shows the **client ID** and, once, the **client
  secret**. Copy the secret now — it is hashed and cannot be shown again
  (you can rotate it later from the application page).
- To restrict who may sign in, bind groups under the application's
  **Access** section. With no bound group, every authenticated user may
  use the app.

## Endpoints

Everything is derived from your `base_url` (the issuer). Most apps only
need the **discovery URL** and auto-configure the rest.

| | URL |
|---|---|
| Issuer | `https://sso.example.com` |
| Discovery | `https://sso.example.com/.well-known/openid-configuration` |
| Authorization | `https://sso.example.com/authorize` |
| Token | `https://sso.example.com/oauth/token` |
| Userinfo | `https://sso.example.com/userinfo` |
| JWKS | `https://sso.example.com/keys` |
| Introspection | `https://sso.example.com/oauth/introspect` |
| Revocation | `https://sso.example.com/revoke` |
| End session (RP logout) | `https://sso.example.com/end_session` |

ID tokens are signed with **ES256**; PKCE (`S256`) is supported.

> **Signing algorithm.** Kivraid signs ID tokens with **ES256** by
> default, and can be switched to **RS256** instance-wide with
> `oidc.signing_algorithm` (see
> [configuration](../configuration.md#id-token-signing-algorithm)). Most
> clients read the algorithm from discovery or JWKS and just work. A few
> pin it: some let you select ES256 (Immich, SonarQube — match your
> instance or login fails signature verification), and BookStack accepts
> **only** RS256, so run the instance on RS256 for it. RS256 is the
> universally accepted baseline, so switching the whole instance to it is
> always safe.

## Scopes

| Scope | Adds |
|---|---|
| `openid` | required; yields `sub` |
| `profile` | `name`, `preferred_username`, `picture`, `updated_at` |
| `email` | `email`, `email_verified` |
| `groups` | `groups` (the user's group names) |
| `offline_access` | a refresh token (rotated on use) |

## Claims

`profile`, `email` and `groups` claims are present in **both** the ID
token and the userinfo response, so even simple clients that never call
userinfo get the user's identity.

| Claim | Example | Notes |
|---|---|---|
| `sub` | `f70fc5bb-b3e9-…` | Stable **opaque UUID**. Never changes, even if the user is renamed. |
| `preferred_username` | `amelia` | The login name. |
| `name` | `Amelia Laurent` | Display name. |
| `picture` | `https://sso.example.com/oidc/avatar/…` | Avatar URL; present only if the user uploaded a photo. |
| `email` | `amelia@example.com` | `email_verified` is always `true`. |
| `groups` | `["engineering"]` | Group names; needs the `groups` scope. |

> **The one thing to get right:** map the app's *username* to
> `preferred_username`, not to `sub`. `sub` is an opaque UUID meant as a
> stable internal key — if an app uses it as the visible username, every
> account shows up as a UUID. Use `sub` only where the app wants a
> stable unique identifier and `preferred_username` (or `email`) for the
> human-readable handle.

## Group-based roles

Kivraid does not assign application roles itself — it exposes the user's
groups in the `groups` claim, and each app maps those to its own roles
(admin/editor/viewer, etc.). Create the groups in **Admin → Groups**,
add members, and reference the group names in the app's role mapping.
The per-app guides show the exact syntax.
