# Immich

Immich signs in through its native **OAuth / OpenID Connect** support.
Replace `sso.example.com` with your Kivraid `base_url` and
`immich.example.com` with your Immich URL throughout.

## In Kivraid

Register an OpenID Connect application (see
[the generic reference](README.md#register-an-application-in-kivraid)):

- **Redirect URIs** (one per line, exact match):
  - `https://immich.example.com/auth/login` — web sign-in
  - `https://immich.example.com/user-settings` — linking OAuth from the account page
  - `app.immich:///oauth-callback` — the iOS/Android mobile apps
- **Client type:** Confidential

Copy the client ID and secret.

The mobile redirect uses the custom scheme `app.immich:///oauth-callback`
(three slashes — an empty host). If Kivraid rejects a non-`http(s)`
redirect URI, use the mobile override described in the Notes below and
register the HTTPS forwarding endpoint instead.

## In Immich

**Administration → Settings → OAuth Settings.** Enable it and fill in:

- **Issuer URL:** `https://sso.example.com`

  Immich runs discovery itself, appending
  `/.well-known/openid-configuration` — enter the base issuer, not the
  discovery URL.
- **Client ID:** from Kivraid
- **Client Secret:** from Kivraid
- **Scope:** `openid email profile` (add `groups` only if you use the
  group override below)
- **Storage Label Claim:** `preferred_username` (the default)
- **ID Token Signed Response Algorithm:** `ES256`

  Kivraid signs ID tokens with ES256; Immich defaults this field to
  `RS256`, so you must change it or discovery/verification will fail.
- **Button Text:** e.g. `Login with Kivraid`
- **Auto Register:** on, to create Immich accounts on first login.

Immich keys each account to the OIDC `sub` claim (the stable Kivraid
UUID), so accounts survive a rename. The **Storage Label Claim** is what
becomes the human-readable label on uploaded assets — leaving it at
`preferred_username` gives readable names (e.g. `amelia`) instead of the
opaque UUID.

## Roles and quota from claims

Immich can read two custom claims that Kivraid does **not** emit out of
the box:

- **Role Claim** (default `immich_role`, values `user` / `admin`)
- **Storage Quota Claim** (default `immich_quota`, in GiB)

Kivraid's standard claims are `sub`, `preferred_username`, `name`,
`email`, `email_verified`, and `groups`; it does not produce
`immich_role` or `immich_quota`. Unless you extend Kivraid to emit those
exact claims, leave these fields empty and instead:

- set roles and per-user storage in Immich under **Administration →
  Users**, and
- set a fallback with **Default Storage Quota (GiB)** (`0` = unlimited).

Kivraid's `groups` claim has no direct mapping to Immich roles.

## Notes

- **Single logout:** set Immich's **End Session Endpoint** to
  `https://sso.example.com/end_session` to end the Kivraid session when a
  user logs out of Immich. If Kivraid sends back-channel logout, point
  it at `https://immich.example.com/api/oauth/backchannel-logout`.
- **Mobile custom-scheme workaround:** if `app.immich:///oauth-callback`
  cannot be registered in Kivraid, host an HTTPS endpoint that forwards
  to it and set Immich's **Mobile Redirect URI Override** to
  `https://immich.example.com/api/oauth/mobile-redirect`; register that
  HTTPS URL in Kivraid in place of the custom scheme.
- **Exact-match redirect URIs:** a sign-in error almost always means the
  URI in Kivraid does not match what Immich sends. All three URIs above
  must match exactly — scheme, host, and path — as Immich sees them
  behind your proxy. Check Immich's **External Domain** setting so it
  builds callbacks on `https://immich.example.com`, not an internal host.
- Field labels have shifted between Immich releases (older builds group
  these under **OAuth**); if a label here differs, match by meaning.
