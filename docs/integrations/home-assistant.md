# Home Assistant

Home Assistant has **no native OpenID Connect support**, so there is no
first-party Kivraid OIDC setup for it. Its built-in authentication
providers are local username/password (`homeassistant`), `trusted_networks`,
and `command_line` only — none of them speak OIDC. This guide states the
situation honestly and gives you the reliable option (Kivraid forward auth)
plus one optional community path. Replace `sso.example.com` with your
Kivraid `base_url` and `home.example.com` with your Home Assistant URL
throughout.

## Reliable option: Kivraid forward auth

Put Home Assistant behind your reverse proxy and protect it with Kivraid
[forward auth](../forward-auth.md). Kivraid then gates access at the proxy:
an unauthenticated visitor is bounced to the Kivraid login before any
request reaches Home Assistant.

Important caveats specific to Home Assistant:

- **This does not replace Home Assistant's own login.** Home Assistant does
  not consume the `Remote-User` / `Remote-Email` / `Remote-Name` /
  `Remote-Groups` headers that forward auth sets, so users still see the
  Home Assistant login page after passing Kivraid. Forward auth adds a gate
  in front; it is not single sign-on into Home Assistant.
- **The mobile apps and API break under a login wall.** The Home Assistant
  companion apps, webhooks, and long-lived access token / REST + WebSocket
  API clients cannot complete the interactive Kivraid login. Exclude those
  paths (e.g. `/api/`, `/auth/`) from the forward-auth middleware, or scope
  the gate to the web UI only.
- **Trusted-proxy hygiene.** Home Assistant's own HTTP integration must
  trust the proxy for client IPs to be correct:

  ```yaml
  # configuration.yaml
  http:
    use_x_forwarded_for: true
    trusted_proxies:
      - 172.16.0.0/12   # your reverse proxy's address/range
  ```

  Home Assistant warns that a network listed in `trusted_proxies` must
  **not** also be a `trusted_networks` auth network — otherwise anyone
  behind the proxy is treated as pre-authenticated. Do not combine
  forward auth with a `trusted_networks` provider covering the proxy.

See [../forward-auth.md](../forward-auth.md) for the proxy middleware
configuration (Traefik / nginx / Caddy) and the required Kivraid
`forward_auth.domains` allowlist.

## Optional: community OIDC component

If you want an actual "Sign in with Kivraid" button inside Home Assistant,
the community custom component
[`hass-oidc-auth`](https://github.com/christiaangoossens/hass-oidc-auth)
(by christiaangoossens) adds an OpenID Connect client / relying-party auth
provider. It is a third-party integration, not part of Home Assistant core,
and not maintained by Kivraid — install and trust it at your own
discretion.

When configuring it, point it at Kivraid's discovery document and use the
standard Kivraid values:

- **Discovery URL:** `https://sso.example.com/.well-known/openid-configuration`
- **Scopes:** `openid profile email groups`
- **Username claim:** `preferred_username` (never `sub`, which is an opaque
  UUID)
- **Client type in Kivraid:** register an OpenID Connect application
  (Confidential or Public/PKCE per the component's requirements) and set the
  redirect URI to the exact callback the component documents.

The exact configuration keys and callback path are defined by that
component, not by Kivraid — follow its README rather than any values
guessed here. Register the matching redirect URI in
**Kivraid → Applications → New application → OpenID Connect** so it is an
exact match.

## Notes

- Native OIDC in Home Assistant core is a long-standing open request but is
  not shipped as of this writing; verify the current state before relying
  on it.
- Restrict who can reach Home Assistant by binding groups under the
  application's **Access** section in Kivraid (forward auth) — or, with the
  community component, however that component maps the `groups` claim.
