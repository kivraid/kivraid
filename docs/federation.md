# Federation (upstream OIDC)

Kivraid can act as an **OpenID Connect relying party** to upstream identity
providers, so users sign in through an existing IdP (Authentik, Keycloak,
Google, …) and Kivraid federates their accounts. Configure this under
**Admin → Federation**, which has two tabs: **Providers** and **Routing**.

Generic OIDC only for now — any issuer that publishes a discovery document
works. Non-OIDC social providers (e.g. GitHub) are not supported yet.

## Registering a provider

Under **Federation → Providers → New provider**:

- **Issuer URL** — the provider's base URL; its
  `/.well-known/openid-configuration` is fetched to discover the endpoints.
  Use **Test discovery** to confirm it resolves before saving.
- **Client ID / secret** — the credentials of the OAuth client you register
  at the upstream. Leave the secret empty for a public client (Kivraid then
  uses PKCE). The secret is encrypted at rest.
- **Scopes** — space-separated, must include `openid` (default
  `openid profile email`; add e.g. `groups` if the provider gates the groups
  claim behind a scope).
- **Claim mapping** — which claims carry the email, name and groups. The
  stable `sub` claim always identifies the account.
- **Allow sign-up** — provision a Kivraid account automatically on first
  login. Off means only already-linked users can sign in.

Register these two URLs (shown on the provider page) at the upstream:

- the **redirect URI** — `https://<your-kivraid>/login/upstream/<id>/callback`
- the **post-logout redirect URI** — `https://<your-kivraid>/login`, if the
  provider supports RP-initiated logout.

An enabled provider shows a **"Continue with …"** button on the login page.

## Login routing (home-realm discovery)

Rather than click a button, users can just type their identifier and be
routed automatically. Under **Federation → Routing**, the entered identifier
is matched **most-specific first**:

1. an **exact identifier** rule (`alice@example.com → provider`),
2. then an **email domain** rule (`@example.com → provider`),
3. then the **default** (local password, or a provider).

A rule targeting `local` sends the user to the normal password step; a
provider target redirects into that provider. An unknown or disabled target
falls back to local rather than dead-ending.

## Provisioning and linking

On a successful upstream login, Kivraid resolves the account in this order:

1. **Already linked** — a user matching this provider and `sub` signs in.
2. **Link by email** — an existing local/LDAP account is linked **only when
   the email is verified on both sides**, to avoid account takeover. A
   collision on an unverified email is refused, not hijacked.
3. **Provision** — otherwise a new federated user is created, if the provider
   allows sign-up.

Federated sign-in bypasses the local password and two-factor steps: the
upstream owns authentication.

## Groups

The provider's groups claim is mirrored onto Kivraid groups on every login
(like the LDAP group sync): matching groups are created by name, tagged to
the provider, and the user's membership in them is refreshed each time. A
group flagged **"Members are administrators"** therefore lets the upstream
drive who administers Kivraid.

## Logout

When a federated user signs out, Kivraid also signs them out at the upstream
(RP-initiated logout) when the provider advertises an end-session endpoint,
then returns to the login page. Local sessions just end as usual.

## Notes

- The relying party (and its discovery) is cached per provider and rebuilt
  only when the provider's configuration changes.
- Deleting a provider keeps its federated users, but they can no longer sign
  in through it.
