# Portainer

Portainer signs in through its **Custom OAuth** provider (Settings →
Authentication → OAuth). Replace `sso.example.com` with your Kivraid
`base_url` and `portainer.example.com` with your Portainer URL throughout.

## In Kivraid

Register an OpenID Connect application (see
[the generic reference](README.md#register-an-application-in-kivraid)):

- **Redirect URI:** `https://portainer.example.com` — this is the value you
  type into Portainer's **Redirect URL** field (your Portainer instance
  URL). It must match Kivraid **character for character**, including scheme,
  port, and trailing slash. If you run Portainer on its default HTTPS port
  the value is typically `https://portainer.example.com:9443`.
- **Client type:** Confidential

Copy the client ID and secret.

## In Portainer

Go to **Settings → Authentication**, choose **OAuth**, and select the
**Custom** provider. Fill in the OAuth configuration:

| Field | Value |
| --- | --- |
| Client ID | `<client id from Kivraid>` |
| Client secret | `<client secret from Kivraid>` |
| Authorization URL | `https://sso.example.com/authorize` |
| Access token URL | `https://sso.example.com/oauth/token` |
| Resource URL | `https://sso.example.com/userinfo` |
| Redirect URL | `https://portainer.example.com` |
| Logout URL | `https://sso.example.com/end_session` |
| User identifier | `preferred_username` |
| Scopes | `openid profile email groups` |

`User identifier = preferred_username` is the important line: Portainer
names each account from this claim. Leave it as the opaque `sub` and every
account shows up as a UUID. (If you prefer email-based usernames, set it to
`email` instead.)

Enter the scopes **space-separated, not comma-separated** — Portainer treats
the whole string as one value otherwise.

Turn on **Use SSO** so users are redirected straight to Kivraid, and
**Automatic user provisioning** if you want Portainer to create an account on
first login rather than requiring it in advance.

## Roles from groups

Portainer **Community Edition cannot map OAuth claims to teams or roles** —
every OAuth user is created as a standard (non-admin) user, and you assign
teams and permissions manually in **Users** and **Teams**.

Automatic team membership from the provider is a **Portainer Business
Edition** feature. On BE, add a **Team memberships** mapping that keys off a
claim from the Resource URL response; request the `groups` scope (already in
the table above) so Kivraid returns the user's group names, then map each
Kivraid group to a Portainer team. Create the groups in Kivraid under
**Admin → Groups**. On CE the `groups` scope is harmless but unused, so you
can drop it to `openid profile email`.

To keep users out of Portainer entirely unless they belong to a specific
group, bind that group under the application's **Access** section in Kivraid.

## Notes

- Single logout: the **Logout URL** above points at Kivraid's
  `/end_session`, so signing out of Portainer also ends the Kivraid session.
- Most sign-in failures (`redirect_uri_mismatch`) come from the Redirect URL
  not matching exactly. Register in Kivraid the *same* string you typed into
  Portainer's Redirect URL field — same scheme, host, port, and trailing
  slash, as seen from the browser behind any reverse proxy.
- **Auth Style** controls how the client ID and secret are sent to the token
  endpoint. Kivraid accepts `client_secret_basic` and `client_secret_post`,
  so Portainer's default (auto-detect) works; pin it only if a proxy strips
  the `Authorization` header.
- UI labels here match Portainer 2.x. Older releases split these fields
  across a slightly different layout, but the field meanings are unchanged.
</content>
</invoke>
