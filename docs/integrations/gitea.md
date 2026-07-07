# Gitea

Gitea (and Forgejo) sign in through an **OAuth2 authentication source** of
type OpenID Connect. Replace `sso.example.com` with your Kivraid
`base_url` and `gitea.example.com` with your Gitea URL.

## In Kivraid

Register an OpenID Connect application (see
[the generic reference](README.md#register-an-application-in-kivraid)):

- **Redirect URI:** `https://gitea.example.com/user/oauth2/Kivraid/callback`

  The `Kivraid` segment is the **Authentication Name** you give the
  source in Gitea (next step) — they must match. If you name it
  differently, change the URI to match.
- **Client type:** Confidential

## In Gitea

**Site Administration → Identity & Access → Authentication Sources → Add
Authentication Source.**

- **Authentication Type:** OAuth2
- **Authentication Name:** `Kivraid` (must match the redirect URI above)
- **OAuth2 Provider:** OpenID Connect
- **Client ID (Key):** the client ID from Kivraid
- **Client Secret:** the client secret from Kivraid
- **OpenID Connect Auto Discovery URL:**
  `https://sso.example.com/.well-known/openid-configuration`
- **Additional Scopes:** `groups` (only needed for group-to-team mapping)

Gitea maps the username from `preferred_username` and the email from
`email` automatically.

## Roles and teams from groups

To map Kivraid groups onto Gitea org teams, expand **Map claimed groups
to Organization teams** and set:

- **Claim name providing group names for this source:** `groups`
- **Group Claim value for administrator users** (optional): a group name
  whose members become Gitea admins, e.g. `gitea-admins`.
- **Map claimed groups to Organization teams:** a JSON object, e.g.

  ```json
  {"developers": {"my-org": ["Developers"]}}
  ```

Create the groups in **Admin → Groups** in Kivraid and add members.

## Notes

- Existing local Gitea accounts can be linked on first OIDC sign-in if
  their email matches; otherwise a new account is created.
- A redirect-URI error almost always means the **Authentication Name**
  and the URI's `.../oauth2/<name>/callback` segment disagree.
