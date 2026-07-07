# BookStack

BookStack signs in through its native **OpenID Connect** authentication
method (`AUTH_METHOD=oidc`). Replace `sso.example.com` with your Kivraid
`base_url` and `bookstack.example.com` with your BookStack URL throughout.

> **Set Kivraid to RS256 first.** BookStack validates ID tokens **only**
> when signed with **RS256** ("Only RS256 is currently supported as a token
> signing algorithm"), while Kivraid defaults to ES256. Configure your
> Kivraid instance with `oidc.signing_algorithm: rs256` (or
> `KIVRAID_OIDC_SIGNING_ALGORITHM=rs256`) — see
> [configuration](../configuration.md#id-token-signing-algorithm). RS256 is
> accepted by every other app too, so this switch is safe instance-wide;
> just re-check any app where you pinned ES256. Without it, BookStack
> rejects the token and sign-in fails.

## In Kivraid

Register an OpenID Connect application (see
[the generic reference](README.md#register-an-application-in-kivraid)):

- **Redirect URI:** `https://bookstack.example.com/oidc/callback`
- **Client type:** Confidential

Copy the client ID and secret.

## In BookStack

OIDC is configured through environment variables (in `.env` or your
container environment), not the web UI:

```sh
AUTH_METHOD=oidc
OIDC_NAME=Kivraid                     # label on the login button
OIDC_CLIENT_ID=<client id from Kivraid>
OIDC_CLIENT_SECRET=<client secret from Kivraid>
OIDC_ISSUER=https://sso.example.com
OIDC_ISSUER_DISCOVER=true             # read /.well-known/openid-configuration
OIDC_DISPLAY_NAME_CLAIMS=name         # visible display name
OIDC_EXTERNAL_ID_CLAIM=sub            # stable account key (default)
```

BookStack requests the `openid`, `profile` and `email` scopes by default
and takes the email from the standard `email` claim. It has no separate
"username" field — an account is identified internally by its **External
Authentication ID**, which maps to `sub` (the stable Kivraid UUID), while
the readable display name comes from the `name` claim. Leaving
`OIDC_EXTERNAL_ID_CLAIM=sub` is deliberate: it keeps the account key stable
across renames, and users still see their `name`, not the UUID.

Since v24.02 BookStack uses PKCE (`S256`) automatically, which Kivraid
supports.

## Roles from groups

Set these to sync the Kivraid `groups` claim onto BookStack roles:

```sh
OIDC_USER_TO_GROUPS=true
OIDC_GROUPS_CLAIM=groups
OIDC_ADDITIONAL_SCOPES=groups         # Kivraid gates the groups claim behind this scope
OIDC_REMOVE_FROM_GROUPS=true          # drop users from roles they no longer match
```

BookStack matches each OIDC group name against a BookStack **role display
name**, ignoring case (names are normalised to lowercase with spaces
replaced by hyphens). Create Kivraid groups in **Admin → Groups** whose
names line up with your BookStack roles (for example a Kivraid group
`editors` matches the built-in `Editor` role). You can override the match
per role via the role's **External Authentication IDs** field in BookStack.

## Notes

- **If you prefer to keep the instance on ES256**, put BookStack behind
  Kivraid [forward auth](../forward-auth.md) instead of using OIDC.
  BookStack has no built-in reverse-proxy header login, so forward auth
  gates access at the proxy rather than logging users in directly.
- **Single logout:** set `OIDC_END_SESSION_ENDPOINT=true` so BookStack uses
  the RP-initiated logout endpoint advertised by discovery
  (`https://sso.example.com/end_session`) and ends the Kivraid session on
  logout.
- **Redirect-URI errors:** the value in Kivraid must match
  `https://bookstack.example.com/oidc/callback` exactly, including the
  scheme and host as BookStack sees them (check `APP_URL` in BookStack when
  it runs behind a proxy).
- Switching an existing instance from `AUTH_METHOD=standard` to `oidc` does
  not auto-link accounts by email; sign in once as an admin under
  `standard` first if you need to preserve existing users.
