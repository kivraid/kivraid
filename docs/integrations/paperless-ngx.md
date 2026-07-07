# Paperless-ngx

Paperless-ngx signs in through **django-allauth's OpenID Connect
provider**, configured with the `PAPERLESS_SOCIALACCOUNT_PROVIDERS` JSON
setting. Replace `sso.example.com` with your Kivraid `base_url` and
`paperless.example.com` with your Paperless-ngx URL throughout.

The examples below use `kivraid` as the provider ID. It appears in the
callback URL, so whatever you choose here must match on both sides.

## In Kivraid

Register an OpenID Connect application (see
[the generic reference](README.md#register-an-application-in-kivraid)):

- **Redirect URI:** `https://paperless.example.com/accounts/oidc/kivraid/login/callback/`
- **Client type:** Confidential

Copy the client ID and secret.

## In Paperless-ngx

OIDC is not enabled by default. Add the allauth OpenID Connect app and
the provider configuration through environment variables (or the
matching lines in `paperless.conf`):

```bash
PAPERLESS_APPS="allauth.socialaccount.providers.openid_connect"
PAPERLESS_SOCIALACCOUNT_PROVIDERS='{
  "openid_connect": {
    "OAUTH_PKCE_ENABLED": true,
    "APPS": [
      {
        "provider_id": "kivraid",
        "name": "Kivraid",
        "client_id": "<client id from Kivraid>",
        "secret": "<client secret from Kivraid>",
        "settings": {
          "server_url": "https://sso.example.com",
          "token_auth_method": "client_secret_basic"
        }
      }
    ],
    "SCOPE": ["openid", "profile", "email", "groups"]
  }
}'
```

Notes on the values:

- `server_url` is the Kivraid issuer (the `base_url`, no trailing
  slash). allauth appends `/.well-known/openid-configuration` and
  discovers the authorization, token, userinfo and JWKS endpoints from
  there, so you do not list them individually.
- `OAUTH_PKCE_ENABLED: true` turns on PKCE (`S256`), which Kivraid
  supports.
- `token_auth_method` is optional; `client_secret_basic` and
  `client_secret_post` both work with Kivraid.

You do not map claims by hand. The allauth OpenID Connect provider
already reads the username from `preferred_username`, the email from
`email`, and the display name from `name`, and it links the account on
the stable `sub` UUID (its `uid_field`). This is exactly the mapping you
want: the username comes from `preferred_username`, not from the opaque
`sub`.

To let first-time users through, allow signup from the SSO identity:

```bash
PAPERLESS_SOCIAL_AUTO_SIGNUP=true
```

Once SSO works you can hide the local login form:

```bash
PAPERLESS_DISABLE_REGULAR_LOGIN=true
PAPERLESS_REDIRECT_LOGIN_TO_SSO=true
```

`PAPERLESS_DISABLE_REGULAR_LOGIN` does not block the Django admin
(`/admin/`) or local API credentials; block `/admin/` at your reverse
proxy if you need to close that path.

## Roles from groups

Paperless-ngx can sync the Kivraid `groups` claim to its own groups:

```bash
PAPERLESS_SOCIAL_ACCOUNT_SYNC_GROUPS=true
```

With this on, a user is added to (and removed from) Paperless groups on
each SSO login to match their Kivraid group membership. The groups must
already exist in Paperless-ngx under **Settings → Users & Groups** with
names that match the Kivraid group names exactly; Paperless assigns the
permissions you attach to those groups. The `groups` scope must be
present in the provider `SCOPE` list above for the claim to be sent.

To keep users out of Paperless entirely unless they belong to a group,
bind the groups under the application's **Access** section in Kivraid.

## Notes

- Single sign-out: logging out of Paperless-ngx ends the Paperless
  session only. To also end the Kivraid session, send the user to
  `https://sso.example.com/end_session` (Kivraid's RP-initiated logout
  endpoint); Paperless has no built-in setting for an upstream logout
  URL.
- The redirect URI in Kivraid must match
  `https://paperless.example.com/accounts/oidc/kivraid/login/callback/`
  exactly, **including the trailing slash** and the `provider_id`
  segment (`kivraid` here). A mismatched provider ID or a missing slash
  is the most common failure.
- Paperless builds the callback URL with `https` by default
  (`PAPERLESS_ACCOUNT_DEFAULT_HTTP_PROTOCOL`). Behind a reverse proxy,
  make sure Paperless knows its external URL (`PAPERLESS_URL`) so the
  callback host matches what you registered in Kivraid.
- `PAPERLESS_SOCIALACCOUNT_PROVIDERS` is a single JSON value; keep it on
  one logical line or quote it as shown so the shell or Docker env file
  does not split it.
- Setting names can drift between releases. If a key is not recognised,
  check the [Paperless-ngx configuration
  reference](https://docs.paperless-ngx.com/configuration/) for your
  version.
