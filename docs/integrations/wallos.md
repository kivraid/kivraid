# Wallos

Wallos signs in through its built-in **OIDC** login, configured from the
Admin panel. Replace `sso.example.com` with your Kivraid `base_url` and
`wallos.example.com` with your Wallos URL throughout.

## In Kivraid

Register an OpenID Connect application (see
[the generic reference](README.md#register-an-application-in-kivraid)):

- **Redirect URI:** `https://wallos.example.com/index.php`
- **Client type:** Confidential

Copy the client ID and secret.

## In Wallos

Sign in as an administrator, open **Admin** and scroll to the OIDC/OAuth
settings. Enable OIDC and fill in:

| Field | Value |
|-------|-------|
| Provider Name | `Kivraid` |
| Client ID | *client ID from Kivraid* |
| Client Secret | *client secret from Kivraid* |
| Auth URL | `https://sso.example.com/authorize` |
| Token URL | `https://sso.example.com/oauth/token` |
| User Info URL | `https://sso.example.com/userinfo` |
| Redirect URL | `https://wallos.example.com/index.php` |
| Logout URL | `https://sso.example.com/end_session` |
| User Identifier Field | `preferred_username` |
| Scopes | `openid profile email` |

`User Identifier Field` defaults to `sub`. Change it to
`preferred_username`, or Wallos will use Kivraid's opaque UUID as the
account name. Wallos authenticates to the token endpoint with
`client_secret_post`, which Kivraid supports.

If you want Wallos to provision accounts on first sign-in, enable
**Create User Automatically** in the same panel.

## Roles from groups

Wallos has no group-to-role mapping: all accounts are regular users
(the first/admin account aside), so the Kivraid `groups` claim is not
consumed. To restrict who may sign in, bind the allowed groups under the
application's **Access** section in Kivraid.

## Notes

- Single sign-out: the optional **Logout URL** above points Wallos at
  Kivraid's `/end_session` endpoint so logging out of Wallos also ends the
  Kivraid session.
- If sign-in fails with a redirect-URI error, the value in Kivraid must
  match `https://wallos.example.com/index.php` exactly, including scheme
  and host as Wallos sees them behind your proxy.
- Field labels may drift between Wallos releases; match by meaning if a
  label differs from the table above.
