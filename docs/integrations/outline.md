# Outline

Outline signs in through its built-in **OpenID Connect** provider,
configured entirely through environment variables. Replace
`sso.example.com` with your Kivraid `base_url` and
`outline.example.com` with your Outline URL throughout.

## In Kivraid

Register an OpenID Connect application (see
[the generic reference](README.md#register-an-application-in-kivraid)):

- **Redirect URI:** `https://outline.example.com/auth/oidc.callback`
- **Client type:** Confidential

Copy the client ID and secret.

## In Outline

Set these environment variables (in `docker-compose.yml`, the
`.env` file, or however you inject config):

```sh
OIDC_CLIENT_ID=<client id from Kivraid>
OIDC_CLIENT_SECRET=<client secret from Kivraid>
OIDC_AUTH_URI=https://sso.example.com/authorize
OIDC_TOKEN_URI=https://sso.example.com/oauth/token
OIDC_USERINFO_URI=https://sso.example.com/userinfo
OIDC_USERNAME_CLAIM=preferred_username
OIDC_DISPLAY_NAME=Kivraid
OIDC_SCOPES=openid offline_access profile email
OIDC_LOGOUT_URI=https://sso.example.com/end_session
```

`OIDC_SCOPES` **must** include `offline_access`: Outline requests a
refresh token, and sign-in fails if the provider was never asked to
issue one. Kivraid supports the `offline_access` scope.

`OIDC_USERNAME_CLAIM=preferred_username` is the important line. It is
Outline's default, but set it explicitly so the username is the readable
login name (e.g. `amelia`) rather than the opaque `sub` UUID. Outline
reads the display name from the `name` claim and the account email from
the `email` claim automatically; there are no separate mapping
variables for those.

Instead of the three explicit URIs above you can let Outline discover
them, by setting only `OIDC_ISSUER_URL=https://sso.example.com`
alongside the client ID and secret. Keep `OIDC_SCOPES` set either way.

## Roles from groups

Self-hosted Outline does not map an OIDC `groups` claim to Outline
groups or roles — this has been requested upstream but is slated to be
an enterprise/cloud feature, so there is no config key for it here.
Manage Outline groups and admin rights inside Outline. To control who
can sign in at all, bind the allowed Kivraid groups under the
application's **Access** section in Kivraid.

## Notes

- Single sign-out: `OIDC_LOGOUT_URI=https://sso.example.com/end_session`
  ends the Kivraid session on logout. Outline warns that without this
  (or `OIDC_DISABLE_REDIRECT`) users cannot log out cleanly, because it
  otherwise sends them straight back to the provider and back in.
- A redirect-URI error means the value in Kivraid must match
  `https://outline.example.com/auth/oidc.callback` exactly — no trailing
  slash, and the scheme and host as Outline sees them behind your proxy
  (`URL` in Outline's environment).
- Env var names are stable across recent Outline releases; if a variable
  is ignored, confirm your version documents it on the Outline OIDC
  hosting page.
