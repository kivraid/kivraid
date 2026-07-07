# Weblate

Weblate signs in through its generic **OpenID Connect** backend, provided by
[python-social-auth](https://python-social-auth.readthedocs.io/en/latest/backends/oidc.html)
(available since Weblate 4.13-1). Replace `sso.example.com` with your Kivraid
`base_url` and `weblate.example.com` with your Weblate URL throughout.

## In Kivraid

Register an OpenID Connect application (see
[the generic reference](README.md#register-an-application-in-kivraid)):

- **Redirect URI:** `https://weblate.example.com/accounts/complete/oidc/`
- **Client type:** Confidential

Copy the client ID and secret.

## In Weblate

The generic backend is named `oidc`. Enable it in `settings.py` by adding it to
`AUTHENTICATION_BACKENDS` (always keep `weblate.accounts.auth.WeblateUserBackend`,
which Weblate needs for core functionality) and setting the endpoint and
credentials:

```python
AUTHENTICATION_BACKENDS = (
    "social_core.backends.open_id_connect.OpenIdConnectAuth",
    "weblate.accounts.auth.WeblateUserBackend",
)

# Kivraid OpenID Connect. OIDC_ENDPOINT is the issuer, without the
# /.well-known/openid-configuration suffix; Weblate appends it to discover
# the endpoints, JWKS and scopes automatically.
SOCIAL_AUTH_OIDC_OIDC_ENDPOINT = "https://sso.example.com"
SOCIAL_AUTH_OIDC_KEY = "<client id from Kivraid>"
SOCIAL_AUTH_OIDC_SECRET = "<client secret from Kivraid>"
SOCIAL_AUTH_OIDC_USERNAME_KEY = "preferred_username"
```

`SOCIAL_AUTH_OIDC_USERNAME_KEY = "preferred_username"` is the important line.
The backend uses the `sub` claim as the internal identifier, but the username
it shows must come from `preferred_username`; otherwise every account is
labelled with the opaque `sub` UUID. (`preferred_username` is in fact the
backend's default, but set it explicitly so the behaviour is not left to a
version default.) Email and display name are read from the `email` and `name`
claims automatically. The backend requests the `openid`, `profile` and `email`
scopes.

### Docker

The official Docker image exposes the same settings as environment variables
(also since 4.13-1):

```yaml
environment:
  WEBLATE_SOCIAL_AUTH_OIDC_OIDC_ENDPOINT: https://sso.example.com
  WEBLATE_SOCIAL_AUTH_OIDC_KEY: <client id from Kivraid>
  WEBLATE_SOCIAL_AUTH_OIDC_SECRET: <client secret from Kivraid>
  WEBLATE_SOCIAL_AUTH_OIDC_USERNAME_KEY: preferred_username
  WEBLATE_SOCIAL_AUTH_OIDC_TITLE: Kivraid          # optional button label
```

## Teams and roles

Weblate's generic OIDC backend does not map the `groups` claim to Weblate teams
or permissions — it only consumes `sub`, `preferred_username`, `email` and
`name`. Manage authorization inside Weblate under **Manage → Users** and its
teams, or use automatic team assignment rules that match on the user's email.
There is no need to request the `groups` scope from Kivraid for this integration.

## Notes

- **Single logout:** logging out of Weblate clears only the local Weblate
  session; the backend does not call Kivraid's `/end_session` endpoint, so the
  Kivraid session survives. To end it, send users to
  `https://sso.example.com/end_session` after they log out.
- **Redirect URI must match exactly.** Kivraid compares redirect URIs verbatim,
  including the trailing slash: the value must be
  `https://weblate.example.com/accounts/complete/oidc/` as Weblate sees its own
  host behind your proxy. Set `WEBLATE_SITE_DOMAIN` (or `SITE_DOMAIN` in
  `settings.py`) to the public host so Weblate builds the callback URL correctly.
- The backend's own environment/setting name doubles the word `OIDC`
  (`SOCIAL_AUTH_OIDC_OIDC_ENDPOINT`) — that is correct, not a typo.
