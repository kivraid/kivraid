# Opengist

Opengist signs in through its built-in **OpenID Connect** provider, which
reads the Kivraid discovery document and derives every endpoint from it.
Replace `sso.example.com` with your Kivraid `base_url` and
`opengist.example.com` with your Opengist URL throughout.

## In Kivraid

Register an OpenID Connect application (see
[the generic reference](README.md#register-an-application-in-kivraid)):

- **Redirect URI:** `https://opengist.example.com/oauth/openid-connect/callback`
- **Client type:** Confidential

Copy the client ID and secret.

## In Opengist

Configure the `oidc` block in Opengist's YAML config file (or the matching
`OG_OIDC_*` environment variables). Opengist discovers the authorization,
token, userinfo and JWKS endpoints from the discovery URL, so you only
supply the discovery URL, client ID and secret:

```yaml
oidc:
  provider-name: Kivraid
  client-key: <client id from Kivraid>
  secret: <client secret from Kivraid>
  discovery-url: https://sso.example.com/.well-known/openid-configuration
```

The equivalent environment variables are:

```sh
OG_OIDC_PROVIDER_NAME=Kivraid
OG_OIDC_CLIENT_KEY=<client id from Kivraid>
OG_OIDC_SECRET=<client secret from Kivraid>
OG_OIDC_DISCOVERY_URL=https://sso.example.com/.well-known/openid-configuration
```

Also make sure Opengist's `external-url` is set to `https://opengist.example.com`
so the callback URL it builds matches the redirect URI registered above.

Opengist requests the `openid`, `email`, `profile` and `groups` scopes and
authenticates to the token endpoint with `client_secret_post`, which Kivraid
supports. It maps the account from the standard OIDC claims automatically;
it does not expose a key to choose which claim becomes the username, so the
provider's `preferred_username` / `email` / `name` claims are consumed as-is.

## Roles from groups

Opengist can grant admin rights from the Kivraid `groups` claim. Point it at
the claim and name the group whose members become admins:

```yaml
oidc:
  group-claim-name: groups
  admin-group: opengist-admins
```

Or as environment variables:

```sh
OG_OIDC_GROUP_CLAIM_NAME=groups
OG_OIDC_ADMIN_GROUP=opengist-admins
```

Admin status is re-evaluated on every login, so removing a user from
`opengist-admins` in Kivraid revokes their admin rights at the next sign-in.
Create the group in **Admin → Groups** and add members. Note the `groups`
scope must be granted (it is, per the scope list above) for this claim to be
present. To keep users out of Opengist entirely unless they belong to a
group, bind the group under the application's **Access** section in Kivraid.

## Notes

- Opengist does not implement RP-initiated logout against the provider:
  signing out of Opengist ends only the local Opengist session, not the
  Kivraid session. Browse to `https://sso.example.com/end_session` to end
  the Kivraid session as well.
- If sign-in fails with a redirect-URI error, the value in Kivraid must
  match `https://opengist.example.com/oauth/openid-connect/callback` exactly.
  Opengist derives that URL from its `external-url` setting, so a wrong or
  missing `external-url` (common behind a reverse proxy) is the usual cause.
- Config key names are current as of Opengist's OAuth providers documentation;
  if the labels drift in a newer release, check the `oidc` section of the
  official config reference.
