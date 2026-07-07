# Harbor

Harbor signs in through its built-in **OIDC** authentication mode, using
Kivraid's discovery document to find the endpoints. Replace
`sso.example.com` with your Kivraid `base_url` and `harbor.example.com`
with your Harbor URL throughout.

## In Kivraid

Register an OpenID Connect application (see
[the generic reference](README.md#register-an-application-in-kivraid)):

- **Redirect URI:** `https://harbor.example.com/c/oidc/callback`
- **Client type:** Confidential

Copy the client ID and secret.

## In Harbor

Sign in as an admin and go to **Administration → Configuration →
Authentication**. Set **Auth Mode** to **OIDC** (this can only be changed
while no non-admin users exist) and fill in:

| Field | Value |
| --- | --- |
| OIDC Provider Name | `Kivraid` (label shown on the login button) |
| OIDC Endpoint | `https://sso.example.com` |
| OIDC Client ID | *client ID from Kivraid* |
| OIDC Client Secret | *client secret from Kivraid* |
| Group Claim Name | `groups` |
| OIDC Scope | `openid,profile,email,groups,offline_access` |
| Username Claim | `preferred_username` |
| Verify Certificate | checked (uncheck only for self-signed TLS) |
| Automatic onboarding | checked |

Notes on the values:

- **OIDC Endpoint** is the issuer only. Harbor appends
  `/.well-known/openid-configuration` itself to discover the authorization,
  token, userinfo, and JWKS endpoints.
- **OIDC Scope** is **comma-separated** (not space-separated). Keep
  `offline_access` so Harbor can obtain a refresh token; drop `groups` only
  if you are not mapping groups.
- **Username Claim** must be `preferred_username`. Left blank, Harbor falls
  back to the opaque `sub` UUID and every account shows up as a UUID.

Click **Test OIDC Server** to confirm the endpoint, then **Save**.

## Roles from groups

Harbor reads the `groups` claim (via **Group Claim Name** above) and
onboards each value as a Harbor group. Grant those groups access under
**Projects → *project* → Members**, adding the group as a member with a
role (Guest, Developer, Maintainer, Project Admin).

To make a Kivraid group into Harbor system administrators, set the **OIDC
Admin Group** field on the same configuration page to that group's name
(only one admin group is supported). Members of it become Harbor admins on
their next login. An optional **OIDC Group Filter** (a regular expression)
restricts which claim values Harbor imports.

Create these groups in **Admin → Groups** in Kivraid and add members. To
keep users out of Harbor entirely unless they belong to a group, bind the
groups under the application's **Access** section in Kivraid.

## Notes

- **CLI / `docker login`:** OIDC users cannot push or pull with their
  Kivraid password. Each user must open **User Profile** in Harbor and
  generate a **CLI secret**, then use that as the password for
  `docker login harbor.example.com`.
- **Single logout:** signing out of Harbor clears only the Harbor session;
  it does not call Kivraid's `/end_session`, so the Kivraid session stays
  open. Log out of Kivraid separately to end SSO.
- **Redirect URI:** it must match `https://harbor.example.com/c/oidc/callback`
  exactly. Harbor prints the expected value at the bottom of the OIDC
  configuration page — copy it from there and paste it into Kivraid,
  matching the scheme and host as Harbor sees them behind your proxy.
- Field labels above are from Harbor 2.x; older releases lack the OIDC
  Admin Group and Group Filter fields.
</content>
</invoke>
