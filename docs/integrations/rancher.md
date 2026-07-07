# Rancher

Rancher signs in through its **Generic OIDC** auth provider (Rancher v2.9+).
Replace `sso.example.com` with your Kivraid `base_url` and
`rancher.example.com` with your Rancher server URL throughout.

## In Kivraid

Register an OpenID Connect application (see
[the generic reference](README.md#register-an-application-in-kivraid)):

- **Redirect URI:** `https://rancher.example.com/verify-auth`
- **Client type:** Confidential

Copy the client ID and secret.

## In Rancher

**☰ → Users & Authentication → Auth Provider → Generic OIDC.**

Fill in the *Configure an OIDC account* form:

- **Client ID:** from Kivraid
- **Client Secret:** the client secret from Kivraid
- **Private Key / Certificate:** leave empty (only needed to present a client
  key pair to the IdP; Kivraid does not require one)
- **Rancher URL:** `https://rancher.example.com`
- **Issuer:** `https://sso.example.com`
- **Auth Endpoint:** `https://sso.example.com/authorize`
- **Endpoints:** leave on *Generate*. Rancher reads the rest of the endpoints
  (token, userinfo, JWKS) from Kivraid's
  `https://sso.example.com/.well-known/openid-configuration`. If you switch to
  *Specify (advanced)*, the values are token `https://sso.example.com/oauth/token`,
  userinfo `https://sso.example.com/userinfo`, JWKS `https://sso.example.com/keys`.
- **Custom Name Claim:** `name`
- **Custom Email Claim:** `email`
- **Custom Groups Claim:** `groups`
- **Enable PKCE (S256):** optional; Kivraid supports it.

Click **Enable**. Rancher opens a Kivraid login in a popup to complete the
first sign-in and confirm the configuration.

Rancher keys each account on the opaque `sub` internally and shows the
**Custom Name Claim** in the UI, so leaving it at `name` gives readable
display names instead of the `sub` UUID.

## Roles from groups

Rancher reads the **Custom Groups Claim** (`groups`) for RBAC. Kivraid returns
it as a JSON array of group names, which is the format Rancher expects. Once
sign-in works, grant access under **Users & Authentication → Role Templates**
and the cluster/project **Members** tabs by adding a *group* principal — the
Kivraid group name — rather than individual users, so membership follows the
`groups` claim.

To restrict who may sign in to Rancher at all, bind the allowed groups under
the application's **Access** section in Kivraid.

## Notes

- Single logout: under the provider's **Log Out** behavior, choose to also log
  out of the IdP and set the **End Session Endpoint** to
  `https://sso.example.com/end_session` to end the Kivraid session on logout.
- Redirect-URI pitfall: the value registered in Kivraid must be exactly
  `https://rancher.example.com/verify-auth` (scheme, host, and the
  `/verify-auth` path). A mismatch here is the usual cause of a login that
  fails after the Kivraid prompt, and Rancher's error text can be misleading.
- The `groups` claim requires the `groups` scope. The Generic OIDC form does
  not expose a scopes field; if group-based access does not work, the scope
  list is editable on the auth-config resource (`kubectl edit oidcconfig` /
  the auth config via the API).
- Rancher also ships a dedicated **Keycloak (OIDC)** provider that uses the
  same `/verify-auth` redirect, but it is tuned for Keycloak (it asks for a
  Keycloak URL and realm and expects Keycloak service-account roles and
  mappers). Use **Generic OIDC** for Kivraid.
- UI labels drift between Rancher releases; the field names above match
  current v2.x. Older versions may not offer Generic OIDC at all.
