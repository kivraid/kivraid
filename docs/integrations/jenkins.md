# Jenkins

Jenkins signs in through the **OpenID Connect Authentication** plugin
(`oic-auth`), which is not bundled — install it first from **Manage Jenkins
→ Plugins → Available plugins** (search for "OpenID Connect
Authentication") and restart. Replace `sso.example.com` with your Kivraid
`base_url` and `jenkins.example.com` with your Jenkins URL throughout.

## In Kivraid

Register an OpenID Connect application (see
[the generic reference](README.md#register-an-application-in-kivraid)):

- **Redirect URI:** `https://jenkins.example.com/securityRealm/finishLogin`
- **Client type:** Confidential

Copy the client ID and secret.

## In Jenkins

**Manage Jenkins → Security**, then under **Security Realm** select
**Login with Openid Connect**.

- **Client id:** the client ID from Kivraid
- **Client secret:** the client secret from Kivraid
- **Configuration mode:** *Automatic configuration* (Discovery), with
  **Well-known configuration endpoint:**
  `https://sso.example.com/.well-known/openid-configuration`
- **Scopes** (under Advanced, *Override scopes*):
  `openid profile email groups`

Then expand the user-claim fields (labelled *User fields* / *Advanced*) and
set the claim mappings. Jenkins defaults the username to `sub`, so this
mapping is the important part — without it every user shows up as an opaque
UUID:

- **User name field** (`userNameField`): `preferred_username`
- **Full name field** (`fullNameFieldName`): `name`
- **Email field** (`emailFieldName`): `email`
- **Groups field** (`groupsFieldName`): `groups`

Each field accepts a JMESPath expression over the ID token / userinfo
claims; the bare claim name shown above is sufficient here.

## Roles from groups

The plugin only populates group memberships from the `groups` claim — it
does not assign permissions itself. Combine it with an authorization
strategy (Jenkins' built-in **Matrix-based security** / **Project-based
Matrix Authorization Strategy**, or the **Role-based Authorization
Strategy** plugin) and grant permissions to the Kivraid group names as they
arrive in the `groups` claim (e.g. `jenkins-admins`).

Create those groups in **Admin → Groups** in Kivraid and add members. To
keep users out of Jenkins entirely unless they are in a group, bind the
groups under the application's **Access** section in Kivraid.

## Notes

- Single logout: enable **Logout from OpenID Provider**
  (`logoutFromOpenidProvider`) so logging out of Jenkins also ends the
  Kivraid session. The plugin uses the discovery document's `end_session`
  endpoint; set the post-logout redirect URL if you want users returned to
  a specific page.
- Lock yourself out safely: Jenkins keeps the security realm change until
  you save. If OIDC login fails, you can recover through
  `<JENKINS_HOME>/config.xml` (or the standard disable-security recovery)
  rather than the UI.
- A redirect-URI error means the value in Kivraid must match
  `https://jenkins.example.com/securityRealm/finishLogin` exactly,
  including the scheme and host as Jenkins sees them behind your proxy
  (set the correct **Jenkins URL** under **Manage Jenkins → System**).
- UI labels drift between plugin releases; the JCasC field names in
  parentheses above (`userNameField`, `groupsFieldName`, …) are stable if
  the on-screen label differs from what you see.
