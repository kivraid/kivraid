# SonarQube

Self-hosted SonarQube (SonarQube Server and Community Build) has **no
native OpenID Connect support** — its only built-in SSO is SAML. OIDC is
provided by the third-party community plugin
[`sonar-auth-oidc`](https://github.com/sonar-auth-oidc/sonar-auth-oidc)
(maintained by vaulttec, not by SonarSource). This guide covers that
plugin. Replace `sso.example.com` with your Kivraid `base_url` and
`sonarqube.example.com` with your SonarQube URL throughout.

> Native OIDC exists only in **SonarQube Cloud** (with an Enterprise
> licence). If you would rather not run a third-party plugin, protect
> SonarQube with Kivraid [forward auth](../forward-auth.md) instead.

## Install the plugin

Install `sonar-auth-oidc` before configuring anything, either from
**Administration → Marketplace** (search for "OpenID Connect"), or by
dropping the release jar into `$SONARQUBE_HOME/extensions/plugins/` and
restarting SonarQube. Confirm your SonarQube version is on the plugin's
compatibility list (it has been tested up to SonarQube 9.9.x).

Also set the server base URL (with no trailing slash) under
**Administration → Configuration → General → Server base URL**, or
`sonar.core.serverBaseURL` in `sonar.properties` — the plugin builds the
callback from it, and redirects break if it is wrong.

## In Kivraid

Register an OpenID Connect application (see
[the generic reference](README.md#register-an-application-in-kivraid)):

- **Redirect URI:** `https://sonarqube.example.com/oauth2/callback/oidc`
- **Client type:** Confidential

Copy the client ID and secret.

## In SonarQube

Go to **Administration → Configuration → General Settings → Security →
OpenID Connect**. The fields map to these plugin properties:

| Setting | Property key | Value |
| --- | --- | --- |
| Enabled | `sonar.auth.oidc.enabled` | `true` |
| Issuer URI | `sonar.auth.oidc.issuerUri` | `https://sso.example.com` |
| Client ID | `sonar.auth.oidc.clientId.secured` | *(client ID from Kivraid)* |
| Client secret | `sonar.auth.oidc.clientSecret.secured` | *(client secret from Kivraid)* |
| Additional scopes | `sonar.auth.oidc.scopes` | `openid email profile groups` |
| ID token signature algorithm | `sonar.auth.oidc.idTokenSigAlg` | `ES256` |
| Login strategy | `sonar.auth.oidc.loginStrategy` | `Preferred username` |
| Allow users to sign up | `sonar.auth.oidc.allowUsersToSignUp` | `true` |

The **Issuer URI** is the Kivraid base URL itself (the plugin appends
`/.well-known/openid-configuration` to discover the endpoints); do not
add that suffix yourself.

Set **ID token signature algorithm** to match your Kivraid instance —
`ES256` by default, or `RS256` if you switched it. A mismatch makes every
login fail signature verification.

**Login strategy** `Preferred username` is the important choice: it uses
the `preferred_username` claim (e.g. `amelia`) as the SonarQube login.
Leaving it on `Unique` would derive the login from the opaque `sub`
UUID.

## Roles from groups

The plugin can sync SonarQube group membership from a claim. Enable it:

| Setting | Property key | Value |
| --- | --- | --- |
| Sync groups | `sonar.auth.oidc.groupsSync` | `true` |
| Groups claim name | `sonar.auth.oidc.groupsSync.claimName` | `groups` |

Kivraid emits the `groups` claim (an array of group names) when the
`groups` scope is requested, which matches the JSON string-array format
the plugin expects. Create matching groups in SonarQube under
**Administration → Security → Groups** and grant them permissions there;
membership is then driven by Kivraid on each login. To keep everyone
else out, bind the allowed groups under the application's **Access**
section in Kivraid.

## Notes

- **No single logout.** The plugin signs users out of SonarQube only,
  not out of Kivraid; the Kivraid session at
  `https://sso.example.com/end_session` is untouched. There is no
  RP-initiated logout setting in the plugin.
- **Exact-match redirect URI.** The value registered in Kivraid must be
  exactly `https://sonarqube.example.com/oauth2/callback/oidc`, matching
  the scheme and host SonarQube sees behind your reverse proxy. If it
  does not match the server base URL, login fails with a redirect error.
- **`.secured` properties.** The client ID and secret keys carry a
  `.secured` suffix and are normally entered through the UI rather than
  `sonar.properties`.
- **UI labels may drift** between plugin releases; match by the property
  keys above if a field name differs in your version.
