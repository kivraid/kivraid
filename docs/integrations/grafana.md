# Grafana

Grafana signs in through its **Generic OAuth** integration. Replace
`sso.example.com` with your Kivraid `base_url` and
`grafana.example.com` with your Grafana URL throughout.

## In Kivraid

Register an OpenID Connect application (see
[the generic reference](README.md#register-an-application-in-kivraid)):

- **Redirect URI:** `https://grafana.example.com/login/generic_oauth`
- **Client type:** Confidential

Copy the client ID and secret.

## In Grafana

Set these in `grafana.ini` (or the matching `GF_AUTH_GENERIC_OAUTH_*`
environment variables):

```ini
[auth.generic_oauth]
enabled = true
name = Kivraid
client_id = <client id from Kivraid>
client_secret = <client secret from Kivraid>
scopes = openid profile email groups
auth_url = https://sso.example.com/authorize
token_url = https://sso.example.com/oauth/token
api_url = https://sso.example.com/userinfo
use_pkce = true
login_attribute_path = preferred_username
email_attribute_path = email
name_attribute_path = name
```

`login_attribute_path = preferred_username` is the important line: Grafana
would otherwise fall back to the opaque `sub` UUID as the username.

## Roles from groups

Map Kivraid groups to Grafana roles with `role_attribute_path` (a JMESPath
over the token claims). For example, members of a `grafana-admins` group
become admins, everyone else a viewer:

```ini
role_attribute_path = contains(groups[*], 'grafana-admins') && 'Admin' || contains(groups[*], 'grafana-editors') && 'Editor' || 'Viewer'
```

Create those groups in **Admin → Groups** and add members. To keep users
out of Grafana entirely unless they are in a group, set
`role_attribute_strict = true` and bind the groups under the
application's **Access** section in Kivraid.

## Notes

- Single sign-out: set `signout_redirect_url = https://sso.example.com/end_session`
  to end the Kivraid session when logging out of Grafana.
- If sign-in fails with a redirect-URI error, the value in Kivraid must
  match `https://grafana.example.com/login/generic_oauth` exactly,
  including scheme and host as Grafana sees them behind your proxy
  (check `root_url` in Grafana).
