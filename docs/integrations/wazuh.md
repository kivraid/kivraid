# Wazuh

The Wazuh dashboard is built on OpenSearch Dashboards, so it signs in
through the **OpenSearch security plugin's OpenID Connect** backend: the
Wazuh indexer validates the token and the dashboard drives the login
flow. Replace `sso.example.com` with your Kivraid `base_url` and
`wazuh.example.com` with your Wazuh dashboard URL throughout.

## In Kivraid

Register an OpenID Connect application (see
[the generic reference](README.md#register-an-application-in-kivraid)):

- **Redirect URI:** `https://wazuh.example.com/auth/openid/login`
- **Client type:** Confidential

Copy the client ID and secret. OpenSearch always sends the client secret
on the token request, so a Public/PKCE client will not work here.

## In Wazuh

OpenID Connect is configured in two files. There is nothing to install —
it ships with the security plugin.

### 1. Wazuh indexer — `/etc/wazuh-indexer/opensearch-security/config.yml`

Add an `openid_auth_domain` under `authc:`:

```yaml
openid_auth_domain:
  http_enabled: true
  transport_enabled: true
  order: 1
  http_authenticator:
    type: openid
    challenge: false
    config:
      subject_key: preferred_username
      roles_key: groups
      openid_connect_url: https://sso.example.com/.well-known/openid-configuration
  authentication_backend:
    type: noop
```

- `subject_key: preferred_username` sets the Wazuh username to the login
  name (e.g. `amelia`). Do not use `sub` — it is an opaque UUID and every
  account would show as a UUID.
- `roles_key: groups` reads Kivraid's `groups` claim. Kivraid emits
  `groups`, not `roles`, so this key must be `groups` for role mapping to
  work.

Apply the change by running `securityadmin.sh` (edits to `config.yml`
are only loaded into the cluster by this script, not by restarting the
service):

```sh
export JAVA_HOME=/usr/share/wazuh-indexer/jdk
bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
  -f /etc/wazuh-indexer/opensearch-security/config.yml -t config \
  -cacert /etc/wazuh-indexer/certs/root-ca.pem \
  -cert /etc/wazuh-indexer/certs/admin.pem \
  -key /etc/wazuh-indexer/certs/admin-key.pem \
  -icl -nhnv -h 127.0.0.1
```

(Adjust the certificate paths to your install.)

### 2. Wazuh dashboard — `/etc/wazuh-dashboard/opensearch_dashboards.yml`

```yaml
opensearch_security.auth.type: "openid"
opensearch_security.openid.connect_url: "https://sso.example.com/.well-known/openid-configuration"
opensearch_security.openid.client_id: "<client id from Kivraid>"
opensearch_security.openid.client_secret: "<client secret from Kivraid>"
opensearch_security.openid.base_redirect_url: "https://wazuh.example.com"
opensearch_security.openid.scope: "openid profile email groups"
opensearch_security.openid.logout_url: "https://sso.example.com/end_session"
```

`base_redirect_url` builds the callback the dashboard sends to Kivraid;
with the value above it resolves to `https://wazuh.example.com/auth/openid/login`,
which must match the redirect URI you registered. Restart the dashboard
after editing this file.

## Roles from groups

Wazuh authorizes through OpenSearch **backend roles**: the values in the
`groups` claim arrive as backend roles, which you map to Wazuh/OpenSearch
roles in `/etc/wazuh-indexer/opensearch-security/roles_mapping.yml`. For
example, to make members of a Kivraid `wazuh-admins` group full
administrators, add the group as a `backend_role` under the built-in
`all_access` (and Wazuh's `admin`) mapping:

```yaml
all_access:
  reserved: false
  backend_roles:
    - "admin"
    - "wazuh-admins"
  description: "Maps the Kivraid wazuh-admins group to full access"
```

Reload `roles_mapping.yml` with the same `securityadmin.sh` invocation as
above but `-f .../roles_mapping.yml -t rolesmapping`. Create the group in
Kivraid under **Admin → Groups**, add members, and to keep everyone else
out of Wazuh entirely, bind the allowed groups under the application's
**Access** section in Kivraid.

## Notes

- **Single sign-out:** `opensearch_security.openid.logout_url` above ends
  the Kivraid session (`/end_session`) when a user logs out of the
  dashboard.
- **Redirect-URI exact match:** an authentication error after the Kivraid
  prompt almost always means the registered URI does not match
  `https://wazuh.example.com/auth/openid/login` exactly — including scheme
  and host as the dashboard sees itself. If the dashboard runs under a
  `server.basePath`, that path is part of the callback and must be in the
  registered URI too.
- Kivraid signs ID tokens with ES256. The security plugin fetches the
  matching key from the JWKS endpoint advertised in the discovery
  document (Kivraid's `/keys`), so no signing algorithm needs to be
  configured on the Wazuh side.
- Wazuh's own SSO documentation currently leads with SAML; the OpenID
  Connect keys shown here come from the underlying OpenSearch security
  plugin and the `opensearch_security.*` names are stable across recent
  Wazuh 4.x releases. If a key is rejected after an upgrade, check the
  security plugin's OpenID Connect reference for your version.
