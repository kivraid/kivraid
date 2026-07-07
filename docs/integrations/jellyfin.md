# Jellyfin

Jellyfin has **no native OpenID Connect support**. SSO is provided by an
**unofficial community plugin**, the [SSO-Auth plugin by 9p4](https://github.com/9p4/jellyfin-plugin-sso),
which adds an OIDC login button to the Jellyfin sign-in page. This guide
covers that plugin. Replace `sso.example.com` with your Kivraid `base_url`
and `jellyfin.example.com` with your Jellyfin URL throughout.

## In Kivraid

Register an OpenID Connect application (see
[the generic reference](README.md#register-an-application-in-kivraid)):

- **Redirect URI:** `https://jellyfin.example.com/sso/OID/redirect/kivraid`
  (the last path segment is the provider name you choose in the plugin;
  this guide uses `kivraid` — it must match exactly)
- **Client type:** Confidential

Copy the client ID and secret.

## In Jellyfin

### Install the plugin

The plugin is not in the default catalog, so add its repository first:

1. **Dashboard → Plugins → Repositories → Add** and enter the manifest URL:

   ```
   https://raw.githubusercontent.com/9p4/jellyfin-plugin-sso/manifest-release/manifest.json
   ```

2. **Dashboard → Plugins → Catalog**, install **SSO-Auth**, then restart
   Jellyfin.

### Configure the OID provider

Open the plugin at **Dashboard → Plugins → SSO-Auth** and add an **OID
Provider**. Name it `kivraid` (this name is the last segment of the
redirect URI above). Set:

| Field | Value |
|-------|-------|
| **OID Endpoint** | `https://sso.example.com` (the issuer; the plugin appends `/.well-known/openid-configuration`) |
| **OpenID Client ID** | client ID from Kivraid |
| **OID Secret** | client secret from Kivraid |
| **Enabled** | on |
| **Scopes** | `profile`, `email`, `groups` (`openid` is always sent) |

The plugin uses `preferred_username` from the token as the Jellyfin
username, so accounts show the login name rather than the opaque `sub`
UUID — no extra mapping is needed.

Add a login link to the sign-in page (for provider `kivraid`):

```
https://jellyfin.example.com/sso/OID/start/kivraid
```

You can inject this as a custom button via **Dashboard → General → Custom
CSS / branding**, or share the URL directly.

## Roles from groups

The plugin reads roles from a claim named by **Role Claim**; set it to
`groups` so it consumes the Kivraid `groups` claim (which requires the
`groups` scope above). Then:

- **Enable Authorization by plugin** — on, so the plugin sets each user's
  permissions from the claim.
- **Admin Roles** — group names whose members become Jellyfin admins,
  e.g. `jellyfin-admins`.
- **Roles** — group names required to sign in at all. Leave empty to allow
  any authenticated Kivraid user; set it (e.g. `jellyfin-users`) to
  restrict access to members of those groups.

Create the matching groups in Kivraid under **Admin → Groups**, add
members, and bind them under the application's **Access** section to keep
non-members out entirely.

### Folder restrictions

The same page controls library access:

- **Enable All Folders** — on gives users every library.
- **Enabled Folders** — when *Enable All Folders* is off, pick the specific
  libraries users from this provider may see.
- **Enable Folder Roles** — map group membership to library access instead
  of a fixed list, granting folders per role.

## Notes

- This is a third-party community plugin, not part of Jellyfin itself.
  Review its behavior before relying on it, and expect field labels to
  drift between plugin releases — the config keys above (`oidEndpoint`,
  `oidClientId`, `oidSecret`, `roleClaim`, `enableAllFolders`,
  `enabledFolders`, `enableFolderRoles`) are the underlying names in
  `SSO-Auth.xml` if the UI wording differs.
- The redirect URI in Kivraid must match
  `https://jellyfin.example.com/sso/OID/redirect/kivraid` exactly,
  including scheme, host (as seen behind your proxy), and the provider
  name segment. A mismatch is the most common cause of login failure.
- Kivraid supports RP-initiated logout at
  `https://sso.example.com/end_session`, but the plugin does not wire
  Jellyfin logout to it, so signing out of Jellyfin leaves the Kivraid
  session active.
</content>
</invoke>
