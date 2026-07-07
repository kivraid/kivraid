# Nextcloud

Nextcloud signs in through the **OpenID Connect user backend**
(`user_oidc`) app. Replace `sso.example.com` with your Kivraid
`base_url` and `nextcloud.example.com` with your Nextcloud URL.

Install the app first: **Apps → Integration → OpenID Connect user
backend.**

## In Kivraid

Register an OpenID Connect application (see
[the generic reference](README.md#register-an-application-in-kivraid)):

- **Redirect URI:** `https://nextcloud.example.com/apps/user_oidc/code`
- **Client type:** Confidential

## In Nextcloud

**Administration settings → OpenID Connect → Register a new provider.**

- **Identifier:** `Kivraid` (shown on the login button)
- **Client ID / Client secret:** from Kivraid
- **Discovery endpoint:**
  `https://sso.example.com/.well-known/openid-configuration`
- **Scope:** `openid profile email`

Under **Attribute mapping**:

- **User ID mapping:** `sub`
- **Display name mapping:** `name`
- **Email mapping:** `email`

Mapping the User ID to `sub` (the stable UUID) is deliberate here:
Nextcloud uses it as the immutable internal account key, so a user keeps
their files even if renamed. The login button and display name still
show the readable `name`. If you specifically want the Nextcloud
username to be the login handle, map it to `preferred_username` instead —
but then renaming a user in Kivraid orphans their Nextcloud account.

## Notes

- To send users straight to Kivraid (skip the Nextcloud login form), set:

  ```sh
  occ config:app:set user_oidc allow_multiple_user_backends --value=0
  ```

- Group provisioning from the `groups` claim is available in recent
  `user_oidc` versions under the provider's group settings; add `groups`
  to the scope if you enable it.
- A redirect-URI error means the value in Kivraid must exactly match
  `https://nextcloud.example.com/apps/user_oidc/code`, using the host
  and scheme Nextcloud sees behind your proxy (`overwrite.cli.url` /
  `trusted_proxies` in Nextcloud).
