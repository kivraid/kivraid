# Proxmox VE

Proxmox VE signs in through an **OpenID Connect realm**. Replace
`sso.example.com` with your Kivraid `base_url` and `pve.example.com`
with your Proxmox web UI address.

## In Kivraid

Register an OpenID Connect application (see
[the generic reference](README.md#register-an-application-in-kivraid)):

- **Redirect URI:** the exact URL you use to reach the Proxmox web UI,
  including the port, e.g. `https://pve.example.com:8006`

  Proxmox builds the redirect from the address in your browser, so this
  must match how you actually connect (hostname and `:8006`). If you use
  the IP or a different port, register that instead.
- **Client type:** Confidential

## In Proxmox

**Datacenter → Permissions → Realms → Add → OpenID Connect Server.**

- **Issuer URL:** `https://sso.example.com`
- **Realm:** `kivraid` (an internal name)
- **Client ID:** from Kivraid
- **Client Key:** the client secret from Kivraid
- **Username claim:** `preferred_username` (or `email`)
- **Autocreate users:** enable if you want accounts created on first
  login; otherwise create them beforehand as `<username>@kivraid`.
- **Scopes:** `openid profile email`

## Permissions

Proxmox does not read the `groups` claim into its permission system;
grant privileges to the realm's users (or to a Proxmox group you add
them to) under **Datacenter → Permissions**. Autocreated users have no
privileges until you assign a role.

## Notes

- The username claim you pick decides the Proxmox account name
  (`amelia@kivraid`). `preferred_username` gives readable names; avoid
  `sub`, which would create UUID-named accounts.
- Proxmox requires the issuer to be reachable over HTTPS with a valid
  certificate from the node; a plain-HTTP `base_url` will not work.
