# Forgejo

Forgejo is a fork of Gitea, and its OpenID Connect setup is identical — an
**OAuth2 authentication source** of type OpenID Connect. Follow the
[Gitea guide](gitea.md) for every step; only the differences below are
Forgejo-specific. Replace `sso.example.com` with your Kivraid `base_url`
and `forgejo.example.com` with your Forgejo URL.

## In Kivraid

Same as Gitea. Register an OpenID Connect application (Confidential) with:

- **Redirect URI:** `https://forgejo.example.com/user/oauth2/Kivraid/callback`

  The `Kivraid` segment is the **Authentication Name** you give the source
  in Forgejo — they must match.

## In Forgejo

The one difference is the menu path. Forgejo puts the sources directly under
Site Administration (no "Identity & Access" subsection):

**Profile icon → Site Administration → Authentication Sources → Add
Authentication Source** (direct URL: `/admin/auths/new`).

The form fields are the same as Gitea (Authentication Type OAuth2, OAuth2
Provider OpenID Connect, Client ID/Secret, OpenID Connect Auto Discovery URL
`https://sso.example.com/.well-known/openid-configuration`, Additional Scopes
`groups`). Username maps from `preferred_username` and email from `email`
automatically.

## Roles and teams from groups

Identical to Gitea — see [Roles and teams from groups](gitea.md#roles-and-teams-from-groups).

## Notes

- The redirect-URI and account-linking notes in the
  [Gitea guide](gitea.md#notes) apply unchanged.
- UI labels may drift between Forgejo releases; the menu path above matches
  recent versions.
</content>
</invoke>
