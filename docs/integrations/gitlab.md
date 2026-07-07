# GitLab

Self-hosted GitLab signs in through its **OmniAuth OpenID Connect**
provider. Replace `sso.example.com` with your Kivraid `base_url` and
`gitlab.example.com` with your GitLab URL throughout.

## In Kivraid

Register an OpenID Connect application (see
[the generic reference](README.md#register-an-application-in-kivraid)):

- **Redirect URI:** `https://gitlab.example.com/users/auth/openid_connect/callback`
- **Client type:** Confidential

Copy the client ID and secret.

## In GitLab

Edit `/etc/gitlab/gitlab.rb` (Linux package install), then run
`sudo gitlab-ctl reconfigure`. Kivraid publishes a discovery document,
so set `discovery: true` and point `issuer` at the base URL; GitLab
fetches the endpoints and signing keys from
`https://sso.example.com/.well-known/openid-configuration`.

```ruby
gitlab_rails['omniauth_enabled'] = true
gitlab_rails['omniauth_allow_single_sign_on'] = ['openid_connect']
gitlab_rails['omniauth_block_auto_created_users'] = false

gitlab_rails['omniauth_providers'] = [
  {
    name: "openid_connect",
    label: "Kivraid",
    args: {
      name: "openid_connect",
      scope: ["openid", "profile", "email", "groups"],
      response_type: "code",
      issuer: "https://sso.example.com",
      discovery: true,
      client_auth_method: "basic",
      uid_field: "preferred_username",
      pkce: true,
      client_options: {
        identifier: "<client id from Kivraid>",
        secret: "<client secret from Kivraid>",
        redirect_uri: "https://gitlab.example.com/users/auth/openid_connect/callback"
      }
    }
  }
]
```

`uid_field: "preferred_username"` is the important line: without it
GitLab falls back to the opaque `sub` UUID for the account's unique
identifier. GitLab reads the display name from the `name` claim and the
address from the `email` claim automatically.

`client_auth_method: "basic"` uses HTTP Basic auth to the token endpoint
(Kivraid's `client_secret_basic`). Kivraid also accepts
`client_secret_post`, which the gem selects with `"query"`.

## Roles from groups

The OmniAuth provider can restrict access and assign roles from the
`groups` claim. These keys go inside a `gitlab:` block nested under
`client_options`:

```ruby
client_options: {
  identifier: "<client id from Kivraid>",
  secret: "<client secret from Kivraid>",
  redirect_uri: "https://gitlab.example.com/users/auth/openid_connect/callback",
  gitlab: {
    groups_attribute: "groups",
    required_groups: ["gitlab-users"],
    admin_groups: ["gitlab-admins"],
    external_groups: ["gitlab-external"]
  }
}
```

- `required_groups` — only members of these groups may sign in.
- `admin_groups` — members become GitLab administrators.
- `external_groups` — members are created as external users.
- `auditor_groups` — members become auditors (Premium/Ultimate only).

Create the matching groups in Kivraid under **Admin → Groups** and add
members. You can also bind the application to specific groups under its
**Access** section in Kivraid so the token is only issued to allowed
users in the first place.

## Notes

- The `groups` claim is only emitted when the `groups` scope is
  requested, so keep `groups` in the `scope` array if you use any of the
  group settings above.
- If sign-in fails with a redirect-URI error, the value in Kivraid must
  match `https://gitlab.example.com/users/auth/openid_connect/callback`
  exactly, including scheme and host as GitLab sees them behind your
  proxy (check `external_url` in `gitlab.rb`).
- Single sign-out: GitLab does not call the OpenID Provider's
  `end_session` endpoint on logout, so logging out of GitLab leaves the
  Kivraid session active. Users must log out of Kivraid separately at
  `https://sso.example.com/end_session`.
- Provider key names come from the `omniauth-openid-connect` gem; older
  GitLab releases may not support every setting shown here (for example
  `pkce`). Check the OpenID Connect page in the docs for your version.
