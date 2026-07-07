# NetBox

NetBox signs in through **python-social-auth** using its generic
`OpenIdConnectAuth` backend. Replace `sso.example.com` with your Kivraid
`base_url` and `netbox.example.com` with your NetBox URL throughout.

## In Kivraid

Register an OpenID Connect application (see
[the generic reference](README.md#register-an-application-in-kivraid)):

- **Redirect URI:** `https://netbox.example.com/oauth/complete/oidc/`
  (the trailing slash is required)
- **Client type:** Confidential

Copy the client ID and secret.

## In NetBox

Add the following to `configuration.py` and restart NetBox. The
`OIDC_ENDPOINT` is the Kivraid issuer **without** any path suffix:
python-social-auth appends `/.well-known/openid-configuration` itself and
auto-discovers the authorization, token, userinfo and JWKS endpoints from
there.

```python
REMOTE_AUTH_ENABLED = True
REMOTE_AUTH_BACKEND = 'social_core.backends.open_id_connect.OpenIdConnectAuth'

SOCIAL_AUTH_OIDC_OIDC_ENDPOINT = 'https://sso.example.com'
SOCIAL_AUTH_OIDC_KEY = '<client id from Kivraid>'
SOCIAL_AUTH_OIDC_SECRET = '<client secret from Kivraid>'
SOCIAL_AUTH_OIDC_SCOPE = ['profile', 'email', 'groups']
```

`openid` is always requested; the extra scopes above pull `name`, `email`
and the `groups` claim into the userinfo response.

The `OpenIdConnectAuth` backend already uses the `preferred_username` claim
for the Django username, which is exactly what Kivraid populates with the
login name, so the account is created as `amelia` rather than the opaque
`sub` UUID. You can make that explicit if you like:

```python
SOCIAL_AUTH_OIDC_USERNAME_KEY = 'preferred_username'
```

Email and display name (`name`) are mapped automatically by the backend's
`user_details` pipeline step.

## Roles from groups

NetBox does not map the `groups` claim to staff/superuser status out of the
box; you add a small pipeline. Create `netbox/netbox/custom_pipeline.py`:

```python
from django.contrib.auth.models import Group


def add_groups(response, user, backend, *args, **kwargs):
    for name in response.get('groups', []):
        group, _ = Group.objects.get_or_create(name=name)
        user.groups.add(group)


def remove_groups(response, user, backend, *args, **kwargs):
    groups = response.get('groups', [])
    for group in user.groups.all():
        if group.name not in groups:
            user.groups.remove(group)


def set_roles(response, user, backend, *args, **kwargs):
    groups = response.get('groups', [])
    user.is_superuser = 'netbox-admins' in groups
    user.is_staff = user.is_superuser or 'netbox-staff' in groups
    user.save()
```

Then append these to the authentication pipeline in `configuration.py`. Copy
NetBox's default `SOCIAL_AUTH_PIPELINE` (defined in `netbox/settings.py`) and
add the three functions at the end:

```python
SOCIAL_AUTH_PIPELINE = (
    'social_core.pipeline.social_auth.social_details',
    'social_core.pipeline.social_auth.social_uid',
    'social_core.pipeline.social_auth.social_user',
    'social_core.pipeline.user.get_username',
    'social_core.pipeline.social_auth.associate_by_email',
    'social_core.pipeline.user.create_user',
    'social_core.pipeline.social_auth.associate_user',
    'social_core.pipeline.social_auth.load_extra_data',
    'social_core.pipeline.user.user_details',
    'netbox.custom_pipeline.add_groups',
    'netbox.custom_pipeline.remove_groups',
    'netbox.custom_pipeline.set_roles',
)
```

Because the pipeline also *writes* the `groups` field, tell python-social-auth
not to treat it as an immutable protected field, otherwise sign-in fails:

```python
SOCIAL_AUTH_PROTECTED_USER_FIELDS = ['groups']
```

Create `netbox-admins` and `netbox-staff` in Kivraid under
**Admin → Groups**, add members, and to keep everyone else out of NetBox
bind those groups under the application's **Access** section in Kivraid.
NetBox object permissions can then be attached to the matching Django groups.

## Notes

- Single sign-out: set `LOGOUT_REDIRECT_URL = 'https://sso.example.com/end_session'`
  so logging out of NetBox also ends the Kivraid session.
- If NetBox sits behind a TLS-terminating proxy and builds the callback as
  `http://`, add `SOCIAL_AUTH_REDIRECT_IS_HTTPS = True` so the redirect URI
  matches the `https://` value registered in Kivraid.
- The redirect URI is matched exactly. It must be
  `https://netbox.example.com/oauth/complete/oidc/`, including the scheme,
  host as NetBox sees it, and the trailing slash.
- The backend key is `oidc`, which is why every setting is prefixed
  `SOCIAL_AUTH_OIDC_` and the callback path is `/oauth/complete/oidc/`. If you
  change the backend you must change all of these together.
