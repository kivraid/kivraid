# Forward auth

Kivraid can protect applications that have no native SSO support through
the reverse proxy's auth subrequest mechanism (Traefik `forwardAuth`,
nginx `auth_request`, Caddy `forward_auth`).

The proxy asks `GET /outpost/auth` on every request:

- **Authenticated** (valid Kivraid session cookie): `200` with identity
  headers the proxy can copy upstream: `Remote-User`, `Remote-Email`,
  `Remote-Name`, `Remote-Groups` (comma-separated).
- **Anonymous**: `302` to the Kivraid login page with a `next` back to the
  original URL — if the target host is allowlisted — otherwise `401`.

Because the post-login redirect leaves Kivraid's own origin, the allowed
hosts must be declared explicitly (open-redirect protection):

```yaml
# kivraid.yaml
forward_auth:
  domains:
    - ".home.example.com"      # any subdomain of home.example.com
    - "grafana.example.com"    # exact host
```

Authentication relies on the Kivraid session cookie being scoped to the
Kivraid host: the proxies below forward the original request's cookies to
the auth endpoint, so the check works even though the protected
application lives on a different (sub)domain. No cookie-domain sharing is
required.

## Traefik

```yaml
http:
  middlewares:
    kivraid:
      forwardAuth:
        address: "https://auth.example.com/outpost/auth"
        trustForwardHeader: true
        authResponseHeaders:
          - Remote-User
          - Remote-Email
          - Remote-Name
          - Remote-Groups
  routers:
    myapp:
      rule: "Host(`app.example.com`)"
      middlewares: [kivraid]
      service: myapp
```

## nginx

```nginx
location / {
    auth_request /kivraid-auth;
    auth_request_set $user   $upstream_http_remote_user;
    auth_request_set $email  $upstream_http_remote_email;
    proxy_set_header Remote-User  $user;
    proxy_set_header Remote-Email $email;
    error_page 401 = @kivraid-login;
    proxy_pass http://myapp;
}

location = /kivraid-auth {
    internal;
    proxy_pass https://auth.example.com/outpost/auth;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host  $host;
    proxy_set_header X-Forwarded-Uri   $request_uri;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
}

location @kivraid-login {
    return 302 https://auth.example.com/login?next=$scheme://$host$request_uri;
}
```

## Caddy

```caddyfile
app.example.com {
    forward_auth https://auth.example.com {
        uri /outpost/auth
        copy_headers Remote-User Remote-Email Remote-Name Remote-Groups
    }
    reverse_proxy myapp:8080
}
```

## Per-application authorization

Register a **forward-auth application** in Admin → Applications (choose
the "Forward auth" integration) and list its protected hosts. When a
request's `X-Forwarded-Host` matches one of them, Kivraid enforces that
application's group access policy: members who fail it get `403`, so the
protected app never sees an unauthorized user. An application with no
policy allows any authenticated user. Give it a launch URL to make it
appear in the user portal's launcher.

The `forward_auth.domains` config still governs which hosts may be used
as post-login redirect targets (open-redirect protection); a registered
proxy application's hosts are trusted for that too.

## Notes

- The identity headers are only trustworthy when set by the proxy —
  make sure the upstream application cannot receive them directly from
  clients.
