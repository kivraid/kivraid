# Kivraid

A lightweight identity provider in Go. Same core job as Authentik — SSO
in front of your applications, users from a local database or an LDAP
directory — but shipped as **a single static binary with an embedded
SQLite database**: no Python, no PostgreSQL, no Redis, no workers.

## Features

- **OpenID Connect provider** — authorization code flow with PKCE,
  refresh token rotation, discovery, JWKS (ES256, keys encrypted at
  rest), userinfo, introspection, revocation, RP-initiated logout.
- **Forward auth** — protect apps without native SSO via Traefik, nginx
  or Caddy, registered as first-class applications with their own group
  access policy ([docs/forward-auth.md](docs/forward-auth.md)).
- **User sources** — local accounts (Argon2id) and live LDAP directories
  (OpenLDAP, LLDAP): bind authentication, group sync, and self-service
  password change written back via RFC 3062.
- **Two-factor authentication** — optional TOTP (authenticator apps)
  with single-use recovery codes, for local and directory users alike;
  admins can reset a locked-out user.
- **User portal** — application launcher, profile, password change,
  two-factor enrollment, session list with revocation. Light and dark,
  fast, no SPA.
- **Admin** — application wizard (OIDC or forward-auth), client secret
  displayed and rotatable, editable token lifetimes, uploadable icons
  and descriptions, group-based access policies, directory management
  with connection test, audit trail.
- **Hardening** — server-side revocable sessions, CSRF, strict CSP,
  login rate limiting, append-only audit log, all secrets hashed or
  encrypted at rest.
- **SQLite or PostgreSQL** — SQLite by default (zero external services);
  Postgres for larger installs. The full test suite runs against both.

## Quickstart (binary)

Requirements: Go 1.26+ to build. The Tailwind CSS standalone CLI is
downloaded automatically by `make` (no Node required).

```sh
make build
./kivraid config init      # writes kivraid.yaml with a random secret_key
./kivraid serve            # http://127.0.0.1:9000
```

On first visit, Kivraid invites you to register the administrator
account (a `user add` CLI is also available for scripted setups).

## Quickstart (Docker)

```sh
make docker
docker volume create kivraid
docker run --rm -v kivraid:/data kivraid config init --config /data/kivraid.yaml
docker run -d --name kivraid -v kivraid:/data -p 9000:9000 kivraid
```

Then open the instance and register the administrator account.

The image is built `FROM scratch` and runs as an unprivileged user; all
state lives in the `/data` volume.

## systemd

A hardened unit (DynamicUser, StateDirectory, syscall filtering) is
provided in [packaging/kivraid.service](packaging/kivraid.service) with
installation steps in its header comment.

## Resource footprint

Kivraid targets small hosts. Measured in the `FROM scratch` container
(Linux, capped at 256 MB): ~26 MB idle RSS, and it survives bursts of
concurrent logins without OOM. Two knobs keep it lean:

- Password hashing (Argon2id) runs the lighter OWASP profile (19 MiB per
  hash) behind a small concurrency limiter, so a login storm cannot
  exhaust memory.
- `GOMEMLIMIT` is set automatically from the container's memory limit, so
  the garbage collector respects the host's budget; idle memory is
  returned to the OS periodically.

Give the container a memory limit (e.g. `--memory=256m`) and Kivraid
adapts to it.

## Configuration

`kivraid config init` generates a commented starting point. Every key
has a `KIVRAID_*` environment override.

| Key | Env | Default | Description |
|---|---|---|---|
| `listen` | `KIVRAID_LISTEN` | `127.0.0.1:9000` | HTTP listen address. |
| `base_url` | `KIVRAID_BASE_URL` | `http://localhost:9000` | Public URL; also the OIDC issuer. `https://` enables secure cookies. |
| `secret_key` | `KIVRAID_SECRET_KEY` | — | ≥ 32 chars; protects keys and directory credentials at rest. Changing it invalidates them. |
| `database.driver` | `KIVRAID_DB_DRIVER` | `sqlite` | `sqlite` or `postgres`. |
| `database.dsn` | `KIVRAID_DB_DSN` | `kivraid.db` | SQLite file path, or a `postgres://user:pass@host/db` URL. |
| `forward_auth.domains` | `KIVRAID_FORWARD_AUTH_DOMAINS` | `[]` | Hosts allowed for forward-auth post-login redirects (`.suffix` matches subdomains). |
| `log_level` | `KIVRAID_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error`. |

Run Kivraid behind a TLS-terminating reverse proxy in production and set
`base_url` to the public `https://` URL; the OIDC issuer must match it.

## Connecting an application

Create the application in **Admin → Applications** — the wizard issues
the client credentials (the secret is shown once) and lists every
endpoint to paste into the app. Scopes: `openid profile email groups`.
Restrict who may sign in by binding groups in the application's
**Access** section.

## LDAP directories

Configure sources in **Admin → Directories**. Users authenticate by
bind; profile, groups and photo are read at login and mirrored into a
local shadow row (never the password). The group filter supports both
membership models — `{dn}` for groupOfNames/groupOfUniqueNames and
`{username}` for posixGroup's `memberUid` — and the service bind can be
anonymous if the directory allows unauthenticated searches. Password
write-back uses the RFC 3062 Password Modify operation on the user's
own connection, so the directory's ACLs stay in charge (and it keeps
working with an anonymous service bind).

Local users and groups are managed in **Admin → Users** and **Admin →
Groups**; directory-sourced entries appear there too but stay read-only
(only Kivraid-side flags like administrator/active can be changed on a
directory user). Any group — local or directory — can be flagged
**"Members are administrators"**: the administrator role is then
computed from membership on top of the per-user flag, so flagging a
synced LDAP group lets the directory drive who administers Kivraid.

Local fixtures for manual testing (OpenLDAP seeded with users, LLDAP):
`docker compose -f fixtures/ldap/docker-compose.yml up -d` — connection
settings are documented in that file.

## Development

```sh
make build          # generate CSS + sqlc code, then go build
make css-watch      # rebuild CSS on template changes
make test           # run tests
```

See [DESIGN.md](DESIGN.md) for architecture decisions and the roadmap
(next: Postgres support, TOTP, WebAuthn).
