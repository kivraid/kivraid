<p align="center">
  <img src="docs/img/logo.svg" alt="Kivraid" width="88" height="88">
</p>

<h1 align="center">Kivraid</h1>

<p align="center">
  A modern, lightweight identity provider — SSO for your apps,<br>
  shipped as <strong>one static Go binary</strong> with an embedded database.
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> ·
  <a href="#features">Features</a> ·
  <a href="#how-it-compares">Compare</a> ·
  <a href="docs/configuration.md">Docs</a>
</p>

---

Kivraid does the same core job as [Authentik](https://goauthentik.io/):
single sign-on in front of your applications, with users from a local
database or an LDAP directory. The difference is what it takes to run it.

Authentik is a Python platform that needs PostgreSQL, Redis and background
workers. Kivraid is **a single binary with an embedded SQLite database** —
no external services, no runtime, no worker fleet. It idles at around
**26 MB of RAM** and adapts to whatever memory limit you give the
container. And it comes with a genuinely nice, fast web UI in light and
dark — no SPA.

If you want most of Authentik's day-to-day value on a small host — a Pi, a
cheap VPS, a homelab, a side of an existing app — without the operational
weight, that's what Kivraid is for.

## Why Kivraid

- 📦 **One binary, zero dependencies** — static Go binary, embedded SQLite.
  No Python, PostgreSQL, Redis or workers to run. (PostgreSQL is optional
  for larger installs.)
- 🪶 **Tiny footprint** — ~26 MB idle RSS; `GOMEMLIMIT` is set from the
  container's limit so the GC respects your budget and survives login
  bursts without OOM.
- ✨ **A UI you'll actually enjoy** — server-rendered, fast, light & dark,
  built with Tailwind. Login, self-service portal and admin all polished.
- 🔋 **Batteries included** — OIDC provider, forward auth, LDAP, TOTP and
  passkeys, an admin console and an audit trail, all in the box.
- 🔒 **Secure by default** — revocable server-side sessions, CSRF, strict
  CSP, rate limiting, and every secret hashed or encrypted at rest.

## Screenshots

> Replace the images below with real captures (`docs/img/`).

<p align="center">
  <img src="docs/img/login.png" alt="Sign-in screen" width="800"><br>
  <em>Sign in — clean, themeable, with passwordless passkey support.</em>
</p>

<p align="center">
  <img src="docs/img/portal.png" alt="User portal" width="800"><br>
  <em>The self-service portal: app launcher, profile, sessions, 2FA and passkeys.</em>
</p>

<p align="center">
  <img src="docs/img/admin.png" alt="Admin console" width="800"><br>
  <em>Admin: applications, directories, users, groups and the audit log.</em>
</p>

## Features

- **OpenID Connect provider** — authorization code flow with PKCE, refresh
  token rotation, discovery, JWKS (ES256, keys encrypted at rest),
  userinfo, introspection, revocation, RP-initiated logout.
- **Forward auth** — protect apps without native SSO via Traefik, nginx or
  Caddy, registered as first-class applications with their own group access
  policy. See [docs/forward-auth.md](docs/forward-auth.md).
- **User sources** — local accounts (Argon2id) and live LDAP directories
  (OpenLDAP, LLDAP): bind authentication, paged group sync (RFC 2696), and
  self-service password change written back via RFC 3062. See
  [docs/ldap.md](docs/ldap.md).
- **Two-factor authentication** — optional TOTP (authenticator apps) with
  single-use recovery codes, for local and directory users alike; admins
  can reset a locked-out user.
- **Passkeys (WebAuthn)** — register device biometrics or a security key
  and sign in passwordless; a discoverable passkey is phishing-resistant
  and stands in for both password and second factor.
- **User portal** — application launcher, profile, password change,
  two-factor and passkey enrollment, session list with revocation.
- **Admin** — application wizard (OIDC or forward-auth), client secret
  displayed and rotatable, editable token lifetimes, uploadable icons and
  descriptions, group-based access policies, directory management with
  connection test, and an append-only audit trail.
- **Hardening** — server-side revocable sessions, CSRF, strict CSP, login
  rate limiting, all secrets hashed or encrypted at rest.
- **SQLite or PostgreSQL** — SQLite by default (zero external services);
  Postgres for larger installs. The full test suite runs against both.

## Quickstart

**Binary** — requires Go 1.26+ to build (the Tailwind CSS standalone CLI is
downloaded automatically by `make`; no Node required):

```sh
make build
./kivraid serve            # http://127.0.0.1:9000
```

**Docker** — built `FROM scratch`, runs unprivileged, all state in `/data`:

```sh
make docker
docker volume create kivraid
docker run -d --name kivraid -v kivraid:/data -p 9000:9000 kivraid
```

Either way, Kivraid generates its config with a random `secret_key` on
first run — no init step. Open the instance and register the administrator
account on first visit. See [docs/deployment.md](docs/deployment.md) for
systemd and the resource footprint.

## How it compares

The self-hosted auth landscape runs from minimal OIDC providers to full
identity platforms. Kivraid sits in the middle: more than a passkey-only
OIDC provider, far lighter than a platform. The table is a spectrum from
narrow to broad.

| | Pocket ID | **Kivraid** | Authelia | Authentik |
|---|---|---|---|---|
| Runtime | one Go binary | one Go binary | one Go binary | Python + workers |
| Required services | none (SQLite) | none (SQLite) | none (SQLite; Redis for HA) | PostgreSQL + Redis |
| Idle memory | tens of MB | ~26 MB | tens of MB | hundreds of MB |
| Managed via | web admin | web admin | config files | web admin |
| User sources | local (passkey) | local + LDAP | file / LDAP | local / LDAP / social |
| Auth methods | passkeys | password, TOTP, passkeys | password, TOTP, WebAuthn, Duo | many |
| Forward auth | ✗ | ✓ | ✓ (its core job) | ✓ (proxy outpost) |
| Protocols | OIDC | OIDC, forward auth | OIDC, forward auth | OIDC, SAML, LDAP/RADIUS, proxy |
| SAML | ✗ | ✗ | ✗ | ✓ |

**Reading it:** [Pocket ID](https://github.com/pocket-id/pocket-id) is the
closest in spirit — same single-binary-plus-SQLite DNA — but deliberately
passkey-only and OIDC-only; pick it if that's genuinely all you need.
[Authelia](https://www.authelia.com/) overlaps heavily (Go, lightweight,
forward auth, OIDC) but is declarative: users and rules live in config
files, with powerful per-resource access control and no admin UI — great
for a GitOps setup. [Authentik](https://goauthentik.io/) and
[Keycloak](https://www.keycloak.org/) are full platforms (SAML, flow
engines, federation, multi-tenancy) at the cost of a much heavier runtime.
[Kanidm](https://kanidm.com/) is another lightweight, passkey-first option
(Rust) if you want its own directory and replication.

**What Kivraid does _not_ do** (by design): no visual flow engine, no SAML,
no RADIUS or LDAP-server outposts, no SCIM provisioning, no multi-tenancy.
If you need those, reach for Authentik or Keycloak.

<sub>Comparisons reflect these projects as of mid-2026 and are simplified;
they move fast, so verify current capabilities before relying on them.</sub>

## Documentation

- [Configuration](docs/configuration.md) — config file, env overrides, TLS,
  connecting an application.
- [LDAP directories](docs/ldap.md) — bind auth, group models, write-back.
- [Forward auth](docs/forward-auth.md) — protecting apps without native SSO.
- [Deployment](docs/deployment.md) — Docker, systemd, resource footprint.
- [DESIGN.md](DESIGN.md) — architecture decisions and roadmap.

## Development

```sh
make build          # generate CSS + sqlc code, then go build
make css-watch      # rebuild CSS on template changes
make test           # run tests (add KIVRAID_TEST_POSTGRES_DSN for Postgres)
```
