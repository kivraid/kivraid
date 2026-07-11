# Kivraid — Design Document

A lightweight identity provider (IdP) in Go. Same core job as Authentik —
SSO in front of your applications, users from a local database or an LDAP
directory — but shipped as a single static binary with an embedded database,
targeting a fraction of Authentik's footprint (Authentik: Python + PostgreSQL
+ Redis + worker processes, ~1 GB RAM; Kivraid target: one process, < 50 MB).

Status: decisions settled 2026-07-02. The visual direction (Linear/Vercel-style
minimal) is a default pick, easy to re-skin later via design tokens.

## Goals

1. **OIDC provider**: applications are registered against Kivraid and
   authenticate users via OpenID Connect / OAuth2. The application setup
   experience deliberately mirrors Authentik's steps (create provider →
   create application → bind access policy) so migration is familiar.
2. **User sources**: local accounts (stored in SQLite) and/or one or more
   LDAP directories. LDAP users authenticate via bind; profile and groups
   are read live from the directory.
3. **Self-service user portal**: a user can log in, see their profile
   (the portal is their "public" interface to the directory), change their
   password (written back to LDAP for directory users), and list/revoke
   their active sessions.
4. **Resource friendly**: single binary, embedded assets, SQLite by
   default, no external services, no background worker fleet.
5. **A genuinely beautiful UI**: modern, minimal and crystal-clear
   (Linear/Vercel-inspired), light and dark mode. The interface is a
   first-class feature, not an afterthought — it is the main thing users
   and admins see, and a key differentiator against Authentik's utilitarian
   admin.

## Non-goals (v1)

- SAML 2.0 (heavy XML/signature machinery; possible later).
- Authentik's generic flow engine. Kivraid ships a fixed but configurable
  login pipeline (identify → password → optional MFA) instead of
  user-designed flow graphs. This is the single biggest simplification
  versus Authentik and the main source of the resource savings.
- Outposts (LDAP server emulation, RADIUS, proxy deployed separately).
- SCIM provisioning, invitations, self-registration (later, maybe).
- Multi-tenancy.

## Decisions

### Protocols

- **OIDC / OAuth2** — core of the project. Authorization code flow with
  PKCE, refresh tokens, `client_credentials` for machine clients. Discovery
  document, JWKS endpoint, RP-initiated logout, token introspection and
  revocation.
- **Forward auth** — `auth_request`-style endpoints for Traefik, Nginx and
  Caddy, to protect apps with no native SSO support. Cheap to add once OIDC
  sessions exist, very common in homelab setups. Confirmed for v1.
- SAML, LDAP outpost: out of scope for v1.

### Storage

- **SQLite by default, PostgreSQL supported.** SQLite via
  `modernc.org/sqlite` (pure Go, no CGO, trivial cross-compilation), WAL
  mode — the zero-dependency default that carries the "single binary"
  pitch. Postgres via `jackc/pgx` for larger installs or HA.
- How the dual-engine support actually landed (M6):
  - **One query set with `$n` placeholders**: Postgres requires them and
    SQLite supports them natively, so a single sqlc-generated package
    (codegen runs against the Postgres schema) serves both engines over
    `database/sql` (modernc for SQLite, pgx stdlib for Postgres).
  - Per-dialect migration files with shared numbering
    (`migrations/sqlite/`, `migrations/postgres/`): `TIMESTAMP`/`BLOB`
    vs `timestamptz`/`bytea`, and the scs session-store schema each
    driver expects.
  - Portable SQL only in queries — the common subset both engines parse
    (`RETURNING`, boolean literals, `LIMIT $1`).
  - Tests: `storetest.Open` gives each test a fresh SQLite file, or a
    throwaway Postgres database when `KIVRAID_TEST_POSTGRES_DSN` is set;
    CI runs the full suite against both engines.

### LDAP integration

- LDAP is a **live source**, not synced to the local DB (no sync jobs, no
  conflict handling — simpler than Authentik's approach).
- Authentication: search for the user with a service account, then bind as
  the user with the supplied password.
- Profile and group membership are read from the directory at login and
  cached in the session.
- **Password write-back**: the user portal's "change password" writes to
  the directory. Targets: **OpenLDAP and LLDAP** — both support the
  Password Modify extended operation (RFC 3062), which is the single code
  path we implement (no Active Directory `unicodePwd` handling in v1).
  Requires a service account with write permission, or the operation can
  be performed on the user's own bound connection where the directory's
  ACLs allow self-service password change.
- **Password reset** (opt-in per source, default off) is distinct from
  write-back: the "forgot password" email flow and admin-initiated resets
  set a new password *without* knowing the current one, so they bind as the
  **service account** and require it to hold write permission on user
  passwords. Write-back only ever binds as the user, so the two are
  separate flags.
- Multiple LDAP sources supported; each source maps directory groups to
  Kivraid groups.

### Frontend

- **Server-rendered Go templates**, all assets embedded via `go:embed`.
  No Node build chain, no SPA. A small vanilla JS file covers the
  interactivity shipped so far (theme toggle, clipboard copy, confirm
  dialogs); htmx remains the plan for genuinely dynamic admin widgets
  but is only added the day a page needs it — no unused bytes in the
  binary.
- Server-rendered does **not** mean austere — the UI is a headline
  requirement. See "Design system" below.

### Design system

Visual direction: **minimal and crystal-clear, Linear/Vercel-inspired** —
generous whitespace, refined typography, hairline borders, subtle depth,
restrained motion. Light **and** dark mode (toggle + `prefers-color-scheme`
default).

- **Tailwind CSS v4** via the **standalone CLI** (single binary, no Node
  runtime dependency): utilities keep the templates uniform and make
  iteration fast. The CLI runs at build time only (`go generate` +
  Makefile target, binary pinned per platform); the compiled stylesheet is
  embedded with `go:embed`, so the shipped artifact stays a single Go
  binary with zero runtime tooling.
- Design tokens live in Tailwind v4's CSS-first `@theme` block (colors,
  spacing, radii, shadows, fonts) plus `[data-theme=dark]` overrides — the
  entire skin still changes in one file. Repeated component patterns
  (buttons, cards, inputs) get thin component classes composed from the
  theme rather than copy-pasted utility strings in templates.
- **Typography**: a single embedded variable font (Inter or Geist, WOFF2,
  subset) + `ui-monospace` for client IDs, secrets and code. Tight
  headings, relaxed body, tabular numerals in tables.
- **Component inventory** (one shared library used by login, portal and
  admin): auth card (the login screen is the product's face — it must be
  the best-looking page), app-launcher grid with icons, data tables with
  empty states, forms with inline validation, slide-over panels for
  create/edit, toasts, badges, skeleton loaders for htmx swaps.
- **Details that make it feel premium**: consistent 8-pt spacing grid,
  focus rings (accessibility is part of "limpide"), 150–200 ms ease-out
  transitions, `prefers-reduced-motion` respected, real empty states with
  a call to action instead of blank tables.
- Icons: embedded SVG sprite (Lucide subset).

### Application model (mirroring Authentik)

Authentik separates *Provider* (protocol config) from *Application*
(catalog entry + access policy). Kivraid keeps that split because it maps
well to reality and eases migration:

- **Provider** (OIDC): client_id, client secret (hashed), redirect URIs,
  allowed scopes, token lifetimes, signing key.
- **Application**: name, slug, icon, launch URL, linked provider, and an
  access policy (v1: "allow these groups"; richer policies later).
- The admin UI offers a combined "create application + provider" wizard,
  like Authentik's, so the common case is one screen.

### Login pipeline

Fixed sequence, configurable via settings (not a flow graph):

1. Identify (username or email; sources tried in configured order:
   local first, then LDAP sources).
2. Password (local: Argon2id verify; LDAP: user bind).
3. MFA step — TOTP (authenticator apps) with single-use recovery codes,
   held in a pending session until the second factor is verified.
4. Session established (server-side session, cookie holds only the ID).

A discoverable **passkey (WebAuthn)** is an alternative to the whole
pipeline: being phishing-resistant it authenticates the user outright,
bypassing both the password and the TOTP step. Passkeys are resident/
discoverable so login is usernameless.

## Architecture

```
cmd/kivraid/            main: config load, DB open/migrate, HTTP server
internal/
  config/               file (YAML/TOML) + env overrides
  store/                SQLite: migrations, queries (sqlc)
  sources/
    local/              local users, Argon2id
    ldap/               bind auth, profile/group read, password write-back
  session/              server-side sessions (SQLite-backed)
  oidc/                 OP implementation (authorize, token, userinfo,
                        discovery, JWKS, logout, introspection, revocation)
  forwardauth/          traefik/nginx/caddy endpoints
  web/
    portal/             user self-service (profile, password, sessions, app launcher)
    admin/              apps, providers, users, groups, LDAP sources, settings
    templates/, static/ (go:embed)
  policy/               access evaluation (group-based in v1)
  audit/                append-only audit log in SQLite
```

### Key library choices

| Concern | Choice | Notes |
|---|---|---|
| OIDC provider | `zitadel/oidc` (v3) | Maintained, certified-adjacent OP framework; we implement its storage interfaces on SQLite. Alternative `ory/fosite` is more powerful but much heavier to integrate. |
| LDAP | `go-ldap/ldap/v3` | The de-facto standard. |
| SQLite driver | `modernc.org/sqlite` | Pure Go, no CGO. |
| Postgres driver | `jackc/pgx/v5` | When Postgres support lands (M6). |
| Queries | `sqlc` | Compile-time-checked SQL, no runtime ORM cost; dual engine configs (sqlite + postgresql) over portable SQL. |
| Migrations | embedded `.sql` + tiny runner (or `pressly/goose`) | Keep it boring. |
| HTTP router | stdlib `net/http` (Go 1.22+ patterns) | No framework needed. |
| Sessions | `alexedwards/scs` (SQLite/Postgres store) | Server-side, revocable — required for the "view/revoke my sessions" feature. |
| Password hashing | `golang.org/x/crypto/argon2` (Argon2id) | |
| TOTP | `pquerna/otp` | Authenticator-app second factor + recovery codes. |
| Passkeys | `go-webauthn/webauthn` | Discoverable/resident credentials; passwordless, phishing-resistant login. Public keys stored in `webauthn_credentials`. |
| Templates | stdlib `html/template` | `templ` is nice but adds codegen; revisit if templates get painful. |
| CSS | Tailwind v4 standalone CLI | Build-time only (no Node); output embedded via `go:embed`. |

### Token & key management

- Signing keys (ES256 default) generated at first start, stored encrypted
  at rest in SQLite, exposed via JWKS, with manual rotation in the admin
  (automatic rotation later).
- Access tokens: JWT, short-lived (default 5 min). Refresh tokens: opaque,
  hashed in DB, rotated on use. Authorization codes: opaque, single-use,
  10-min TTL.

## Data model (first cut)

```
users(id, username, email, name, password_hash, source, ldap_source_id,
      ldap_dn, active, created_at, ...)
groups(id, name) / user_groups(user_id, group_id)
ldap_sources(id, name, url, bind_dn, bind_password_enc, base_dn,
             user_filter, group_filter, attr_map, password_writeback, ...)
providers(id, type, client_id, client_secret_hash, redirect_uris,
          scopes, token_lifetimes, signing_key_id, ...)
applications(id, name, slug, icon, launch_url, provider_id, ...)
app_policies(app_id, group_id)
sessions(token_hash, user_id, data, ip, user_agent, expires_at, ...)
oauth_codes / oauth_refresh_tokens (hashed, with client + user + scopes)
signing_keys(id, alg, private_key_enc, public_key, active, created_at)
audit_log(id, ts, actor, action, object, detail)
```

LDAP users get a local *shadow row* in `users` on first login (identity,
group cache, MFA enrollment, session ownership) — but never their password.

## Milestones

1. **M0 — skeleton + design system**: config, SQLite + migrations, session
   store, local users; design tokens, base component library, and a
   login page + minimal portal (profile) that already look finished — the
   design system is built first, not retrofitted.
2. **M1 — OIDC OP**: discovery, authorize + PKCE, token, userinfo, JWKS;
   admin CRUD for provider+application (combined wizard); validate against
   Grafana or Gitea.
3. **M2 — LDAP**: source config, bind auth, group mapping, shadow users
   (OpenLDAP + LLDAP tested via docker-compose fixtures).
4. **M3 — portal complete**: change password (local Argon2id + LDAP
   write-back via RFC 3062), session list/revoke, app launcher filtered
   by access policy.
5. **M4 — hardening**: audit log, rate limiting on login, logout flows,
   token revocation/introspection, forward auth (Traefik/Nginx/Caddy).
6. **M5 — polish & packaging**: full UI pass (empty states, dark mode
   audit, motion), admin UX, Docker image `FROM scratch`, systemd unit,
   docs.
7. **M6 — Postgres**: pgx store implementation, dual-engine CI.

Delivered post-v1: TOTP and WebAuthn/passkeys; an admin overview dashboard,
audit-log filtering and CSV export, per-instance branding (instance name and
logo — the first database-backed setting, held in `instance_settings` rather
than the config file), user impersonation for support, and manual OIDC
signing-key rotation. Also SMTP email delivery (admin-managed in the
database, password encrypted at rest), which powers self-service password
reset (local accounts, and directory accounts where the per-source reset
flag is on) and email-address verification (feeding the OIDC
`email_verified` claim). Instance settings — branding, email and the
read-only system/diagnostics view — are grouped under one tabbed Settings
page. Possible later: SAML, invitations/self-registration.

## Security notes (must-hold invariants)

- All secrets hashed (client secrets, refresh tokens, session tokens) or
  encrypted at rest (LDAP bind password, signing keys) with a key derived
  from a `secret_key` in the config.
- CSRF protection on every state-changing form; `SameSite=Lax` +
  `Secure` + `HttpOnly` cookies.
- Login rate limiting per account and per IP; constant-time comparisons;
  identical error for "unknown user" and "bad password".
- Open-redirect protection: exact-match redirect URIs only.
- No password ever logged; audit log records events, not credentials.
