# Configuration

Kivraid reads a single YAML file (`kivraid.yaml` by default; override with
`--config`). On first run `kivraid serve` generates one with a random
`secret_key` if it is missing — there is no separate init step. For scripted
setups, `kivraid config init` writes a commented starting point and
`kivraid user add` creates an account.

Every key has a `KIVRAID_*` environment override, which takes precedence
over the file.

| Key | Env | Default | Description |
|---|---|---|---|
| `listen` | `KIVRAID_LISTEN` | `127.0.0.1:9000` | HTTP listen address. |
| `base_url` | `KIVRAID_BASE_URL` | `http://localhost:9000` | Public URL; also the OIDC issuer. `https://` enables secure cookies. |
| `secret_key` | `KIVRAID_SECRET_KEY` | — | ≥ 32 chars; protects keys and directory credentials at rest. Changing it invalidates them. |
| `database.driver` | `KIVRAID_DB_DRIVER` | `sqlite` | `sqlite` or `postgres`. |
| `database.dsn` | `KIVRAID_DB_DSN` | `kivraid.db` | SQLite file path, or a `postgres://user:pass@host/db` URL. |
| `forward_auth.domains` | `KIVRAID_FORWARD_AUTH_DOMAINS` | `[]` | Hosts allowed for forward-auth post-login redirects (`.suffix` matches subdomains). |
| `session.lifetime` | `KIVRAID_SESSION_LIFETIME` | `168h` | Absolute maximum session age, measured from login. |
| `session.idle_timeout` | `KIVRAID_SESSION_IDLE_TIMEOUT` | `0s` | Inactivity timeout (sliding, capped by `lifetime`); `0s` disables it. |
| `trusted_proxies` | `KIVRAID_TRUSTED_PROXIES` | `[]` | Proxies (IPs or CIDRs) whose `X-Forwarded-For` is trusted for client IPs. |
| `oidc.signing_algorithm` | `KIVRAID_OIDC_SIGNING_ALGORITHM` | `es256` | ID token signature: `es256` or `rs256`. |
| `log_level` | `KIVRAID_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error`. |

Durations use Go's syntax (`168h`, `30m`, `90s`, `0s`).

## Sessions

`session.lifetime` is a hard ceiling from login — a session expires after
it no matter how active the user is. `session.idle_timeout`, when set to a
non-zero duration, adds an inactivity window that **slides**: every request
resets the countdown, but never beyond `lifetime`. So `idle_timeout: 30m`
with `lifetime: 168h` means "logged out after 30 minutes idle, and in any
case at most 7 days after signing in". `idle_timeout` may not exceed
`lifetime`.

Sessions are server-side and revocable regardless of these values: users
can end them from the portal and admins from the user page.

## TLS and the issuer

Run Kivraid behind a TLS-terminating reverse proxy in production and set
`base_url` to the public `https://` URL. The OIDC issuer is derived from
`base_url`, so it must match exactly what relying parties are configured
with, and `https://` is what flips session cookies to `Secure` and turns
on the `Strict-Transport-Security` header.

When behind a proxy, also set `trusted_proxies` to the proxy's address
(e.g. `["10.0.0.0/8"]` or the Docker network range). Client IPs — used
for login rate limiting, the audit log and the session list — are then
taken from `X-Forwarded-For`, walking the chain from the right past
trusted hops. Without it the header is ignored, since anyone reaching
Kivraid directly could spoof it.

## First run

1. `kivraid serve` starts the server and generates the config if absent.
2. Open the instance; the first visitor is prompted to register the
   administrator account (no seeding required).
3. From there, manage everything from the web UI.

## ID token signing algorithm

Kivraid signs OIDC ID tokens with **ES256** by default — modern, compact,
and understood by most clients. A few applications only accept **RS256**
(the universally supported OIDC baseline); set `oidc.signing_algorithm:
rs256` for those. RS256 works with every OIDC client, so switching the
whole instance to it is a safe way to cover a stubborn app.

Switching is live and non-disruptive: Kivraid generates the new key on the
next start and keeps the old public key in its JWKS, so tokens issued
before the switch still verify. The catch is any app where you *pinned*
the algorithm (e.g. Immich, SonarQube — see
[integrations](integrations/)): update its setting to match, or its next
sign-in fails signature verification.

## Connecting an application

Create the application in **Admin → Applications** — the wizard issues the
client credentials (the secret is shown once) and lists every endpoint to
paste into the app. Request the scopes `openid profile email groups`.

Choose who may sign in in the application's **Access** section: *Everyone
signed in*, or *Only selected groups*. A restricted application fails
closed: if its groups are all deleted, nobody can sign in until you pick
new groups or open it to everyone.

The same section can **require two-factor authentication** for that
application alone.

Step-by-step recipes for common applications (Grafana, Nextcloud, Gitea,
Proxmox) and a generic OIDC reference live in
[docs/integrations](integrations/).

For apps without native OIDC support, use [forward auth](forward-auth.md).

## Two-factor requirements

**Admin → Settings → Security** sets who must sign in with a second
factor: nobody (optional, the default), administrators, or everyone. A
session counts as two-factor when it was opened with an authenticator code,
a passkey, or an upstream identity provider (federated users authenticate
there). Anyone required but not enrolled is sent to set up an authenticator
app before reaching any other page, continues right after, and can no
longer turn two-factor off. A user who is enrolled but holds an older,
password-only session is asked to sign in again.

An application can also require two-factor on its own (its **Access**
section); this applies to OIDC sign-ins and forward auth alike.

## Sign-in alerts

With email delivery configured, **Admin → Settings → Security** can email
users whenever their account signs in from a new device — a browser that
has never signed in as them (Kivraid recognizes browsers by the encrypted
account-chooser cookie). The message gives the browser, IP address, time
and sign-in method, and links to the user's sessions page. An account's
very first sign-in sends nothing. The option is off by default: right
after it is turned on, each user's next sign-in on every browser counts as
new.
