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

## Connecting an application

Create the application in **Admin → Applications** — the wizard issues the
client credentials (the secret is shown once) and lists every endpoint to
paste into the app. Request the scopes `openid profile email groups`.

Restrict who may sign in by binding groups in the application's **Access**
section; with no bound group, every authenticated user may use the app.

Step-by-step recipes for common applications (Grafana, Nextcloud, Gitea,
Proxmox) and a generic OIDC reference live in
[docs/integrations](integrations/).

For apps without native OIDC support, use [forward auth](forward-auth.md).
