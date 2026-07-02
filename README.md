# Kivraid

A lightweight identity provider in Go. Same core job as Authentik — SSO in
front of your applications, users from a local database or an LDAP
directory — but shipped as a single static binary with an embedded SQLite
database.

See [DESIGN.md](DESIGN.md) for the full architecture and roadmap.

## Status

Early development (milestone M0): local users, sessions, login page and
user portal skeleton. No OIDC yet.

## Development

Requirements: Go 1.26+. The Tailwind CSS standalone CLI is downloaded
automatically by `make` (no Node required).

```sh
make build          # generate CSS + sqlc code, then go build
make css-watch      # rebuild CSS on template changes
make test           # run tests

./kivraid config init                # writes kivraid.yaml with a random secret_key
./kivraid user add --username admin --email you@example.com --admin
./kivraid serve                      # http://127.0.0.1:9000
```

Every config key has a `KIVRAID_*` environment override
(e.g. `KIVRAID_SECRET_KEY`, `KIVRAID_LISTEN`, `KIVRAID_DB_DSN`).
