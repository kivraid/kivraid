# Deployment

## Docker

A multi-arch (amd64/arm64) image is published on GHCR for every release;
`make docker` builds the same image locally.

```sh
docker volume create kivraid
docker run -d --name kivraid -v kivraid:/data -p 9000:9000 \
  ghcr.io/kivraid/kivraid
```

For Compose, [docker-compose.yml](../docker-compose.yml) at the
repository root is a ready-to-use deployment (volume, memory limit, the
env overrides worth setting).

## PostgreSQL

SQLite is the right default: zero services, trivial backup, and more
than enough for the workload of an identity provider. Reach for
PostgreSQL when you already run one (shared backup/monitoring/replication
tooling) or want the database on a separate host:

```yaml
# kivraid.yaml
database:
  driver: postgres
  dsn: "postgres://kivraid:secret@db.internal:5432/kivraid"
```

or via `KIVRAID_DB_DRIVER=postgres` and `KIVRAID_DB_DSN=...`.
[docker-compose.postgres.yml](../docker-compose.postgres.yml) is a
ready-to-use Compose stack with a bundled PostgreSQL 18. Migrations run
automatically at startup on either engine, and the full test suite runs
against both in CI.

Pick the engine when you first deploy: there is no built-in tool to move
existing data between SQLite and PostgreSQL.

The config is generated in the volume on first run; then open the instance
and register the administrator account.

The image is built `FROM scratch` and runs as an unprivileged user; all
state lives in the `/data` volume.

## systemd

A hardened unit (DynamicUser, StateDirectory, syscall filtering) is
provided in [../packaging/kivraid.service](../packaging/kivraid.service),
with installation steps in its header comment.

## Resource footprint

Kivraid targets small hosts. Measured in the `FROM scratch` container
(Linux, capped at 256 MB): **~26 MB idle RSS**, and it survives bursts of
concurrent logins without OOM. Two knobs keep it lean:

- Password hashing (Argon2id) runs the lighter OWASP profile (19 MiB per
  hash) behind a small concurrency limiter, so a login storm cannot exhaust
  memory.
- `GOMEMLIMIT` is set automatically from the container's memory limit, so
  the garbage collector respects the host's budget; idle memory is returned
  to the OS periodically.

Give the container a memory limit (e.g. `--memory=256m`) and Kivraid adapts
to it.

## Backup, restore, upgrades

All state lives in the database, but SQLite runs in WAL mode: copying
`kivraid.db` alone while the server runs can miss recent writes. Either
stop the service and copy `kivraid.db`, `kivraid.db-wal` and
`kivraid.db-shm` together, or take a consistent online snapshot:

```sh
sqlite3 /var/lib/kivraid/kivraid.db ".backup /backups/kivraid.db"
```

With PostgreSQL, use `pg_dump` as usual.

Keep the config file (or at least its `secret_key`) with the backup:
signing keys, TOTP secrets and directory credentials are encrypted with
it and are unrecoverable without it.

Upgrading is replacing the binary (or pulling a newer image) and
restarting — pending migrations run automatically at startup.
**Downgrades are not supported**: migrations are forward-only, and an
older binary refuses to start on a database written by a newer one. To
roll back, restore the database backup taken before the upgrade.

## Health checks

`GET /healthz` returns `200 ok`. The Docker image declares a
`HEALTHCHECK` using the built-in `kivraid healthcheck` subcommand
(the `FROM scratch` image has no curl), which you can also point at a
non-default port with `--url`.

## Behind a reverse proxy

Run Kivraid behind a TLS-terminating proxy and set `base_url` to the public
`https://` URL — see [configuration.md](configuration.md#tls-and-the-issuer).
