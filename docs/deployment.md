# Deployment

## Docker

A multi-arch (amd64/arm64) image is published on GHCR for every release;
`make docker` builds the same image locally.

```sh
docker volume create kivraid
docker run -d --name kivraid -v kivraid:/data -p 9000:9000 \
  ghcr.io/lporcheron/kivraid
```

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

## Behind a reverse proxy

Run Kivraid behind a TLS-terminating proxy and set `base_url` to the public
`https://` URL — see [configuration.md](configuration.md#tls-and-the-issuer).
