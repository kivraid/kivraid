# Debian-based build stage: the Tailwind standalone CLI is glibc-linked
# and does not run on Alpine/musl.
FROM golang:1.26-bookworm AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN make css \
 && CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/kivraid ./cmd/kivraid \
 && mkdir -p /out/data

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/kivraid /kivraid
COPY --from=build --chown=65532:65532 /out/data /data

USER 65532:65532
VOLUME /data
EXPOSE 9000
ENV KIVRAID_LISTEN=0.0.0.0:9000 \
    KIVRAID_DB_DSN=/data/kivraid.db

ENTRYPOINT ["/kivraid"]
CMD ["serve", "--config", "/data/kivraid.yaml"]
