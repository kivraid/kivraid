# Debian-based build stage: the Tailwind standalone CLI is glibc-linked
# and does not run on Alpine/musl.
# The stage always runs on the build platform and cross-compiles for the
# target platform (TARGETOS/TARGETARCH are set by buildx; empty on a plain
# docker build, where Go then defaults to the host platform).
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
ARG TARGETOS TARGETARCH
RUN make css \
 && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
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
