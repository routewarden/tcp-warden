# syntax=docker/dockerfile:1.7
# Multi-stage Dockerfile for RouteWarden TCP Warden
#
# Build-time args injected by docker buildx / goreleaser:
#   BUILDPLATFORM  – native platform of the builder host  (e.g. linux/amd64)
#   TARGETOS       – target OS                            (e.g. linux)
#   TARGETARCH     – target CPU arch                      (e.g. arm64)
#   VERSION        – binary version string                (e.g. v1.1.1)
#
# ──────────────────────────────────────────────────────────────────────────────
# Stage 1 – compile (runs on the NATIVE host platform via cross-compilation,
#           avoids QEMU emulation for the expensive Go build step)
# ──────────────────────────────────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

# These are populated automatically by BuildKit from the --platform flag
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev

WORKDIR /src
COPY go.mod go.sum ./

# Cache Go module downloads across builds — invalidated only when go.mod/go.sum change
RUN --mount=type=cache,target=/root/go/pkg/mod \
    go mod download

COPY . .

# Cache the Go build cache — incremental recompilation on source changes only
RUN --mount=type=cache,target=/root/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /bin/tcp-warden .

# Trim the Go toolchain that gets copied to the runtime image
RUN rm -rf /usr/local/go/test /usr/local/go/api /usr/local/go/doc

# ──────────────────────────────────────────────────────────────────────────────
# Stage 2 – runtime image (runs on the TARGET platform)
# ──────────────────────────────────────────────────────────────────────────────
FROM alpine:3.20

# Runtime deps: git + libcap for plugin compilation, su-exec for privilege drop
RUN apk --no-cache add ca-certificates tzdata git libcap su-exec && \
    git config --system --add safe.directory "*"

# Go toolchain — needed at runtime for on-demand plugin compilation
COPY --from=builder /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"

COPY --from=builder /bin/tcp-warden /usr/local/bin/tcp-warden

# Source tree for plugin compilation (modules downloaded on-demand into volume)
COPY --from=builder /src /usr/src/tcp-warden
ENV GOPATH=/var/lib/routewarden/go
ENV GOCACHE=/var/lib/routewarden/cache
ENV CGO_ENABLED=0
ENV ROUTEWARDEN_SRC_DIR=/usr/src/tcp-warden
WORKDIR /usr/src/tcp-warden

# Create non-root user and all required directories (including socket dir)
RUN addgroup -g 1000 -S routewarden && \
    adduser -u 1000 -S routewarden -G routewarden -D -h /home/routewarden && \
    mkdir -p \
      /etc/routewarden \
      /var/log/routewarden \
      /var/lib/routewarden/plugins \
      /var/lib/routewarden/go \
      /var/lib/routewarden/cache \
      /home/routewarden \
      /var/run/routewarden && \
    chown -R routewarden:routewarden \
      /etc/routewarden \
      /var/log/routewarden \
      /var/lib/routewarden \
      /usr/src/tcp-warden \
      /usr/local/bin \
      /home/routewarden \
      /var/run/routewarden && \
    setcap 'cap_net_bind_service=+ep' /usr/local/bin/tcp-warden

ENV ROUTEWARDEN_PLUGINS_CACHE=/var/lib/routewarden/plugins
ENV ROUTEWARDEN_CONFIG=/etc/routewarden/tcp-warden.yaml

VOLUME ["/etc/routewarden", "/var/lib/routewarden", "/var/log/routewarden", "/var/run/routewarden"]

# 9091: management API (TCP, optional — prefer unix socket via /var/run/routewarden)
EXPOSE 9091 2222 2525 1110 1143

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Starts as root → chowns bind-mounted /var/run/routewarden → su-exec routewarden
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/usr/local/bin/tcp-warden", "run"]
