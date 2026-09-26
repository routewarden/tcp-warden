# Multi-stage Dockerfile for RouteWarden TCP Warden
FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=1.0.2
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /bin/tcp-warden .

# Remove unnecessary Go toolchain tests and docs to reduce layer size
RUN rm -rf /usr/local/go/test /usr/local/go/api /usr/local/go/doc

FROM alpine:3.20

# Install runtime dependencies including git for plugin pulling
RUN apk --no-cache add ca-certificates tzdata git && \
    git config --global --add safe.directory "*"

COPY --from=builder /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"

COPY --from=builder /bin/tcp-warden /usr/local/bin/tcp-warden

# Copy source tree for modular plugin compilation (cached modules download on-demand to volume)
COPY --from=builder /src /usr/src/tcp-warden
ENV GOPATH=/var/lib/routewarden/go
ENV CGO_ENABLED=0
ENV ROUTEWARDEN_SRC_DIR=/usr/src/tcp-warden
WORKDIR /usr/src/tcp-warden

# Directory structure for config, logs, and plugins cache
RUN mkdir -p /etc/routewarden /var/log/routewarden /var/lib/routewarden/plugins /var/lib/routewarden/go

# Plugins cache directory (mountable via Docker volume)
ENV ROUTEWARDEN_PLUGINS_CACHE=/var/lib/routewarden/plugins

VOLUME ["/etc/routewarden", "/var/lib/routewarden/plugins", "/var/log/routewarden"]

EXPOSE 9091 2222 2525 1110 1143

ENTRYPOINT ["/usr/local/bin/tcp-warden"]
CMD ["run", "--config", "/etc/routewarden/tcp-warden.yaml"]
