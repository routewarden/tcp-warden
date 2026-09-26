# Multi-stage Dockerfile for RouteWarden TCP Warden
FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=1.0.0
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /bin/tcp-warden .

FROM alpine:3.20

# Install runtime dependencies including git and go for plugin pulling & test execution
RUN apk --no-cache add ca-certificates tzdata git go
COPY --from=builder /bin/tcp-warden /usr/local/bin/tcp-warden

# Directory structure for config, logs, and plugins cache
RUN mkdir -p /etc/routewarden /var/log/routewarden /var/lib/routewarden/plugins

# Plugins cache directory (mountable via Docker volume)
ENV ROUTEWARDEN_PLUGINS_CACHE=/var/lib/routewarden/plugins

VOLUME ["/etc/routewarden", "/var/lib/routewarden/plugins", "/var/log/routewarden"]

EXPOSE 9091 2222 2525 1110 1143

ENTRYPOINT ["/usr/local/bin/tcp-warden"]
CMD ["run", "--config", "/etc/routewarden/tcp-warden.yaml"]
