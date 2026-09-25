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

RUN apk --no-cache add ca-certificates tzdata
COPY --from=builder /bin/tcp-warden /usr/local/bin/tcp-warden

RUN mkdir -p /etc/routewarden /var/log/routewarden

EXPOSE 9091 2222 2525 1110 1143

ENTRYPOINT ["/usr/local/bin/tcp-warden"]
CMD ["run", "--config", "/etc/routewarden/tcp-warden.yaml"]
