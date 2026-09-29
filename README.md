# RouteWarden TCP Warden (`tcp-warden`)

<div align="center">

![RouteWarden Banner](https://raw.githubusercontent.com/routewarden/traefik-warden/main/assets/banner.png)

[![Go Reference](https://pkg.go.dev/badge/github.com/routewarden/tcp-warden.svg)](https://pkg.go.dev/github.com/routewarden/tcp-warden)
[![Go Report Card](https://goreportcard.com/badge/github.com/routewarden/tcp-warden)](https://goreportcard.com/report/github.com/routewarden/tcp-warden)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Protocol-Aware Layer 4 TCP Security Proxy & Firewall Daemon**

</div>

---

## Overview

**RouteWarden TCP Warden** (`tcp-warden`) is a standalone, lightweight, high-performance **Layer 4 security reverse proxy** designed to protect infrastructure services (SSH, SMTP, POP3, IMAP, databases, and raw TCP streams) from brute-force authentication, botnet reconnaissance, volumetric floods, and credential stuffing.

While RouteWarden's HTTP plugins protect web traffic on Traefik, Caddy, and NGINX, `tcp-warden` stands in front of underlying non-HTTP protocols with deep protocol inspection and automatic threat mitigation.

```
Incoming TCP Connections (SSH :2222, SMTP :2525, POP3 :1110, DB :5433)
                              │
                              ▼
               ┌──────────────────────────────┐
               │    RouteWarden TCP Warden    │
               │   ────────────────────────   │
               │ 1. GeoIP Lookup              │
               │ 2. In-Memory Banlist Check   │
               │ 3. CrowdSec LAPI Stream      │
               │ 4. CIDR IP Filter (Allow/Deny│
               │ 5. Geo-block (ISO Countries) │
               │ 6. Token-Bucket Rate Limiter │
               │ 7. Protocol Deep Inspection  │
               │ 8. SIEM JSONL & SSE Bus      │
               └──────────────┬───────────────┘
                              │
                              ▼
            Legitimate Upstream Infrastructure
         (sshd :22, postfix :25, dovecot :110, postgres :5432)
```

---

- **Modular Plugin Architecture (Self-Testing & Auto-Disable)**:
  - The core daemon provides high-performance transparent Layer 4 TCP proxying (`generic` / `tcp`).
  - All protocol-specific inspectors (`ssh`, `smtp`, `pop3`, `imap`, `postgres`, `mysql`, `redis`, `http`, `ftp`, `tls_sni`, plus custom protocols) are isolated into independent, modular plugins in [`routewarden/plugins`](https://github.com/routewarden/plugins).
  - **Self-Testing on Load**: Every plugin implements an automated in-memory `SelfTest() error` suite using synthetic connections.
  - **Auto-Disable Resilience**: The daemon runs plugin self-tests during boot; if any plugin fails its self-test, it is **automatically disabled** (`StatusDisabled`), preventing security bypasses or panics while keeping all other services operational.
  - **Custom & Third-Party Plugins**: Anyone can author custom protocol inspectors (`tcp-warden plugins create <name>`) with typed configurations and self-testing.
- **Deep Protocol Inspection**:
  - **SSH**: Non-destructive banner validation and real-time scanning for `SSH_MSG_USERAUTH_FAILURE` (type 51) packets to count and ban brute-force attackers.
  - **SMTP**: Line-by-line inspection, `MAIL FROM` domain wildcard blocking (`*.tempmail.com`), recipient counting, and transparent `STARTTLS`/`DATA` handover.
  - **POP3**: `USER`/`PASS` tracking, `-ERR` failure counter, and `STLS` handover.
  - **IMAP**: `LOGIN`/`AUTHENTICATE` tracking, `NO`/`BAD` error counter, and `STARTTLS` handover.
  - **PostgreSQL Plugin**: Handshake inspection, SSLRequest negotiation, and server `ErrorResponse` code `28P01` / `28000` credential stuffing detection.
  - **MySQL / MariaDB Plugin**: HandshakeResponse41 parsing, SSL detection, and `0xFF` ERR packet code `1045` (Access Denied) brute-force tracking.
  - **Redis Plugin**: Inline & RESP command parsing, `AUTH` password failure detection (`-WRONGPASS`), and command blocking (`FLUSHALL`, `CONFIG`, `KEYS`).
  - **FTP Plugin**: Command/response tracking (`USER`/`PASS`), `530 Login incorrect` error detection, and `AUTH TLS` transparent handover.
  - **TLS SNI Plugin**: Zero-decryption ClientHello parsing to extract Server Name Indication and enforce domain allow/deny rules.
  - **Echo Filter (Example Plugin)**: Ingress payload inspection blocking signature keywords or exploit strings (`EXPLOIT`, `DROP TABLE`).
  - **MQTT (Example Plugin)**: IoT broker inspection verifying CONNECT packets and blacklisting rogue ClientID prefixes (`bot-`, `scanner-`).
  - **Generic TCP**: High-throughput zero-allocation bi-directional streaming pipe for databases and arbitrary services.
- **Native CrowdSec LAPI Bouncer**:
  - Connects directly to CrowdSec Local API (`/v1/decisions/stream`).
  - Caches community blocklists and custom decisions in memory with zero overhead on the hot path.
  - Custom parsers and scenarios provided out of the box.
- **8-Stage Connection Pipeline**:
  - Multi-tiered defense executing in sub-millisecond time.
- **Configurable Rejection Modes**:
  - `drop`: Immediate TCP RST / connection closure.
  - `reject`: Protocol-appropriate refusal message.
  - `tarpit`: Delays closing the connection to exhaust scanner threads.
  - `silent`: Discard bytes without acknowledgement.
- **REST API & SSE Event Stream**:
  - Real-time endpoints on `:9091` for health, metrics, active banlist management, and live security events.
  - Directly tail-able by the RouteWarden web dashboard.

---

## Configuration (`tcp-warden.yaml`)

```yaml
version: "1.0"

global:
  max_connections: 10000
  ban_duration: "1h"
  ban_after_failures: 5
  tarpit_ms: 1000
  log_file: "/var/log/routewarden/tcp-warden.jsonl"
  geoip_db: "/etc/routewarden/GeoLite2-Country.mmdb"

api:
  enabled: true
  listen: "127.0.0.1:9091"

crowdsec:
  enabled: true
  lapi_url: "http://127.0.0.1:8080"
  api_key: "${CROWDSEC_API_KEY}"
  update_frequency: "10s"

services:
  ssh:
    listen: ":2222"
    upstream: "127.0.0.1:22"
    protocol: "ssh"
    rate_limit:
      connections_per_minute: 20
      burst: 5
    geo_block:
      deny_countries: ["RU", "CN", "KP"]
    ip_filter:
      allow: ["10.0.0.0/8", "192.168.0.0/16", "127.0.0.1/32"]
      deny: ["198.51.100.0/24"]
    max_auth_failures: 3
    ban_after_failures: 3
    ban_duration: "2h"
    response:
      mode: "reject"
      reject_message: "Connection rejected by RouteWarden"
    ssh:
      banner: "RouteWarden SSH Guard"

  smtp:
    listen: ":2525"
    upstream: "127.0.0.1:25"
    protocol: "smtp"
    rate_limit:
      connections_per_minute: 30
      burst: 10
    smtp:
      max_recipients: 10
      blocked_sender_domains: ["*.tempmail.com", "spam.org"]

  postgres:
    listen: ":5433"
    upstream: "127.0.0.1:5432"
    protocol: "postgres"
    max_auth_failures: 3
    ban_after_failures: 3

  mysql:
    listen: ":3307"
    upstream: "127.0.0.1:3306"
    protocol: "mysql"
    max_auth_failures: 3
    ban_after_failures: 3

  redis:
    listen: ":6380"
    upstream: "127.0.0.1:6379"
    protocol: "redis"
    redis:
      blocked_commands: ["FLUSHALL", "CONFIG", "SHUTDOWN"]

  ftp:
    listen: ":2121"
    upstream: "127.0.0.1:21"
    protocol: "ftp"
    max_auth_failures: 3

  tls-proxy:
    listen: ":8443"
    upstream: "127.0.0.1:443"
    protocol: "tls"
    tls:
      allowed_domains: ["*.example.com"]
      blocked_domains: ["*.malicious.org"]

  database:
    listen: ":15432"
    upstream: "127.0.0.1:5432"
    protocol: "tcp"
    rate_limit:
      connections_per_minute: 120
      burst: 30
    ip_filter:
      allow: ["10.0.0.0/8", "127.0.0.1"]
```

---

## CLI Usage

### 1. Start the Daemon
```bash
tcp-warden run --config tcp-warden.yaml
```

### 2. Verify Configuration
```bash
tcp-warden validate --config tcp-warden.yaml
```

### 3. List Plugins & Health Status
```bash
tcp-warden plugins list
```

### 4. Run Plugin Self-Tests On-Demand
```bash
# Test all registered plugins
tcp-warden plugins test

# Test a specific plugin
tcp-warden plugins test postgres
```

### 5. Check Live Status & Metrics
```bash
tcp-warden status --api http://127.0.0.1:9091
```

### 6. Inspect Active Banlist
```bash
tcp-warden banlist --api http://127.0.0.1:9091
```

### 7. Manually Ban or Unban an IP
```bash
# Ban an IP
tcp-warden ban 198.51.100.42 --duration 2h --reason "brute_force" --api http://127.0.0.1:9091

# Unban an IP
tcp-warden unban 198.51.100.42 --api http://127.0.0.1:9091
```

---

## Docker & Docker Compose

Run with Docker host networking for minimum latency and zero NAT overhead:

```bash
docker run -d \
  --name tcp-warden \
  --network host \
  -v $(pwd)/tcp-warden.yaml:/etc/routewarden/tcp-warden.yaml:ro \
  -v /var/log/routewarden:/var/log/routewarden \
  ghcr.io/routewarden/tcp-warden:latest
```

Or deploy alongside CrowdSec via `docker-compose.yml`:

```bash
docker compose up -d
```

---

## Ecosystem Integration

- **RouteWarden CLI (`rwarden`)**:
  - Generate starter configurations: `rwarden generate tcp-warden > tcp-warden.yaml`
  - Offline verification: `rwarden validate tcp-warden.yaml`
  - Dashboard monitoring: `rwarden dashboard --log /var/log/routewarden/tcp-warden.jsonl`
- **CrowdSec**:
  - Full acquisition and parsers included under `crowdsec/`.

---

## License

MIT © [RouteWarden](https://github.com/routewarden)
