# Phase 14c — Network Security Hardening

## Status: OPEN

Supplement to `PHASE_14.md` and `PHASE_14b.md`.

Addresses the network security layer that the parent document leaves underspecified:
internal TLS, Docker network segmentation, container hardening, egress control,
certificate lifecycle, anomaly alerting, and backend TLS validation. These items
were flagged as CRITICAL/HIGH in `docs/security/COMPREHENSIVE_SECURITY_AUDIT.md`
(items #4 and #5) and in `docs/DMZ_DEPLOYMENT_READINESS.md` (P1 remediation).

---

## 1. Network Topology

### 1.1 PoC / Single-Host (`docker-compose.yml`)

The existing PoC already has two networks (`ja4proxy-frontend`, `ja4proxy-backend`).
This phase adds a third:

```
┌─────────────────────────────────────────────────────────────────────┐
│  net-edge  172.28.0.0/24        internet-facing tier                │
│    HAProxy :443 :80                                                 │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ TCP :8080  (PROXY protocol)
┌──────────────────────────▼──────────────────────────────────────────┐
│  net-proxy  172.29.0.0/24       data-plane tier                     │
│    JA4proxy ×N     mock-backend :8443     Redis (read/write)        │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ Redis Streams + AUTH + TLS
┌──────────────────────────▼──────────────────────────────────────────┐
│  net-mgmt  172.30.0.0/24        management + observability tier     │
│    Analytics node      Management FastAPI      Prometheus           │
│    Grafana             Nginx (TLS → FastAPI Unix socket)            │
└─────────────────────────────────────────────────────────────────────┘
```

**Key isolation properties:**

| Rule | Enforcement |
|------|-------------|
| HAProxy has no route to `net-mgmt` | HAProxy joined only to `net-edge` + `net-proxy` |
| Internet has no route to Redis | Redis on `net-proxy` only; no host port published |
| Internet has no route to `net-mgmt` | `net-mgmt` has no container on `net-edge` |
| Analytics cannot reach internet | Analytics joined only to `net-mgmt`; nftables egress rule |
| Management FastAPI cannot reach internet | Same |
| Prometheus scrapes from `net-mgmt` only | All `*/metrics` bound to `net-mgmt` interface |

### 1.2 Production / Multi-Host (`docker-compose.prod.yml`)

The existing production file already defines four networks. This phase adds the
management tier split and enforces that Redis is never on `net-edge`:

```
net-edge        172.20.0.0/24   HAProxy only
net-proxy       172.21.0.0/24   JA4proxy ×N, Redis cluster, Backend
net-monitoring  172.22.0.0/24   Prometheus, Grafana, Alertmanager
net-management  172.23.0.0/24   Analytics, Management FastAPI, Nginx, Kibana
```

Redis nodes appear on `net-proxy` and `net-management`. **Never** on `net-edge`.
The Analytics node appears on `net-management` **only** — it writes findings to Redis
over `net-management`, not directly to `net-proxy`.

### 1.3 `docker-compose.yml` network block

```yaml
networks:
  net-edge:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/24
    driver_opts:
      com.docker.network.bridge.name: br-ja4-edge
  net-proxy:
    driver: bridge
    internal: true          # No default gateway — cannot reach internet
    ipam:
      config:
        - subnet: 172.29.0.0/24
    driver_opts:
      com.docker.network.bridge.name: br-ja4-proxy
  net-mgmt:
    driver: bridge
    internal: true          # No default gateway
    ipam:
      config:
        - subnet: 172.30.0.0/24
    driver_opts:
      com.docker.network.bridge.name: br-ja4-mgmt
```

`internal: true` removes the default gateway from those networks. Containers on
`net-proxy` and `net-mgmt` cannot initiate outbound connections unless a specific
host route is added (see §6 Egress). HAProxy on `net-edge` has a normal gateway
for internet traffic.

### 1.4 Per-service network assignment

```yaml
services:
  haproxy:
    networks: [net-edge, net-proxy]

  proxy:
    networks: [net-proxy]         # only the data plane
    # AbuseIPDB / RDAP / DNS calls: see §6 selective egress

  redis:
    networks: [net-proxy, net-mgmt]
    # net-proxy: proxy instances read/write
    # net-mgmt: analytics and management read/write

  analytics:
    networks: [net-mgmt]

  management:
    networks: [net-mgmt]

  nginx:                          # TLS termination for management UI
    networks: [net-mgmt]
    ports:
      - "127.0.0.1:8090:8090"    # host-exposed only on loopback
```

---

## 2. Internal CA and Certificate Lifecycle

### 2.1 One-time setup

```bash
# scripts/gen-internal-certs.sh
#!/bin/bash
set -euo pipefail

CERT_DIR="${CERT_DIR:-certs/internal}"
DAYS_CA=3650
DAYS_SVC=365
COUNTRY="IE"
ORG="JA4Proxy"

mkdir -p "${CERT_DIR}"
cd "${CERT_DIR}"

# ── CA ──────────────────────────────────────────────────────────────────
openssl genrsa -out ca.key 4096
openssl req -new -x509 -key ca.key -out ca.crt \
  -days "${DAYS_CA}" \
  -subj "/C=${COUNTRY}/O=${ORG}/CN=ja4proxy-internal-ca"
chmod 400 ca.key

# ── Per-service certs ───────────────────────────────────────────────────
for SVC in redis proxy analytics management nginx prometheus; do
  openssl genrsa -out "${SVC}.key" 2048
  openssl req -new -key "${SVC}.key" \
    -out "${SVC}.csr" \
    -subj "/C=${COUNTRY}/O=${ORG}/CN=${SVC}.ja4proxy.internal"
  openssl x509 -req \
    -in "${SVC}.csr" \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "${SVC}.crt" \
    -days "${DAYS_SVC}" \
    -extfile <(printf "subjectAltName=DNS:%s.ja4proxy.internal,DNS:localhost,IP:127.0.0.1" "${SVC}")
  chmod 400 "${SVC}.key"
  rm "${SVC}.csr"
done

echo "Certs written to ${CERT_DIR}/"
echo "CA fingerprint: $(openssl x509 -in ca.crt -noout -fingerprint -sha256)"
```

All cert material lives in `certs/internal/` (gitignored). The CA key never leaves
the deployment host. Renew service certs annually with `scripts/rotate-certs.sh`
(see §2.3).

### 2.2 Compose volume mount

```yaml
secrets:
  ca_cert:
    file: ./certs/internal/ca.crt
  redis_cert:
    file: ./certs/internal/redis.crt
  redis_key:
    file: ./certs/internal/redis.key
  proxy_cert:
    file: ./certs/internal/proxy.crt
  proxy_key:
    file: ./certs/internal/proxy.key
  management_cert:
    file: ./certs/internal/management.crt
  management_key:
    file: ./certs/internal/management.key
  nginx_cert:
    file: ./certs/internal/nginx.crt
  nginx_key:
    file: ./certs/internal/nginx.key

services:
  redis:
    secrets:
      - ca_cert
      - redis_cert
      - redis_key

  proxy:
    secrets:
      - ca_cert
      - proxy_cert
      - proxy_key
```

Docker secrets are mounted as files under `/run/secrets/` inside the container.
They never appear in `docker inspect` environment output. Secret files are owned
by root:root 0400 by default; containers that need them must run as root or have
the file chown'd to their service UID in an entrypoint script.

### 2.3 Cert expiry monitoring

Add to `monitoring/prometheus/prometheus.yml`:

```yaml
scrape_configs:
  - job_name: cert_expiry
    metrics_path: /probe
    params:
      module: [tls_connect]
    static_configs:
      - targets:
          - redis.ja4proxy.internal:6380
          - management.ja4proxy.internal:8090
          - proxy.ja4proxy.internal:9090   # metrics endpoint
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: blackbox-exporter:9115
```

AlertManager rule (add to `monitoring/alertmanager/rules/certs.rules.yml`):

```yaml
groups:
  - name: certificate_expiry
    rules:
      - alert: InternalCertExpiringSoon
        expr: probe_ssl_earliest_cert_expiry - time() < 30 * 24 * 3600
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "Internal cert expiring in < 30 days: {{ $labels.instance }}"

      - alert: InternalCertExpiryCritical
        expr: probe_ssl_earliest_cert_expiry - time() < 7 * 24 * 3600
        for: 15m
        labels:
          severity: critical
        annotations:
          summary: "Internal cert expires in < 7 days: {{ $labels.instance }}"

      - alert: InternalCertExpired
        expr: probe_ssl_earliest_cert_expiry - time() < 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Internal cert EXPIRED: {{ $labels.instance }}"
```

### 2.4 Zero-downtime cert rotation

```bash
# scripts/rotate-certs.sh
# Rotates a single service cert without restarting Redis/proxy.
# Usage: ./scripts/rotate-certs.sh redis
SVC="$1"
CERT_DIR="certs/internal"

# 1. Generate new cert (old cert stays in place)
openssl genrsa -out "${CERT_DIR}/${SVC}.key.new" 2048
openssl req -new -key "${CERT_DIR}/${SVC}.key.new" \
  -out "${CERT_DIR}/${SVC}.csr" \
  -subj "/C=IE/O=JA4Proxy/CN=${SVC}.ja4proxy.internal"
openssl x509 -req \
  -in "${CERT_DIR}/${SVC}.csr" \
  -CA "${CERT_DIR}/ca.crt" -CAkey "${CERT_DIR}/ca.key" -CAcreateserial \
  -out "${CERT_DIR}/${SVC}.crt.new" \
  -days 365 \
  -extfile <(printf "subjectAltName=DNS:%s.ja4proxy.internal,DNS:localhost" "${SVC}")

# 2. Atomically swap
mv "${CERT_DIR}/${SVC}.crt.new" "${CERT_DIR}/${SVC}.crt"
mv "${CERT_DIR}/${SVC}.key.new" "${CERT_DIR}/${SVC}.key"
rm -f "${CERT_DIR}/${SVC}.csr"

# 3. Signal service to reload (no restart needed for Redis, Nginx)
case "${SVC}" in
  redis)
    docker compose exec redis redis-cli --tls \
      --cert /run/secrets/redis_cert \
      --key /run/secrets/redis_key \
      --cacert /run/secrets/ca_cert \
      CONFIG REWRITE
    docker compose kill -s SIGHUP redis
    ;;
  nginx)
    docker compose kill -s SIGHUP nginx
    ;;
  proxy)
    # Python proxy: SIGHUP triggers hot reload
    docker compose kill -s SIGHUP proxy
    ;;
esac
echo "Cert rotated for ${SVC}. Old connections unaffected until they close."
```

---

## 3. TLS for Every Internal Connection

### 3.1 Proxy → Backend TLS (fixes audit item #4 CRITICAL)

`proxy.py` currently opens the backend connection with no SSL context. Fix:

```python
# src/security/backend_tls.py

import ssl
import os

def make_backend_ssl_context(config: dict) -> ssl.SSLContext | None:
    """
    Build an SSLContext for the proxy → backend connection.
    Returns None if backend TLS is disabled (PoC mode only).
    Raises at startup if cert files are configured but unreadable.
    """
    tls_cfg = config.get("backend", {}).get("tls", {})
    if not tls_cfg.get("enabled", False):
        return None

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = tls_cfg.get("verify_hostname", True)
    ctx.verify_mode = ssl.CERT_REQUIRED

    ca_path = tls_cfg.get("ca_cert_path") or os.environ.get("BACKEND_CA_CERT")
    if ca_path:
        ctx.load_verify_locations(cafile=ca_path)
    else:
        ctx.load_default_certs()

    # Optional mTLS: present our client cert to the backend
    client_cert = tls_cfg.get("client_cert_path") or os.environ.get("BACKEND_CLIENT_CERT")
    client_key  = tls_cfg.get("client_key_path")  or os.environ.get("BACKEND_CLIENT_KEY")
    if client_cert and client_key:
        ctx.load_cert_chain(certfile=client_cert, keyfile=client_key)

    return ctx
```

`proxy.py` `_forward_to_backend()` passes the context to `asyncio.open_connection`:

```python
ssl_ctx = make_backend_ssl_context(self.config)
reader, writer = await asyncio.open_connection(
    self.backend_host,
    self.backend_port,
    ssl=ssl_ctx,
    server_hostname=self.backend_host if ssl_ctx else None,
)
```

`config/proxy.yml` addition:

```yaml
backend:
  host: "127.0.0.1"
  port: 8443
  tls:
    enabled: true               # Default: true. Set false only for PoC/dev.
                                # CAUTION: disabling sends plaintext to backend.
    verify_hostname: true       # Default: true. Verifies backend cert CN/SAN.
    ca_cert_path: ""            # CA cert for backend; "" uses system trust store.
                                # Set via BACKEND_CA_CERT env var.
    client_cert_path: ""        # Optional: present client cert (mTLS to backend).
    client_key_path: ""         # Set via BACKEND_CLIENT_CERT / BACKEND_CLIENT_KEY.
```

Startup emits a WARNING if `backend.tls.enabled = false`:

```
WARN | tls | event=backend_tls_disabled | effect=proxy→backend traffic is plaintext
```

### 3.2 Proxy → Redis TLS (fixes audit item #5 CRITICAL)

Redis 6+ supports TLS natively. Configuration in `redis.conf` (mounted as volume):

```
# redis.conf
tls-port 6380
port 0                          # Disable plaintext port entirely

tls-cert-file /run/secrets/redis_cert
tls-key-file  /run/secrets/redis_key
tls-ca-cert-file /run/secrets/ca_cert

tls-auth-clients yes            # Require client cert (mTLS)
tls-protocols "TLSv1.2 TLSv1.3"
tls-ciphers "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES256-GCM-SHA384"
tls-prefer-server-ciphers yes
```

`proxy.py` Redis connection (in `_init_redis()`):

```python
redis_url = self.config["redis"]["url"]   # redis://localhost:6380
ssl_cfg   = self.config["redis"].get("tls", {})

if ssl_cfg.get("enabled", False):
    import ssl as ssl_mod
    ctx = ssl_mod.SSLContext(ssl_mod.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl_mod.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cafile=ssl_cfg["ca_cert_path"])
    ctx.load_cert_chain(
        certfile=ssl_cfg["client_cert_path"],
        keyfile=ssl_cfg["client_key_path"],
    )
    self.redis_client = await aioredis.from_url(
        redis_url,
        ssl=ctx,
        ssl_certfile=ssl_cfg["client_cert_path"],
        ssl_keyfile=ssl_cfg["client_key_path"],
        ssl_ca_certs=ssl_cfg["ca_cert_path"],
        decode_responses=True,
    )
else:
    self.redis_client = await aioredis.from_url(redis_url, decode_responses=True)
```

`config/proxy.yml`:

```yaml
redis:
  url: "rediss://redis:6380"    # rediss:// enables TLS in redis-py
  tls:
    enabled: true               # Default: true in production.
    ca_cert_path: "/run/secrets/ca_cert"
    client_cert_path: "/run/secrets/proxy_cert"
    client_key_path: "/run/secrets/proxy_key"
```

### 3.3 Analytics → Redis TLS

Same pattern as §3.2. The Analytics node uses `redis-py` (`redis.asyncio`) with the
`analytics` client cert:

```python
# analytics/redis_client.py
def make_redis_client(config):
    tls = config.get("redis", {}).get("tls", {})
    if tls.get("enabled"):
        return Redis(
            host=..., port=6380,
            ssl=True,
            ssl_certfile=tls["client_cert_path"],
            ssl_keyfile=tls["client_key_path"],
            ssl_ca_certs=tls["ca_cert_path"],
        )
    return Redis(host=..., port=6379)
```

### 3.4 Management FastAPI → Redis TLS

Same. The management server's `get_redis()` in `server.py` passes the `management`
client cert pair.

### 3.5 HAProxy → JA4proxy

**Same host:** Use a UNIX socket instead of TCP. No encryption needed; UNIX domain
sockets are isolated to the filesystem:

```
# haproxy.cfg
backend ja4proxy_backend
    server proxy unix@/var/run/ja4proxy/proxy.sock

# proxy.py listens on socket
bind_path: "/var/run/ja4proxy/proxy.sock"   # new config key; exclusive with bind_host
```

Socket permissions: `srw-------` owned by `haproxy:ja4proxy` (shared group).

**Cross-host (production multi-instance):** TLS with the `proxy` service cert.
HAProxy validates the proxy cert against the internal CA:

```
# haproxy.cfg
backend ja4proxy_backend
    option ssl-hello-chk
    server proxy1 172.21.0.10:8080 ssl \
        crt /etc/haproxy/certs/haproxy.pem \
        ca-file /etc/haproxy/certs/ca.crt \
        verify required
```

### 3.6 Prometheus → service metrics endpoints

All `/metrics` endpoints must bind to the `net-mgmt` interface address only (not
`0.0.0.0`). Prometheus scrapes over HTTPS with a self-signed cert. No client cert
required from Prometheus (scraping is one-directional).

Proxy metrics binding:

```yaml
metrics:
  port: 9090
  bind_host: "172.30.0.N"       # net-mgmt IP; never 0.0.0.0
  tls:
    enabled: true
    cert_path: "/run/secrets/proxy_cert"
    key_path: "/run/secrets/proxy_key"
  auth:
    enabled: true               # See §5
    token: ""                   # Set via METRICS_TOKEN env var
```

### 3.7 Management UI: Nginx → FastAPI via Unix socket

```nginx
# nginx/nginx.conf
server {
    listen 8090 ssl;
    ssl_certificate     /run/secrets/nginx_cert;
    ssl_certificate_key /run/secrets/nginx_key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;

    location / {
        proxy_pass http://unix:/var/run/management/fastapi.sock;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

FastAPI binds to the Unix socket only (never to a TCP port):

```python
# management/main.py
import uvicorn
uvicorn.run(
    "management.server:create_app",
    uds="/var/run/management/fastapi.sock",
    factory=True,
)
```

Socket volume shared between `nginx` and `management` containers:

```yaml
volumes:
  mgmt_socket:
    driver: local

services:
  management:
    volumes:
      - mgmt_socket:/var/run/management
  nginx:
    volumes:
      - mgmt_socket:/var/run/management
```

---

## 4. Redis Security Depth

### 4.1 ACLs — per-service command restrictions

Redis 6+ ACL file (`redis-acls.conf`, mounted as volume):

```
# redis-acls.conf

# Disable the default user
user default off nopass nocommands

# Proxy: read/write bans, JA4 lists, beaconing, rate limiting, streams
user proxy on >PROXY_PASSWORD \
  ~ban:* ~ja4:* ~beacon:* ~rate:* ~hll:* ~bloom:* ~config:thresholds \
  +GET +SET +DEL +EXPIRE +TTL \
  +SADD +SREM +SISMEMBER +SMEMBERS +SCARD \
  +ZADD +ZRANGEBYSCORE +ZREM +ZCARD \
  +HGET +HSET +HINCRBY +HGETALL \
  +PFADD +PFCOUNT \
  +XADD \
  +PING +AUTH +QUIT

# Analytics: full stream read + write findings
user analytics on >ANALYTICS_PASSWORD \
  ~ja4proxy:events ~analytics:* ~ban_cidr:* \
  +XREAD +XREADGROUP +XACK +XADD +XRANGE +XREVRANGE +XLEN \
  +GET +SET +DEL +EXPIRE \
  +PING +AUTH +QUIT

# Management: full r/w on management keys + dial + policy
user management on >MANAGEMENT_PASSWORD \
  ~ban:* ~ja4:* ~dial:* ~policy:* ~config:* ~management:* \
  ~mgmt:ratelimit:* \
  +GET +SET +DEL +EXPIRE +TTL \
  +SADD +SREM +SISMEMBER +SMEMBERS \
  +HGET +HSET +HGETALL +HMSET \
  +LPUSH +LTRIM +LRANGE +LLEN \
  +INCR +EXPIRE \
  +XADD +XREVRANGE \
  +SCAN \
  +PING +AUTH +QUIT

# Read-only user for Prometheus exporter
user prometheus-exporter on >EXPORTER_PASSWORD \
  ~* \
  +INFO +PING +AUTH +CLIENT +LATENCY +SLOWLOG +CONFIG|GET
```

The proxy user **cannot** call `CONFIG`, `DEBUG`, `SLAVEOF`, `FLUSHDB`, `FLUSHALL`,
`KEYS`, `EVAL`, or `SCRIPT`. These are the dangerous commands historically used in
Redis exploitation.

### 4.2 Rename dangerous commands

Add to `redis.conf` as a defense-in-depth against authenticated clients abusing
dangerous commands even if ACLs are misconfigured:

```
rename-command CONFIG    ""
rename-command DEBUG     ""
rename-command SLAVEOF   ""
rename-command REPLICAOF ""
rename-command FLUSHALL  ""
rename-command FLUSHDB   ""
rename-command KEYS      ""
rename-command EVAL      ""
rename-command SCRIPT    ""
```

`CONFIG` is still needed internally by Redis. Use `config rewrite` only via the
`redis-cli` tool connecting as an admin user with a separate credential.

### 4.3 Protected mode and bind address

```
# redis.conf (additions)
protected-mode yes          # Refuses connections if no auth and no bind specified
bind 172.29.0.N 172.30.0.N ::1  # Explicit interface bind; never 0.0.0.0
```

### 4.4 Persistence

```
appendonly yes
appendfsync everysec        # fsync every second — balance between durability and perf
no-appendfsync-on-rewrite no
```

---

## 5. Metrics Endpoint Authentication

The Prometheus `/metrics` endpoint is currently unauthenticated (audit item HIGH #1).

Add Bearer token validation to the metrics endpoint in `proxy.py`:

```python
# src/observability/metrics_auth.py

import os
import hmac
import hashlib

_METRICS_TOKEN: str = ""

def load_metrics_token() -> None:
    global _METRICS_TOKEN
    _METRICS_TOKEN = os.environ.get("METRICS_TOKEN", "")
    if not _METRICS_TOKEN:
        logger.warning(
            "observability | event=metrics_auth_disabled "
            "| effect=Prometheus /metrics endpoint is unauthenticated"
        )

def validate_metrics_request(authorization: str) -> bool:
    if not _METRICS_TOKEN:
        return True   # fail open if not configured
    if not authorization or not authorization.startswith("Bearer "):
        return False
    token = authorization[7:]
    return hmac.compare_digest(
        token.encode(),
        _METRICS_TOKEN.encode(),
    )
```

Alternative for Prometheus scraping: IP-allowlist only (simpler, no token
rotation needed):

```python
METRICS_ALLOWED_CIDRS = os.environ.get("METRICS_ALLOWED_CIDRS", "172.30.0.0/24")
```

Prometheus scrape config with bearer token:

```yaml
scrape_configs:
  - job_name: ja4proxy
    scheme: https
    tls_config:
      ca_file: /etc/prometheus/certs/ca.crt
    authorization:
      credentials_file: /etc/prometheus/metrics_token
    static_configs:
      - targets: ["proxy:9090"]
```

---

## 6. Egress Filtering

### 6.1 Why it matters

A compromised analytics or management container should not be able to:
- Exfiltrate ban lists, API keys, or internal config to an attacker's server
- Reach the internet to download additional payloads
- Pivot to the proxy data plane

Docker's `internal: true` network removes the default gateway but does not prevent
all outbound traffic — a container could still reach other containers on networks it's
legitimately joined to. nftables rules on the host enforce the additional constraints.

### 6.2 Host nftables rules

Add to `/etc/nftables.d/ja4proxy.nft` (applied by Ansible; see §14f):

```nft
table inet ja4proxy {

  chain DOCKER-USER {
    type filter hook forward priority -1; policy accept;

    # ── Block net-mgmt → net-edge (should be impossible by network topology) ──
    iifname "br-ja4-mgmt" oifname "br-ja4-edge" \
      log prefix "JA4_ANOMALOUS_MGMT_EDGE: " level warn \
      counter drop

    # ── Block net-proxy → internet (proxy needs selective egress; see below) ──
    # Proxy containers need AbuseIPDB (api.abuseipdb.com:443),
    # RDAP (IANA bootstrap + RIR endpoints), and DNS.
    # Allow only those; drop everything else from net-proxy to internet.
    iifname "br-ja4-proxy" oifname != "br-ja4-proxy" \
      ip daddr != @proxy_allowed_egress \
      log prefix "JA4_BLOCKED_EGRESS: " level warn \
      counter drop

    # ── Block net-mgmt → internet ──────────────────────────────────────────────
    iifname "br-ja4-mgmt" oifname != { "br-ja4-proxy", "br-ja4-mgmt" } \
      log prefix "JA4_ANOMALOUS_MGMT_INET: " level warn \
      counter drop
  }

  # Proxy's allowed external destinations
  set proxy_allowed_egress {
    type ipv4_addr
    flags interval
    # Populated at deploy time by scripts/update-egress-allowlist.sh
    # DNS resolvers:
    elements = { 8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1 }
  }
}
```

The `proxy_allowed_egress` set is populated with the resolved IP ranges of
AbuseIPDB, RDAP IANA bootstrap, and the GeoLite2 update CDN at deploy time:

```bash
# scripts/update-egress-allowlist.sh
# Run at deploy and weekly via cron; resolves and updates the nftables set.
for host in api.abuseipdb.com rdap.iana.org; do
  dig +short "$host" | grep -E '^[0-9.]+$'
done | while read -r ip; do
  nft add element inet ja4proxy proxy_allowed_egress "{ ${ip} }"
done
```

### 6.3 Anomalous connection alerting

The LOG rules above write to the kernel ring buffer. `journald` captures them.
A systemd unit reads them and feeds a Prometheus text file:

```bash
# /usr/local/bin/ja4proxy-anomaly-counter.sh (run via systemd timer, every 30s)
#!/bin/bash
COUNT=$(journalctl -k --since "30s ago" --no-pager -q \
  | grep -c "JA4_ANOMALOUS" || true)
echo "# HELP ja4proxy_anomalous_network_connections_total" \
  > /var/lib/node_exporter/ja4proxy_network.prom.tmp
echo "# TYPE ja4proxy_anomalous_network_connections_total counter" \
  >> /var/lib/node_exporter/ja4proxy_network.prom.tmp
echo "ja4proxy_anomalous_network_connections_total ${COUNT}" \
  >> /var/lib/node_exporter/ja4proxy_network.prom.tmp
mv /var/lib/node_exporter/ja4proxy_network.prom.tmp \
  /var/lib/node_exporter/ja4proxy_network.prom
```

AlertManager rule:

```yaml
- alert: AnomalousContainerNetworkTraffic
  expr: increase(ja4proxy_anomalous_network_connections_total[5m]) > 0
  for: 0m
  labels:
    severity: critical
  annotations:
    summary: "Container made a cross-network connection that should be impossible"
    description: >
      A container attempted a network connection that the topology forbids.
      This may indicate a container escape, misconfiguration, or active attack.
      Check kernel logs: journalctl -k | grep JA4_ANOMALOUS
```

---

## 7. Container Runtime Hardening

### 7.1 Base compose stanza (apply to all services)

```yaml
x-hardened: &hardened
  cap_drop: [ALL]
  read_only: true
  tmpfs:
    - /tmp:size=64m,mode=1777
    - /run:size=32m
  security_opt:
    - no-new-privileges:true
    - seccomp:./security/seccomp/default.json
  user: "10001:10001"
  init: true          # tini as PID 1: proper signal handling, zombie reaping

services:
  proxy:
    <<: *hardened
    cap_add: []       # No capabilities needed; bind port > 1024

  redis:
    <<: *hardened
    cap_add: []

  analytics:
    <<: *hardened

  management:
    <<: *hardened

  nginx:
    <<: *hardened
    cap_add: [NET_BIND_SERVICE]   # Needed to bind port 8090
```

### 7.2 Seccomp profile

`security/seccomp/default.json` — start from Docker's default and additionally
block dangerous syscalls:

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    {
      "names": [
        "accept", "accept4", "bind", "close", "connect",
        "epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait",
        "epoll_pwait", "epoll_pwait2",
        "fcntl", "fstat", "futex", "getpid", "getppid",
        "getsockname", "getsockopt", "gettid",
        "listen", "lstat", "mmap", "mprotect", "munmap",
        "nanosleep", "open", "openat", "pipe", "pipe2",
        "poll", "ppoll", "pread64", "pwrite64",
        "read", "readv", "recvfrom", "recvmsg", "recvmmsg",
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
        "select", "sendmsg", "sendto", "sendmmsg",
        "setsockopt", "shutdown", "sigaltstack",
        "socket", "stat", "sysinfo",
        "uname", "write", "writev",
        "exit", "exit_group",
        "arch_prctl", "brk", "clone", "clone3",
        "set_robust_list", "set_tid_address",
        "tgkill", "wait4", "waitid"
      ],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "names": [
        "ptrace", "process_vm_readv", "process_vm_writev",
        "keyctl", "add_key", "request_key",
        "userfaultfd", "perf_event_open",
        "init_module", "finit_module", "delete_module",
        "kexec_load", "kexec_file_load",
        "iopl", "ioperm",
        "swapon", "swapoff",
        "mount", "umount2",
        "chroot", "pivot_root",
        "setns", "unshare"
      ],
      "action": "SCMP_ACT_ERRNO"
    }
  ]
}
```

The blocked list prevents: debugging/tracing other processes (`ptrace`), kernel
module loading, mounting filesystems, and namespace manipulation — the most common
container escape vectors.

### 7.3 Read-only filesystem exceptions

Services that need writable paths must declare them explicitly:

| Service | Writable paths | Why |
|---------|---------------|-----|
| proxy | `/tmp`, `/run` | Temp files, socket, PID file |
| redis | `/data` (volume) | AOF persistence |
| analytics | `/tmp` | NumPy temp files |
| management | `/tmp`, `/run/management` | Socket to Nginx |
| nginx | `/tmp`, `/run`, `/var/cache/nginx` | Nginx temp files |

### 7.4 Non-root users

Each service runs as a dedicated UID:

```dockerfile
# In each service's Dockerfile
RUN groupadd -g 10001 ja4proxy && \
    useradd -u 10001 -g ja4proxy -s /sbin/nologin -M ja4proxy
USER 10001:10001
```

`docker compose` `user: "10001:10001"` overrides the image default if needed.

### 7.5 Image security

All base images pinned by digest in `docker-compose.prod.yml`:

```yaml
services:
  proxy:
    image: python:3.12-slim@sha256:<digest>
```

Image vulnerability scanning in CI (add to `.github/workflows/ci.yml` or
equivalent):

```yaml
- name: Scan proxy image
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: ja4proxy-proxy:latest
    severity: CRITICAL,HIGH
    exit-code: 1            # Fail CI on critical/high vulns
    ignore-unfixed: false
```

SBOM generation (add to release pipeline):

```bash
syft ja4proxy-proxy:latest -o spdx-json > sbom-proxy.spdx.json
```

---

## 8. PROXY Protocol Spoof Prevention

The proxy trusts the source IP in the PROXY protocol header only from known upstream
CIDRs (`trusted_cidrs` in config). The network layer must enforce this at the
firewall level so that an attacker on the same network cannot spoof a PROXY header
and impersonate a trusted CDN:

```nft
# Only HAProxy's container IPs may connect to proxy port 8080
# (or the UNIX socket path if using §3.5 same-host deployment)
table inet ja4proxy {
  chain proxy_ingress {
    type filter hook input priority 0; policy drop;

    # Allow established connections
    ct state { established, related } accept

    # Allow from HAProxy container IP range only
    ip saddr 172.28.0.0/24 tcp dport 8080 accept

    # Log and drop everything else to port 8080
    tcp dport 8080 log prefix "JA4_PROXY_SPOOF_ATTEMPT: " level warn drop
  }
}
```

AlertManager rule:

```yaml
- alert: ProxyProtocolSpoofAttempt
  expr: increase(ja4proxy_anomalous_network_connections_total{type="proxy_spoof"}[5m]) > 0
  for: 0m
  labels:
    severity: critical
  annotations:
    summary: "Connection to proxy port 8080 from non-HAProxy source"
```

---

## 9. Dependency and Supply Chain Security

### 9.1 Python dependencies

Add to CI pipeline:

```bash
# Check Python deps for known CVEs
pip-audit --requirement requirements.txt --format json --output pip-audit.json
# Fail on any critical/high CVE
python3 -c "
import json, sys
data = json.load(open('pip-audit.json'))
critical = [v for dep in data['dependencies'] for v in dep.get('vulns',[])
            if v.get('fix_versions')]
if critical:
    print('Vulnerable packages found:', critical)
    sys.exit(1)
"
```

### 9.2 Go dependencies (Phase 15 onwards)

```bash
govulncheck ./...
goleak       # Goroutine leak detector
```

### 9.3 Dependency pinning

`requirements.txt` must pin to exact versions (already done). Add a weekly
`dependabot` or `renovate` config to surface security updates:

```yaml
# .github/dependabot.yml
updates:
  - package-ecosystem: pip
    directory: /
    schedule:
      interval: weekly
    open-pull-requests-limit: 5
```

---

## 10. Docker Daemon Security

If Docker daemon remote API is enabled for CI/CD:

```json
{
  "tls": true,
  "tlsverify": true,
  "tlscacert": "/etc/docker/ca.pem",
  "tlscert":   "/etc/docker/server-cert.pem",
  "tlskey":    "/etc/docker/server-key.pem",
  "hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2376"]
}
```

Only CI/CD agents with a valid client cert signed by the Docker daemon CA may
connect on port 2376. The Unix socket remains for local admin use.

If remote API is not needed, ensure it's not listening:

```bash
# Verify: should show only unix socket
ss -tlnp | grep dockerd
```

---

## 11. Structured Log Events Added in This Phase

All new log events follow the schema in `docs/OBSERVABILITY_STANDARDS.md §2`.

| event | level | fields |
|-------|-------|--------|
| `backend_tls_disabled` | WARN | `host`, `port` |
| `backend_tls_cert_error` | ERROR | `host`, `error` |
| `redis_tls_disabled` | WARN | `url` |
| `redis_tls_cert_error` | FATAL | `url`, `error` |
| `metrics_auth_disabled` | WARN | `bind`, `effect` |
| `cert_expiry_warning` | WARN | `service`, `days_remaining` |
| `anomalous_network_connection` | CRITICAL | `src_network`, `dst_network`, `src_ip`, `dst_ip` |
| `proxy_spoof_attempt` | CRITICAL | `src_ip`, `port`, `protocol` |
| `egress_blocked` | WARN | `container`, `dst_ip`, `dst_port` |

---

## 12. Prometheus Metrics Added in This Phase

| Metric | Type | Labels | Notes |
|--------|------|--------|-------|
| `ja4proxy_anomalous_network_connections_total` | Counter | `type` | From kernel log feed |
| `ja4proxy_tls_backend_errors_total` | Counter | `error_type` | Backend TLS handshake failures |
| `ja4proxy_tls_redis_errors_total` | Counter | `error_type` | Redis TLS conn failures |
| `ja4proxy_cert_expiry_days` | Gauge | `service` | From blackbox exporter |
| `ja4proxy_container_egress_blocked_total` | Counter | `container` | From nftables LOG feed |

---

## 13. New AlertManager Rules

File: `monitoring/alertmanager/rules/network_security.rules.yml`

```yaml
groups:
  - name: network_security
    rules:

      - alert: BackendTLSDisabled
        expr: ja4proxy_config_info{backend_tls="false"} == 1
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Proxy→backend connection is plaintext"

      - alert: RedisTLSDisabled
        expr: ja4proxy_config_info{redis_tls="false"} == 1
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Proxy→Redis connection is plaintext"

      - alert: AnomalousContainerNetworkTraffic
        expr: increase(ja4proxy_anomalous_network_connections_total[5m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Container made a cross-network connection that should be impossible"
          description: "Check: journalctl -k | grep JA4_ANOMALOUS"

      - alert: ProxyProtocolSpoofAttempt
        expr: increase(ja4proxy_anomalous_network_connections_total{type="proxy_spoof"}[5m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Connection to proxy on port 8080 from non-HAProxy source IP"

      - alert: InternalCertExpiringSoon
        expr: ja4proxy_cert_expiry_days < 30
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "Internal cert expires in {{ $value }} days: {{ $labels.service }}"
          description: "Run: ./scripts/rotate-certs.sh {{ $labels.service }}"

      - alert: InternalCertExpiryCritical
        expr: ja4proxy_cert_expiry_days < 7
        for: 15m
        labels:
          severity: critical
        annotations:
          summary: "Internal cert expires in {{ $value }} days: {{ $labels.service }}"

      - alert: ContainerEgressBlocked
        expr: increase(ja4proxy_container_egress_blocked_total[5m]) > 0
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "Container egress blocked by nftables: {{ $labels.container }}"
          description: "A container attempted an unauthorised outbound connection"
```

---

## 14. TDD Test Checklist

Tests must be written before implementation code.

### 14c-unit (`tests/unit/test_network_hardening.py`)

- [ ] `test_backend_tls_disabled_emits_warning` — config `backend.tls.enabled=false` → WARN logged at startup
- [ ] `test_backend_tls_enabled_creates_ssl_context` — `make_backend_ssl_context()` returns `ssl.SSLContext` with `CERT_REQUIRED`
- [ ] `test_backend_tls_wrong_ca_raises_at_startup` — invalid CA path → `FileNotFoundError` at init
- [ ] `test_backend_tls_hostname_verification_on_by_default` — `ctx.check_hostname = True`
- [ ] `test_backend_tls_client_cert_loaded_when_configured` — `ctx.load_cert_chain()` called
- [ ] `test_redis_tls_disabled_emits_warning` — same pattern as backend
- [ ] `test_metrics_token_missing_allows_request` — fail-open when no `METRICS_TOKEN`
- [ ] `test_metrics_token_present_rejects_wrong_token` — 401 on wrong token
- [ ] `test_metrics_token_present_accepts_correct_token` — 200 on correct token
- [ ] `test_metrics_token_timing_safe` — uses `hmac.compare_digest`, not `==`
- [ ] `test_seccomp_profile_is_valid_json` — parses without error
- [ ] `test_seccomp_profile_blocks_ptrace` — `ptrace` in blocked list
- [ ] `test_seccomp_profile_blocks_mount` — `mount` in blocked list
- [ ] `test_redis_acl_proxy_user_cannot_config` — ACL entry for proxy has no `+CONFIG`
- [ ] `test_redis_acl_proxy_user_cannot_flushdb` — `+FLUSHDB` absent
- [ ] `test_redis_acl_analytics_user_cannot_flushdb` — same

### 14c-integration (`tests/integration/test_tls_connections.py`)

- [ ] `test_proxy_connects_to_redis_with_tls` — mock TLS Redis; proxy connects; handshake completes
- [ ] `test_proxy_rejects_redis_with_wrong_cert` — bad server cert → connection fails, proxy continues without Redis (fail open)
- [ ] `test_proxy_backend_tls_handshake` — mock TLS backend; proxy forwards connection; data passes through
- [ ] `test_management_api_requires_https` — plain HTTP to port 8090 → redirect or reject
- [ ] `test_redis_acl_rejects_config_command` — proxy Redis client cannot issue CONFIG; catches error, logs, continues

### 14c-chaos (`tests/chaos/test_network_failures.py`)

- [ ] `test_redis_tls_cert_expires_mid_run` — swap Redis cert at runtime; proxy reconnects; fail open during gap
- [ ] `test_backend_tls_cert_rejected` — mock backend returns wrong cert; proxy logs error, sends 502 to client, does not crash
- [ ] `test_network_partition_between_proxy_and_redis` — drop net-proxy→redis; proxy fails open; connections continue

### 14c-adversarial (`tests/adversarial/test_proxy_spoof.py`)

- [ ] `test_proxy_header_from_untrusted_cidr_rejected` — PROXY protocol from non-HAProxy IP → client IP not trusted
- [ ] `test_proxy_header_from_trusted_cidr_accepted` — PROXY protocol from HAProxy CIDR → real IP extracted

### 14c-performance (`tests/performance/bench_tls.py`)

- [ ] `test_tls_backend_connection_overhead` — p99 latency overhead vs plaintext < 2ms for established connections
- [ ] `test_tls_redis_connection_overhead` — per-command TLS overhead < 0.5ms p99

---

## 15. Acceptance Criteria

### 15a. Network topology

- [ ] `docker network inspect br-ja4-proxy` shows no gateway (internal network)
- [ ] `docker network inspect br-ja4-mgmt` shows no gateway (internal network)
- [ ] Analytics container cannot ping 8.8.8.8 (egress blocked)
- [ ] Management container cannot ping 8.8.8.8 (egress blocked)
- [ ] Proxy container CAN reach AbuseIPDB API (selective egress allowed)
- [ ] Redis has no published port on the host (`docker port redis` is empty)

### 15b. TLS

- [ ] `openssl s_client -connect redis:6380` with wrong client cert → `HANDSHAKE_FAILURE`
- [ ] `openssl s_client -connect redis:6380` with valid proxy cert → `Verify return code: 0`
- [ ] `openssl s_client -connect nginx:8090` shows TLS 1.3 negotiated
- [ ] HTTP (plain) to port 8090 → rejected or redirected
- [ ] Backend TLS disabled → WARN in startup log; metric `ja4proxy_config_info{backend_tls="false"}` == 1
- [ ] Redis TLS disabled → WARN in startup log; metric `ja4proxy_config_info{redis_tls="false"}` == 1

### 15c. Redis ACLs

- [ ] `redis-cli -u proxy CONFIG GET maxmemory` → `(error) NOPERM`
- [ ] `redis-cli -u proxy FLUSHDB` → `(error) NOPERM`
- [ ] `redis-cli -u proxy KEYS '*'` → `(error) NOPERM`
- [ ] `redis-cli -u analytics XREAD COUNT 1 STREAMS ja4proxy:events 0` → succeeds
- [ ] `redis-cli -u analytics FLUSHDB` → `(error) NOPERM`

### 15d. Container hardening

- [ ] `docker inspect proxy | jq '.[].HostConfig.CapDrop'` → `["ALL"]`
- [ ] `docker inspect proxy | jq '.[].HostConfig.ReadonlyRootfs'` → `true`
- [ ] `docker inspect proxy | jq '.[].HostConfig.SecurityOpt'` → includes `no-new-privileges:true`
- [ ] Process inside proxy container runs as UID 10001 (`docker exec proxy id`)
- [ ] `docker exec proxy mount` → no writable mounts except declared tmpfs and volumes

### 15e. Anomaly alerting

- [ ] Manually inject a LOG-triggering packet (via `iptables` TRACE) → AlertManager fires within 60s
- [ ] Cert with 6 days remaining → `InternalCertExpiryCritical` fires within 15 minutes
- [ ] Cert with 29 days remaining → `InternalCertExpiringSoon` fires within 1 hour

### 15f. Operational

- [ ] `./scripts/gen-internal-certs.sh` completes without error; produces 7 cert/key pairs
- [ ] `./scripts/rotate-certs.sh redis` replaces cert without restarting Redis container
- [ ] `./scripts/rotate-certs.sh nginx` replaces cert without restarting Nginx container; connection drops < 1s
- [ ] `promtool check rules monitoring/alertmanager/rules/network_security.rules.yml` → OK

---

## 16. Files Added or Modified in This Phase

```
scripts/gen-internal-certs.sh       NEW — internal CA + per-service certs
scripts/rotate-certs.sh             NEW — zero-downtime cert rotation
scripts/update-egress-allowlist.sh  NEW — refresh nftables proxy egress set
/etc/nftables.d/ja4proxy.nft        NEW — host-level network rules (via Ansible)
security/seccomp/default.json       NEW — custom seccomp profile
redis-acls.conf                     NEW — Redis ACL file
nginx/nginx.conf                    NEW — TLS termination + Unix socket proxy
src/security/backend_tls.py         NEW — SSLContext factory for proxy→backend
src/observability/metrics_auth.py   NEW — Bearer/IP auth for /metrics
management/main.py                  MODIFY — bind to Unix socket
monitoring/alertmanager/rules/network_security.rules.yml  NEW
monitoring/alertmanager/rules/certs.rules.yml             NEW
docs/phases/PHASE_14c.md            NEW (this file)
docker-compose.yml                  MODIFY — three networks, secrets, hardening stanza
docker-compose.prod.yml             MODIFY — align with three-tier model
config/proxy.yml                    MODIFY — backend.tls, redis.tls, metrics.tls sections
tests/unit/test_network_hardening.py        NEW (16 tests)
tests/integration/test_tls_connections.py  NEW (5 tests)
tests/chaos/test_network_failures.py        NEW (3 tests)
tests/adversarial/test_proxy_spoof.py       NEW (2 tests)
tests/performance/bench_tls.py              NEW (2 tests)
docs/REDIS_SCHEMA.md                MODIFY — no new keys; document ACL user mapping
docs/decisions/ADR-014c.md          NEW — why nftables over in-container firewall
```

---

## 17. ADR-014c — Why nftables on Host, Not In-Container Firewall

**Context:** We need to enforce network isolation between Docker containers.
Options considered:

| Option | Pros | Cons |
|--------|------|------|
| `NET_ADMIN` + iptables inside container | Familiar; per-container | Requires privileged cap; if container is compromised, attacker can modify its own rules |
| Docker network `internal: true` | Simple; enforced by daemon | Only removes default gateway; doesn't prevent lateral movement within a network |
| Host nftables keyed to bridge CIDRs | Enforced outside container; attacker cannot modify | Requires host-level Ansible; tied to Docker bridge naming |
| Kubernetes NetworkPolicy | Ideal for K8s; enforced by CNI | Not applicable in Docker Compose deployment |

**Decision:** Host nftables rules, applied via Ansible, keyed to the Docker bridge
interface names (`br-ja4-*`). Rules are written outside any container and cannot be
modified by a compromised container (no `NET_ADMIN` capability). Complement with
`internal: true` on `net-proxy` and `net-mgmt` for a defence-in-depth layer.

**Consequences:**
- Ansible must be run on the Docker host; not portable to managed container runtimes
- Bridge names must be stable; the `com.docker.network.bridge.name` driver option
  makes them stable across restarts
- Revisit: if deployment moves to K8s, replace with NetworkPolicy resources
