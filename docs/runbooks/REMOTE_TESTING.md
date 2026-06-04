# Remote Manual Testing — JA4proxy

Test the full JA4proxy stack from a remote laptop: browser, curl, bot, logs,
and dashboards.

---

## Quick start

```bash
# 1. On the proxy server, start everything with remote access
make remote-start

# 2. Wait for services to stabilize
make remote-status

# 3. Verify your laptop can reach the proxy
curl -sk https://<SERVER_IP>:443

# 4. Open the Management UI
#    http://<SERVER_IP>:8090/login

# 5. Open Grafana dashboards
#    http://<SERVER_IP>:3001/login

# 6. Run the test bot
python3 scripts/test-bot.py --proxy <SERVER_IP> --port 443

# 7. Done? Close the ports
make remote-stop
```

---

## Prerequisites

- **`.env` file** on the proxy server with these values set:
  ```bash
  REDIS_PASSWORD=<your-redis-password>
  GRAFANA_PASSWORD=<your-grafana-password>
  UI_PASSWORD=<management-ui-password>
  BACKEND_HOST=<your-backend-host-or-ip>
  ```
- **Docker + docker compose** on the proxy server
- **Network** — your laptop must be able to reach the proxy server's IP on
  the ports listed below. If they're on different networks, use an SSH tunnel
  (see below).
- **Proxy server started** with `make remote-start` (not `make start`, which
  only binds to 127.0.0.1)

---

## Port reference

| Port | Service | Protocol | Auth | URL |
|------|---------|----------|------|-----|
| 443 | HAProxy (TLS passthrough) | HTTPS | none | `https://<host>:443` |
| 8404 | HAProxy stats | HTTP | basic | `http://<host>:8404/stats` |
| 8081 | Direct proxy | HTTPS | none | `https://<host>:8081` |
| 9090 | Proxy metrics | HTTP | none | `http://<host>:9090/metrics` |
| 9091 | Prometheus | HTTP | none | `http://<host>:9091` |
| 3001 | Grafana | HTTP | form | `http://<host>:3001` |
| 8090 | Management UI | HTTP | form | `http://<host>:8090/login` |
| 8091 | Admin API | HTTP | JWT | `http://<host>:8091/docs` |
| 9093 | Alertmanager | HTTP | none | `http://<host>:9093` |

---

## Browser

### Management UI

1. Open `http://<SERVER_IP>:8090/login`
2. Log in with the credentials from `.env` (`UI_USERNAME` / `UI_PASSWORD`)
3. Browse connections, blocking rules, threat intelligence feeds

### Grafana

1. Open `http://<SERVER_IP>:3001/login`
2. Log in as `admin` with the password from `.env` (`GRAFANA_PASSWORD`)
3. Open the **JA4 Proxy Security Dashboard** (auto-provisioned)
4. Browse to **Explore** → select **Loki** datasource → run `{container="ja4proxy"}` to see every log line

### Prometheus

1. Open `http://<SERVER_IP>:9091`
2. Try queries: `ja4proxy_connections_total`, `ja4proxy_blocked_total`, `up`
3. Alert rules at `http://<SERVER_IP>:9093`

---

## Curl

### Through HAProxy (port 443 — TLS passthrough)

```bash
# Basic connectivity
curl -sk https://<SERVER_IP>:443

# Check the backend response
curl -sk https://<SERVER_IP>:443/health

# Verbose to see TLS handshake details
curl -skv https://<SERVER_IP>:443 2>&1 | head -20
```

### Direct to proxy (port 8081)

```bash
curl -sk https://<SERVER_IP>:8081
curl -skv https://<SERVER_IP>:8081
```

### Proxy metrics

```bash
curl -s http://<SERVER_IP>:9090/metrics | grep -E "ja4proxy_(connections|blocked|errors)"
```

---

## Test bot

The test bot (`scripts/test-bot.py`) uses only Python stdlib — no `pip install`
needed. It tries several TLS client profiles against the proxy and reports
per-connection verdicts.

```bash
# Run from your laptop (requires Python 3.10+)
python3 scripts/test-bot.py --proxy <SERVER_IP> --port 443

# Run all profiles with JA4 fingerprint hints
python3 scripts/test-bot.py --proxy <SERVER_IP> --port 443 --show-ja4

# Ping mode — single connection, exit 0 on success
python3 scripts/test-bot.py --proxy <SERVER_IP> --port 443 --ping

# Run only one profile by index
python3 scripts/test-bot.py --proxy <SERVER_IP> --port 443 --profile 0

# List available profiles
python3 scripts/test-bot.py --list-profiles

# Use environment variables instead of flags
PROXY_HOST=10.0.0.5 PROXY_PORT=443 python3 scripts/test-bot.py
```

Typical output:

```
JA4proxy Test Bot
  Target:   10.0.0.5:443
  Profiles: 5 connections

  ✓ ALLOWED  Chrome-like (modern browser)           [JA4 ~t13h2http1.1000000]  45ms
  ✓ ALLOWED  Python-requests (no ALPN, default)     [JA4 ~t1300000000000000]  52ms
  ✗ BLOCKED  Scanner-like (TLS 1.2, one cipher)     [JA4 ~t1200000000000000]  5030ms
  ✓ ALLOWED  curl-like (TLS 1.2, modern cipher)     [JA4 ~t1200000000000000]  48ms
  ✗ BLOCKED  Minimal (TLS 1.2, single cipher)       [JA4 ~t1200000000000000]  5012ms

✓ Summary: 5 total, 3 allowed, 2 blocked
```

---

## Logs — see every connection

### Grafana Loki (recommended)

1. Open Grafana at `http://<SERVER_IP>:3001`
2. Go to **Explore** (compass icon in sidebar)
3. Select **Loki** as the data source
4. Query: `{container="ja4proxy"}`
5. Filter by level: `{container="ja4proxy"} |= `level=info``
6. To see blocked connections: `{container="ja4proxy"} |= `blocked``
7. Click **Live** (top right) to tail logs in real time

### Docker logs (from the proxy server)

```bash
# Tail all proxy logs
docker compose -f deploy/docker/docker-compose.poc.yml logs -f proxy

# Tail only the last 50 lines
docker compose -f deploy/docker/docker-compose.poc.yml logs --tail=50 proxy

# Filter for blocked connections
docker compose -f deploy/docker/docker-compose.poc.yml logs proxy 2>&1 | grep -i block

# Follow both proxy and HAProxy
docker compose -f deploy/docker/docker-compose.poc.yml logs -f proxy haproxy
```

### All services

```bash
# Quick log overview
make logs

# Tail all POC containers
docker compose -f deploy/docker/docker-compose.poc.yml logs -f

# Tail monitoring containers
docker compose -f deploy/docker/docker-compose.monitoring.yml logs -f
```

---

## Traffic generator (Docker-based)

The `tls-traffic-generator.py` is a more sophisticated bot that runs inside
Docker and generates realistic mixed traffic:

```bash
# Start the traffic generator container alongside the stack
docker compose -f deploy/docker/docker-compose.poc.yml run --rm trafficgen

# Or from the existing stack, run one-off
docker compose -f deploy/docker/docker-compose.poc.yml exec trafficgen \
  python /app/tls-traffic-generator.py --target-host proxy --target-port 8080 \
  --duration 30 --good-percent 15 --workers 10
```

---

## SSH tunnels (alternative to 0.0.0.0)

If you prefer not to expose ports to the network, use SSH port forwarding:

```bash
# From your laptop, create tunnels for the key services
ssh -L 8090:localhost:8090 \
    -L 3001:localhost:3001 \
    -L 9091:localhost:9091 \
    -L 443:localhost:443 \
    user@<SERVER_IP>

# Then open localhost URLs in your browser:
#   http://localhost:8090  — Management UI
#   http://localhost:3001  — Grafana
#   http://localhost:9091  — Prometheus
#   https://localhost:443  — Proxy (HAProxy)
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `curl: (7) Connection refused` | Proxy not running, or port blocked by firewall | `make remote-start` on server; check firewall |
| `curl: (35) SSL connect error` | TLS handshake failed | Check proxy logs; verify backend is reachable |
| Test bot shows all BLOCKED | Proxy is blocking aggressively | Check `config/proxy.yml` dial setting; try `make dial LEVEL=100` to allow all |
| Grafana 404 | Grafana still starting | Wait 30s; `docker compose -f deploy/docker/docker-compose.monitoring.yml logs grafana` |
| Loki shows no logs | Promtail not scraping | Check `docker compose -f deploy/docker/docker-compose.monitoring.yml ps` — all should be Up |
| Port already in use | Something else binds to the same port | Stop the other service or change `HOST_PORT_*` in `.env` |

---

## Cleanup

```bash
# Stop remote stack (keeps Redis data)
make remote-stop

# Stop + wipe everything
make stop-clean

# Verify ports are closed
ss -tlnp | grep -E ":(443|8081|9090|9091|3001|8090|8404|9093)"
```
