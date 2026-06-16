<!--
title: JA4proxy — Operations Guide
audience: operator
last_reviewed: 2026-06-15
phase: v2.0
-->

# JA4proxy — Operations Guide (v2.0.0)

Welcome to the central manual for operating and maintaining JA4proxy. This guide consolidates all operational procedures, blocking logic, capacity planning, and troubleshooting.

## 🚀 Lifecycle Management

### Single-Host Setup (clean DMZ box — phase-231b)

For a single server in a DMZ (only `443` public, no HAProxy needed), the
zero-compile bootstrapper installs runtime deps, runs an interactive wizard,
generates secrets, and wires systemd + firewall + logrotate + a daily backup:

```bash
sudo ./scripts/bootstrap.sh                    # interactive install (container mode)
sudo ./scripts/bootstrap.sh --mode native      # native ja4pd binary instead of compose
sudo ./scripts/bootstrap.sh --check            # dry-run diagnostics
sudo ./scripts/bootstrap.sh --uninstall        # remove (prompts before purging volumes)
```

The wizard (`ja4p init`, run by the bootstrapper or standalone as `bin/ja4p init`)
prompts for the protected backend, deploy mode (native binary or containerized),
admin bind IP, admin user, networking (PROXY protocol, upstream LB, allowed SNIs),
TLS certificates, threat-intel API keys, and hardening options (firewall, Fail2Ban,
CrowdSec, monitoring stack, backup encryption). It **generates strong secrets
into `.env` (chmod 600) and never prints them** — the on-screen summary shows
`[generated — see .env]`. Published admin ports default to the real scheme
(Management UI **8090**, metrics 9090, Prometheus 9091, Grafana 3000) and
stay on loopback; nothing is hard-locked (override via `HOST_PORT_*`). The
proxy starts in **monitor mode (`dial: 0`)** — raise the dial only after
confirming legitimate traffic flows.

> Air-gapped hosts: drop a pre-built `ja4proxy-offline.tar.gz` next to the repo
> and the bootstrapper `docker load`s it (no egress). Production hosts are
> **zero-compile** — the bootstrapper refuses to run if `gcc`/`make`/`go` are
> present; ship pre-built `ja4pd`/`ja4p` binaries or images.
> 
> **Management Console Assets**: All frontend dependencies (Tailwind CSS, HTMX, Alpine.js, Chart.js) are fully vendored under `management/static/vendor/` and locked with a strict Content Security Policy (`script-src 'self'`). The UI runs completely offline without making any third-party CDN or font requests.

### Starting and Stopping

| Action | Command | Description |
|--------|---------|-------------|
| **Start Production** | `make start` | Starts proxy, Redis, and monitoring stack in production mode. |
| **Start POC** | `make start-poc` | Starts proxy, Redis, and monitoring stack via Docker. |
| **Stop All** | `make stop` | Stops all services (persists data). |
| **Check Health** | `make status` | Shows container health and decision metrics. |

### Configuration & Validation
Most configuration changes in `config/proxy.yml` can be applied without a restart.

1. **Modify Configuration**: Edit `config/proxy.yml`.
2. **Validate**: Run `ja4p config validate` (v2.0+).
3. **Reload**: Run `make reload` or send `SIGHUP` to the Go process.

---

## 🛡 Security Operations (The Dial)

The **Dial (0-100)** is your primary lever for controlling proxy aggression.

- **Dial 0 (Monitor Mode):** Scores all risk signals but blocks nothing. Use for baselining.
- **Dial 100 (Full Enforcement):** Enforces all configured risk thresholds.
- **Effective Threshold Table**: See [`docs/OPERATIONS_MAPPING.md`](OPERATIONS_MAPPING.md).

### Enforcement Paths
1. **Hard Blocks**: Immediate RST for blacklisted IPs/JA4s. Independent of the Dial.
2. **Scored Decisions**: Action (Allow/Tarpit/Block) depends on the Dial setting.

---

---

## 🔴 Threat Posture Monitoring

The Management Console dashboard includes a full-width situation bar atop the page that displays the current security posture. It is polled every 10 seconds and shows one of four states:

| State | Colour | Meaning | Recommended Action |
|---|---|---|---|
| **NOMINAL** | Green | Proxy is running. 0 blocking actions in last 5 minutes. | None — normal operation. |
| **ELEVATED** | Amber | 1–9 blocking actions detected in last 5 minutes. | Review the Live Connection Feed and audit log. Check if this is expected (e.g., a known scan). |
| **ACTIVE** | Red | 10+ blocking actions in last 5 minutes. | Investigate immediately. Check top attacking IP, event stream, and dial setting. Consider raising the dial if legitimate traffic is being blocked. |
| **PROXY_DOWN** | Red | No proxy heartbeat key found in Redis. | The proxy has not reported a heartbeat in the last 90 seconds. Check `docker ps` and the proxy logs. Restart if needed. |

### How It Works

1. **Heartbeat**: The Go proxy (`ja4pd`) writes `proxy:heartbeat:{hostname}` to Redis every 60 seconds with a 90-second TTL. On graceful shutdown the key is deleted immediately for fast detection.
2. **Event Stream**: The management API reads the last 5 minutes of `events:connection` (Redis Stream, max 1000 entries). It counts `block`/`ban`/`tarpit` actions to classify the threat state.
3. **Polling**: The dashboard polls `/api/v1/partials/situation` every 10 seconds via HTMX. The bar updates without a full page reload.

### Manual Verification

```bash
# Verify heartbeat is being written
redis-cli keys 'proxy:heartbeat:*'

# Simulate a proxy-down scenario (heartbeat will re-appear within 60s)
redis-cli del "$(redis-cli keys 'proxy:heartbeat:*' | head -1)"

# Verify the situation bar shows data by calling the endpoint directly
curl -s http://localhost:8090/api/v1/partials/situation -H 'Cookie: session=<token>'
```

---

## 🏢 Multi-Environment Isolation

You can run multiple parallel environments on a single machine (e.g., a "stable" dev environment and an "experimental" one).

### Setting up a new environment:
1. Create a new directory and clone the repo, or use a separate folder.
2. Run \`make init\`.
3. When prompted, provide a unique **Environment Name Prefix** (e.g., \`ja4-dev-2\`).
4. Provide a **Port Offset** (e.g., \`2000\`). This will shift all ports (Ingress will be \`2443\`, Grafana \`5000\`, etc.).

The system will automatically isolate all Docker containers, networks, and volumes for that specific prefix.

## 📈 Capacity & Scaling (Go Proxy)

| Metric | Recommendation | Notes |
|--------|----------------|-------|
| **Small** | 1 instance (≤5k conn/s) | Suitable for most applications. |
| **Medium** | 2 instances (≤15k conn/s) | High availability (HA) pair. |
| **Large** | 4+ instances (≤30k conn/s) | Requires HAProxy load balancer. |

**Scaling Trigger:** Add an instance if CPU usage exceeds **70%** or allow-path latency exceeds **1ms**.

---

## 🔧 Troubleshooting

- **Redis Connectivity**: Check `REDIS_URL` and `REDIS_PASSWORD` in `.env`.
- **Latency Spikes**: Check per-signal metrics in Prometheus (`ja4proxy_signal_latency_seconds`).
- **Scoring Drift**: Ensure all nodes are connected to the same Redis state for consistency.

---


## 🧪 Manual Testing & Verification

For a quick "smoke test" of a running system, use these commands:

### 1. Test the "Allow" Path
Verify the proxy correctly forwards legitimate traffic.
```bash
curl -kv https://localhost:443/
```
*Expected: 200 OK from the backend.*

### 2. Test the "Security" Path (Pipeline Simulation)
Use the CLI to see how the proxy would score a specific IP without sending real traffic.
```bash
./bin/ja4p test ip 8.8.8.8
```
*Expected: Detailed signal breakdown (e.g., "asn_classifier", "blocklist_spamhaus").*

### 3. Test a "Block" Event
Force a security violation by using an old TLS version.
```bash
curl -k --tls-max 1.1 https://localhost:443/
```
*Expected: Connection dropped or sent to Tarpit (if Dial > 0).*

---

## 📊 Viewing Logs & Assets

| Asset | Location | Description |
| :--- | :--- | :--- |
| **Proxy Logs** | `make logs` | Real-time structured JSON logs (decisions, errors). |
| **Metrics** | [localhost:9090/metrics](http://localhost:9090/metrics) | Raw Prometheus metrics from the Go proxy. |
| **Grafana** | [localhost:3000](http://localhost:3000) | Visual dashboards (Security, Performance, Health). |
| **Redis** | [localhost:8001](http://localhost:8001) | Redis Insight UI to inspect lists, dial state, and events. |
| **Health API** | `curl localhost:9090/health/deep` | JSON status of the proxy, Redis, and Security pipeline. |

## 📚 Reference Links
- **[Signal Mapping (MITRE ATT&CK)](OPERATIONS_MAPPING.md)**
- **[Runbook Index](runbooks/)**
- **[Architecture Deep-Dive](security/ARCHITECTURE.md)**
