<!--
title: JA4proxy — Operations Guide
audience: operator
last_reviewed: 2026-06-04
phase: v2.0
-->

# JA4proxy — Operations Guide (v2.0.0)

Welcome to the central manual for operating and maintaining JA4proxy. This guide consolidates all operational procedures, blocking logic, capacity planning, and troubleshooting.

## 🚀 Lifecycle Management

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
