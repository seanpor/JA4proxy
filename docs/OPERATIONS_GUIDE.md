# JA4proxy — Operations Guide (v2.0.0)

Welcome to the central manual for operating and maintaining JA4proxy. This guide consolidates all operational procedures, blocking logic, capacity planning, and troubleshooting.

## 🚀 Lifecycle Management

### Starting and Stopping

| Action | Command | Description |
|--------|---------|-------------|
| **Start Production** | `make start` | Starts proxy, Redis, and monitoring stack via Docker. |
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

## 📚 Reference Links
- **[Signal Mapping (MITRE ATT&CK)](OPERATIONS_MAPPING.md)**
- **[Runbook Index](runbooks/)**
- **[Architecture Deep-Dive](security/ARCHITECTURE.md)**
