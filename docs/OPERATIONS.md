# JA4proxy — Operations Guide

Welcome to the central manual for operating and maintaining JA4proxy. This guide consolidates all operational procedures, blocking logic, capacity planning, and troubleshooting.

---

## 🚀 Lifecycle Management

### Starting and Stopping

| Action | Command | Description |
|--------|---------|-------------|
| **Start Everything** | `make start` | Starts proxy, Redis, and monitoring stack. |
| **Start POC Only** | `make deploy-poc` | Starts just the proxy and Redis. |
| **Stop All** | `make stop` | Stops all services (persists Redis data). |
| **Clean Reset** | `make stop-clean` | Stops all services and **wipes all data volumes**. |
| **Check Status** | `make status` | Shows container health and basic metrics. |

### Configuration & Hot Reload
Most configuration changes in `config/proxy.yml` can be applied without a restart.

- **Hot-Reload:** Send `SIGHUP` to the proxy process or run `make reload`.
- **Restart Required:** Listen port changes, Redis URL changes, or TLS certificate path updates.

---

## 🛡 Security Operations (The Dial)

The **Dial (0-100)** is your primary lever for controlling proxy aggression.

- **Dial 0 (Monitor Mode):** Scopes all risk signals but blocks nothing. Use for baselining.
- **Dial 100 (Full Enforcement):** Enforces all configured risk thresholds.
- **Formula:** Effective Threshold = `round(101 - (dial/100) * (101 - base_threshold))`.

### Effective Threshold Table
| Dial | Flag | Rate-limit | Tarpit | Block | Ban  |
|------|------|------------|--------|-------|------|
| **0** (Monitor) | 101 | 101 | 101 | 101 | 101 |
| **50** | 60 | 68 | 78 | 86 | 93 |
| **100** (Full) | 20 | 35 | 55 | 70 | 85 |

### Blocking Categories
1. **Hard Bypass Blocks:** Immediate RST for JA4/Country blacklists or Spamhaus matches. Dial-independent.
2. **Scored Blocks:** Dial-dependent. Scored 0-100 based on TLS, SNI, ASN, and behavioral signals.

---

## 📈 Capacity & Scaling

### Instance Sizing (Go Proxy)
The Go proxy is highly efficient and should be your default for production.

| Metric | Recommendation | Notes |
|--------|----------------|-------|
| **Small** | 1 instance (≤5k conn/s) | Suitable for most apps. |
| **Medium** | 2 instances (≤15k conn/s) | High availability pair. |
| **Large** | 3-4 instances (≤30k conn/s) | Requires HAProxy load balancer. |

**Scaling Trigger:** Add an instance if CPU usage exceeds **70%** for more than 5 minutes.

---

## 🔧 Troubleshooting

### Common Deployment Issues
- **Container fails to start:** Check `docker-compose logs`. Ensure ports 8080/9090 are not in use.
- **Redis "Connection Refused":** Verify Redis is running (`make status`) and the password in `.env` matches.
- **Config not loading:** Run `python3 -c "import yaml; yaml.safe_load(open('config/proxy.yml'))"` to check for syntax errors.

---

## 📚 Runbook Index
If an alert fires, follow the specific runbook below:

### System Health
- [Availability SLI Low](runbooks/slo_availability.md)
- [Redis Latency High](runbooks/ja4proxy_redis_latency_high.md)
- [Node Unhealthy](runbooks/ja4proxy_node_unhealthy.md)
- [Tarpit Pool Full](runbooks/ja4proxy_tarpit_pool_full.md)

### Security Incidents
- [High Block Rate](runbooks/ja4proxy_block_rate_high.md)
- [Campaign Detected](runbooks/ja4proxy_campaign_detected.md)
- [Unexpected Dial Change](runbooks/ja4proxy_dial_change_unexpected.md)
- [Certificate Expiring](runbooks/ja4proxy_certificate_expiring.md)

### Maintenance
- [Credential Rotation](runbooks/credential_rotation.md)
- [TLS Cert Rotation](runbooks/tls_certificate_rotation.md)
- [Go Proxy Migration](runbooks/go_proxy_migration.md)
- [GDPR Data Erasure](runbooks/gdpr_erasure.md)
