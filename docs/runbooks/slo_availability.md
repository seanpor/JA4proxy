# Runbook — SLO: Availability

> **Alert sources:** `JA4ProxyAvailabilityFastBurn`, `JA4ProxyAvailabilitySlowBurn`
> **SLI:** `job:ja4proxy_availability:ratio_rate*`
> **Target:** 99.9% (28-day error budget = 40 min of bad minutes)
> **Phase:** 63

The availability SLI counts a connection as **good** if it reached a policy
decision and **bad** if it tripped `ja4proxy_connection_errors_total` before a
decision was made. Fail-open behaviour means most external failures count as
"good" — so if availability is degrading, the proxy itself is in trouble.

---

## Step 1 — Confirm the alert is real

```bash
# Current 5-minute SLI
curl -sg 'http://prometheus:9090/api/v1/query?query=job:ja4proxy_availability:ratio_rate5m' | jq '.data.result'

# 1h burn rate
curl -sg 'http://prometheus:9090/api/v1/query?query=job:ja4proxy_availability:burn_rate1h' | jq '.data.result'

# 28-day budget remaining (1.0 = full, 0.0 = exhausted)
curl -sg 'http://prometheus:9090/api/v1/query?query=job:ja4proxy_availability:budget_remaining28d' | jq '.data.result'
```

A real fast-burn alert needs both 1h and 6h burn rates above 14.4×.

## Step 2 — Identify the dominant error_type

```promql
topk(5, sum by (error_type) (rate(ja4proxy_connection_errors_total[15m])))
```

Possible values (source-aware as of phase-63 review-fix):

| `error_type` | Source | Meaning |
|---|---|---|
| `client_read_timeout` | client | Idle TCP read timed out — usually benign client churn, but a sudden spike means upstream LB or scanner abandoning |
| `client_read_error` | client | Other client-side read failure (reset, etc.) |
| `backend_dial_timeout` | backend | Cannot reach backend within `connection_timeout` — upstream overload or network |
| `backend_dial_error` | backend | Backend dial failed for non-timeout reason |
| `backend_refused` | backend | Backend returned `connection refused` / `no route` — backend down or firewall |
| `redis_timeout` | redis | Redis call exceeded deadline (note: Redis errors are also surfaced via `ja4proxy_redis_operations_total{result="error"}`) |
| `redis_error` | redis | Other Redis error |
| `oom` | any | Process or container ran out of memory |
| `unknown` | any | Unclassified — file an issue |

`tls_parse_error` is **not** an availability error: malformed ClientHellos
still reach the policy pipeline (scored without JA4) and are counted in the
good term. Spikes show up in `ja4proxy_signal_total` instead.

The dominant label tells you which subsystem is failing.

## Step 3 — Diagnose by error_type

### `redis_timeout` / `redis_error`
```bash
redis-cli -h <redis-host> --latency
redis-cli -h <redis-host> INFO clients | grep -E 'connected_clients|maxclients'
redis-cli -h <redis-host> SLOWLOG GET 10
```
Check `monitoring/grafana` Redis dashboard. If Redis is the root cause,
follow `docs/runbooks/redis_operations.md`. Cross-reference
`ja4proxy_redis_operations_total{result="error"}` by command.

### `backend_refused` / `backend_dial_timeout` / `backend_dial_error`
```bash
# From a proxy host
nc -zv <backend-host> 443
curl -kv https://<backend-host>/health
```
Likely backend outage, overload, or firewall change. Page the backend on-call.
`backend_dial_timeout` typically means saturation; `backend_refused` means
the listener is gone.

### `client_read_timeout` / `client_read_error`
A small baseline of these is normal (idle clients dropping). A sudden spike
correlated with no backend issue usually means an upstream LB or a scanner
hanging up. Check the LB's egress logs and `ja4proxy_signal_total` for
beaconing patterns. **Not normally a real outage** — confirm the burn-rate
alert is not being driven entirely by client churn before paging the wider
team.

### `oom`
```bash
kubectl top pod -l app=ja4proxy           # Kubernetes
docker stats --no-stream ja4proxy          # Compose
journalctl -u ja4proxy.service --since '15 min ago' | grep -i oom   # systemd
```
Scale horizontally or raise the memory limit, then capture a heap profile.

## Step 4 — Mitigate

Hot-reload after a config fix (production deployment forms):

```bash
systemctl kill --signal=HUP ja4proxy.service       # systemd
docker kill --signal=HUP ja4proxy                  # Docker Compose
podman kill --signal=HUP ja4proxy                  # Podman/Quadlet
kubectl exec -it ja4proxy-xxxxx -- kill -HUP 1     # Kubernetes
```

If a recent deploy is the cause, roll back with the standard CI/CD
deployment pipeline. The Go proxy is stateless — rolling back is safe.

## Escalation

- Primary on-call: [FILL IN]
- Secondary / SRE: [FILL IN]
- Slack channel: [FILL IN]
- PagerDuty service: [FILL IN]
