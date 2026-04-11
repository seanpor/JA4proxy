<!--
title: "SLO redis correctness Runbook"
audience: oncall, sre
last_reviewed: 2026-04-10
phase: 86
-->

# Runbook — SLO: Redis Correctness

> **Alert sources:** `JA4ProxyRedisCorrectnessFastBurn`, `JA4ProxyRedisCorrectnessSlowBurn`
> **SLI:** `job:ja4proxy_redis_correctness:ratio_rate*`
> **Target:** 99.5% of Redis operations succeed
> **Phase:** 63

The proxy fails open when Redis is unreachable: bans, rate limits, and
block lists do not apply, but legitimate traffic still flows. A correctness
SLO breach means **policy enforcement is degraded**, not that user traffic
is failing. Treat as a security issue, not a user-impact issue.

---

## Step 1 — Confirm and identify failing commands

```bash
curl -sg 'http://prometheus:9090/api/v1/query?query=job:ja4proxy_redis_correctness:ratio_rate5m' | jq '.data.result'
```

Break down by command + result:

```promql
topk(10, sum by (command) (rate(ja4proxy_redis_operations_total{result="error"}[5m])))
```

If a single command (e.g. `evalsha`) dominates, the script may have been
flushed — restart the proxy or run `SCRIPT LOAD` from a maintenance script.

## Step 2 — Inspect Redis health

```bash
redis-cli -h <redis-host> INFO server   | grep -E 'redis_version|uptime'
redis-cli -h <redis-host> INFO memory   | grep -E 'used_memory_human|maxmemory|mem_fragmentation_ratio'
redis-cli -h <redis-host> INFO clients  | grep -E 'connected_clients|maxclients|blocked'
redis-cli -h <redis-host> INFO stats    | grep -E 'rejected_connections|evicted_keys'
redis-cli -h <redis-host> CLUSTER INFO  # if cluster
redis-cli -h <redis-host> SLOWLOG GET 20
```

Common causes:
- **Memory pressure** — `evicted_keys` rising; raise `maxmemory` or shrink TTLs.
- **Connection pool exhaustion** — `rejected_connections` rising; increase
  `maxclients` or audit pool sizes in `config/proxy.yml`.
- **Network partition** — proxy host unable to reach Redis; check `iptables`
  / security groups / k8s NetworkPolicies.

## Step 3 — Verify fail-open is actually open

```promql
# If this dropped to zero while errors are climbing, the proxy is hung
rate(ja4proxy_connections_total[5m])
```

If the connection rate dropped along with Redis correctness, fail-open is
not working — escalate immediately.

## Step 4 — Mitigate

```bash
# Restart Redis if it has gone unresponsive
systemctl restart redis-server
docker restart ja4proxy-redis
kubectl rollout restart statefulset/redis

# Hot-reload the proxy after Redis is healthy
systemctl kill --signal=HUP ja4proxy.service
docker kill --signal=HUP ja4proxy
podman kill --signal=HUP ja4proxy
kubectl exec -it ja4proxy-xxxxx -- kill -HUP 1
```

For deeper Redis diagnostics see `docs/runbooks/redis_operations.md`.

## Escalation

- Primary on-call: [FILL IN]
- Redis on-call: [FILL IN]
- Security on-call (policy enforcement degraded): [FILL IN]
- Slack channel: [FILL IN]
