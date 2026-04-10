<!--
title: Disaster_Recovery
audience: Operators, Security Teams, On-Call
last_reviewed: 2026-04-10
phase: 64c
-->

# Runbook: Disaster Recovery

## See Also

Before using this runbook, confirm which scenario applies. Several related
runbooks cover specific subsystems in more depth:

| Runbook | When to use |
|---------|-------------|
| [redis_operations.md](redis_operations.md) | Routine Redis maintenance, memory tuning, key-space audits |
| [go_proxy_operations.md](go_proxy_operations.md) | Day-2 Go proxy ops: GC tuning, memory, diagnostics |
| [go_proxy_migration.md](go_proxy_migration.md) | Python-to-Go migration procedures |
| [security_incident_response.md](security_incident_response.md) | Active security incidents (attacker in progress) |
| [feed_management.md](feed_management.md) | Threat-intel feed troubleshooting |
| [external_api_failures.md](external_api_failures.md) | AbuseIPDB / RDAP / MaxMind outages |
| [scaling.md](scaling.md) | Horizontal scaling procedures and thresholds |
| [zero_downtime_rollouts.md](zero_downtime_rollouts.md) | Zero-downtime config rollout procedures |

---

## Deployment Quick Reference

| Operation | Docker Compose | Kubernetes | RHEL / Podman Quadlet |
|---|---|---|---|
| Start | `docker compose up -d` | `helm install ja4proxy deploy/helm/ja4proxy/ --wait` | `systemctl start ja4proxy` |
| Stop | `docker compose down` | `helm delete ja4proxy` | `systemctl stop ja4proxy` |
| Status | `docker compose ps` | `kubectl get pods -l app=ja4proxy` | `systemctl status ja4proxy` |
| Logs | `docker compose logs --tail=50 ja4proxy` | `kubectl logs -l app=ja4proxy --tail=50` | `journalctl -u ja4proxy -n 50` |
| Hot-reload | `docker kill --signal=HUP ja4proxy` | `kubectl exec ja4proxy-xxx -- kill -HUP 1` | `systemctl kill -s HUP ja4proxy.service` |
| Health | `curl -sf http://localhost:8090/api/v1/health/deep` | `kubectl exec ja4proxy-xxx -- wget -qO- http://localhost:8090/api/v1/health/deep` | `curl -sf http://localhost:8090/api/v1/health/deep` |

> **Note:** Replace `ja4proxy-xxx` with the actual pod name from
> `kubectl get pods -l app=ja4proxy`.

---

## Scenario 1: Redis Failure

### Symptoms

- Prometheus alert: `ja4proxy_redis_operations_total{result="error"}` rising.
- Proxy logs: `WARN redis_reconnect_failed` or `ERROR redis_unavailable`.
- Management UI health endpoint returns `degraded` for the Redis component.
- Ban enforcement and rate limiting stop working (proxy fails open).

### Impact

- **Security posture degraded:** active bans are not enforced, rate-limit
  counters are lost, and new block decisions cannot propagate between instances.
- **No user-facing outage:** the proxy continues forwarding traffic using its
  local in-process cache. ALLOW decisions remain cached; BLOCK decisions with
  short TTLs may expire and default to ALLOW (fail-open by design).
- **Analytics stream paused:** `XADD` calls fail silently; events buffer
  in-process and are lost if the proxy restarts before Redis returns.

### Simulate

```bash
# Docker Compose — pause the Redis container (reversible)
docker compose pause redis

# Kubernetes
kubectl exec redis-0 -- redis-cli DEBUG SLEEP 120

# Verify proxy logs show reconnection attempts
docker compose logs --tail=20 ja4proxy | grep -i redis
```

### Recovery Steps

1. **Identify root cause.** Check Redis logs and host-level resources (OOM,
   disk full, network partition). See [redis_operations.md](redis_operations.md)
   for detailed diagnostics.
2. **Restore Redis availability.**
   - Container restart: `docker compose restart redis`
   - Kubernetes: `kubectl delete pod redis-0` (StatefulSet recreates it)
   - RHEL: `systemctl restart redis`
3. **Verify reconnection.** The Go proxy auto-reconnects with exponential
   backoff. Watch for `INFO redis_connected` in proxy logs.
4. **Confirm state recovery.** Run the deep health check:
   ```bash
   curl -sf http://localhost:8090/api/v1/health/deep | python3 -m json.tool
   ```
5. **Verify ban enforcement resumed.** Check that
   `ja4proxy_redis_operations_total{result="error"}` has stopped climbing and that
   `ja4proxy_connections_total{action="block"}` resumes counting.

### RTO

5 minutes.

### RPO

Zero — the proxy does not lose data during a Redis outage. In-process cache
serves decisions. Analytics events in the buffer are lost only if the proxy
itself restarts before Redis returns.

---

## Scenario 2: Single Proxy Node Failure

### Symptoms

- HAProxy marks one backend as DOWN (health check fails after `inter` seconds).
- Prometheus: `haproxy_backend_active_servers` drops by one.
- The failed node stops emitting metrics and logs.

### Impact

- **Reduced capacity:** remaining nodes absorb the traffic. If the fleet was
  near capacity, latency rises and connection queuing increases.
- **No outage for users:** HAProxy routes around the failed node transparently.

### Simulate

```bash
# Docker Compose — stop one proxy instance
docker compose stop ja4proxy-2

# Kubernetes — delete a pod (Deployment recreates it)
kubectl delete pod ja4proxy-xxx

# Verify HAProxy sees the backend as DOWN
curl -sf http://localhost:8404/stats | grep ja4proxy
```

### Recovery Steps

1. **Check why the node failed.** Inspect logs from the dead node:
   ```bash
   # Docker Compose
   docker compose logs --tail=100 ja4proxy-2

   # Kubernetes
   kubectl logs ja4proxy-xxx --previous
   ```
2. **Restart the node.**
   - Docker Compose: `docker compose up -d ja4proxy-2`
   - Kubernetes: the Deployment controller auto-recreates the pod. If stuck in
     CrashLoopBackOff, fix the underlying issue first.
   - RHEL: `systemctl restart ja4proxy`
3. **Verify HAProxy marks it UP.** Watch the HAProxy stats page or:
   ```bash
   curl -sf http://localhost:8404/stats | grep ja4proxy
   ```
4. **Confirm health.** Run the deep health check against the recovered node.

### RTO

2 minutes.

### RPO

Zero — no state is lost. The proxy is stateless; all shared state lives in
Redis.

---

## Scenario 3: Total Fleet Failure

### Symptoms

- HAProxy returns 503 to all clients (all backends DOWN).
- Prometheus: `haproxy_backend_active_servers` is 0.
- No proxy metrics are being emitted.
- **This is a P1 incident.** Escalate immediately.

### Impact

- **Complete outage:** no traffic reaches the backend. All users see 503 errors
  or connection resets.

### Simulate

> **WARNING:** This simulation causes a full outage. Only run in staging or
> during a scheduled maintenance window.

```bash
# Docker Compose — stop all proxy instances
docker compose stop ja4proxy

# Kubernetes — scale to zero
kubectl scale deployment ja4proxy --replicas=0
```

### Recovery Steps

1. **Declare a P1 incident.** Follow your organisation's incident management
   process. Open a bridge call.
2. **Collect logs from all nodes before restarting** (they may contain the root
   cause):
   ```bash
   # Docker Compose
   docker compose logs --tail=500 ja4proxy > /tmp/ja4proxy_fleet_crash.log 2>&1

   # Kubernetes
   for pod in $(kubectl get pods -l app=ja4proxy -o name); do
     kubectl logs "$pod" --previous >> /tmp/ja4proxy_fleet_crash.log 2>&1
   done
   ```
3. **Identify the cause.** Common fleet-wide failures:
   - Bad config push (see Scenario 4).
   - OOM kill on all nodes (check `dmesg | grep -i oom`).
   - Shared dependency failure (Redis, DNS, certificate expiry).
   - Bad binary deployment (rollback to previous image tag).
4. **If caused by config:** revert config and hot-reload. See Scenario 4.
5. **If caused by a bad deploy:** roll back:
   ```bash
   # Docker Compose
   docker compose pull   # pulls previous known-good tag
   docker compose up -d

   # Kubernetes
   kubectl rollout undo deployment/ja4proxy
   ```
6. **Restart the fleet:**
   ```bash
   # Docker Compose
   docker compose up -d

   # Kubernetes
   kubectl scale deployment ja4proxy --replicas=3  # or your target count
   ```
7. **Verify recovery.** Confirm all backends are UP in HAProxy and the deep
   health check passes on every node.
8. **Post-incident.** Write an incident report. Update this runbook if a new
   failure mode was discovered.

### RTO

15 minutes.

### RPO

Last Redis checkpoint. In-flight analytics events that were buffered in proxy
memory are lost. All persistent state (bans, rate-limit counters, config) is in
Redis and survives a fleet restart.

---

## Scenario 4: Config Corruption / Malformed Dial

### Symptoms

- Sudden spike in blocks (dial accidentally set too high) or sudden drop in
  blocks (dial set to 0 unintentionally, or thresholds misconfigured).
- Prometheus: `ja4proxy_dial_current` shows an unexpected value.
- Prometheus: `ja4proxy_connections_total{action="block"}` rate changes sharply.
- Management UI policy audit log shows a recent change.

### Impact

- **If dial too high:** legitimate users are being blocked (false positives).
  This is the highest-severity operational error — every second matters.
- **If dial too low or zero:** security posture is degraded but users are
  unaffected. Lower urgency, but still requires correction.

### Simulate

```bash
# Push a bad dial value via the Management API
curl -X PUT http://localhost:8090/api/v1/config/dial \
  -H 'Content-Type: application/json' \
  -d '{"dial": 100}'

# Verify the proxy picked it up
curl -sf http://localhost:8090/api/v1/config | python3 -m json.tool | grep dial
```

### Recovery Steps

1. **Immediately drop to dial=0 (monitor mode).** This stops all blocking
   while you investigate. No traffic is affected at dial=0.
   ```bash
   # Via Management API
   curl -X PUT http://localhost:8090/api/v1/config/dial \
     -H 'Content-Type: application/json' \
     -d '{"dial": 0}'
   ```
2. **Verify dial=0 is active on all nodes.** The config propagates via Redis
   pub/sub. Confirm:
   ```bash
   curl -sf http://localhost:8090/api/v1/config | python3 -m json.tool | grep dial
   ```
3. **Identify the bad config change.** Check the policy audit log:
   ```bash
   redis-cli LRANGE management:policy_audit -10 -1
   ```
4. **Revert the config file if needed.** If `config/proxy.yml` was corrupted:
   ```bash
   # Restore from git
   git checkout HEAD -- config/proxy.yml

   # Hot-reload without restart
   # Docker Compose:
   docker kill --signal=HUP ja4proxy
   # Kubernetes:
   kubectl exec ja4proxy-xxx -- kill -HUP 1
   # RHEL:
   systemctl kill --signal=HUP ja4proxy.service
   ```
5. **Restore the intended dial value.** Only after confirming the config is
   correct:
   ```bash
   curl -X PUT http://localhost:8090/api/v1/config/dial \
     -H 'Content-Type: application/json' \
     -d '{"dial": 75}'   # your intended value
   ```
6. **Monitor for 15 minutes.** Watch `ja4proxy_connections_total` and
   `ja4proxy_risk_score` to confirm normal patterns resume.

### RTO

3 minutes to reach monitor mode (dial=0). Full recovery (correct dial restored)
typically under 10 minutes.

### RPO

Zero — no data is lost. Scoring continues at dial=0; only enforcement is
paused.

---

## Scenario 5: Redis Data Loss

### Symptoms

- Redis returns to service but keys are missing (e.g., after an unclean restart
  without persistence, or after running `FLUSHALL`).
- Prometheus: `ja4proxy_connections_total{action="block"}` drops to zero.
- Management UI shows no active bans or rate-limit state.
- Proxy logs: `WARN cache_miss` for IPs that should be banned.

### Impact

- **All dynamic state is lost:** bans, rate-limit counters, beaconing history,
  session-resumption tracking, HyperLogLog counters, analytics stream.
- **Static config is unaffected:** JA4 black/whitelists, CIDR lists, and GeoIP
  data are loaded from files at startup and remain in-process.
- **Proxy continues forwarding traffic** in fail-open mode while state rebuilds.

### Simulate

> **WARNING:** This destroys all Redis state. Only run in staging.

```bash
redis-cli FLUSHALL
```

### Recovery Steps

#### Option A: Restore from Phase 19 Backup (preferred)

1. **Locate the latest backup.** Phase 19 backups are stored in
   `/var/backups/ja4proxy/backups/` by default:
   ```bash
   ls -lt /var/backups/ja4proxy/backups/*.bin | head -5
   ```
2. **Validate the backup integrity:**
   ```bash
   python3 -m src.cli.backup_cli validate \
     /var/backups/ja4proxy/backups/<filename>.bin
   ```
3. **Restore using the Phase 19 Python backup tool** (non-destructive mode
   merges with any existing keys):
   ```bash
   python3 -m src.cli.backup_cli restore \
     /var/backups/ja4proxy/backups/<filename>.bin
   ```
   For a destructive restore (wipes current Redis state first, then restores):
   ```bash
   python3 -m src.cli.backup_cli restore --force \
     /var/backups/ja4proxy/backups/<filename>.bin
   ```
   Alternatively, invoke the restorer directly from Python:
   ```python
   from src.backup.restorer import BackupRestorer
   restorer = BackupRestorer(redis_host="localhost", redis_port=6379, redis_db=0)
   restorer.restore_backup(
       "/var/backups/ja4proxy/backups/<filename>.bin",
       "/var/backups/ja4proxy/backups/<filename>.bin.manifest.json",
       destructive=False,
   )
   ```
4. **Verify restored state:**
   ```bash
   redis-cli DBSIZE
   redis-cli KEYS "ban:*" | head -5
   curl -sf http://localhost:8090/api/v1/health/deep | python3 -m json.tool
   ```
5. **Confirm proxy is using restored state.** Watch for
   `ja4proxy_connections_total{action="block"}` to resume climbing.

#### Option B: No Backup Available — Rebuild from Live Traffic

1. **Set dial=0 immediately** to prevent false decisions while state is empty:
   ```bash
   curl -X PUT http://localhost:8090/api/v1/config/dial \
     -H 'Content-Type: application/json' \
     -d '{"dial": 0}'
   ```
2. **The proxy will rebuild state organically** as new connections arrive.
   Rate-limit counters, beaconing detection, and HyperLogLog counters
   repopulate from live traffic. This takes 1 to 4 hours depending on traffic
   volume.
3. **Re-apply critical bans manually** if you have a record of them (incident
   logs, SIEM exports):
   ```bash
   redis-cli SET "ban:<ip>" "manual_restore" EX 86400
   ```
4. **Gradually raise the dial** as state rebuilds. Monitor
   `ja4proxy_risk_score` for at least 30 minutes at each dial
   increment before raising further.
5. **Schedule a Phase 19 backup** once state has stabilised to prevent
   recurrence.

### RTO

- **With backup:** 30 minutes (locate backup, validate, restore, verify).
- **Without backup:** 4 hours (time for state to rebuild from live traffic to
  a useful level).

### RPO

Last backup timestamp. Any state changes between the backup and the data loss
event are not recoverable. Without a backup, RPO equals the full state history
(complete loss).

---

## Runbook Exercise History

<!-- Phase 64d GameDay exercises will be appended below this line. -->
<!-- Format: | Date | Scenario | Result | Notes | Duration | -->
