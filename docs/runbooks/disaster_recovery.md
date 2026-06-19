<!--
title: "disaster recovery Runbook"
audience: oncall, sre
last_reviewed: 2026-04-10
phase: 86
-->

# Disaster Recovery Runbook

> **Scope:** Catastrophic failures requiring coordination across 2+ systems
> (proxy + Redis + HAProxy + config). For routine single-service operations,
> see the linked runbooks below.
>
> **Audience:** On-call engineers, SREs, security operators
>
> **Last updated:** 2026-04-10 (Phase 64c)

---

## See also

These runbooks cover **routine operations** for individual systems. This DR
runbook is for scenarios that require **coordinated recovery** of multiple
systems simultaneously.

| Runbook | Covers |
|---------|--------|
| [Redis Operations](redis_operations.md) | Routine Redis ops (start, stop, AOF rewrite, slowlog) |
| [Go Proxy Operations](go_proxy_operations.md) | Day-2 Go proxy ops (start, stop, log rotation) |
| [Go Proxy Migration](go_proxy_migration.md) | Python → Go migration procedure |
| [Security Incident Response](security_incident_response.md) | Active security incidents (attacks, intrusions) |
| [Feed Management](feed_management.md) | Threat-intel feed troubleshooting |
| [External API Failures](external_api_failures.md) | AbuseIPDB/RDAP/MaxMind outages |
| [Scaling](scaling.md) | Horizontal scaling, adding proxy nodes |
| [Zero-Downtime Rollouts](zero_downtime_rollouts.md) | Zero-downtime config rollout |

---

## Deployment quick reference

All recovery procedures below reference this table for deployment-specific
commands. Replace the generic names with your actual service names.

| Operation | Docker Compose | Kubernetes | RHEL / systemd |
|---|---|---|---|
| **Start** | `docker compose -f deploy/docker/docker-compose.poc.yml up -d` | `helm install ja4proxy deploy/helm/ja4proxy/ --wait` | `systemctl --user start ja4proxy` |
| **Stop** | `docker compose -f deploy/docker/docker-compose.poc.yml down` | `helm delete ja4proxy` | `systemctl --user stop ja4proxy` |
| **Status** | `docker compose -f deploy/docker/docker-compose.poc.yml ps` | `kubectl get pods -l app=ja4proxy` | `systemctl --user status ja4proxy` |
| **Logs** | `docker compose -f deploy/docker/docker-compose.poc.yml logs --tail=50 ja4proxy` | `kubectl logs -l app=ja4proxy --tail=50` | `journalctl --user -u ja4proxy -n 50` |
| **Hot-reload** | `docker kill --signal=HUP ja4proxy` | `kubectl exec ja4proxy-xxx -- kill -HUP 1` | `systemctl kill --signal=HUP ja4proxy.service` |
| **Health** | `curl -sf http://localhost:8090/api/v1/health/deep` | `kubectl exec ja4proxy-xxx -- wget -qO- http://localhost:8090/api/v1/health/deep` | `curl -sf http://localhost:8090/api/v1/health/deep` |

> All Docker commands use `docker compose` (v2, space-separated), never
> `docker-compose` (v1).

---

## Scenario 1: Redis failure

**Symptoms:**
- `ja4proxy_redis_operations_total{result="error"}` metric spikes in Grafana/Prometheus
- Health endpoint reports `"redis": "unreachable"` or `"redis": "degraded"`
- New bot bans stop appearing; existing bans may still be enforced (cached)
- Rate limiting is disabled — all connections bypass the rate limiter

**Impact:**
The proxy fails open. It continues to pass TLS connections to backends but
loses three capabilities:
1. **Ban enforcement** — IP/JA4 bans stored only in Redis are not checked.
   Previously cached bans (in-process) still work until the proxy restarts.
2. **Rate limiting** — The sliding window counter is in Redis. All connections
   bypass rate limits until Redis recovers.
3. **Dial updates** — Config changes published via Redis PubSub are not
   received. The proxy continues with its current dial value.

The proxy **does not** crash or drop connections. It logs warnings and
continues operating in degraded mode.

**Simulate:**
```bash
# Docker Compose
docker compose -f deploy/docker/docker-compose.poc.yml stop redis

# Verify degraded state
curl -sf http://localhost:8090/api/v1/health/deep | python3 -m json.tool
# Expected: "redis": "unreachable" or similar degraded indicator
```

**Recovery:**
1. Restart Redis:
   ```bash
   # Docker Compose
   docker compose -f deploy/docker/docker-compose.poc.yml start redis
   ```
2. Wait for the proxy to reconnect (typically 5–15 seconds). The proxy
   polls Redis on a reconnect backoff schedule.
3. Verify reconnection:
   ```bash
   curl -sf http://localhost:8090/api/v1/health/deep | python3 -c \
     "import sys,json; d=json.load(sys.stdin); assert d.get('redis')=='healthy', f'Redis still unhealthy: {d}'"
   ```
4. Verify ban enforcement has resumed:
   ```bash
   # Check that Redis has ban keys
   redis-cli -a "$REDIS_PASSWORD" --scan --pattern 'ban:*' | head -5
   ```
5. If the proxy did not auto-reconnect after 60 seconds, hot-reload it:
   ```bash
   docker kill --signal=HUP ja4proxy
   ```

**RTO:** 5 minutes (includes Redis restart + proxy reconnection + verification)
**RPO:** Zero. Redis persistent data (AOF/RDB) survives a normal stop/start.
No ban or rate-limit state is lost.

---

## Scenario 2: Single proxy node failure

**Symptoms:**
- HAProxy backend health check marks the node as DOWN
- `ja4proxy_haproxy_backend_status` metric shows backend as DOWN in Grafana
- Brief increase in connection errors (during the `fall` window)
- Traffic redistributes to remaining healthy nodes

**Impact:**
HAProxy stops sending new connections to the failed node within `inter × fall`
seconds (default: 2s × 2 = 4s). Existing connections to the failed node are
dropped. Clients retry and are routed to remaining healthy nodes.

The remaining nodes handle 100% of traffic. If only one node was running,
all connections fail until the node recovers.

**Simulate:**
```bash
# Docker Compose — stop the proxy container
docker compose -f deploy/docker/docker-compose.poc.yml stop ja4proxy

# Verify HAProxy marks backend DOWN
docker compose -f deploy/docker/docker-compose.poc.yml exec haproxy \
  echo "show stat" | socat stdio unix-connect:/var/run/haproxy/admin.sock \
  | grep -E "^pxname|ja4proxy" | cut -d, -f1,2,18
# Expected: ja4proxy backend shows status DOWN (18 = status field)
```

**Recovery:**
1. Restart the proxy:
   ```bash
   docker compose -f deploy/docker/docker-compose.poc.yml start ja4proxy
   ```
2. Wait for HAProxy to mark the backend UP (`rise` window, default: 2 checks × 2s = 4s):
   ```bash
   # Poll until backend is UP
   for i in $(seq 1 30); do
     STATUS=$(docker compose -f deploy/docker/docker-compose.poc.yml exec haproxy \
       echo "show stat" | socat stdio unix-connect:/var/run/haproxy/admin.sock 2>/dev/null \
       | grep ja4proxy | cut -d, -f18)
     [ "$STATUS" = "UP" ] && echo "Backend UP after ${i}s" && break
     sleep 1
   done
   ```
3. Verify health endpoint:
   ```bash
   curl -sf http://localhost:8090/api/v1/health/deep | python3 -m json.tool
   ```
4. Check that ban enforcement is active (proxy should reconnect to Redis
   and resume checks immediately):
   ```bash
   # Send a test connection and check logs for ban check
   docker compose -f deploy/docker/docker-compose.poc.yml logs --tail=10 ja4proxy \
     | grep -i "ban\|block\|allow" | head -5
   ```

**RTO:** 2 minutes (includes container restart + HAProxy health check window)
**RPO:** Zero. No data is stored in the proxy process. All state is in Redis.

---

## Scenario 3: Total fleet failure

**Symptoms:**
- All HAProxy backends marked DOWN
- 503 errors to all users
- `ja4proxy_haproxy_backend_status` shows all backends DOWN
- Health endpoint unreachable (all proxy nodes down)
- **P1 incident** — declare immediately

**Impact:**
Zero traffic reaches backends. All users see connection refused or 503.
This is the most severe operational state. No security decisions are being
made because no proxy is running.

**Simulate:**
```bash
# Docker Compose — stop all proxy nodes
docker compose -f deploy/docker/docker-compose.poc.yml stop ja4proxy
# If scaled: docker compose -f deploy/docker/docker-compose.scale.yml stop ja4proxy-1 ja4proxy-2 ja4proxy-3 ja4proxy-4

# Verify all backends DOWN
docker compose -f deploy/docker/docker-compose.poc.yml exec haproxy \
  echo "show stat" | socat stdio unix-connect:/var/run/haproxy/admin.sock 2>/dev/null \
  | grep -E "ja4proxy" | cut -d, -f1,2,18
```

**Recovery:**
1. **Declare P1 incident.** Page the on-call SRE and security engineer.
2. **Collect logs** from all proxy nodes before restarting (evidence for
   root cause analysis):
   ```bash
   docker compose -f deploy/docker/docker-compose.poc.yml logs ja4proxy > /tmp/ja4proxy-crash-logs-$(date +%Y%m%dT%H%M%S).txt
   ```
3. **Identify root cause:**
   - **OOM kill:** `dmesg | grep -i oom | grep ja4proxy` — if found, check
     memory limits in compose file and increase before restarting.
   - **Config error:** Check the last config change — was a bad dial or
     blocklist pushed? Revert via git:
     ```bash
     git log --oneline -5 config/
     git diff HEAD~1 config/proxy.yml
     ```
   - **Infrastructure failure:** Check Docker daemon (`systemctl status docker`),
     host resources (`free -h`, `df -h`).
   - **Redis failure cascading:** If Redis went down first, the proxy may
     have been in degraded mode. Check Redis status:
     ```bash
     docker compose -f deploy/docker/docker-compose.poc.yml ps redis
     redis-cli -a "$REDIS_PASSWORD" PING
     ```
4. **Fix the root cause** before restarting. Do not restart into a known
   bad state.
5. **If config was the cause, revert to last known good:**
   ```bash
   git checkout HEAD~1 config/proxy.yml
   docker cp config/proxy.yml ja4proxy:/app/config/proxy.yml
   docker kill --signal=HUP ja4proxy
   ```
6. **Restart fleet:**
   ```bash
   docker compose -f deploy/docker/docker-compose.poc.yml up -d
   ```
7. **Verify:**
   - All backends UP in HAProxy
   - Health endpoint returns 200
   - Send test traffic and verify allow/block decisions
   - Check Grafana for normal traffic patterns

**RTO:** 15 minutes (P1 declaration + log collection + root cause + restart)
**RPO:** Last Redis checkpoint. If Redis is also down, ban/rate-limit state
is lost and rebuilds from live traffic (1–4 hours).

---

## Scenario 4: Config corruption / malformed dial

**Symptoms:**
- Sudden spike or drop in block rate (check Grafana `ja4proxy_blocks_total`)
- Dial value changed unexpectedly — check health endpoint:
  ```bash
  curl -sf http://localhost:8090/api/v1/health/deep | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(f'dial={d.get(\"dial\", \"unknown\")}')"
  ```
- Legitimate traffic being blocked (dial too high) or attack traffic passing
  through (dial too low)

**Impact:**
The dial multiplier (0–100) scales all signal scores. A corrupted dial
causes systematic over-blocking or under-blocking across all connections.
This affects every decision the proxy makes.

**Recovery:**
This is a **three-phase recovery** to prevent applying bad config to a
recovering fleet:

1. **Phase 1 — Monitor mode (RTO: 30 seconds):**
   Immediately set dial to 0 (monitor mode — all connections allowed but
   still scored and logged):
   ```bash
   redis-cli -a "$REDIS_PASSWORD" SET config:dial 0
   redis-cli -a "$REDIS_PASSWORD" PUBLISH config:dial:change '{"source":"dr-recovery","dial":0}'
   ```
   Verify:
   ```bash
   curl -sf http://localhost:8090/api/v1/health/deep | python3 -c \
     "import sys,json; d=json.load(sys.stdin); assert d.get('dial')==0, f'dial={d.get(\"dial\")}'"
   echo "Dial set to 0 (monitor mode)"
   ```

2. **Phase 2 — Revert config (RTO: 2 minutes):**
   Identify the bad config change:
   ```bash
   git log --oneline -10 config/
   git diff HEAD~1 config/proxy.yml
   ```
   Revert:
   ```bash
   git checkout HEAD~1 config/proxy.yml
   # Push corrected config to all nodes (method depends on your deployment)
   ```

3. **Phase 3 — Restore intended dial (RTO: 30 seconds):**
   Once config is verified, set the dial to the intended value:
   ```bash
   redis-cli -a "$REDIS_PASSWORD" SET config:dial 25  # or your production value
   redis-cli -a "$REDIS_PASSWORD" PUBLISH config:dial:change '{"source":"dr-recovery","dial":25}'
   ```
   Verify:
   ```bash
   curl -sf http://localhost:8090/api/v1/health/deep | python3 -m json.tool
   ```

**RTO:** 3 minutes to monitor mode, 5 minutes to full recovery
**RPO:** Zero. Config is git-tracked; dial is a single Redis key.

---

## Scenario 5: Redis data loss

**Symptoms:**
- All bans cleared — previously blocked IPs/JA4s now allowed
- Rate limit counters reset to zero
- Dial value reset to default (or missing)
- `ban:*` keys are gone from Redis

**Simulate:**
```bash
# WARNING: This destroys all Redis state. Do not run on production.
# Docker Compose
docker compose -f deploy/docker/docker-compose.poc.yml stop redis
docker compose -f deploy/docker/docker-compose.poc.yml down -v
# Find and remove the Redis volume
REDIS_VOL=$(docker volume ls --format '{{.Name}}' | grep redis | head -1)
docker volume rm "$REDIS_VOL"

# Restart with empty Redis
docker compose -f deploy/docker/docker-compose.poc.yml up -d redis
redis-cli -a "$REDIS_PASSWORD" PING  # Should return PONG
redis-cli -a "$REDIS_PASSWORD" DBSIZE  # Should return 0 (empty Redis)
```

**Impact:**
All ban state, rate limit counters, and custom dial values are gone. The
proxy continues operating with default values. Attackers that were banned
will pass through until the proxy re-identifies and re-bans them (1–4 hours
of live traffic, depending on attack volume).

**Recovery:**

**Path A — Restore from Phase 19 backup (RTO: 30 minutes):**
If a recent backup exists (check `/var/backups/ja4proxy/backups/` or your
configured backup path):

> **Note:** The Phase 19 backup system uses `BackupRestorer` (not `Restorer`).
> Backup files follow the naming convention `backup_<timestamp>.bin` with a
> companion manifest `<filename>.manifest.json`. The latest backup filename
> is stored in Redis key `backup:latest`.

```bash
# Load environment for REDIS_PASSWORD and ENCRYPTION_KEY
[ -f .env ] && set -a && source .env && set +a

# Find the latest backup
LATEST=$(redis-cli -a "$REDIS_PASSWORD" GET backup:latest 2>/dev/null)
if [ -z "$LATEST" ]; then
    echo "No backup:latest key in Redis. Check /var/backups/ja4proxy/backups/ manually."
    ls -lt /var/backups/ja4proxy/backups/backup_*.bin 2>/dev/null | head -5
else
    echo "Latest backup: $LATEST"
fi

# Restore using the Phase 19 Python backup tool
BACKUP_DIR="/var/backups/ja4proxy/backups"
BACKUP_FILE="backup_<TIMESTAMP>.bin"  # Replace with actual filename from above
python3 -c "
from src.backup.restorer import BackupRestorer
restorer = BackupRestorer(
    redis_host='localhost',
    redis_port=6379,
    redis_db=0,
    encryption_key='${BACKUP_ENCRYPTION_KEY:-}',
)
restorer.restore_backup(
    backup_path='${BACKUP_DIR}/${BACKUP_FILE}',
    manifest_path='${BACKUP_DIR}/${BACKUP_FILE}.manifest.json',
    destructive=False,
)
"
```

**Verify restoration:**
```bash
redis-cli -a "$REDIS_PASSWORD" --scan --pattern 'ban:*' | wc -l
redis-cli -a "$REDIS_PASSWORD" GET config:dial
```
Set dial to 0 while verifying the restored state is correct, then restore
the intended dial value.

**Path B — Rebuild from live traffic (RTO: 4 hours):**
If no backup exists:
1. Set dial to 0 (monitor mode) while state rebuilds:
   ```bash
   redis-cli -a "$REDIS_PASSWORD" SET config:dial 0
   ```
2. Monitor the ban list growing:
   ```bash
   watch -n 5 'redis-cli -a "$REDIS_PASSWORD" --scan --pattern "ban:*" | wc -l'
   ```
3. Once the ban list reaches expected volume (compare with pre-loss
   Grafana dashboards), restore dial to production value:
   ```bash
   redis-cli -a "$REDIS_PASSWORD" SET config:dial 25  # or your production value
   ```

**RTO:** 30 minutes with backup, 4 hours without
**RPO:** Last Phase 19 backup timestamp. Without backup, all state is lost.

---

## Runbook Exercise History

> GameDay exercises are logged here after each run. See
> [gameday_scenarios.md](gameday_scenarios.md) for exercise definitions.

| Date | Scenario | Exercised By | Duration | Result | Notes |
|------|----------|-------------|----------|--------|-------|
| _empty — run your first GameDay (Phase 64d) to add an entry_ | | | | | |
