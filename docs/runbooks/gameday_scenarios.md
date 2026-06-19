<!--
title: "gameday scenarios Runbook"
audience: oncall, sre
last_reviewed: 2026-04-10
phase: 86
-->

# GameDay Scenarios

> **Purpose:** Validate disaster recovery procedures under realistic conditions.
> Each exercise tests the team's ability to detect, diagnose, and recover
> from a specific failure scenario within the RTO target.
>
> **Scope:** Docker Compose environment (local). K8s and systemd GameDays
> are deferred until those deployment targets are field-validated.
>
> **Last updated:** 2026-04-10 (Phase 64d)

---

## Prerequisites

Before running any GameDay:

1. The team **does not know which scenario will be triggered** (or at least
   the on-call engineer does not). The facilitator chooses a scenario
   at the start.
2. All participants have access to:
   - Grafana dashboard (`http://localhost:3000`)
   - Health endpoint (`http://localhost:8090/api/v1/health/deep`)
   - `docker compose` CLI
   - `redis-cli`
3. The team opens the [disaster recovery runbook](disaster_recovery.md)
   **only after** detecting the incident — not before. This tests detection,
   not reading.
4. A facilitator triggers the failure and measures time.

---

## Exercise 1: Redis outage

**Linked scenario:** [Disaster Recovery §Scenario 1](disaster_recovery.md#scenario-1-redis-failure)

**Environment:** `make start` (Docker Compose, all services up and healthy)

**Duration:** 10 minutes (5 min detection + 5 min recovery)

**Facilitator trigger:**
```bash
docker compose -f deploy/docker/docker-compose.poc.yml stop redis
```

**What the team does BEFORE opening the runbook:**
1. Check Grafana for `ja4proxy_redis_operations_total{result="error"}` — is it spiking?
2. Check the health endpoint — does it report Redis as unreachable?
3. Verify the proxy is still accepting connections (fail-open behaviour).
4. Check Redis container status — is it stopped or crashed?

**Recovery procedure** (open the runbook now):
1. Follow Disaster Recovery §Scenario 1 recovery steps.
2. Restart Redis.
3. Verify proxy reconnection.
4. Verify ban enforcement has resumed.

**Success criteria:**
- Team detects the Redis failure within **2 minutes** of the trigger.
- Team identifies the correct runbook scenario within **1 minute** of detection.
- Redis recovered and proxy reconnected within **5 minutes** total.
- Team confirms ban enforcement is active post-recovery.

**RTO target:** 5 minutes

---

## Exercise 2: Node failure

**Linked scenario:** [Disaster Recovery §Scenario 2](disaster_recovery.md#scenario-2-single-proxy-node-failure)

**Environment:** `make start` (Docker Compose, all services up and healthy)

**Duration:** 5 minutes (1 min detection + 4 min recovery)

**Facilitator trigger:**
```bash
# Stop the proxy container (name may vary — check `docker compose ps`)
PROXY=$(docker compose -f deploy/docker/docker-compose.poc.yml ps --format json \
  | python3 -c "import sys,json; [print(s['Service']) for s in json.load(sys.stdin) if 'proxy' in s.get('Service','').lower()]" | head -1)
docker compose -f deploy/docker/docker-compose.poc.yml stop "$PROXY"
```

**What the team does BEFORE opening the runbook:**
1. Check HAProxy backend status — is the proxy marked DOWN?
2. Check the proxy container status — is it stopped or in a restart loop?
3. Verify remaining backends are still UP (if multiple nodes exist).
4. Check proxy logs for the last error before it stopped.

**Recovery procedure** (open the runbook now):
1. Follow Disaster Recovery §Scenario 2 recovery steps.
2. Restart the proxy.
3. Wait for HAProxy to mark backend UP.
4. Verify health endpoint and ban enforcement.

**Success criteria:**
- Team detects the node failure within **1 minute** of the trigger.
- Team identifies the correct runbook scenario within **30 seconds**.
- Proxy recovered and HAProxy backend UP within **2 minutes** total.

**RTO target:** 2 minutes

---

## Exercise 3: Total fleet failure

**Linked scenario:** [Disaster Recovery §Scenario 3](disaster_recovery.md#scenario-3-total-fleet-failure)

**Environment:** `make start` (Docker Compose, all services up and healthy)

**Duration:** 20 minutes (5 min detection + 15 min recovery)

**Facilitator trigger:**
```bash
# S2 fix: Load environment for REDIS_PASSWORD (required for all facilitator triggers)
[ -f .env ] && set -a && source .env && set +a

# Stop all proxy containers
# N5 fix: Use a for-loop instead of pipe-to-while to avoid subshell env loss
SERVICES=$(docker compose -f deploy/docker/docker-compose.poc.yml ps --format json \
  | python3 -c "
import sys, json
try:
    services = json.load(sys.stdin)
    for s in services:
        name = s.get('Service', s.get('Name', ''))
        if 'proxy' in name.lower():
            print(name)
except Exception:
    pass
" 2>/dev/null || true)

for svc in $SERVICES; do
    docker compose -f deploy/docker/docker-compose.poc.yml stop "$svc"
done
```

**What the team does BEFORE opening the runbook:**
1. **Declare P1 incident** — all backends DOWN, zero traffic served.
2. Check all proxy container statuses — are they all stopped?
3. Collect logs from ALL proxy nodes before restarting (evidence).
4. Check Docker daemon status, host resources, Redis status.
5. Identify root cause: OOM? Config? Infrastructure?

**Recovery procedure** (open the runbook now):
1. Follow Disaster Recovery §Scenario 3 recovery steps.
2. Collect logs from all nodes.
3. Identify and fix root cause.
4. Restart fleet.
5. Verify all backends UP, health endpoint 200, test traffic flows.

**Success criteria:**
- Team declares P1 within **1 minute** of the trigger.
- Root cause identified within **5 minutes**.
- Fleet recovered and all backends UP within **15 minutes** total.
- Post-incident log review completed.

**RTO target:** 15 minutes

---

## Exercise 4: Dial corruption

**Linked scenario:** [Disaster Recovery §Scenario 4](disaster_recovery.md#scenario-4-config-corruption--malformed-dial)

**Environment:** `make start` (Docker Compose, all services up and healthy)

**Duration:** 10 minutes (3 min detection + 7 min recovery)

**Facilitator trigger:**
```bash
# Load environment for REDIS_PASSWORD (required for all facilitator triggers)
[ -f .env ] && set -a && source .env && set +a

# Set dial to an extreme value. The proxy reads config:dial per connection, so
# the SET takes effect immediately; the PUBLISH just nudges any cached config.
# (If pub/sub HMAC is enabled, signed dial changes must go via the management API.)
redis-cli -a "$REDIS_PASSWORD" SET config:dial 100
redis-cli -a "$REDIS_PASSWORD" PUBLISH config:dial:change '{"source":"gameday","dial":100}'
```

**What the team does BEFORE opening the runbook:**
1. Check Grafana for sudden spike/drop in block rate.
2. Check health endpoint — what is the current dial value?
3. Verify the dial change was not intentional (check recent config changes).
4. Check if legitimate traffic is being blocked or attack traffic is passing.

**Recovery procedure** (open the runbook now):
1. Follow Disaster Recovery §Scenario 4 three-phase recovery:
   - Phase 1: Set dial to 0 (monitor mode) — **immediate**
   - Phase 2: Revert config — **2 minutes**
   - Phase 3: Restore intended dial — **30 seconds**

**Success criteria:**
- Team detects abnormal dial value within **3 minutes** of the trigger.
- Dial set to 0 (monitor mode) within **3 minutes** total.
- Config reverted and dial restored to intended value within **5 minutes** total.
- Team confirms block rate returned to normal after recovery.

**RTO target:** 5 minutes

---

## Runbook Exercise History

> Log each GameDay exercise here after completion. This table feeds into
> the MTTR baseline (Phase 64h) and the validation report (Phase 64i).

| Date | Exercise | Facilitator | On-Call | Duration | Detection Time | Recovery Time | Result | Notes |
|------|----------|------------|---------|----------|---------------|---------------|--------|-------|
| _empty — run Exercise 1 (Redis outage) to add the first entry_ | | | | | | | | |

---

## Post-Exercise Checklist

After each GameDay exercise:

1. **Restore the stack** to a healthy state:
   ```bash
   make stop && make start
   curl -sf http://localhost:8090/api/v1/health/deep | python3 -m json.tool
   ```
2. **Fill in the exercise history table** above with the measured times.
3. **Copy the exercise entry** to the "Runbook Exercise History" section
   of `disaster_recovery.md` (2-line append, tracked in Phase 64 close-out).
4. **Record gaps surfaced** in `PHASE_64d_notes.md`.
5. **Reset any modified state** (e.g., dial value back to production default).
