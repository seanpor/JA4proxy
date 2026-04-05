# Phase 64: Deployment Validation & Disaster Recovery

---

## 1. Overview

All three deployment topologies for JA4proxy are documented: Docker Compose
(dev/staging), Kubernetes via Helm chart (Phases 72–75), and RHEL 8/9 via Podman
Quadlets (Phase 76). None of those documents have been executed end-to-end in a
controlled environment and verified to produce a working, healthy proxy. A DR runbook
does not exist. No MTTR baseline has been measured.

Enterprise buyers connecting to Phase 80 (SIEM integration) and Phase 84 (compliance
reports) require evidence that deployment procedures work and that recovery from common
failure scenarios has been exercised. A documented Helm chart that has never been
deployed into a real cluster is not evidence. Phase 64 closes this gap.

This phase does NOT write new deployment documentation — Phases 72–75 (Docker/K8s
network isolation), Phase 76 (RHEL/Podman/Quadlets), and Phase 77 (SIEM integration
patterns) already wrote those. It does NOT implement training programs or continuous
improvement processes. It does NOT require human coordination that cannot be scripted or
automated.

What it delivers: a deployment smoke test suite that exercises each topology end-to-end,
a DR runbook with four failure scenarios and tested recovery steps, a GameDay design
document, MTTR baseline measurements, and a pre-enterprise validation report section.

---

## 2. Deployment Smoke Test Suite

All smoke test scripts live in `scripts/smoke/`. Each follows the same contract: exit
code 0 means pass, exit code 1 means fail with the reason printed to stderr. All scripts
write structured pass/fail output to `test-results/smoke/` (created if absent) with a
timestamp prefix so CI artifacts are retained across runs.

### 2.1 `scripts/smoke/test_docker_compose.sh`

CI-runnable. Tests the full Docker Compose stack: starts it, verifies all containers are
Running and healthy, sends a synthetic connection through the proxy, then tears down
cleanly.

```bash
#!/usr/bin/env bash
set -euo pipefail

RESULTS_DIR="test-results/smoke"
mkdir -p "$RESULTS_DIR"
LOG="$RESULTS_DIR/docker-compose-$(date +%Y%m%dT%H%M%S).log"

log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
fail() { log "FAIL: $*"; exit 1; }

log "Starting Docker Compose stack..."
docker-compose up -d 2>>"$LOG" || fail "docker-compose up failed"

log "Waiting for health endpoint (max 60s)..."
for i in $(seq 1 60); do
  if curl -sf --max-time 5 http://localhost:8090/api/v1/health/deep >/dev/null 2>&1; then
    log "Health endpoint OK after ${i}s"
    break
  fi
  [ "$i" -eq 60 ] && fail "Health endpoint did not respond within 60s"
  sleep 1
done

log "Checking all containers are Running..."
UNHEALTHY=$(docker-compose ps --format json 2>/dev/null \
  | python3 -c "import sys,json; [print(s['Service']) for s in json.load(sys.stdin) if s.get('State') != 'running']" \
  2>/dev/null || true)
[ -n "$UNHEALTHY" ] && fail "Containers not running: $UNHEALTHY"

log "Sending synthetic TLS connection through port 8080..."
# openssl s_client exits non-zero for TLS errors; a connection-refused also exits non-zero.
# We accept any TLS-level response (including the proxy's block/tarpit) as proof of connectivity.
echo "Q" | openssl s_client -connect localhost:8080 -servername localhost \
  -verify_return_error 2>>"$LOG" || {
  # Proxy may reject the connection at TLS level — that is acceptable.
  # What is NOT acceptable is connection refused (means proxy is not listening).
  grep -q "Connection refused" "$LOG" && fail "Proxy port 8080 is not listening"
  log "Proxy responded at TLS layer (connection accepted and processed)"
}

log "Tearing down stack..."
docker-compose down -v 2>>"$LOG" || fail "docker-compose down failed"

log "PASS: Docker Compose smoke test"
echo "PASS" > "$RESULTS_DIR/docker-compose.result"
```

### 2.2 `scripts/smoke/test_helm_kind.sh`

CI-runnable via GitHub Actions. Creates a single-node `kind` cluster, installs the Helm
chart with `--wait`, runs a health check inside the cluster, then deletes the cluster.

```bash
#!/usr/bin/env bash
set -euo pipefail

RESULTS_DIR="test-results/smoke"
mkdir -p "$RESULTS_DIR"
LOG="$RESULTS_DIR/helm-kind-$(date +%Y%m%dT%H%M%S).log"

log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
fail() { log "FAIL: $*"; exit 1; }

# Prerequisite check
if ! command -v kind &>/dev/null; then
  log "SKIP: kind not found. Install kind (https://kind.sigs.k8s.io) to run this test."
  log "On CI (GitHub Actions): add 'uses: helm/kind-action@v1' before this step."
  exit 0
fi

if ! command -v helm &>/dev/null; then
  fail "helm not found — install Helm 3 (https://helm.sh/docs/intro/install/)"
fi

CLUSTER_NAME="ja4proxy-smoke"

cleanup() {
  log "Deleting kind cluster..."
  kind delete cluster --name "$CLUSTER_NAME" 2>>"$LOG" || true
}
trap cleanup EXIT

log "Creating kind cluster: $CLUSTER_NAME"
kind create cluster --name "$CLUSTER_NAME" 2>>"$LOG" \
  || fail "kind create cluster failed"

log "Installing Helm chart..."
helm install ja4proxy deploy/helm/ja4proxy/ \
  --wait --timeout=120s \
  --set image.tag=latest \
  2>>"$LOG" || fail "helm install failed"

log "Checking DaemonSet pod status..."
kubectl rollout status daemonset/ja4proxy --timeout=60s 2>>"$LOG" \
  || fail "DaemonSet did not become ready within 60s"

POD=$(kubectl get pods -l app=ja4proxy -o jsonpath='{.items[0].metadata.name}' 2>>"$LOG")
[ -z "$POD" ] && fail "No ja4proxy pods found"

log "Running health check inside pod: $POD"
kubectl exec "$POD" -- \
  wget -qO- http://localhost:8080/health 2>>"$LOG" \
  || fail "Health check inside pod failed"

log "PASS: Helm + kind smoke test"
echo "PASS" > "$RESULTS_DIR/helm-kind.result"
# Cluster deleted by trap
```

The GitHub Actions step that invokes this script requires `helm/kind-action@v1` as a
prior step to ensure `kind` and `kubectl` are available. Add this to
`.github/workflows/ci.yml` under a separate `smoke-k8s` job.

### 2.3 `scripts/smoke/test_podman_quadlet.sh`

NOT run in CI. This script is for manual validation on a RHEL 8/9 or Fedora host before
any enterprise pilot deployment. It requires Podman ≥ 4.4 (Quadlet support) and a
systemd user session.

```bash
#!/usr/bin/env bash
set -euo pipefail

RESULTS_DIR="test-results/smoke"
mkdir -p "$RESULTS_DIR"
LOG="$RESULTS_DIR/podman-quadlet-$(date +%Y%m%dT%H%M%S).log"

log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
fail() { log "FAIL: $*"; exit 1; }

# Platform check
if ! command -v podman &>/dev/null; then
  log "SKIP: podman not found. This script requires RHEL 8/9 or Fedora with Podman >= 4.4."
  exit 0
fi

PODMAN_VERSION=$(podman --version | awk '{print $3}')
PODMAN_MAJOR=$(echo "$PODMAN_VERSION" | cut -d. -f1)
PODMAN_MINOR=$(echo "$PODMAN_VERSION" | cut -d. -f2)
if [ "$PODMAN_MAJOR" -lt 4 ] || { [ "$PODMAN_MAJOR" -eq 4 ] && [ "$PODMAN_MINOR" -lt 4 ]; }; then
  log "SKIP: Podman $PODMAN_VERSION < 4.4. Quadlet support requires Podman >= 4.4."
  exit 0
fi

QUADLET_SRC="deploy/rhel/quadlets"
QUADLET_DST="$HOME/.config/containers/systemd"

log "Copying Quadlet unit files from $QUADLET_SRC to $QUADLET_DST..."
mkdir -p "$QUADLET_DST"
cp "$QUADLET_SRC"/*.{container,network,kube} "$QUADLET_DST"/ 2>>"$LOG" \
  || fail "Failed to copy Quadlet unit files"

log "Reloading systemd user daemon..."
systemctl --user daemon-reload 2>>"$LOG" || fail "systemctl daemon-reload failed"

log "Starting ja4proxy service..."
systemctl --user start ja4proxy 2>>"$LOG" || fail "systemctl start ja4proxy failed"

log "Waiting for health endpoint (max 30s)..."
for i in $(seq 1 30); do
  if curl -sf --max-time 3 http://localhost:8080/health >/dev/null 2>&1; then
    log "Health endpoint OK after ${i}s"
    break
  fi
  [ "$i" -eq 30 ] && fail "Health endpoint did not respond within 30s"
  sleep 1
done

log "Stopping and disabling service..."
systemctl --user stop ja4proxy 2>>"$LOG" || log "WARN: stop returned non-zero (may be OK)"
systemctl --user disable ja4proxy 2>>"$LOG" || true

log "Cleaning up Quadlet unit files..."
rm -f "$QUADLET_DST"/ja4proxy.{container,network,kube} 2>>"$LOG" || true
systemctl --user daemon-reload 2>>"$LOG" || true

log "PASS: Podman Quadlet smoke test"
echo "PASS" > "$RESULTS_DIR/podman-quadlet.result"
```

This script is documented in the Phase 76 deployment guide under "Pre-Deployment
Validation". It must be run by the operator on the target RHEL host and the resulting
`test-results/smoke/podman-quadlet-*.log` retained as deployment evidence.

---

## 3. Disaster Recovery Runbook

`docs/runbooks/disaster_recovery.md` — create this file.

The runbook covers four failure scenarios. Each scenario follows the same structure:
symptoms (what you observe first), impact (what the proxy does during the failure),
simulation (how to deliberately trigger the failure in a test environment), and recovery
steps (ordered commands with expected outputs).

### 3.1 Scenario 1: Redis Failure

The most likely production failure. The proxy is designed to fail-open when Redis is
unavailable, so legitimate traffic continues — but bans are not enforced, rate limiting
is disabled, and all scoring degrades to local-cache-only decisions.

**Symptoms:**
- `ja4proxy_redis_errors_total` rising (Grafana alert fires)
- `GET /api/v1/health/deep` returns `"redis": "degraded"` or `"redis": "unreachable"`
- `ja4proxy health --all-nodes` shows `redis_latency_ms: timeout` on one or more nodes

**Impact:**
- Proxy fails-open: all connections pass through without Redis-backed checks
- Active bans not enforced (local LRU cache continues to enforce recently-seen bans for up to 30 minutes)
- Rate limiting disabled (sliding-window Lua scripts cannot execute)
- AbuseIPDB and Spamhaus decisions served from local cache until TTL expiry

**Simulate (Docker Compose):**
```bash
docker-compose stop redis
# Observe: health endpoint degrades, ja4proxy_redis_errors_total increments
# Restore:
docker-compose start redis
```

**Recovery steps:**
1. Confirm Redis is the failure: `docker-compose ps redis` or `systemctl status redis`
2. If Redis crashed: `docker-compose restart redis` or `systemctl restart redis`
3. If Redis disk full: free space, then restart Redis
4. Wait for automatic reconnect — the proxy reconnects via connection pool retry with
   exponential backoff; no proxy restart required
5. Verify recovery: `curl -s http://localhost:8090/api/v1/health/deep | python3 -m json.tool`
   — `"redis": "healthy"` must appear within 30 seconds of Redis restart
6. Confirm `ja4proxy_redis_errors_total` has stopped rising

**RTO target:** 5 minutes from detection to full restoration
**RPO:** Zero — the proxy's fail-open behaviour during the outage is logged to the audit
stream; Redis state (bans, rate limit counters, enrichment cache) is persistent and
survives a container restart with a mounted volume

### 3.2 Scenario 2: Single Proxy Node Failure

One proxy node crashes or becomes unresponsive. HAProxy's health checks detect the
failure within `inter` seconds (default: 2s) and stop routing traffic to it.

**Symptoms:**
- HAProxy admin socket: `echo "show stat" | socat - /var/run/haproxy/admin.sock | grep ja4proxy` shows one backend DOWN
- Traffic volume on remaining nodes increases
- Alerts: `ja4proxy_active_connections` drops on one node, rises on others

**Impact:**
- All traffic continues to flow through remaining nodes
- No requests are dropped (HAProxy redistributes immediately)
- Capacity reduction: if only one node remains, throughput ceiling halves

**Simulate (Docker Compose):**
```bash
docker-compose stop ja4proxy-1
# Observe: HAProxy marks ja4proxy-1 DOWN; traffic flows to ja4proxy-2
# Restore:
docker-compose start ja4proxy-1
```

**Recovery steps:**
1. Check the failed node: `docker-compose ps ja4proxy-1` or `systemctl status ja4proxy@1`
2. Read last 50 log lines: `docker-compose logs --tail=50 ja4proxy-1`
3. Look for: OOM kill (`exit code 137`), config parse error at startup, or Redis auth failure
4. Restart: `docker-compose restart ja4proxy-1` or `systemctl restart ja4proxy@1`
5. Verify: HAProxy marks the backend UP within 10 seconds (two consecutive passing health checks at `inter 2s rise 2`)
6. If repeated crashes: check `dmesg` for OOM events, check `ja4proxy_errors_total` for the error category

**RTO target:** 2 minutes
**RPO:** Zero — all state is in shared Redis; the restarted node resumes with full state

### 3.3 Scenario 3: Total Fleet Failure

All proxy nodes are simultaneously unavailable. HAProxy has no healthy backends.
Incoming connections queue until HAProxy's `timeout connect` is reached, then return
503. This is the highest-severity scenario.

**Symptoms:**
- HAProxy: all backends show DOWN
- End users receive 503 Service Unavailable
- `ja4proxy_active_connections` is zero on all nodes
- Pager fires

**Simulate (Docker Compose):**
```bash
docker-compose stop ja4proxy-1 ja4proxy-2
# All backends down; HAProxy returns 503
```

**Recovery steps:**
1. Page on-call: this is a P1 incident
2. Identify cause: check logs on all nodes simultaneously:
   ```bash
   docker-compose logs --tail=50 ja4proxy-1 ja4proxy-2
   # or on Kubernetes:
   kubectl logs -l app=ja4proxy --tail=50 --all-containers
   ```
3. If config corruption suspected (all nodes exiting with parse error on startup):
   ```bash
   git log --oneline config/proxy.yml | head -5
   git show HEAD:config/proxy.yml | python3 -c "import yaml,sys; yaml.safe_load(sys.stdin)" \
     && echo "Config is valid YAML"
   # If corrupted, revert:
   git checkout HEAD~1 -- config/proxy.yml
   ```
4. Restart fleet:
   - Docker Compose: `docker-compose up -d ja4proxy-1 ja4proxy-2`
   - Kubernetes: `kubectl rollout restart daemonset/ja4proxy`
   - RHEL/Ansible: `ansible-playbook deploy/ansible/playbooks/restart-fleet.yml`
5. Monitor HAProxy: backends should return UP within 10 seconds of proxy startup
6. Verify end-to-end: `curl -sf --max-time 10 https://your-service-hostname/ -o /dev/null -w "%{http_code}"`
7. Conduct post-incident review within 24 hours; document in `docs/incidents/`

**RTO target:** 15 minutes
**RPO:** Last Redis checkpoint (Redis AOF or RDB snapshot, depending on persistence config)

### 3.4 Scenario 4: Config Corruption / Malformed Dial Change

The proxy accepts and applies a config reload with a malformed dial value or invalid
CIDR in an allowlist, causing unexpected blocking or blanket allowance.

**Symptoms:**
- Sudden spike or drop in `ja4proxy_blocked_total`
- Alarm: `ja4proxy_dial_setting` jumps unexpectedly
- Management UI shows dial at 100 (or 0) without operator intent
- Legitimate users start reporting 403/RST errors

**Simulate:**
```bash
# Set dial to 100 to simulate aggressive blocking
redis-cli SET ja4proxy:dial 100

# Or corrupt a config value and trigger reload:
echo "security_policy: {tls_version_bypass: {enabled: not-a-bool}}" >> config/proxy.yml
kill -HUP $(pgrep -f proxy.py)
```

**Recovery steps:**
1. Immediate mitigation — drop to monitor mode to stop any blocking:
   ```bash
   ja4proxy-cli dial set 0 --confirm
   # or via Redis directly if the CLI is unavailable:
   redis-cli SET ja4proxy:dial 0
   redis-cli PUBLISH ja4proxy:config_reload '{"source":"emergency","dial":0}'
   ```
2. Identify what changed:
   ```bash
   git diff config/proxy.yml
   # Check policy audit log (last 20 entries):
   redis-cli LRANGE management:policy_audit 0 19 | python3 -m json.tool
   ```
3. Revert config to last known good:
   ```bash
   git checkout HEAD -- config/proxy.yml
   ```
4. Trigger hot reload:
   ```bash
   ja4proxy-cli config reload
   # or: kill -HUP $(pgrep -f proxy.py)
   ```
5. Restore dial to intended value:
   ```bash
   ja4proxy-cli dial set <previous-value> --confirm
   ```
6. Verify: `ja4proxy_blocked_total` returns to baseline rate

**RTO target:** 3 minutes to monitor mode; investigation and full restoration within 15 minutes
**RPO:** Zero for config (git-tracked); ban/rate-limit state unaffected

---

## 4. GameDay Design

`docs/runbooks/gameday_scenarios.md` — create this file.

A GameDay is a live exercise where the operations team deliberately triggers a failure
scenario and practices recovery without referring to the runbook until they are stuck.
The purpose is to verify that the runbook works, identify gaps, and build muscle memory
for the recovery procedures.

**When to run GameDays:**
- The first GameDay is mandatory before any enterprise pilot deployment. Run all four
  scenarios in sequence in a staging environment. Document the date and results in
  `docs/runbooks/disaster_recovery.md` under a "Runbook Exercise History" section.
- Subsequent GameDays are recommended quarterly, rotating through the four scenarios.
  Rotate which team member is "on-call responder" so that recovery knowledge is not
  siloed.

### 4.1 GameDay Scenario 1: Redis Outage

**Environment:** Docker Compose staging stack (full replica of production topology)
**Duration:** 30 minutes
**Trigger command:**
```bash
docker-compose stop redis
```
**What the team does before checking the runbook:**
- Identify the failure from Grafana/Prometheus alerts
- Determine the blast radius (what is failing, what is still working)
- Attempt to restore Redis and verify recovery

**Success criteria:**
- Team identifies `ja4proxy_redis_errors_total` as the leading indicator within 2 minutes
- Recovery completed (Redis restarted, proxy reconnected, health endpoint returns healthy) within 5 minutes (RTO target)
- Team notes any gaps in the alert definitions or runbook wording

### 4.2 GameDay Scenario 2: Node Failure

**Environment:** Docker Compose staging stack with two proxy containers
**Duration:** 20 minutes
**Trigger command:**
```bash
docker-compose stop ja4proxy-1
```
**What the team does before checking the runbook:**
- Identify which node failed from HAProxy stats
- Confirm traffic is flowing correctly to the remaining node
- Restart the failed node

**Success criteria:**
- Team identifies the failed backend within 1 minute using HAProxy stats
- Node restarted and HAProxy marks it UP within 2 minutes (RTO target)
- No traffic was dropped during the failure (verify via request counters on remaining node)

### 4.3 GameDay Scenario 3: Total Fleet Failure

**Environment:** Docker Compose staging stack
**Duration:** 45 minutes
**Trigger command:**
```bash
docker-compose stop ja4proxy-1 ja4proxy-2
```
**What the team does before checking the runbook:**
- Confirm all proxy nodes are down from HAProxy stats
- Collect logs from both nodes to identify the cause
- Attempt restart of the fleet

**Success criteria:**
- Root cause identified (or ruled out) within 5 minutes
- Fleet restarted within 15 minutes (RTO target)
- End-to-end connectivity verified before GameDay is declared complete

### 4.4 GameDay Scenario 4: Dial Corruption

**Environment:** Docker Compose staging stack
**Duration:** 20 minutes
**Trigger command:**
```bash
redis-cli SET ja4proxy:dial 100 && \
  redis-cli PUBLISH ja4proxy:config_reload '{"source":"gameday","dial":100}'
```
**What the team does before checking the runbook:**
- Identify the unexpected blocking spike from Grafana dashboard
- Trace the cause to an unexpected dial value
- Drop to monitor mode and restore the intended dial setting

**Success criteria:**
- Team drops to monitor mode within 3 minutes (RTO target)
- Root cause (dial value in Redis) identified and corrected within 5 minutes
- Proxy behaviour verified to match the restored dial value

---

## 5. MTTR Baseline Measurement

`scripts/measure_mttr.sh` — automates Scenarios 1, 2, and 4 in a local Docker Compose
environment and records actual recovery times. Scenario 3 (total fleet failure) is not
automated because it requires deliberate operator judgment for the cause-investigation
phase; include it in GameDay exercises instead.

```bash
#!/usr/bin/env bash
set -euo pipefail

OUTPUT="MTTR_BASELINE.md"
COMPOSE="docker-compose"

log() { echo "[$(date -u +%H:%M:%S)] $*"; }
fail() { log "FAIL: $*"; exit 1; }

require_healthy() {
  local timeout="${1:-60}"
  for i in $(seq 1 "$timeout"); do
    if curl -sf --max-time 3 http://localhost:8090/api/v1/health/deep >/dev/null 2>&1; then
      echo "$i"
      return 0
    fi
    sleep 1
  done
  echo "TIMEOUT"
  return 1
}

log "Ensuring stack is up and healthy before measurement..."
$COMPOSE up -d
WAIT=$(require_healthy 90) || fail "Stack did not become healthy before measurement"
log "Stack healthy after ${WAIT}s"

declare -A MEASURED_S
declare -A PASS

# ── Scenario 1: Redis failure ─────────────────────────────────────────────────
log "=== Scenario 1: Redis failure ==="
$COMPOSE stop redis
START=$(date +%s)
until ! curl -sf --max-time 3 http://localhost:8090/api/v1/health/deep \
    | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get('redis')=='unreachable' else 1)" \
    >/dev/null 2>&1; do
  sleep 1
done
log "Degraded state detected"
$COMPOSE start redis
END=$(date +%s)
# Wait for recovery
until curl -sf --max-time 3 http://localhost:8090/api/v1/health/deep \
    | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get('redis')=='healthy' else 1)" \
    >/dev/null 2>&1; do
  sleep 1
  [ $(($(date +%s) - END)) -gt 60 ] && { log "Redis did not recover within 60s"; break; }
done
MTTR_1=$(($(date +%s) - START))
MEASURED_S[1]=$MTTR_1
PASS[1]=$([ "$MTTR_1" -le 300 ] && echo "PASS" || echo "FAIL")
log "Scenario 1 MTTR: ${MTTR_1}s (RTO: 300s) — ${PASS[1]}"

# ── Scenario 2: Single node failure ──────────────────────────────────────────
log "=== Scenario 2: Single proxy node failure ==="
$COMPOSE stop ja4proxy-1
START=$(date +%s)
$COMPOSE start ja4proxy-1
# Wait for HAProxy to mark the backend healthy (health check passes)
until $COMPOSE exec haproxy sh -c \
    'echo "show stat" | socat - /var/run/haproxy/admin.sock 2>/dev/null | grep ja4proxy-1 | grep -q "^[^,]*,[^,]*,UP"' \
    >/dev/null 2>&1; do
  sleep 1
  [ $(($(date +%s) - START)) -gt 120 ] && { log "Node did not recover within 120s"; break; }
done
MTTR_2=$(($(date +%s) - START))
MEASURED_S[2]=$MTTR_2
PASS[2]=$([ "$MTTR_2" -le 120 ] && echo "PASS" || echo "FAIL")
log "Scenario 2 MTTR: ${MTTR_2}s (RTO: 120s) — ${PASS[2]}"

# ── Scenario 4: Dial corruption ───────────────────────────────────────────────
log "=== Scenario 4: Dial corruption ==="
redis-cli SET ja4proxy:dial 100
redis-cli PUBLISH ja4proxy:config_reload '{"source":"measure_mttr","dial":100}' >/dev/null
START=$(date +%s)
# Recovery: drop to monitor mode
redis-cli SET ja4proxy:dial 0
redis-cli PUBLISH ja4proxy:config_reload '{"source":"measure_mttr","dial":0}' >/dev/null
# Verify dial is 0 in health endpoint
until curl -sf --max-time 3 http://localhost:8090/api/v1/health/deep \
    | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get('dial')==0 else 1)" \
    >/dev/null 2>&1; do
  sleep 1
  [ $(($(date +%s) - START)) -gt 60 ] && { log "Dial did not reset within 60s"; break; }
done
MTTR_4=$(($(date +%s) - START))
MEASURED_S[4]=$MTTR_4
PASS[4]=$([ "$MTTR_4" -le 180 ] && echo "PASS" || echo "FAIL")
log "Scenario 4 MTTR: ${MTTR_4}s (RTO: 180s) — ${PASS[4]}"

# ── Write MTTR_BASELINE.md ────────────────────────────────────────────────────
cat > "$OUTPUT" <<EOF
# MTTR Baseline

Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Environment: Docker Compose (local)

| Scenario | Trigger | Measured MTTR | RTO Target | Result |
|----------|---------|---------------|------------|--------|
| 1: Redis failure | \`docker-compose stop redis\` | ${MEASURED_S[1]}s | 300s | ${PASS[1]} |
| 2: Single node failure | \`docker-compose stop ja4proxy-1\` | ${MEASURED_S[2]}s | 120s | ${PASS[2]} |
| 4: Dial corruption | \`redis-cli SET ja4proxy:dial 100\` | ${MEASURED_S[4]}s | 180s | ${PASS[4]} |

Scenario 3 (total fleet failure) is exercised via GameDay only — not automated.
See: docs/runbooks/gameday_scenarios.md

## Notes

- MTTR is measured from trigger command to full health endpoint recovery.
- Scenario 2 MTTR ends when HAProxy marks the restarted node UP (two consecutive health checks).
- Scenario 4 MTTR ends when the health endpoint reflects \`"dial": 0\`.
- All scenarios were run in sequence on the same Docker Compose stack.
EOF

log "MTTR_BASELINE.md written"

OVERALL="PASS"
for k in 1 2 4; do
  [ "${PASS[$k]}" != "PASS" ] && OVERALL="FAIL"
done
log "Overall result: $OVERALL"
[ "$OVERALL" = "PASS" ] || exit 1
```

Run this script once on the developer workstation before any enterprise pilot deployment
and commit `MTTR_BASELINE.md` to the repository. The baseline is used in:
- Phase 86 capacity planning (provides concrete latency inputs)
- Phase 84 compliance evidence (demonstrates DR has been tested with measured outcomes)

---

## 6. Pre-Enterprise Validation Report Integration

Phase 62 introduced `scripts/generate_validation_report.py`. Add a `--section
deployment` flag that appends a deployment evidence section to the report.

The section includes:
- Smoke test results: links to `test-results/smoke/*.result` files with pass/fail summary
- MTTR baseline table: read from `MTTR_BASELINE.md` and embedded verbatim
- DR runbook exercise history: read from the "Runbook Exercise History" section of
  `docs/runbooks/disaster_recovery.md`
- Sign-off line: `"DR runbook exercised via GameDay: [DATE]"` (extracted from the runbook)

```python
# Extend scripts/generate_validation_report.py

def _section_deployment(report_dir: Path) -> str:
    lines = ["## Deployment Validation Evidence", ""]

    # Smoke test results
    smoke_dir = Path("test-results/smoke")
    lines.append("### Smoke Tests")
    if smoke_dir.exists():
        for result_file in sorted(smoke_dir.glob("*.result")):
            status = result_file.read_text().strip()
            lines.append(f"- {result_file.stem}: **{status}**")
    else:
        lines.append("- No smoke test results found. Run `make smoke` first.")
    lines.append("")

    # MTTR baseline
    mttr_file = Path("MTTR_BASELINE.md")
    lines.append("### MTTR Baseline")
    if mttr_file.exists():
        lines.extend(mttr_file.read_text().splitlines())
    else:
        lines.append("- `MTTR_BASELINE.md` not found. Run `make measure-mttr` first.")
    lines.append("")

    # DR runbook exercise history
    dr_runbook = Path("docs/runbooks/disaster_recovery.md")
    lines.append("### DR Runbook Exercise History")
    if dr_runbook.exists():
        content = dr_runbook.read_text()
        if "Runbook Exercise History" in content:
            section = content.split("Runbook Exercise History", 1)[1].split("\n## ", 1)[0]
            lines.extend(section.strip().splitlines())
        else:
            lines.append("- No exercise history recorded yet. Run a GameDay first.")
    lines.append("")

    return "\n".join(lines)
```

Call `_section_deployment()` when `--section deployment` is passed and append the result
to the report before the final sign-off block.

---

## 7. Makefile Targets

Add to the bottom of `Makefile` (never edit existing targets):

```makefile
## Phase 64 targets
smoke: smoke-docker
	@if command -v kind >/dev/null 2>&1; then \
	  $(MAKE) smoke-k8s; \
	else \
	  echo "kind not found — skipping Helm/kind smoke test. Install kind to run it."; \
	fi

smoke-docker:
	bash scripts/smoke/test_docker_compose.sh

smoke-k8s:
	bash scripts/smoke/test_helm_kind.sh

measure-mttr:
	bash scripts/measure_mttr.sh
```

`make smoke` is the CI target. `make smoke-docker` is added as a required CI job in
`.github/workflows/ci.yml`. `make smoke-k8s` is added as an optional CI job (runs if
`kind` is available via `helm/kind-action`). `make measure-mttr` is run locally by the
operator before an enterprise pilot and is not run in CI.

---

## 8. Acceptance Criteria

- [ ] `scripts/smoke/test_docker_compose.sh` exists, passes in CI (`make smoke-docker`), and writes a result file to `test-results/smoke/`
- [ ] `scripts/smoke/test_helm_kind.sh` exists and passes in a local `kind` environment or in CI via `helm/kind-action`; result is documented
- [ ] `scripts/smoke/test_podman_quadlet.sh` exists, skips gracefully on non-RHEL platforms, and is documented in the Phase 76 deployment guide as the manual pre-deployment validation step
- [ ] `docs/runbooks/disaster_recovery.md` exists and documents all four scenarios with symptoms, impact, `simulate:` command, recovery steps, RTO target, and RPO
- [ ] Each scenario in `docs/runbooks/disaster_recovery.md` includes a `simulate:` command that can be run without modifying any source files
- [ ] `scripts/measure_mttr.sh` exists and produces `MTTR_BASELINE.md` with results for Scenarios 1, 2, and 4
- [ ] `MTTR_BASELINE.md` shows measured MTTR within the RTO target for all three automated scenarios
- [ ] `docs/runbooks/gameday_scenarios.md` exists and documents all four GameDay exercises with trigger command, expected symptoms, team actions, and success criteria
- [ ] `docs/runbooks/disaster_recovery.md` contains a "Runbook Exercise History" section with at least one dated entry (first GameDay completed before enterprise pilot)
- [ ] `scripts/generate_validation_report.py` is extended (as specified in §6) to accept `--section deployment` and appends smoke test results, MTTR baseline, and DR exercise history to the report
- [ ] `make smoke`, `make smoke-docker`, `make smoke-k8s`, and `make measure-mttr` targets are added to the bottom of `Makefile`
- [ ] `make smoke-docker` is added as a required status check in `.github/workflows/ci.yml`
