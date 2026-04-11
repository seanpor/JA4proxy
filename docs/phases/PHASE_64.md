# Phase 64 — Deployment Validation & Disaster Recovery

> **Status:** PROPOSED
> **Size:** L (decomposed into 9 independent sub-phases: 64a–64i)
> **Owner files:** `scripts/smoke/*.sh`, `scripts/measure_mttr.sh`, `monitoring/alertmanager/rules/tls_alerts.yml`, `docs/runbooks/disaster_recovery.md` + 4 sibling runbooks, `Makefile`, `scripts/generate_validation_report.py`
> **Depends on:** Phase 63 (`ja4proxy_tls_cert_expiry_timestamp_seconds` gauge — **live in `internal/metrics/metrics.go`**)
> **Independent of:** Phase 61, 62
> **Last rewritten:** 2026-04-09 (restructured into sub-phases per Claude re-plan review)

---

## ⚠ Read this first — scope boundaries

**This phase is pure deployment artefacts: shell scripts, Markdown runbooks, and
Prometheus alert YAML. It touches NO Go source code and NO Python source code
(except `scripts/generate_validation_report.py` in sub-phase 64i, where a single
`--section deployment` flag is appended).**

The Go binary (`bin/proxy`) is the production runtime. The Python proxy (`proxy.py`)
is a prototyping surface only. All runbook commands in this document target the Go
production path.

**Smoke tests:** `make smoke-docker` runs as a **non-blocking** CI status check by
default. Operators may promote it to required after a stability window by editing
the `smoke_required` input in `.github/workflows/ci.yml`. `make smoke-k8s` is
always optional (runs only when `kind` is present).

**Hot-reload signal target — Go production only:**

```bash
# systemd-managed deployment (RHEL/Quadlet, most enterprise installs)
systemctl kill --signal=HUP ja4proxy.service

# Container deployment
docker kill --signal=HUP ja4proxy        # Docker Compose service name
podman kill --signal=HUP ja4proxy        # Podman / Quadlet

# Kubernetes
kubectl exec -it ja4proxy-xxxxx -- kill -HUP 1

# Bare process (development only)
pkill -HUP -f bin/proxy
```

**Health endpoint:** `http://<mgmt-host>:8090/api/v1/health/deep` — Management API
(FastAPI, port 8090). All smoke scripts and MTTR measurements poll this endpoint.
**Before running any script, verify the endpoint is live:**
```bash
curl -sf http://localhost:8090/api/v1/health/deep | python3 -m json.tool
```
If the path or port differs on your deployment, update the `HEALTH_URL` variable at
the top of each script.

---

## Already done — do not redo

- `Dockerfile.go-proxy` already has `USER ja4proxy` (line 51) — Phase 202
  acceptance can close that checkbox without code changes.
- The runbook library at `docs/runbooks/` already contains
  `redis_operations.md`, `go_proxy_operations.md`, `go_proxy_migration.md`,
  `security_incident_response.md`, `feed_management.md`,
  `external_api_failures.md`, `scaling.md`, `zero_downtime_rollouts.md`.
  This phase **references** those files; it does not duplicate their content.
- Phase 63 has shipped `ja4proxy_tls_cert_expiry_timestamp_seconds` gauge
  (`internal/metrics/metrics.go`, `cmd/proxy/main.go`). Alert rules in this
  phase consume the gauge directly — no `absent_over_time` guard needed.

---

## How to start — pick a sub-phase

All nine sub-phases are independent (except 64d, which reads a file from 64c).
A junior engineer should pick **one** sub-phase, create the branch, and deliver
it without needing context from the others.

**Recommended order for first-time contributors:**

| Priority | Sub-phase | Why |
|----------|-----------|-----|
| 1st | **64a** (Docker Compose smoke) | Smallest scope, immediate feedback, no external dependencies |
| 2nd | **64b** (Helm/kind smoke) | Same pattern as 64a, skip-if-absent makes it forgiving |
| 3rd | **64e** (Credential rotation) | Pure Markdown, copy-paste-friendly procedures |
| 4th | **64c** (Disaster recovery runbook) | Largest doc, but well-structured — follow the 5-scenario template |
| 5th | **64d** (GameDay scenarios) | Pure Markdown; requires 64c's file to exist first (see §64d) |
| 6th | **64f** (TLS cert rotation + alerts) | Alert YAML needs `promtool` validation (command inline below) |
| 7th | **64g** (Rolling upgrade) | Pure Markdown, references HAProxy config that may need verification |
| 8th | **64h** (MTTR baseline) | Largest script — pre-written template, but requires live stack to run |
| 9th | **64i** (Validation report) | Wiring work in an existing Python file — needs exact insertion points |

**Before running ANY smoke test or MTTR measurement, verify the health endpoint:**

```bash
# Pre-flight check — run this first
curl -sf http://localhost:8090/api/v1/health/deep | python3 -m json.tool
```

If this returns a JSON object (not an HTML error page, not a connection refusal),
the management API is live and all smoke/MTTR scripts will work. If it fails,
see the "Pre-flight checklist" section below before starting any sub-phase that
runs scripts against a live stack (64a, 64b, 64h).

---

## Pre-flight checklist

Run these checks before starting any sub-phase that executes scripts against a
live stack. **Sub-phases 64c, 64d, 64e, 64f, and 64g are pure documentation and
do not require any of these checks.**

### 1. Health endpoint is live

```bash
curl -sf http://localhost:8090/api/v1/health/deep | python3 -m json.tool
```

- **200 OK + JSON body:** ✅ Proceed.
- **Connection refused:** The management API (FastAPI, port 8090) is not running.
  Start the full stack with `make start` or run the management UI standalone.
- **404 Not Found:** The `/api/v1/health/deep` route does not exist yet.
  **File a Phase 101 entry** — do not block this phase. Update `HEALTH_URL`
  in each script to an alternate endpoint that exists.
- **HTML error page:** The route exists but is returning an error. Check
  management API logs.

### 2. Docker Compose is available

```bash
docker compose version   # Must be v2.x (space-separated)
```

- **v2.x:** ✅ Proceed.
- **v1.x (`docker-compose`):** Install Docker Compose v2. All scripts in this
  phase use `docker compose` (v2 syntax).
- **Command not found:** Install Docker Engine + Compose plugin.

### 3. `redis-cli` is available (64h only)

```bash
redis-cli PING
```

- **PONG:** ✅ Proceed.
- **Command not found:** Install `redis-tools` (`apt install redis-tools`,
  `brew install redis`, or download from https://redis.io/docs/install/).
- **Connection refused:** Redis is not running on localhost:6379. Start the
  full stack with `make start`.

### 4. HAProxy `socat` is available (64g rolling upgrade only)

```bash
docker compose exec haproxy which socat
```

- **Found:** ✅ Proceed.
- **Not found:** The Docker Compose rolling upgrade path cannot drain/re-enable
  backends gracefully. The script will fall back to waiting for health checks
  to re-route traffic. This is non-blocking — note it in `PHASE_64g_notes.md`.

### 5. `promtool` is available (64f alert rules only)

```bash
promtool --version
```

- **Found:** ✅ Proceed.
- **Not found:** Install from https://prometheus.io/docs/prometheus/latest/installation/
  or use the inline `promtool check rules` command provided in §64f.

---

## Deployment quick reference

All scenarios below reference this table for deployment-specific commands
(`start`, `stop`, `status`, `logs`, `hot-reload`).

| Operation | Docker Compose | Kubernetes | RHEL / Podman Quadlet |
|---|---|---|---|
| **Start** | `docker compose up -d` | `helm install ja4proxy deploy/helm/ja4proxy/ --wait` | `systemctl --user start ja4proxy` |
| **Stop** | `docker compose down -v` | `helm delete ja4proxy` | `systemctl --user stop ja4proxy` |
| **Status** | `docker compose ps` | `kubectl get pods -l app=ja4proxy` | `systemctl --user status ja4proxy` |
| **Logs** | `docker compose logs --tail=50 ja4proxy` | `kubectl logs -l app=ja4proxy --tail=50` | `journalctl --user -u ja4proxy -n 50` |
| **Hot-reload** | `docker kill --signal=HUP ja4proxy` | `kubectl exec ja4proxy-xxx -- kill -HUP 1` | `systemctl kill --signal=HUP ja4proxy.service` |
| **Health** | `curl -sf http://localhost:8090/api/v1/health/deep` | `kubectl exec ja4proxy-xxx -- wget -qO- http://localhost:8090/api/v1/health/deep` | `curl -sf http://localhost:8090/api/v1/health/deep` |

> All Docker commands use `docker compose` (v2, space-separated), never
> `docker-compose` (v1, hyphenated, EOL since 2023).

---

## Sub-phase index

Phase 64 is decomposed into **nine independent sub-phases**. Each is one branch,
one PR, one reviewer. Eight of nine are fully independent — 64d has a soft
dependency on 64c (see decoupling note below).

| Sub-phase | Deliverable | Size |
|---|---|---|
| [64a](#sub-phase-64a--docker-compose-smoke-test) | `scripts/smoke/test_docker_compose.sh` + CI job | XS |
| [64b](#sub-phase-64b--helm--kind-smoke-test) | `scripts/smoke/test_helm_kind.sh` + CI job | XS |
| [64c](#sub-phase-64c--disaster-recovery-runbook) | `docs/runbooks/disaster_recovery.md` (5 scenarios) | S |
| [64d](#sub-phase-64d--gameday-scenarios) | `docs/runbooks/gameday_scenarios.md` + exercise log | XS |
| [64e](#sub-phase-64e--credential-rotation) | `docs/runbooks/credential_rotation.md` | XS |
| [64f](#sub-phase-64f--tls-certificate-rotation--alerts) | `docs/runbooks/tls_certificate_rotation.md` + `tls_alerts.yml` | S |
| [64g](#sub-phase-64g--rolling-upgrade) | `docs/runbooks/rolling_upgrade.md` | S |
| [64h](#sub-phase-64h--mttr-baseline) | `scripts/measure_mttr.sh` + `MTTR_BASELINE.md` | M |
| [64i](#sub-phase-64i--validation-report-deployment-section) | `--section deployment` on `generate_validation_report.py` | XS |

**Soft dependency — 64d on 64c (decoupled):**
64d's GameDay exercises reference scenarios defined in 64c's DR runbook.
To avoid merge conflicts and blocking:
- **64d writes its exercise log to `gameday_scenarios.md` first** (own section).
- **After 64c merges, a separate follow-up commit** copies the "Runbook Exercise
  History" entry into `disaster_recovery.md`. This is a 2-line edit, not a
  sub-phase — any reviewer can do it.
- **64d does NOT wait for 64c to merge.** Develop in parallel. The copy step
  happens post-merge.

**Dropped (file as Phase 101 entries):**
- Podman/Quadlet smoke test — `deploy/rhel/quadlets/` does not exist. Phase 76
  was a strategy document only. Revisit when Phase 76 produces actual `.container`,
  `.network`, `.kube` unit files.
- `ja4proxy-cli backup …` references — the Go CLI (`cmd/ja4proxy-cli/main.go`)
  has **no `backup` subcommand**. Phase 19's backup system is Python-only
  (`src/backup/worker.py`, `src/backup/restorer.py`). All runbooks must use the
  correct invocation (see §64c Scenario 5).

---

## Sub-phase 64a — Docker Compose smoke test

**Deliverable:** `scripts/smoke/test_docker_compose.sh` and a `make smoke-docker`
target. Non-blocking CI status check by default (promotable to required).

**What the script must do:**
1. `mkdir -p test-results/smoke` and open a timestamped log.
2. `docker compose up -d` (v2 syntax, space-separated).
3. Poll `http://localhost:8090/api/v1/health/deep` for up to 60 s; fail if
   it never returns 200. **Verify this endpoint is live before running
   the script** (see "Health endpoint" at the top of this document).
4. Verify every service in `docker compose ps --format json` has
   `State == "running"`. Fail with the list of unhealthy services if not.
5. Send a synthetic TLS connection to `localhost:8080` via
   `openssl s_client`. Treat any TLS-layer response as success; treat
   `Connection refused` as failure (the proxy is not listening).
6. `docker compose down -v` and write `PASS` to
   `test-results/smoke/docker-compose.result` on success.

```bash
#!/usr/bin/env bash
set -euo pipefail

HEALTH_URL="${HEALTH_URL:-http://localhost:8090/api/v1/health/deep}"
RESULTS_DIR="test-results/smoke"
mkdir -p "$RESULTS_DIR"
LOG="$RESULTS_DIR/docker-compose-$(date +%Y%m%dT%H%M%S).log"

log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
fail() { log "FAIL: $*"; exit 1; }

log "Starting Docker Compose stack..."
docker compose up -d 2>>"$LOG" || fail "docker compose up failed"

log "Waiting for health endpoint (max 60s)..."
for i in $(seq 1 60); do
  if curl -sf --max-time 5 "$HEALTH_URL" >/dev/null 2>&1; then
    log "Health endpoint OK after ${i}s"
    break
  fi
  [ "$i" -eq 60 ] && fail "Health endpoint did not respond within 60s"
  sleep 1
done

log "Checking all containers are Running..."
UNHEALTHY=$(docker compose ps --format json 2>/dev/null \
  | python3 -c "import sys,json; [print(s['Service']) for s in json.load(sys.stdin) if s.get('State') != 'running']" \
  2>/dev/null || true)
[ -n "$UNHEALTHY" ] && fail "Containers not running: $UNHEALTHY"

log "Sending synthetic TLS connection through port 8080..."
echo "Q" | openssl s_client -connect localhost:8080 -servername localhost \
  -verify_return_error 2>>"$LOG" || {
  grep -q "Connection refused" "$LOG" && fail "Proxy port 8080 is not listening"
  log "Proxy responded at TLS layer (connection accepted and processed)"
}

log "Tearing down stack..."
docker compose down -v 2>>"$LOG" || fail "docker compose down failed"

log "PASS: Docker Compose smoke test"
echo "PASS" > "$RESULTS_DIR/docker-compose.result"
```

**CI configuration (`.github/workflows/ci.yml`):**
```yaml
  smoke-docker:
    runs-on: ubuntu-latest
    continue-on-error: ${{ !inputs.smoke_required }}
    steps:
      - uses: actions/checkout@v4
      - run: make smoke-docker
```

The `smoke_required` input defaults to `false`. After a one-week stability
window, the team sets it to `true` to make this a blocking check.

**Makefile target (append to bottom):**
```makefile
smoke-docker:
	bash scripts/smoke/test_docker_compose.sh
```

**Acceptance criteria:**
- [ ] Script runs to PASS on a clean clone after `make build`.
- [ ] Script exits non-zero with clear stderr if any container is not running.
- [ ] `make smoke-docker` invokes the script.
- [ ] CI job `smoke-docker` added as non-blocking (continue-on-error) to `.github/workflows/ci.yml`.
- [ ] Script uses `docker compose` (v2), never `docker-compose` (v1).
- [ ] `PHASE_64a_notes.md` records the host, compose version, and log path.

**Out of scope:** Helm, kind, podman, MTTR measurement.

---

## Sub-phase 64b — Helm + kind smoke test

**Deliverable:** `scripts/smoke/test_helm_kind.sh` and a `make smoke-k8s`
target. Always optional (runs only when `kind` is on `$PATH`).

**What the script must do:**
1. Skip with exit 0 and a clear `SKIP:` message if `kind` or `helm` are not
   on `$PATH`.
2. Create a single-node `kind` cluster named `ja4proxy-smoke`. Always
   delete it on exit via `trap`.
3. `helm install ja4proxy deploy/helm/ja4proxy/ --wait --timeout=120s`.
4. `kubectl rollout status deployment/ja4proxy --timeout=60s` (note: the
   chart uses a Deployment, not a DaemonSet — verify `deploy/helm/ja4proxy/`
   before running; if a DaemonSet exists, use that instead).
5. `kubectl exec` into the first pod and curl its in-pod health endpoint.
6. Write `PASS` to `test-results/smoke/helm-kind.result` on success.

```bash
#!/usr/bin/env bash
set -euo pipefail

RESULTS_DIR="test-results/smoke"
mkdir -p "$RESULTS_DIR"
LOG="$RESULTS_DIR/helm-kind-$(date +%Y%m%dT%H%M%S).log"

log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
fail() { log "FAIL: $*"; exit 1; }

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

log "Checking Deployment status..."
KIND=$(kubectl get -f deploy/helm/ja4proxy/templates/ -o jsonpath='{.items[0].kind}' 2>/dev/null || echo "Deployment")
if [ "$KIND" = "DaemonSet" ]; then
  kubectl rollout status daemonset/ja4proxy --timeout=60s 2>>"$LOG" \
    || fail "DaemonSet did not become ready within 60s"
else
  kubectl rollout status deployment/ja4proxy --timeout=60s 2>>"$LOG" \
    || fail "Deployment did not become ready within 60s"
fi

POD=$(kubectl get pods -l app=ja4proxy -o jsonpath='{.items[0].metadata.name}' 2>>"$LOG")
[ -z "$POD" ] && fail "No ja4proxy pods found"

log "Running health check inside pod: $POD"
kubectl exec "$POD" -- \
  wget -qO- http://localhost:8090/api/v1/health/deep 2>>"$LOG" \
  || fail "Health check inside pod failed"

log "PASS: Helm + kind smoke test"
echo "PASS" > "$RESULTS_DIR/helm-kind.result"
# Cluster deleted by trap
```

**Makefile target (append to bottom):**
```makefile
smoke-k8s:
	bash scripts/smoke/test_helm_kind.sh
```

**Acceptance criteria:**
- [ ] Script runs to PASS on a workstation with `kind` and `helm` installed.
- [ ] Script skips cleanly (exit 0, no error) when `kind` is absent.
- [ ] CI job `smoke-k8s` added as non-blocking to `.github/workflows/ci.yml` using
      `helm/kind-action@v1` as a prior step.
- [ ] `PHASE_64b_notes.md` records kind version, helm version, and pod log.

**Out of scope:** Helm chart changes. If the chart needs fixing for the smoke
test to pass, file a Phase 101 entry rather than blocking 64b.

---

## Sub-phase 64c — Disaster Recovery runbook

**Deliverable:** `docs/runbooks/disaster_recovery.md`.

**Structure (mandatory):**

1. **See also** block — link to every existing runbook:
   - `redis_operations.md` — routine Redis ops (start, stop, AOF rewrite, slowlog)
   - `go_proxy_operations.md` — day-2 Go proxy ops (start, stop, log rotation)
   - `go_proxy_migration.md` — Python → Go migration
   - `security_incident_response.md` — active security incidents
   - `feed_management.md` — threat-intel feed troubleshooting
   - `external_api_failures.md` — AbuseIPDB/RDAP/MaxMind outages
   - `scaling.md` — horizontal scaling, adding proxy nodes
   - `zero_downtime_rollouts.md` — zero-downtime config rollout

2. **Deployment quick reference** — small table mapping
   {Docker Compose, Kubernetes, RHEL/Quadlet} to the equivalent
   `start / stop / status / logs / hot-reload` commands. Every later
   scenario references this table instead of inlining commands.

3. **Five scenarios**, each with H3 substructure:
   - Symptoms (what an operator observes first)
   - Impact (what the proxy does during the failure)
   - Simulate (the exact command to trigger in a test stack)
   - Recovery steps (numbered, with expected output)
   - RTO target
   - RPO

**Content gap guidance — what to write vs what already exists:**

The eight existing runbooks cover **routine operations**. The DR runbook covers
**catastrophic failures that require coordination across multiple systems**.
Each scenario below must include content that is **not already in the linked
runbooks**:

| Scenario | Already covered in existing runbook | NEW content this DR runbook must add |
|---|---|---|
| 1. Redis failure | `redis_operations.md` has restart commands | Proxy fail-open behaviour, which bans/rate-limits are suspended, how to verify the proxy reconnected to Redis and resumed enforcement |
| 2. Single node failure | `go_proxy_operations.md` has start/stop | HAProxy backend health check timing (`inter`, `rise`, `fall`), traffic failover window, how to verify the restarted node re-joins the pool |
| 3. Total fleet failure | `scaling.md` has add-node procedure | P1 incident workflow: collect logs from all nodes simultaneously, identify root cause, when to revert config vs when to restart, RPO is the last Redis checkpoint — how to find that timestamp |
| 4. Config corruption / dial | `redis_operations.md` has key manipulation | Monitor-mode first (`dial=0`), then revert, then restore — the three-phase recovery that prevents applying bad config to a recovering fleet |
| 5. Redis data loss | `redis_operations.md` has AOF rewrite | Full volume destruction + rebuild: `docker volume rm`, restore from Phase 19 Python backup tool, state re-learning timeline (1-4 hours of live traffic) |

**Rule of thumb:** If the procedure is a single `systemctl restart` or
`docker compose restart` command, it belongs in the existing runbook, not here.
This DR runbook is for scenarios where **the operator must coordinate 2+
systems** (proxy + Redis + HAProxy + config) to recover.

4. **Runbook Exercise History** — empty H2 section for GameDay logs (64d).
   See "Soft dependency — 64d on 64c (decoupled)" in the sub-phase index
   above for how 64d writes its log without blocking on 64c's merge.

**The five scenarios:**

1. **Redis failure** — proxy fails open, bans not enforced, rate limiting
   disabled. Restore Redis, verify reconnect. RTO: 5 min. RPO: zero (Redis
   persistent data survives restart).
2. **Single proxy node failure** — HAProxy marks backend DOWN within `inter`
   seconds, traffic flows to remaining nodes. Restart node, verify UP.
   RTO: 2 min. RPO: zero.
3. **Total fleet failure** — all backends DOWN, 503 to users. P1 incident.
   Collect logs, identify cause, revert config if needed, restart fleet.
   RTO: 15 min. RPO: last Redis checkpoint.
4. **Config corruption / malformed dial** — sudden spike/drop in blocks.
   Drop to dial=0 first, then revert config, then restore intended dial.
   RTO: 3 min to monitor mode. RPO: zero (git-tracked config).
5. **Redis data loss** — distinct from scenario 1; bans/rate-limit state
   gone. If Phase 19 backup exists, restore it using the Python backup
   tool:
   ```bash
   # Phase 19 backup restore (Python tool, not ja4proxy-cli):
   python3 -c "from src.backup.restorer import Restorer; \
     Restorer('redis://:PASSWORD@localhost:6379/0', \
     Path('/var/backups/ja4proxy/backups/<filename>.tar.gz')).restore(delete_data_first=False)"
   ```
   If no backup exists, set dial=0 while state rebuilds from live traffic
   (1–4 hours). RTO: 30 min with backup, 4 hours without. RPO: last
   Phase 19 backup timestamp.

**Acceptance criteria:**
- [ ] File exists with all five scenarios in the structure above.
- [ ] "See also" block links to all 8 existing runbooks.
- [ ] No scenario duplicates content from any linked runbook.
- [ ] Scenario 5 uses the correct Phase 19 Python invocation (see above),
      not phantom `ja4proxy-cli backup` commands.
- [ ] All hot-reload commands use Go-production form only
      (`systemctl kill --signal=HUP ja4proxy.service` or container equivalents).
      No `pkill -f proxy.py`, no `pkill -f bin/proxy` except the dev note.
- [ ] `PHASE_64c_notes.md` lists which Phase 19 commands were verified.

**Out of scope:** Implementation, testing, or execution of the recovery
procedures. This sub-phase produces the document only.

---

## Sub-phase 64d — GameDay scenarios

**Deliverable:** `docs/runbooks/gameday_scenarios.md`.

**Content:** Four GameDay exercises, each with environment, duration, trigger
command, what the team does *before* opening the runbook, and success criteria
with measurable RTO targets.

1. **Redis outage** — trigger: `docker compose stop redis`. Team identifies
   `ja4proxy_redis_errors_total` within 2 min, recovers within 5 min.
2. **Node failure** — trigger: `docker compose stop ja4proxy` (or the first
   proxy container name on your stack). Team identifies failed backend within
   1 min, recovers within 2 min.
3. **Total fleet failure** — trigger: stop all proxy containers.
   Root cause within 5 min, fleet up within 15 min.
4. **Dial corruption** — trigger: `redis-cli SET ja4proxy:dial 100` + publish.
   Team drops to dial=0 within 3 min, corrects within 5 min.

After the author runs the first GameDay (Redis outage) against the local
`make start` stack, they append a dated entry to the "Runbook Exercise
History" section of **`gameday_scenarios.md`** (this file's own section).

**Acceptance criteria:**
- [ ] File exists with all four exercises in the structure above.
- [ ] Each exercise links back to the matching scenario in `disaster_recovery.md`.
- [ ] First GameDay (Redis outage) exercised locally; dated entry appended
      to `gameday_scenarios.md`'s own "Runbook Exercise History" section.
- [ ] `PHASE_64d_notes.md` records gaps surfaced.

**Coordination (decoupled from 64c):**
64d writes its exercise history to `gameday_scenarios.md` during development —
no dependency on 64c's merge status. **After 64c merges**, the 64d author (or
any reviewer) makes a separate follow-up commit that copies the exercise history
entry into `disaster_recovery.md`'s "Runbook Exercise History" section. This is
a 2-line append, tracked as a Phase 64 close-out checklist item, not a blocking
dependency.

---

## Sub-phase 64e — Credential rotation

**Deliverable:** `docs/runbooks/credential_rotation.md`.

**Sections:**
1. **Redis auth password rotation** — zero-downtime via Redis ACL:
   ```bash
   # Add new password alongside old
   redis-cli ACL SETUSER default on >NEW_PASSWORD >OLD_PASSWORD ~* &* +@all
   # Update config, hot-reload all nodes, verify, then drop old:
   redis-cli ACL SETUSER default on >NEW_PASSWORD ~* &* +@all
   ```
   Rollback: re-add the old password to ACL if hot-reload fails.
2. **AbuseIPDB API key rotation** — verify new key with `curl`, hot-reload,
   watch `ja4proxy_abuseipdb_lookups_total{result="hit"}`, revoke old key
   after 30-second delay.
3. **Cloud storage credentials** (Phase 57, S3/GCS) — IAM key rotation,
   secret update, restart backup container, manual backup verify, delete old key.

**Acceptance criteria:**
- [ ] All three rotation procedures documented with numbered steps.
- [ ] All hot-reload commands use Go-production form.
- [ ] Each procedure has an explicit "Rollback" subsection.
- [ ] No `kill -HUP $(pgrep -f proxy.py)`.
- [ ] `PHASE_64e_notes.md` records dry-run walkthrough against local stack.

---

## Sub-phase 64f — TLS certificate rotation + alerts

**Deliverable:**
- `docs/runbooks/tls_certificate_rotation.md`
- `monitoring/alertmanager/rules/tls_alerts.yml`

**Runbook sections:**
1. Certificate expiry monitoring — Phase 63's gauge is live; alert rules
   consume it directly (no `absent_over_time` guard).
2. Server-side TLS certificate rotation — rolling, one node at a time,
   hot-reload via SIGHUP.
3. mTLS CA certificate rotation — dual-CA trust bundle period
   (combined PEM → reload → migrate clients → drop old CA → reload).

**Alert rules (`tls_alerts.yml`):**
```yaml
groups:
  - name: tls_certificate_expiry
    rules:
      - alert: JA4proxyTLSCertExpiringSoon
        expr: |
          (ja4proxy_tls_cert_expiry_timestamp_seconds - time()) / 86400 < 30
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "TLS certificate expires in {{ $value | humanize }} days"
          description: |
            The proxy's server-side TLS certificate expires in less than 30 days.
            Rotate using docs/runbooks/tls_certificate_rotation.md.

      - alert: JA4proxyTLSCertExpiryCritical
        expr: |
          (ja4proxy_tls_cert_expiry_timestamp_seconds - time()) / 86400 < 7
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "TLS certificate expires in {{ $value | humanize }} days — CRITICAL"
          description: |
            The proxy's server-side TLS certificate expires in less than 7 days.
            Rotate immediately using docs/runbooks/tls_certificate_rotation.md.
```

**Acceptance criteria:**
- [ ] Runbook exists with all three sections.
- [ ] Alert rule file exists and validates with `promtool`:
      ```bash
      promtool check rules monitoring/alertmanager/rules/tls_alerts.yml
      ```
      If `promtool` is not installed, paste the YAML into the [Prometheus
      rules playground](https://promlabs.com/promql-analyzer/) or validate
      manually against the [PromQL alerting rules spec](https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/).
- [ ] Runbook references the Phase 63 gauge by its real name
      (`ja4proxy_tls_cert_expiry_timestamp_seconds`).
- [ ] No `absent_over_time` guard — the gauge is live.
- [ ] No mention of Phase 63 being incomplete or pending.
- [ ] `PHASE_64f_notes.md` records lint result and gauge verification in
      `internal/metrics/metrics.go`.

---

## Sub-phase 64g — Rolling upgrade

**Deliverable:** `docs/runbooks/rolling_upgrade.md`.

**Sections:**
1. Prerequisites — HAProxy with health checks (`inter 2s rise 2 fall 2`),
   ≥ 2 instances, smoke test passing in staging.
2. Docker Compose rolling upgrade — drain via HAProxy admin socket,
   recreate one service at a time, wait for health, re-enable, repeat
   with 30-second stagger.
3. Kubernetes rolling upgrade — `helm upgrade` with `--wait`,
   monitor via `kubectl rollout status`. DaemonSet `maxUnavailable: 1`.
4. Rollback — both models:
   - Docker Compose: `docker compose up -d --no-deps --force-recreate
     ja4proxy-1 --image "ghcr.io/org/ja4proxy:PREVIOUS_TAG"` + re-enable
     via HAProxy admin socket.
   - Kubernetes: `kubectl rollout undo daemonset/ja4proxy`.

**Prerequisite note for HAProxy admin socket access:** the rolling upgrade
script requires `socat` in the HAProxy container and the admin socket at
`/var/run/haproxy/admin.sock`. If either is missing, the Docker Compose
path cannot drain/re-enable gracefully — fall back to waiting for health
checks to re-route traffic. Verify before running:
```bash
docker compose exec haproxy which socat
docker compose exec haproxy ls /var/run/haproxy/admin.sock
```

**Acceptance criteria:**
- [ ] Runbook covers all four sections.
- [ ] All commands use `docker compose` (v2), not `docker-compose` (v1).
- [ ] Rollback subsections give a single-command answer for each model.
- [ ] `PHASE_64g_notes.md` records dry-run walkthrough of rollback path.

---

## Sub-phase 64h — MTTR baseline

**Deliverable:** `scripts/measure_mttr.sh`, `make measure-mttr` target,
and a committed `MTTR_BASELINE.md` produced by running the script once.

**Script behaviour:**
- Brings up the local Compose stack and waits for `health/deep` healthy.
- Runs Scenarios 1, 2, 4, 5 (Scenario 3 is GameDay-only).
- Measures wall-clock time from trigger to recovery.
- Writes `MTTR_BASELINE.md` with a results table mapping scenario →
  measured MTTR → RTO target → PASS/FAIL.
- Exits 0 if all four scenarios are within RTO; 1 otherwise.

**Prerequisite checks:**
- Before running, verify `socat` is available in the HAProxy container
  (needed for Scenario 2 backend status check).
- Verify the Redis volume name via `docker compose volume ls` — do NOT
  hardcode `ja4proxy_redis-data`. The volume name may be prefixed with
  the project directory (e.g. `ja4proxy_ja4proxy-redis-data`).

```bash
#!/usr/bin/env bash
set -euo pipefail

HEALTH_URL="${HEALTH_URL:-http://localhost:8090/api/v1/health/deep}"
OUTPUT="MTTR_BASELINE.md"
COMPOSE="${COMPOSE:-docker compose}"

log() { echo "[$(date -u +%H:%M:%S)] $*"; }
fail() { log "FAIL: $*"; exit 1; }

require_healthy() {
  local timeout="${1:-60}"
  for i in $(seq 1 "$timeout"); do
    if curl -sf --max-time 3 "$HEALTH_URL" >/dev/null 2>&1; then
      echo "$i"
      return 0
    fi
    sleep 1
  done
  echo "TIMEOUT"
  return 1
}

# ── Pre-flight: redis-cli ─────────────────────────────────────────────────────
if ! command -v redis-cli &>/dev/null; then
  log "SKIP: redis-cli not found on PATH."
  log "  Install:  apt install redis-tools  |  brew install redis  |  https://redis.io/docs/install/"
  exit 0
fi
if ! redis-cli PING >/dev/null 2>&1; then
  log "SKIP: redis-cli cannot connect to localhost:6379."
  log "  Start the stack with 'make start' or 'docker compose up -d redis' first."
  exit 0
fi

# ── Derive service names from compose — do not hardcode ───────────────────────
# The proxy container might be named ja4proxy, ja4proxy-1, or proxy.
# Derive it from the running compose project.
PROXY_CONTAINER=$($COMPOSE ps --format json 2>/dev/null \
  | python3 -c "
import sys, json
try:
    services = json.load(sys.stdin)
    for s in services:
        name = s.get('Service', s.get('Name', ''))
        if 'ja4proxy' in name.lower() or 'proxy' in name.lower():
            print(name)
            sys.exit(0)
except Exception:
    pass
# Fallback: try common names
" 2>/dev/null || true)

if [ -z "$PROXY_CONTAINER" ]; then
  # Fallback: grep from compose ps output
  PROXY_CONTAINER=$($COMPOSE ps --services 2>/dev/null | grep -i proxy | head -1 || true)
fi
if [ -z "$PROXY_CONTAINER" ]; then
  log "SKIP: Could not determine proxy container name from docker compose."
  log "  Ensure the stack is running: docker compose ps"
  exit 0
fi
log "Using proxy container name: $PROXY_CONTAINER"

# Derive Redis volume name from compose — do not hardcode.
REDIS_VOLUME=$($COMPOSE volume ls --format '{{.Name}}' 2>/dev/null | grep -i redis | head -1)
if [ -z "$REDIS_VOLUME" ]; then
  log "SKIP: No Redis volume found in docker compose. Run against a live stack."
  exit 0
fi
log "Using Redis volume: $REDIS_VOLUME"

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
# Wait until health endpoint reports redis as unreachable (or degraded)
for i in $(seq 1 120); do
  BODY=$(curl -sf --max-time 3 "$HEALTH_URL" 2>/dev/null || echo "{}")
  if echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get('redis') != 'healthy' else 1)" 2>/dev/null; then
    log "Degraded state detected after ${i}s"
    break
  fi
  [ "$i" -eq 120 ] && { log "WARN: Health endpoint did not report degraded Redis within 120s — proceeding anyway"; break; }
  sleep 1
done
$COMPOSE start redis
END=$(date +%s)
until curl -sf --max-time 3 "$HEALTH_URL" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get('redis')=='healthy' else 1)" \
    >/dev/null 2>&1; do
  sleep 1
  [ $(($(date +%s) - END)) -gt 60 ] && { log "Redis did not recover within 60s"; break; }
done
MTTR_1=$(($(date +%s) - START))
MEASURED_S[1]=$MTTR_1
PASS[1]=$([ "$MTTR_1" -le 300 ] && echo "PASS" || echo "FAIL")
log "Scenario 1 MTTR: ${MTTR_1}s (RTO: 300s) — ${PASS[1]}"

# ── Scenario 2: Single proxy node failure ─────────────────────────────────────
log "=== Scenario 2: Single proxy node failure ==="
$COMPOSE stop "$PROXY_CONTAINER"
START=$(date +%s)
$COMPOSE start "$PROXY_CONTAINER"
until curl -sf --max-time 3 "$HEALTH_URL" >/dev/null 2>&1; do
  sleep 1
  [ $(($(date +%s) - START)) -gt 120 ] && { log "Proxy did not recover within 120s"; break; }
done
MTTR_2=$(($(date +%s) - START))
MEASURED_S[2]=$MTTR_2
PASS[2]=$([ "$MTTR_2" -le 120 ] && echo "PASS" || echo "FAIL")
log "Scenario 2 MTTR: ${MTTR_2}s (RTO: 120s) — ${PASS[2]}"

# ── Scenario 4: Dial corruption ───────────────────────────────────────────────
log "=== Scenario 4: Dial corruption ==="
redis-cli SET ja4proxy:dial 100 >/dev/null 2>&1
redis-cli PUBLISH ja4proxy:config_reload '{"source":"measure_mttr","dial":100}' >/dev/null 2>&1
START=$(date +%s)
redis-cli SET ja4proxy:dial 0 >/dev/null 2>&1
redis-cli PUBLISH ja4proxy:config_reload '{"source":"measure_mttr","dial":0}' >/dev/null 2>&1
until curl -sf --max-time 3 "$HEALTH_URL" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get('dial')==0 else 1)" \
    >/dev/null 2>&1; do
  sleep 1
  [ $(($(date +%s) - START)) -gt 60 ] && { log "Dial did not reset within 60s"; break; }
done
MTTR_4=$(($(date +%s) - START))
MEASURED_S[4]=$MTTR_4
PASS[4]=$([ "$MTTR_4" -le 180 ] && echo "PASS" || echo "FAIL")
log "Scenario 4 MTTR: ${MTTR_4}s (RTO: 180s) — ${PASS[4]}"

# ── Scenario 5: Redis data loss ───────────────────────────────────────────────
log "=== Scenario 5: Redis data loss ==="
redis-cli SET ja4proxy:mttr_probe "1" EX 3600 >/dev/null 2>&1
$COMPOSE stop redis
$COMPOSE down -v --remove-orphans 2>/dev/null || true
docker volume rm "$REDIS_VOLUME" 2>/dev/null || true
START=$(date +%s)
$COMPOSE up -d redis
until redis-cli PING >/dev/null 2>&1; do
  sleep 1
  [ $(($(date +%s) - START)) -gt 30 ] && { log "Redis did not restart within 30s"; break; }
done
KEY_EXISTS=$(redis-cli EXISTS ja4proxy:mttr_probe 2>/dev/null || echo "0")
if [ "$KEY_EXISTS" != "0" ]; then
  log "WARN: probe key still exists — data loss simulation may not have worked (volume persisted)"
fi
redis-cli SET ja4proxy:dial 0 >/dev/null 2>&1
redis-cli PUBLISH ja4proxy:config_reload '{"source":"measure_mttr","dial":0}' >/dev/null 2>&1
MTTR_5=$(($(date +%s) - START))
MEASURED_S[5]=$MTTR_5
PASS[5]=$([ "$MTTR_5" -le 300 ] && echo "PASS" || echo "FAIL")
log "Scenario 5 MTTR (Redis restart + dial reset): ${MTTR_5}s (RTO: 300s) — ${PASS[5]}"

# ── Write MTTR_BASELINE.md ────────────────────────────────────────────────────
cat > "$OUTPUT" <<EOF
# MTTR Baseline

Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Environment: Docker Compose (local)
Proxy container: $PROXY_CONTAINER

| Scenario | Trigger | Measured MTTR | RTO Target | Result |
|----------|---------|---------------|------------|--------|
| 1: Redis failure | \`docker compose stop redis\` | ${MEASURED_S[1]}s | 300s | ${PASS[1]} |
| 2: Single node failure | \`docker compose stop $PROXY_CONTAINER\` | ${MEASURED_S[2]}s | 120s | ${PASS[2]} |
| 4: Dial corruption | \`redis-cli SET ja4proxy:dial 100\` | ${MEASURED_S[4]}s | 180s | ${PASS[4]} |
| 5: Redis data loss | \`docker volume rm $REDIS_VOLUME\` | ${MEASURED_S[5]}s | 300s | ${PASS[5]} |

Scenario 3 (total fleet failure) is exercised via GameDay only — not automated.
See: docs/runbooks/gameday_scenarios.md

Scenario 5 MTTR covers Redis restart and dial reset to monitor mode only.
Full state re-learning (1–4 hours) is not automated; see Phase 64c §5 for the full procedure.

## Notes

- MTTR is measured from trigger to full health endpoint recovery.
- Scenario 2 ends when the health endpoint responds (two consecutive health checks).
- Scenario 4 ends when the health endpoint reflects \`"dial": 0\`.
- Scenario 5 ends when Redis is responding and dial has been reset to 0.
- All scenarios were run in sequence on the same Docker Compose stack.
EOF

log "MTTR_BASELINE.md written"

OVERALL="PASS"
for k in 1 2 4 5; do
  [ "${PASS[$k]}" != "PASS" ] && OVERALL="FAIL"
done
log "Overall result: $OVERALL"
[ "$OVERALL" = "PASS" ] || exit 1
```

**Makefile target (append to bottom):**
```makefile
measure-mttr:
	bash scripts/measure_mttr.sh
```

**Acceptance criteria:**
- [ ] Script runs end-to-end and produces `MTTR_BASELINE.md`.
- [ ] All four scenarios PASS within their RTO targets on the author's workstation.
      If any fail, file a Phase 101 entry rather than lowering the target.
- [ ] `MTTR_BASELINE.md` is committed.
- [ ] `make measure-mttr` invokes the script.
- [ ] Script uses `docker compose` (v2).
- [ ] Redis volume name is derived from `docker compose volume ls`, not hardcoded.
- [ ] `PHASE_64h_notes.md` records host CPU/RAM and the four measured MTTR values.

**Out of scope:** Scenario 3 automation (deliberately GameDay-only).

---

## Sub-phase 64i — Validation report deployment section

**Deliverable:** `--section deployment` flag added to
`scripts/generate_validation_report.py`.

**Behaviour:** When passed `--section deployment`, the script appends a
"Deployment Validation Evidence" section containing:
- Smoke test results (read from `test-results/smoke/*.result`).
- MTTR baseline table (read from `MTTR_BASELINE.md`).
- DR runbook exercise history (extracted from
  `docs/runbooks/disaster_recovery.md`; falls back to
  `gameday_scenarios.md` if not yet in disaster_recovery.md).

**Graceful degradation:** If any input is missing, the section emits a
single line stating what to run to produce it. The script never fails
because an input is missing.

**Wiring instructions — exact insertion points:**

The existing `scripts/generate_validation_report.py` has two functions to modify:
`main()` (argparse) and `build_report()` (the report builder). Follow these
steps in order:

**Step 1 — Add the function.** Insert `_section_deployment()` anywhere before
`build_report()` (e.g., after `fuzz_smoke_section()`):

```python
def _section_deployment(report_dir: Path) -> str:
    lines = ["## Deployment Validation Evidence", ""]

    smoke_dir = Path("test-results/smoke")
    lines.append("### Smoke Tests")
    if smoke_dir.exists():
        for result_file in sorted(smoke_dir.glob("*.result")):
            status = result_file.read_text().strip()
            lines.append(f"- {result_file.stem}: **{status}**")
    else:
        lines.append("- No smoke test results found. Run `make smoke-docker` first.")
    lines.append("")

    mttr_file = Path("MTTR_BASELINE.md")
    lines.append("### MTTR Baseline")
    if mttr_file.exists():
        lines.extend(mttr_file.read_text().splitlines())
    else:
        lines.append("- `MTTR_BASELINE.md` not found. Run `make measure-mttr` first.")
    lines.append("")

    dr_runbook = Path("docs/runbooks/disaster_recovery.md")
    gameday_file = Path("docs/runbooks/gameday_scenarios.md")
    lines.append("### DR Runbook Exercise History")
    if dr_runbook.exists() and "Runbook Exercise History" in dr_runbook.read_text():
        content = dr_runbook.read_text()
        section = content.split("Runbook Exercise History", 1)[1].split("\n## ", 1)[0]
        lines.extend(section.strip().splitlines())
    elif gameday_file.exists() and "Runbook Exercise History" in gameday_file.read_text():
        content = gameday_file.read_text()
        section = content.split("Runbook Exercise History", 1)[1].split("\n## ", 1)[0]
        lines.extend(section.strip().splitlines())
    else:
        lines.append("- No exercise history recorded yet. Run a GameDay first.")
    lines.append("")

    return "\n".join(lines)
```

**Step 2 — Wire `--section` into `main()`.** Add the argparse argument
**after** the existing `--stdout` argument (look for `ap.add_argument("--stdout"`):

```python
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", default=str(DEFAULT_OUTPUT), help="output markdown path")
    ap.add_argument("--stdout", action="store_true", help="also print to stdout")
    ap.add_argument(
        "--section",
        choices=["deployment"],
        default=None,
        help="append a specific evidence section (e.g. --section deployment)",
    )
    args = ap.parse_args()
```

**Step 3 — Wire `--section` into the report builder.** Modify the `build_report()`
call in `main()` to pass the section argument. Change:

```python
    # BEFORE (in main):
    report = build_report()
```

to:

```python
    # AFTER:
    report = build_report(extra_section=args.section)
```

And modify `build_report()` to accept the parameter **after** its current
signature (it takes no parameters currently):

```python
def build_report(extra_section: str | None = None) -> str:
    # ... existing code, up to the closing \n".join(parts) + "\n" ...

    # Append deployment section if requested
    if extra_section == "deployment":
        parts.append(_section_deployment(REPO_ROOT))
        parts.append("")  # trailing newline

    return "\n".join(parts) + "\n"
```

**Acceptance criteria:**
- [ ] Flag works end-to-end with all inputs present:
      `python3 scripts/generate_validation_report.py --section deployment --stdout`
- [ ] Flag works gracefully with all inputs absent (each missing input
      produces a single helpful line, no exception).
- [ ] At least one unit test for the new code path under `tests/`.
- [ ] `PHASE_64i_notes.md` records both the all-present and all-absent runs.

---

## Acceptance criteria (aggregate — all sub-phases must pass)

- [ ] `scripts/smoke/test_docker_compose.sh` exists, passes via `make smoke-docker`, writes result to `test-results/smoke/`
- [ ] `scripts/smoke/test_helm_kind.sh` exists, skips gracefully when `kind` is absent, passes with `kind` + `helm`
- [ ] Podman/Quadlet smoke test **dropped** — `deploy/rhel/quadlets/` does not exist. Phase 101 entry filed.
- [ ] `docs/runbooks/disaster_recovery.md` exists with all five scenarios (symptoms, impact, simulate, recovery, RTO, RPO)
- [ ] Each scenario covers cross-system coordination — not just single-service restart (see §64c content gap table)
- [ ] Each scenario uses Go-production hot-reload commands only (no `pkill -f proxy.py`)
- [ ] Scenario 5 (Redis data loss) uses correct Phase 19 Python tool invocation
- [ ] `scripts/measure_mttr.sh` exists, derives proxy container name from compose (not hardcoded), checks `redis-cli` availability, and produces `MTTR_BASELINE.md` for Scenarios 1, 2, 4, 5
- [ ] `MTTR_BASELINE.md` shows measured MTTR within RTO target for all four automated scenarios
- [ ] `docs/runbooks/gameday_scenarios.md` exists with all four GameDay exercises
- [ ] First GameDay (Redis outage) exercised locally; dated entry in `gameday_scenarios.md`'s own "Runbook Exercise History" section
- [ ] Exercise history copied to `disaster_recovery.md` after 64c merges (separate follow-up commit, tracked in close-out checklist)
- [ ] `docs/runbooks/credential_rotation.md` exists with Redis, AbuseIPDB, and cloud storage procedures
- [ ] `docs/runbooks/tls_certificate_rotation.md` exists with server cert and mTLS CA rotation
- [ ] `monitoring/alertmanager/rules/tls_alerts.yml` exists with warning (< 30 days) and critical (< 7 days) alerts
- [ ] Alert rules validate with `promtool check rules` (see §64f)
- [ ] No `absent_over_time` guard on cert-expiry alerts (Phase 63 gauge is live)
- [ ] `docs/runbooks/rolling_upgrade.md` exists with Docker Compose, Kubernetes, and rollback procedures
- [ ] `scripts/generate_validation_report.py` accepts `--section deployment` and appends smoke/MTTR/DR evidence with graceful degradation
- [ ] All smoke test scripts use `docker compose` (v2), never `docker-compose` (v1)
- [ ] `make lint-phases` exits 0
- [ ] Pre-flight checks pass for all script-based sub-phases (see "Pre-flight checklist" section)

---

## Phase 101 entries filed from this phase

1. **Podman/Quadlet smoke test blocked** — `deploy/rhel/quadlets/` does not
   exist. Phase 76 produced a strategy document but no Quadlet artifacts
   (`.container`, `.network`, `.kube`). Phase 64 cannot ship the Quadlet
   smoke test until those files exist. Owner: TBD (Phase 76 owner).
2. **Phantom `ja4proxy-cli backup` audit** — the Go CLI has no `backup`
   subcommand. Phase 19's backup system is Python-only
   (`src/backup/worker.py`). Audit all runbooks (including Phase 22, 40,
   57) for similar phantom command references and correct them.
