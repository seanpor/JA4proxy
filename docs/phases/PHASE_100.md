# Phase 100: Cross-Phase Gap Closure

> **Rolling phase.** Formal tracker for non-blocking gaps from completed
> phases that don't individually justify a dedicated phase. Each item has
> exact file paths, line numbers, and acceptance criteria so any worker can
> pick it up cold without reading the originating phase.

---

## How this phase works

When you pick up an item:
1. Read the **Context** block — it explains why the gap exists and what
   traps to avoid.
2. Follow the **Exact changes** block — precise file, line, and diff.
3. Run the **Verify** command to confirm it passes.
4. Move the item to the **Closed Items** section with the commit SHA.

Items are independent unless noted. Work them in any order.

---

## 2. Open Items

---

### Item 100-A: `source.port` and `destination.ip` absent from ECS events

**Origin:** Phase 80 Critical Review (Gap N1)
**Effort:** ~1 hour

#### Context

The ECS spec mandates `source.port` (the client's ephemeral TCP port) and
`destination.ip` (the backend host the proxy forwards to). Neither appears
in ECS log output today because:

- `ConnectionContext` (the immutable struct passed through the pipeline) has
  no `ClientPort` field.
- `remoteIP()` at `cmd/proxy/main.go:570` already does the right
  `conn.RemoteAddr().(*net.TCPAddr)` cast to get the IP — port is right
  there but discarded.
- `destination.ip` is simply `cfg.Proxy.BackendHost` from config, available
  as `p.cfg.Proxy.BackendHost` inside `handleConn` but never logged.

**Trap:** When PROXY protocol is active (`cfg.Proxy.ProxyProtocol = true`),
the real client IP is overwritten from the PROXY header at
`cmd/proxy/main.go:281`. The client port in that case is NOT available from
the PROXY protocol v1 header (it doesn't carry port information in the
standard implementation here). So when PROXY protocol is enabled, log
`src_port: 0` or omit it — do not panic trying to parse a port from the
PROXY header.

#### Exact changes

**1. `internal/security/models.go` — add `ClientPort int` to `ConnectionContext`**

After the `ClientIP string` field (currently line 20), add:
```go
// ClientPort is the source TCP port. Zero when behind PROXY protocol.
ClientPort int
```

**2. `cmd/proxy/main.go` — populate `ClientPort` in `handleConn`**

`remoteIP()` is at line 570. Add a parallel helper immediately after it:

```go
func remotePort(conn net.Conn) int {
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return addr.Port
	}
	return 0
}
```

In `handleConn`, the `ConnectionContext` is built at line 274:
```go
connCtx := &security.ConnectionContext{
    ClientIP: remoteIP(clientConn),
}
```
Change to:
```go
connCtx := &security.ConnectionContext{
    ClientIP:   remoteIP(clientConn),
    ClientPort: remotePort(clientConn),
}
```
Note: when PROXY protocol overwrites `ClientIP` at line 281, leave
`ClientPort` as-is (zero) — this is correct and intentional.

**3. `cmd/proxy/main.go` — add fields to connection decision log**

The `logrus.Fields{}` map starts at approximately line 330. Add two fields:
```go
"src_port": connCtx.ClientPort,
"dst_ip":   p.cfg.Proxy.BackendHost,
```

**4. `internal/logging/ecs_formatter.go` — map the two new log fields**

In the `buildECSOut` function (or wherever `client_ip` is mapped to
`source.ip`), add alongside the existing `source.ip` mapping:
```go
if v, ok := data["src_port"]; ok {
    out["source.port"] = v
}
if v, ok := data["dst_ip"]; ok {
    out["destination.ip"] = v
}
```

**5. `config/integrations/ecs-sample-event.json` — add both fields**

Add to the existing JSON object:
```json
"source.port": 54321,
"destination.ip": "203.0.113.1"
```

#### Verify

```bash
GOROOT=/snap/go/current go build ./... 2>&1 && echo OK
GOROOT=/snap/go/current go test ./internal/logging/... ./internal/security/... -v 2>&1 | grep -E "PASS|FAIL"
make validate-ecs-schema
```

The existing `TestECSFormatter_SourceIP` tests don't cover `source.port` —
add two new tests to `internal/logging/ecs_formatter_test.go`:
- `TestECSFormatter_SourcePort_Present` — log entry with `src_port: 54321`,
  assert `out["source.port"] == float64(54321)` (JSON numbers decode as float64)
- `TestECSFormatter_SourcePort_AbsentWhenZero` — log entry with `src_port: 0`,
  assert `source.port` is absent from output (zero port = unknown, don't emit)
- `TestECSFormatter_DestinationIP_Present` — log entry with `dst_ip: "10.0.0.1"`,
  assert `out["destination.ip"] == "10.0.0.1"`

---

### Item 100-B: Go proxy `dual_output` logging mode not implemented

**Origin:** Phase 80 Critical Review (Gap N3)
**Effort:** ~2 hours

#### Context

The Python `JSONFormatter` (at `src/utils/logging_config.py:101-103`) supports
`dual_output=True`: it emits two newline-separated JSON strings per log
call — legacy format first, then ECS. This is the documented migration path
for operators switching to ECS without breaking existing Loki dashboards.

The Go proxy has `DualOutput bool` in `LoggingConfig`
(`internal/config/loader.go:408`) and `dual_output: false` in
`config/proxy.yml`. However `newLogger()` in `cmd/proxy/main.go:592-594`
only logs a warning and discards the setting:
```go
if cfg.Logging.DualOutput && cfg.Logging.Format == "ecs" {
    log.Warn("proxy: logging.dual_output=true is a Python-only feature; ...")
}
```

**Trap:** logrus `Formatter.Format()` returns `[]byte` — it can return
multiple newline-separated JSON objects in a single byte slice. The logrus
output writer writes the returned bytes verbatim, so returning
`legacyBytes + []byte("\n") + ecsBytes` works correctly. You do NOT need a
second logger instance.

**Trap:** Do not modify `ECSFormatter.Format()` directly. Add a new
`DualFormatter` struct in a new file so the ECS formatter stays single-
purpose and its existing 58 tests don't need touching.

#### Exact changes

**1. Create `internal/logging/dual_formatter.go`**

```go
package logging

import (
    "bytes"
    "github.com/sirupsen/logrus"
)

// DualFormatter emits two newline-separated JSON log lines per entry:
// a legacy logrus JSON line followed by an ECS 8.x line.
// Used during the transition period when logging.dual_output: true.
type DualFormatter struct {
    Legacy logrus.Formatter // emits legacy format
    ECS    logrus.Formatter // emits ECS format
}

// Format implements logrus.Formatter.
func (d *DualFormatter) Format(entry *logrus.Entry) ([]byte, error) {
    legacyBytes, err := d.Legacy.Format(entry)
    if err != nil {
        return nil, err
    }
    ecsBytes, err := d.ECS.Format(entry)
    if err != nil {
        return nil, err
    }
    // Both formatters already append a trailing newline.
    // Strip the trailing newline from the legacy line before joining.
    legacy := bytes.TrimRight(legacyBytes, "\n")
    return append(append(legacy, '\n'), ecsBytes...), nil
}
```

**2. `cmd/proxy/main.go` — replace the warning with actual implementation**

Replace the warning block at lines 592-594 with:
```go
if cfg.Logging.DualOutput && cfg.Logging.Format == "ecs" {
    log.SetFormatter(&jalogger.DualFormatter{
        Legacy: &logrus.JSONFormatter{
            FieldMap: logrus.FieldMap{
                logrus.FieldKeyTime:  "timestamp",
                logrus.FieldKeyLevel: "level",
                logrus.FieldKeyMsg:   "message",
            },
        },
        ECS: jalogger.NewECSLogrusFormatter("ecs"),
    })
}
```
This block runs after the existing ECS-only formatter is set (line 502),
so the dual formatter overrides it when `dual_output=true`.

**3. Create `internal/logging/dual_formatter_test.go`**

Tests:
- `TestDualFormatter_EmitsTwoLines` — one `Format()` call produces output
  containing exactly two valid JSON objects separated by a newline
- `TestDualFormatter_FirstLineIsLegacy` — first JSON object has `timestamp`
  key and NOT `@timestamp`
- `TestDualFormatter_SecondLineIsECS` — second JSON object has `@timestamp`
  key and NOT `timestamp`
- `TestDualFormatter_BothLinesHaveSameMessage` — `message`/`msg` values match
- `TestDualFormatter_LegacyFormatterError` — if the legacy formatter returns
  an error, `DualFormatter.Format()` returns that error
- `TestDualFormatter_ECSFormatterError` — if the ECS formatter returns an
  error, `DualFormatter.Format()` returns that error

#### Verify

```bash
GOROOT=/snap/go/current go test ./internal/logging/... -v 2>&1 | grep -E "PASS|FAIL"
# Confirm dual_output=true produces two lines at runtime:
# Set logging.format: ecs and logging.dual_output: true in config/proxy.yml,
# build and run: echo | GOROOT=/snap/go/current go run ./cmd/proxy 2>/dev/null | head -2
```

---

### Item 100-C: Webhook dispatcher ignores per-endpoint retry/timeout config

**Origin:** Phase 80 implementation note
**Effort:** ~1.5 hours

#### Context

`WebhookEndpointConfig` (`internal/config/loader.go`) has three per-endpoint
fields: `RetryAttempts int`, `RetryBackoffSeconds float64`, `TimeoutSeconds float64`.

The wiring in `newProxy()` (`cmd/proxy/main.go:145-178`) reads these fields
but **only uses the first endpoint's values** as global defaults for the
entire `DispatcherConfig`. All endpoints then share the same retry/timeout.

The root cause is structural: `DispatcherConfig` (`internal/webhook/delivery.go:36-50`)
holds a single `RetryAttempts`, `RetryBackoff`, and `TimeoutSeconds` that
`deliverToEndpoint()` reads at line 113 and 142. `WebhookEndpoint` (the
per-endpoint type) has no retry/timeout fields of its own.

The fix requires changes at three levels:
1. `WebhookEndpoint` struct — add per-endpoint retry/timeout fields
2. `deliverToEndpoint()` — use per-endpoint values, falling back to the
   global `DispatcherConfig` defaults when zero
3. Wiring in `newProxy()` — populate per-endpoint fields from config

#### Exact changes

**1. `internal/webhook/delivery.go` — add fields to `WebhookEndpoint`**

`WebhookEndpoint` is currently (approximately lines 20-35 — read the file to
confirm exact lines):
```go
type WebhookEndpoint struct {
    ID     string
    URL    string
    Secret string
    Events []string
}
```
Add:
```go
type WebhookEndpoint struct {
    ID                  string
    URL                 string
    Secret              string
    Events              []string
    // Per-endpoint overrides. Zero means "use DispatcherConfig global default".
    RetryAttempts       int
    RetryBackoffSeconds float64
    TimeoutSeconds      float64
}
```

**2. `internal/webhook/delivery.go` — `deliverToEndpoint()` uses per-endpoint values**

`deliverToEndpoint()` starts at line 112. It currently reads:
```go
maxAttempts := d.cfg.RetryAttempts   // line 113
// ...
backoff := d.cfg.RetryBackoff        // line 142
```

Change to use per-endpoint with global fallback:
```go
maxAttempts := ep.RetryAttempts
if maxAttempts == 0 {
    maxAttempts = d.cfg.RetryAttempts
}
// ...
backoffSeconds := ep.RetryBackoffSeconds
if backoffSeconds == 0 {
    backoffSeconds = d.cfg.RetryBackoff.Seconds()
}
backoff := time.Duration(backoffSeconds * float64(time.Second))
```

For `TimeoutSeconds`, `NewDispatcher()` creates a single shared
`http.Client` with one timeout. That needs to become per-call. Change
`deliverToEndpoint()` to build a per-call `http.Client`:
```go
timeout := ep.TimeoutSeconds
if timeout == 0 {
    timeout = d.cfg.TimeoutSeconds
}
if timeout == 0 {
    timeout = 30
}
client := &http.Client{Timeout: time.Duration(timeout * float64(time.Second))}
```
Remove the `client *http.Client` field from `Dispatcher` (or keep it as
a fallback — either approach is fine; per-call client is cleaner).

**3. `cmd/proxy/main.go` — populate per-endpoint fields in wiring**

Replace the current wiring block (lines 145-168) with:
```go
endpoints := make([]webhook.WebhookEndpoint, len(cfg.Webhooks.Endpoints))
for i, e := range cfg.Webhooks.Endpoints {
    endpoints[i] = webhook.WebhookEndpoint{
        ID:                  e.ID,
        URL:                 e.URL,
        Secret:              e.Secret,
        Events:              e.Events,
        RetryAttempts:       e.RetryAttempts,
        RetryBackoffSeconds: e.RetryBackoffSeconds,
        TimeoutSeconds:      e.TimeoutSeconds,
    }
}
```
Also simplify `DispatcherConfig` to safe global defaults only — no
first-endpoint-wins logic:
```go
dispatcherCfg := webhook.DispatcherConfig{
    Endpoints:     endpoints,
    StreamKey:     cfg.Webhooks.StreamKey,
    DLQStreamKey:  cfg.Webhooks.DLQKey,
    RetryAttempts: 3,      // global default; overridden per-endpoint
    RetryBackoff:  5 * time.Second,
    TimeoutSeconds: 30,
}
```

**4. Add a test to `internal/webhook/delivery_test.go`**

`TestDispatcher_PerEndpointRetryConfig` — create two endpoints with
different `RetryAttempts` (e.g. 2 and 4). Mock HTTP server always returns
503. Deliver one event. Assert endpoint 1 made exactly 2 attempts and
endpoint 2 made exactly 4 attempts (use atomic counters per endpoint).

#### Verify

```bash
GOROOT=/snap/go/current go build ./... 2>&1 && echo OK
GOROOT=/snap/go/current go test ./internal/webhook/... -v -run TestDispatcher 2>&1 | grep -E "PASS|FAIL"
```

---

### Item 100-D: Splunk alert action and Sentinel playbooks not tested against Phase 79 API

**Origin:** Phase 80 scoping (Phase 79 in progress at time of Phase 80)
**Effort:** ~1 hour (after Phase 79 merges)
**Blocked on:** Phase 79 merge to main

#### Context

Two Phase 80 deliverables call the Management API:
- `integrations/splunk-ta/ja4proxy-ta/bin/ja4proxy_ban_action.py` —
  calls `POST /api/v1/bans` with a bearer token
- `integrations/sentinel/playbooks/Block-IP-Playbook.json` —
  Logic App that calls the same endpoint

Phase 79 defines the exact API token format (JWT, Operator scope) and
the `/api/v1/bans` request/response schema. Until Phase 79 merges, these
can't be verified end-to-end.

**This item requires no code changes until Phase 79 merges.** Once it does:

#### Verify steps

```bash
# 1. Start management API locally (Phase 79)
cd management && uvicorn api.main:app --port 8090 &

# 2. Obtain a test Operator token from Phase 79 auth endpoint
TOKEN=$(curl -s -X POST http://localhost:8090/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"operator","password":"test"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# 3. Test the alert action script
echo '{"result": {"src_ip": "198.51.100.4"}}' | \
  JA4PROXY_MGMT_URL=http://localhost:8090 \
  JA4PROXY_API_TOKEN="$TOKEN" \
  python3 integrations/splunk-ta/ja4proxy-ta/bin/ja4proxy_ban_action.py
# Expect: exit 0, stderr shows "Successfully banned 198.51.100.4"

# 4. Confirm the ban was recorded
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8090/api/v1/bans | python3 -m json.tool
# Expect: 198.51.100.4 in the bans list
```

If the Phase 79 token format or endpoint path differs from what the script
assumes, update `bin/ja4proxy_ban_action.py` accordingly. Also update the
`Block-IP-Playbook.json` ARM template's HTTP action URL if the path changed.

#### Acceptance criteria
- [ ] Alert action script exits 0 against a running Phase 79 management API
- [ ] Banned IP appears in `GET /api/v1/bans` response
- [ ] Script exits 1 with a clear error message when token is invalid (401)
- [ ] `Block-IP-Playbook.json` HTTP action URL and auth header format match
  Phase 79's actual endpoint

---

### Item 100-E: Splunk TA and Sentinel content pack not live-tested

**Origin:** Phase 80 scoping (no SIEM platform access)
**Effort:** Unknown — requires external access
**Blocked on:** Splunk or Sentinel trial instance

#### Context

The Splunk TA and Sentinel content pack are structurally correct and pass
offline validation (JSON/YAML parse, schema checks). They have not been
installed in a real Splunk or Sentinel environment.

**This item cannot be completed without platform access.** When access is
available:

#### Splunk verification steps

1. Package the TA: `cd integrations/splunk-ta && tar czf ja4proxy-ta.tgz ja4proxy-ta/`
2. Install in Splunk Enterprise 9.x: Apps → Install app from file → upload `ja4proxy-ta.tgz`
3. Restart Splunk if prompted
4. Generate synthetic test events — the sample event at
   `config/integrations/ecs-sample-event.json` is a valid payload. Send it
   as a sourcetype `ja4proxy:telemetry` event.
5. Verify all 5 dashboards render under the JA4proxy app navigation
6. Run each correlation search manually: Settings → Searches, Reports, and
   Alerts → run each saved search. Each should return results from the
   synthetic event.

Common problems to check:
- `props.conf` TIME_PREFIX regex must match the actual `@timestamp` key
  in the ECS JSON — verify the format matches RFC3339Nano.
- CIM FIELDALIAS entries (`src_ip`, `dest_ip`) must resolve correctly;
  check with `| eval test=src_ip` in the search bar.

#### Sentinel verification steps

1. Deploy the ARM template: `integrations/sentinel/data-connector/JA4proxy_DataConnector.json`
   via Azure Portal → Custom Template Deployment.
2. Send a test event via the Log Analytics API using the sample event.
3. Verify `JA4proxy_CL` table appears in Log Analytics workspace.
4. Enable one analytics rule (start with `beaconing-detected.json`).
5. Verify it fires against a synthetic alert event.

#### Acceptance criteria
- [ ] Splunk TA installs without errors in Splunk Enterprise 9.x
- [ ] All 5 dashboards render (may have zero data — that's OK; no errors)
- [ ] At least 3 of 5 correlation searches return expected results against
  synthetic events
- [ ] Sentinel `JA4proxy_CL` table accepts events and at least one analytics
  rule fires

---

### Item 100-F: `security/validation.py` not imported, not tested

**Origin:** cherry-pick from security/fix-tests branch (2026-04-07)
**Effort:** ~2 hours

#### Context

`security/validation.py` (411 lines) was cherry-picked from a stale branch and
fixed (missing imports, broken CSRF timing). It contains `SecurityValidator`,
`InputSanitizer`, `MTLSManager`, `AuditLogger`, and `RateLimitValidator` — none
of which are imported by `proxy.py` or any `src/` module. The file is dead code
today.

The CSRF fix changed the token format: tokens are now `{timestamp}:{hmac}` so
the timestamp is embedded and validation checks within a configurable time window
(`max_age=3600`). Any future integrator must use `generate_csrf_token()` and
`validate_csrf_token()` from the same class instance.

**Trap:** `MTLSManager.validate_certificate_chain()` uses `cryptography.x509`
which requires the `cryptography` package (already in `requirements.txt`).
`AuditLogger` uses `logging.handlers.RotatingFileHandler` and writes to
`audit.log` by default — confirm the configured path is writable before
enabling.

**Trap:** `SecurityValidator.__init__` accepts a GeoIP database path from
config. If the path is absent or the file is missing it logs a warning and
continues — do not hard-fail on missing GeoIP in the validator.

#### Exact changes

**1. Add a minimal integration test file `tests/unit/test_security_validation.py`**

```python
"""Smoke tests for security/validation.py — verifies imports and basic contracts."""
import time
import pytest
from security.validation import SecurityValidator, InputSanitizer

@pytest.fixture
def validator():
    return SecurityValidator({"security": {"csrf_secret": "test-secret"}})

def test_csrf_roundtrip(validator):
    token = validator.generate_csrf_token("sess-1")
    assert validator.validate_csrf_token(token, "sess-1")

def test_csrf_wrong_session(validator):
    token = validator.generate_csrf_token("sess-1")
    assert not validator.validate_csrf_token(token, "sess-2")

def test_csrf_expired(validator):
    token = validator.generate_csrf_token("sess-1")
    # max_age=0 means any token is expired
    assert not validator.validate_csrf_token(token, "sess-1", max_age=0)

def test_csrf_tampered(validator):
    assert not validator.validate_csrf_token("tampered", "sess-1")

def test_sanitizer_strips_null_bytes():
    s = InputSanitizer({})
    assert "\x00" not in s.sanitize_string("hello\x00world")

def test_validate_ip_valid(validator):
    assert validator.validate_ip_address("192.0.2.1", check_reputation=False)

def test_validate_ip_invalid(validator):
    from security.validation import ValidationError
    with pytest.raises(ValidationError):
        validator.validate_ip_address("not-an-ip", check_reputation=False)
```

**2. `Makefile` — add `security/validation.py` to `lint-pylint` scope**

`lint-pylint` currently lints `src/ proxy.py`. Extend to include `security/`:
```makefile
lint-pylint:
	@echo "=== pylint: Python semantic analysis (errors only) ==="
	@python3 -m pylint --errors-only src/ security/ proxy.py \
		&& echo "✓ pylint passed"
```

Integration into the proxy pipeline (wiring `SecurityValidator` into
`pipeline.py`) is out of scope for this item — that is a full phase of work.
This item only ensures the module is importable, tested, and visible to the
linter.

#### Verify

```bash
python3 -m pytest tests/unit/test_security_validation.py -v
python3 -m pylint --errors-only security/validation.py
```

---

### Item 100-G: `SECURITY_REVIEW_PHASE1.md` findings not validated against current codebase

**Origin:** cherry-pick from security/fix-tests branch (2026-04-07)
**Effort:** ~3 hours
**Blocked on:** engineer time to triage each finding

#### Context

`docs/security/SECURITY_REVIEW_PHASE1.md` is a 1,751-line security audit
conducted in February 2026 against the codebase *before* Phases 0–92 were
implemented. It identified 27 vulnerabilities (6 critical, 9 high, 8 medium,
4 low).

An unknown number of these findings are already resolved by subsequent phases
(e.g. Phase 27 remediated IP spoofing and sync/async Redis mismatch; Phase 14
addressed production hardening). An unknown number may still be open.

The document itself contains at least one inaccuracy: it classifies
`yaml.safe_load()` as a critical vulnerability, when `safe_load` is the
*correct* safe API choice. Any triage must read findings critically.

#### Verify steps

For each of the 27 findings in `SECURITY_REVIEW_PHASE1.md`:
1. Search the current codebase for the affected file/pattern
2. Mark the finding: **RESOLVED** (cite the fixing commit/phase), **OPEN**
   (still present, needs a fix), or **INVALID** (misclassification — document
   why)
3. For OPEN findings: open a new gap item in this file (or a dedicated phase
   if the fix is substantial)

Add a triage table at the bottom of `SECURITY_REVIEW_PHASE1.md`:

| # | Finding | Severity | Status | Notes |
|---|---------|----------|--------|-------|
| 1 | ... | Critical | RESOLVED / OPEN / INVALID | Phase N / reason |

#### Acceptance criteria
- [ ] All 27 findings have a Status entry in the triage table
- [ ] Every OPEN finding has either a gap item here or a named future phase
- [ ] Every INVALID finding has a written rationale (not just "wrong")

---

### Item 100-H: `sync-roadmap.py` uses `os.path.basename()` — breaks links for archive/ paths

**Origin:** doc-housekeeping branch review (2026-04-07)
**Effort:** ~30 minutes

#### Context

`scripts/sync-roadmap.py` lines 79 and 95 both call:
```python
plan_file = os.path.basename(data["action_plan"])
```

This strips directory components so `docs/phases/archive/PHASE_28_WORK_PLAN.md`
becomes the bare filename `PHASE_28_WORK_PLAN.md`. The generated markdown link
then resolves relative to `docs/phases/`, pointing to a non-existent file.

Today this is latent: all four `archive/` entries in `manifest.yaml` are
`COMPLETE` phases, and the `TODO_SECTION_MAP` suppresses COMPLETE phases from
`TODO.md` output. But any future `IN_PROGRESS` or `PROPOSED` phase whose
`action_plan` is under `archive/` would produce a silently broken link.

**Trap:** The link target in `TODO.md` must be relative to `docs/phases/`
(where the file lives), not to the repo root. An `archive/` path should render
as `[PHASE_28_WORK_PLAN.md](archive/PHASE_28_WORK_PLAN.md)`.

#### Exact changes

**`scripts/sync-roadmap.py` lines 79 and 95 — replace `os.path.basename()` with a relative path helper**

Replace both occurrences:
```python
plan_file = os.path.basename(data["action_plan"])
```
with:
```python
# Preserve subdirectory (e.g. archive/) so links resolve from docs/phases/
_phases_dir = "docs/phases/"
action_plan = data["action_plan"]
if action_plan.startswith(_phases_dir):
    plan_file = action_plan[len(_phases_dir):]
else:
    plan_file = os.path.basename(action_plan)
```

#### Verify

```bash
python3 scripts/sync-roadmap.py
# Manually verify docs/phases/TODO.md contains no broken archive/ links:
grep "archive/" docs/phases/TODO.md
# Each line should read: [PHASE_XX_WORK_PLAN.md](archive/PHASE_XX_WORK_PLAN.md)
# NOT: [PHASE_XX_WORK_PLAN.md](PHASE_XX_WORK_PLAN.md)
```

---

### Item 100-I: `quick-start.sh` and `scripts/basic_perf_test.sh` not wired into Makefile

**Origin:** cherry-pick from security/fix-tests branch (2026-04-07)
**Effort:** ~15 minutes

#### Context

Two scripts landed in main via the security cherry-pick but have no Makefile
entry points:
- `quick-start.sh` — one-command POC environment startup with health checks
- `scripts/basic_perf_test.sh` — basic latency/throughput test harness

A pre-existing `perf-test` target (Makefile line 699) runs `locust`. The new
script is a lighter alternative that requires no additional dependencies.

`quick-start.sh` currently references `docker/docker-compose.poc.yml`. Confirm
this path is correct before adding the target (the main `deploy-poc` target
uses the same file).

#### Exact changes

Add at the bottom of the Makefile (after the phase-92 PHONY block):

```makefile
## quick-start and perf targets (from security cherry-pick)
quick-start:
	@bash quick-start.sh

perf-test-basic:
	@bash scripts/basic_perf_test.sh $(PROXY_URL)

.PHONY: quick-start perf-test-basic
```

`PROXY_URL` defaults to empty string; `basic_perf_test.sh` already defaults to
`http://localhost:8080` when `$1` is unset.

#### Verify

```bash
make -n quick-start      # dry-run — confirm the target exists and invokes the script
make -n perf-test-basic  # dry-run
make help | grep -E "quick-start|perf-test-basic"
```

---

### Item 100-J: Verify `PATCH /api/v1/bans/{ip}` exists in Phase 79

**Origin:** Phase 81 Critical Review
**Effort:** ~15 minutes
**Blocked on:** Phase 79 merge to main

#### Context

Phase 81's xMatters "Extend Ban" response option (§6.2) calls
`PATCH /api/v1/bans/{ip}` to extend an active ban's TTL by 24h. This endpoint
is listed in Phase 81's §2 API table. Phase 79 defines the Management API; if
`PATCH /api/v1/bans/{ip}` was not implemented there, the xMatters integration
silently fails on "Extend Ban" responses.

#### Verify steps

```bash
# After Phase 79 merges, start the management API and check the OpenAPI spec:
curl -s http://localhost:8090/openapi.json | python3 -c "
import sys, json
spec = json.load(sys.stdin)
paths = spec.get('paths', {})
endpoint = paths.get('/api/v1/bans/{ip}', {})
print('PATCH exists:', 'patch' in endpoint)
print('Methods:', list(endpoint.keys()))
"
```

If `PATCH /api/v1/bans/{ip}` is absent from Phase 79: open a Phase 79 gap
item and add `PATCH /api/v1/bans/{ip}` with body `{"extend_ttl_seconds": N}`
to the management API. The xMatters connector must not be marked complete until
this endpoint exists.

#### Acceptance criteria
- [ ] `PATCH /api/v1/bans/{ip}` present in Phase 79 OpenAPI spec with `extend_ttl_seconds` body field
- [ ] Returns 200 with updated expiry timestamp on success
- [ ] Returns 404 if ban does not exist

---

### Item 100-K: Verify `POST /api/v1/tokens/{id}/rotate` exists in Phase 79

**Origin:** Phase 81 Critical Review
**Effort:** ~15 minutes
**Blocked on:** Phase 79 merge to main

#### Context

Phase 81's token rotation script (`scripts/rotate_soar_token.sh`) calls
`POST /api/v1/tokens/{id}/rotate` on a 90-day schedule to refresh SOAR
platform credentials. If Phase 79 does not deliver this endpoint, the rotation
script cannot be implemented or tested end-to-end.

#### Verify steps

```bash
# After Phase 79 merges:
curl -s http://localhost:8090/openapi.json | python3 -c "
import sys, json
spec = json.load(sys.stdin)
paths = spec.get('paths', {})
print('rotate exists:', '/api/v1/tokens/{id}/rotate' in paths)
"
```

If absent: raise with the Phase 79 author. The endpoint should return the new
token value in the response body so the rotation script can update SOAR platform
assets without a second GET call.

#### Acceptance criteria
- [ ] `POST /api/v1/tokens/{id}/rotate` present in Phase 79 OpenAPI spec
- [ ] Response body contains `{"token": "<new_value>", "expires_at": "<ISO-8601>"}`
- [ ] Old token is invalidated immediately after rotation

---

### Item 100-L: Phase 82 — Phase 79 coordination: 7 missing endpoints and values

**Origin:** Phase 82 Critical Review (§9 Phase 79 Coordination Requirements)
**Effort:** ~1 hour to verify + variable effort to implement if missing
**Blocked on:** Phase 79 in progress

#### Context

Phase 82's policy-as-code tooling (`scripts/ja4proxy-policy.py apply/diff`),
four-eyes workflow, and shadow mode simulation all depend on API surface that
was not in Phase 79's resource catalogue at Phase 82 design time. All 7 items
below must be confirmed as present in Phase 79 before Phase 82 can be called
complete end-to-end. If Phase 79 does not deliver them, they must be added to
Phase 79 or implemented as an extension to the management service.

The Phase 82 code already uses these endpoints — the offline tests mock them.
What's missing is the real API backing them.

#### Verify steps

After Phase 79 merges, check each item against the Phase 79 OpenAPI spec:

```bash
SPEC=$(curl -s http://localhost:8090/openapi.json)

# 1. POST /api/v1/simulation/run
echo "$SPEC" | python3 -c "import sys,json; s=json.load(sys.stdin); print('simulation/run POST:', 'post' in s['paths'].get('/api/v1/simulation/run', {}))"

# 2. GET /api/v1/simulation/{id}/report
echo "$SPEC" | python3 -c "import sys,json; s=json.load(sys.stdin); print('simulation report GET:', 'get' in s['paths'].get('/api/v1/simulation/{id}/report', {}))"

# 3-5. Decisions queue
echo "$SPEC" | python3 -c "import sys,json; s=json.load(sys.stdin); p=s['paths']; print('GET /decisions:', 'get' in p.get('/api/v1/decisions', {})); print('POST approve:', 'post' in p.get('/api/v1/decisions/{id}/approve', {})); print('POST reject:', 'post' in p.get('/api/v1/decisions/{id}/reject', {}))"

# 6. managed_by=policy is a valid value
echo "$SPEC" | python3 -c "import sys,json; s=json.load(sys.stdin); print(json.dumps(s.get('components', {}).get('schemas', {}).get('ManagedBy', {}), indent=2))"

# 7. API returns 202 when approval required
# Test manually: PATCH /api/v1/dial with a dial increase while
# governance.approval_required.dial_increase: true is set.
# Expect: HTTP 202 with body {"decision_id": "...", "status": "pending_approval"}
```

#### For each missing item

If an endpoint is absent from Phase 79, add it to the management service.
The Phase 82 code and mock already define the expected contract:

| Item | Expected contract |
|------|------------------|
| `POST /api/v1/simulation/run` | 202 Accepted + `{"simulation_id": "...", "status": "running", "estimated_completion": "..."}` |
| `GET /api/v1/simulation/{id}/report` | 200 OK + full simulation report JSON (see PHASE_82.md §3.2) |
| `GET /api/v1/decisions` | 200 OK + list of pending decision objects |
| `POST /api/v1/decisions/{id}/approve` | 200 OK + updated decision; triggers deferred change |
| `POST /api/v1/decisions/{id}/reject` | 200 OK + updated decision; discards change |
| `managed_by=policy` | Valid enum value on all mutable resources; filterable via `?managed_by=policy` |
| Mutation endpoints return 202 when approval required | See PHASE_82.md §4.1 |

The mock server contract is in `tests/mocks/management_api_mock.py` — use it
as the spec for the real implementation.

#### Acceptance criteria
- [ ] All 7 items confirmed present in Phase 79 OpenAPI spec
- [ ] `policy apply` against a live Phase 79 API applies allowlist/blocklist/dial changes
- [ ] `policy diff` returns operator-added entries as drift
- [ ] A dial increase with `approval_required.dial_increase: true` returns 202
- [ ] `POST /api/v1/decisions/{id}/approve` triggers the deferred change

---

### Item 100-M: Phase 82 — analytics node pre-conditions for shadow mode

**Origin:** Phase 82 §3.4 (Analytics Node Pre-Conditions)
**Effort:** ~2 days
**Blocked on:** ADR-082.md decision committed (already done), Phase 79 simulation API (100-L)

#### Context

Shadow mode answers "what would dial=X have blocked last week?" — the highest-
value Phase 82 feature. The API endpoints (`POST /api/v1/simulation/run`,
`GET /api/v1/simulation/{id}/report`) will be backed by a simulation runner
that needs signal data to replay.

Two files are missing from `analytics/`:
1. `analytics/signal_retention.py` — writes per-connection signal snapshots to
   Redis and sweeps expired entries. Called after each connection.
2. `analytics/simulation_runner.py` — reads stored snapshots, replays
   `ActionDecider.decide()` at a hypothetical dial, accumulates results,
   enriches FP candidates with FCrDNS data.

The storage backend was decided in `docs/decisions/ADR-082.md`: Option A
(Redis, LZ4 compression) for deployments ≤ 50M connections/month.

**Trap:** The signal snapshot write must be fire-and-forget from the hot path
(same pattern as `BeaconingDetector.maybe_record()` — use
`asyncio.create_task()` after the action is decided). Never await it inline.

**Trap:** The simulation runner iterates potentially millions of keys
(`sim:conn:{hour_epoch}:{conn_id}`). Use Redis `SCAN` with a cursor, not
`KEYS *` — `KEYS *` blocks Redis during iteration and will stall live traffic.

#### Exact changes

**`analytics/signal_retention.py`**

```python
"""Write per-connection signal snapshots for shadow mode replay.

Key: sim:conn:{hour_epoch}:{conn_id}  (Hash, TTL=7776000s = 90 days)
Value fields: timestamp, source_ip, ja4, score, signals (JSON)

Called fire-and-forget via asyncio.create_task() after each connection.
"""
import asyncio
import json
import time
import uuid
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import redis.asyncio as aioredis


async def record_connection_signals(
    redis_client: "aioredis.Redis",
    source_ip: str,
    ja4: str,
    score: int,
    signals: list[dict],
) -> None:
    """Write a connection signal snapshot. Fire-and-forget safe."""
    hour_epoch = int(time.time()) // 3600
    conn_id = uuid.uuid4().hex[:12]
    key = f"sim:conn:{hour_epoch}:{conn_id}"
    await redis_client.hset(key, mapping={
        "timestamp": int(time.time()),
        "source_ip": source_ip,
        "ja4": ja4 or "",
        "score": score,
        "signals": json.dumps(signals),
    })
    await redis_client.expire(key, 7776000)  # 90 days
```

**`analytics/simulation_runner.py`**

The runner logic:
1. `SCAN` for all `sim:conn:{hour_epoch}:*` keys in the requested time range
   (`from_ts` to `to_ts` — filter by `hour_epoch` range, not by inspecting
   each key's `timestamp` field)
2. For each batch of keys, `HGETALL` each and re-run
   `ActionDecider(hypothetical_dial).decide(score)` — import from
   `src.security.action_decider`
3. Count `would_have_blocked`, `would_have_tarpitted`, total connections
4. For connections that would have been blocked: check if FCrDNS data is
   available in `rdns:{ip}` Redis key (written by Phase 7 DNS enrichment).
   If the PTR record resolves to a name matching a known-good pattern
   (e.g. ends in `.partner.com` or contains `monitoring`), flag as FP candidate.
5. Return a dict matching the `GET /api/v1/simulation/{id}/report` schema
   (PHASE_82.md §3.2)

Store simulation job state in `sim:job:{sim_id}` (Hash, 7-day TTL) with
fields: `status` (`running`/`complete`/`failed`), `hypothetical_dial`,
`from_ts`, `to_ts`, `result_json` (JSON-encoded report on completion).

**Unit tests: `tests/unit/test_signal_retention.py`**

```
test_record_writes_correct_key_pattern   — key matches sim:conn:{epoch}:{id}
test_record_sets_90d_ttl                 — TTL is 7776000 seconds
test_record_stores_all_fields            — timestamp, source_ip, ja4, score, signals
test_record_empty_signals                — empty list stored as "[]", not error
```

Use `fakeredis` (already in requirements.txt via Phase 0).

**Unit tests: `tests/unit/test_simulation_runner.py`**

```
test_runner_counts_would_have_blocked    — synthetic snapshots below dial 80 score
                                           correctly counted as blocked at dial 80
test_runner_empty_time_range             — no matching keys → empty results, no crash
test_runner_fp_candidate_identified      — snapshot with FCrDNS resolving to
                                           "monitoring.partner.com" flagged as FP
test_runner_scan_not_keys               — assert runner uses SCAN not KEYS
                                           (patch redis KEYS to raise, confirm passes)
```

#### Verify

```bash
python3 -m pytest tests/unit/test_signal_retention.py tests/unit/test_simulation_runner.py -v
```

#### Acceptance criteria
- [ ] `analytics/signal_retention.py` implemented and tested (4 unit tests pass)
- [ ] `analytics/simulation_runner.py` implemented and tested (4 unit tests pass)
- [ ] Signal retention uses `asyncio.create_task()` (never awaited on hot path)
- [ ] Simulation runner uses Redis `SCAN` cursor, never `KEYS *`
- [ ] 90-day TTL set on every `sim:conn:` key

---

### Item 100-N: Phase 82 — platform-dependent acceptance criteria

**Origin:** Phase 82 §10.2
**Effort:** ~1 day (after 100-L, 100-M complete)
**Blocked on:** 100-L (Phase 79 API), 100-M (analytics node), Management UI phases

#### Context

Phase 82's offline-testable criteria (§10.1) are all met — 20 tests pass.
The following criteria require a running Phase 79 management API, a running
analytics node with signal data, and the Management UI. They are deferred here
to avoid blocking the Phase 82 COMPLETE status.

**Do not mark 100-N complete until 100-L and 100-M are both closed.**

#### Acceptance criteria

- [ ] `policy apply` is idempotent against a live Phase 79 API: running apply
  twice produces "0 added, 0 removed, X unchanged" on the second run
- [ ] `policy diff` correctly identifies entries added via the Management UI
  (not in the policy YAML) as drift with `managed_by=operator`
- [ ] Shadow mode simulation via `POST /api/v1/simulation/run` completes within
  5 minutes for a 30-day window of synthetic traffic (seed with
  `python3 scripts/generate_synthetic_traffic.py --days 30`)
- [ ] Simulation report includes at least 1 FP candidate with FCrDNS enrichment
  when the synthetic traffic contains a connection from a PTR-resolvable IP
- [ ] Four-eyes pending queue visible to Operators and Admins in Management UI
- [ ] Approval gate enforced — dial increase does not apply until a second
  Operator or Admin calls `POST /api/v1/decisions/{id}/approve`
- [ ] `approval_required` config respected per change type (test dial_increase,
  bypass_toggle_change, new_cidr_ban separately)
- [ ] ServiceNow auto-change-record creation: set `governance.itsm_integration.auto_create_change: true`, propose a dial change, verify a Standard Change record is created in ServiceNow with the correct ticket number
- [ ] Audit log entry for every rule change includes `source`, `actor_id`, and
  `approved_by` when four-eyes flow was used
- [ ] Audit log exportable as JSONL via `GET /api/v1/audit` with correct entries
  for all policy apply operations

#### Verify command

```bash
# After Phase 79, analytics node, and Management UI are all running:
python3 scripts/ja4proxy-policy.py apply \
  --file ja4proxy-policy.yaml \
  --url http://ja4proxy-mgmt:8090 \
  --token $OPERATOR_TOKEN
# Second run:
python3 scripts/ja4proxy-policy.py apply \
  --file ja4proxy-policy.yaml \
  --url http://ja4proxy-mgmt:8090 \
  --token $OPERATOR_TOKEN
# Expect: "0 added, 0 removed, N unchanged"
```

---

### Item 100-O: Phase 83 — keychain token storage not implemented

**Origin:** Phase 83 Critical Review (2026-04-07)
**Effort:** ~2–3 hours
**Blocker:** None (env var and config file fallback work fine)

#### Context

The spec (`PHASE_83.md §4`) defines a four-level auth resolution order:
`flag > env > config file > keychain (99designs/keyring)`.

The current implementation in `internal/cli/auth/auth.go` only handles
`flag > env`. The config file fallback is applied in `cmd/ja4proxy-cli/main.go`
`newClient()` (flag > env > config — correct). The keychain level (level 4)
is not implemented.

#### Exact changes needed

1. Add `github.com/99designs/keyring` to `go.mod` (or use
   `github.com/zalando/go-keyring` which is simpler).
2. In `internal/cli/auth/auth.go`, add:
   ```go
   // ResolveTokenWithKeychain extends ResolveToken with a keychain fallback.
   // Resolution order: flagValue → JA4PROXY_TOKEN env var → keyring → "".
   func ResolveTokenWithKeychain(flagValue string) string {
       if tok := ResolveToken(flagValue); tok != "" {
           return tok
       }
       tok, err := keyring.Get("ja4proxy-cli", "token")
       if err == nil && tok != "" {
           return tok
       }
       return ""
   }
   ```
3. Update `newClient()` in `cmd/ja4proxy-cli/main.go` to call
   `auth.ResolveTokenWithKeychain(gf.token)` instead of `auth.ResolveToken(gf.token)`.
4. Add a `login` command stub (or `config set-token`) to store credentials:
   ```
   ja4proxy-cli config set-token <token>   # stores in keyring
   ja4proxy-cli config set-url <url>       # writes to config file
   ```

#### Acceptance criteria

- `TestResolveTokenWithKeychain_KeychainFallback` passes with a mock keyring.
- `ja4proxy-cli config set-token` stores the token and subsequent commands
  pick it up without any flag or env var.
- Unit test documents that flag and env still beat keychain.

---

### Item 100-P: Phase 83 — `confirm_mutating: false` config flag not honoured

**Origin:** Phase 83 Critical Review (2026-04-07)
**Effort:** ~1 hour
**Blocker:** None

#### Context

`PHASE_83.md §4` specifies a `confirm_mutating: true` key in the CLI config
file. When set to `false`, mutating commands should not require `--confirm`
(useful for non-interactive scripts). This flag is parsed by `config.go` but
is never checked in `requireConfirm()`.

#### Exact changes needed

1. In `cmd/ja4proxy-cli/main.go`, update `requireConfirm()`:
   ```go
   func requireConfirm(confirmed bool, _ *cobra.Command) {
       if confirmed {
           return
       }
       // Allow skipping prompt if config says so.
       if cfg, _ := cliconfig.Load(); cfg != nil && !cfg.ConfirmMutating {
           return
       }
       fmt.Fprintf(os.Stderr, "This is a mutating operation. Add --confirm to proceed.\n")
       os.Exit(1)
   }
   ```
2. Add `ConfirmMutating bool \`yaml:"confirm_mutating"\`` field to `CLIConfig`
   in `internal/cli/config/config.go` with a default of `true`.
3. Add a test in `internal/cli/config/config_test.go` that verifies
   `confirm_mutating: false` is parsed correctly.

#### Acceptance criteria

- A test for `config.go` parsing `confirm_mutating: false` passes.
- `requireConfirm` behaviour documented in `docs/developer/RELEASE_PROCESS.md`.

---

## 3. Closed Items

*(None yet — phase opened 2026-04-07)*

---

## 4. Phase completion criteria

Phase 100 is COMPLETE when all fourteen items above are either:
- **Closed** — fix implemented, tests pass, commit SHA recorded, or
- **Explicitly deferred** — moved to a named future phase with written
  rationale (not silently dropped)

**Unblocked (pick up now):** 100-A, 100-B, 100-C, 100-F, 100-H, 100-I, 100-M
**Blocked on Phase 79:** 100-D, 100-J, 100-K, 100-L
**Blocked on 100-L + 100-M:** 100-N
**Blocked on platform access:** 100-E
**Requires engineer triage:** 100-G

---

## Phase 79 SSO/MFA Gaps (100-O through 100-T)

> These items were identified during Phase 79 C7–C9 critical review (2026-04-07).
> See `docs/phases/PHASE_100.md` original Phase 79 section for detailed implementation
> guidance including exact code snippets, import paths, and test patterns.

| Item | Gap | Effort | Blocker |
|------|-----|--------|---------|
| 100-O | Gap 2: SSO login events not written to management:audit_log | ~30 min | None |
| 100-P | Gap 1: OIDC ID token signature not verified (JWKS fetch needed) | ~2–3h | `cryptography` dep |
| 100-Q | Gap 3: No DELETE endpoint for WebAuthn credentials | ~1h | None |
| 100-R | Gap 4: SSO-delegated MFA trust not implemented (MANAGEMENT_SSO_TRUST_IDP_MFA) | ~2h | None |
| 100-S | Gap 5: SAML/OIDC integration test markers not registered in pyproject.toml | ~20 min | None |
| 100-T | Gap 6: Group-to-role mapping from config/proxy.yml not wired | ~3–4h | `pyyaml` dep |

For full per-gap detail (exact file paths, function signatures, import statements, code snippets),
see the original Phase 79 gap descriptions below.

---

## Gap 1 — OIDC ID Token Signature Not Verified

**File**: `management/api/routes/oidc.py`

**Function**: `_extract_claims(id_token: str) -> dict` (currently ~line 113)

**Problem**: `_extract_claims()` base64-decodes the JWT payload without verifying
the RS256/ES256 signature.  An attacker who can MITM or forge a token response
could supply a crafted `id_token` with arbitrary claims (elevated role, different
`sub`).

**Fix**:

The `authlib` package is already a dependency (`authlib>=1.3.0` in
`management/requirements.txt`).  Use it for both JWKS fetching and JWT verification.

1. Add a module-level JWKS cache (simple dict — one entry per `jwks_uri`):

   ```python
   import time
   from authlib.jose import JsonWebKey, jwt as authlib_jwt

   _jwks_cache: dict[str, tuple[object, float]] = {}  # uri → (key_set, expires_at)
   _JWKS_DEFAULT_TTL = 3600  # 1 hour
   ```

2. Add a `_fetch_jwks(jwks_uri: str) -> object` async helper (mockable, same pattern
   as `_fetch_oidc_discovery`):

   ```python
   async def _fetch_jwks(jwks_uri: str) -> object:
       """Fetch and cache JWKS from the IdP.  Returns an authlib KeySet."""
       now = time.monotonic()
       if jwks_uri in _jwks_cache:
           key_set, expires_at = _jwks_cache[jwks_uri]
           if now < expires_at:
               return key_set

       async with httpx.AsyncClient() as client:
           r = await client.get(jwks_uri, timeout=10.0)
           r.raise_for_status()
           # Honour Cache-Control max-age if present; fallback to 1h
           cc = r.headers.get("Cache-Control", "")
           ttl = _JWKS_DEFAULT_TTL
           for part in cc.split(","):
               if part.strip().startswith("max-age="):
                   try:
                       ttl = int(part.strip().split("=", 1)[1])
                   except ValueError:
                       pass
           key_set = JsonWebKey.import_key_set(r.json())
           _jwks_cache[jwks_uri] = (key_set, now + ttl)
           return key_set
   ```

3. Replace `_extract_claims` with a version that verifies the signature:

   ```python
   async def _extract_claims(id_token: str, jwks_uri: str) -> dict:
       """Verify the ID token signature and return its claims.

       Raises:
           HTTPException(401): on signature failure or claim validation failure.
       """
       try:
           key_set = await _fetch_jwks(jwks_uri)
           claims = authlib_jwt.decode(id_token, key_set)
           claims.validate()   # validates exp, iat, iss, aud
           return dict(claims)
       except Exception as exc:
           logger.warning("oidc | event=id_token_invalid | error=%s", exc)
           raise HTTPException(
               status_code=status.HTTP_401_UNAUTHORIZED,
               detail="ID token signature verification failed",
           )
   ```

   Note: `claims.validate()` in authlib checks `exp`, `iat`, and optionally `iss`
   and `aud` if you pass `claims_options` — see authlib docs for RFC 7519 / OIDC
   Core 1.0 Section 3.1.3.7.

4. In `oidc_callback`, pass the JWKS URI to `_extract_claims`:

   ```python
   # After discovery dict is loaded:
   jwks_uri = discovery["jwks_uri"]
   # ...
   claims = await _extract_claims(id_token, jwks_uri)
   ```

   Change the call site from `_extract_claims(id_token)` to
   `await _extract_claims(id_token, jwks_uri)`.

**Test requirements** (add to `management/tests/test_oidc.py`):

- Generate a real RS256 key pair in the test using `cryptography`:
  ```python
  from cryptography.hazmat.primitives.asymmetric import rsa
  from cryptography.hazmat.primitives import serialization
  private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
  ```
- Sign a test `id_token` with the private key using `authlib.jose.jwt.encode()`.
- Mock `_fetch_jwks` to return a `JsonWebKey.import_key_set(...)` from the public key.
- Assert `_extract_claims` succeeds with the signed token.
- Assert `_extract_claims` raises HTTP 401 when the signature is from a different key.
- Assert `_extract_claims` raises HTTP 401 when the token is expired (`exp` in the past).

**Acceptance criteria**:
- `_extract_claims` raises HTTP 401 on invalid signature.
- `_extract_claims` raises HTTP 401 on expired token.
- JWKS are cached: a second call to `_extract_claims` with the same `jwks_uri` does
  not trigger a second HTTP request to the JWKS endpoint.
- TTL defaults to 3600s; respects `Cache-Control: max-age=N` if present.

---

## Gap 2 — SSO Login Events Not Audited

**Files**: `management/api/routes/saml.py`, `management/api/routes/oidc.py`

**Problem**: Successful SAML ACS and OIDC callback logins are logged at INFO level
but are NOT written to `management:audit_log`.  SOC 2 evidence requires all login
events to appear in the audit trail.

**Fix**:

In `saml.py` — add the import:
```python
from ..auth import _client_ip, _create_access_token   # _client_ip was missing
from ..audit_utils import write_audit
```

In `saml_acs`, after the `response.set_cookie(...)` call and before `return response`:
```python
await write_audit(
    redis,
    actor_id=nameid,
    actor_ip=_client_ip(request),
    action_type="sso.login",
    resource_type="session",
    role=role.value,
    after_value={"provider": "saml"},
)
```

In `oidc.py` — add the import:
```python
from ..auth import _client_ip, _create_access_token   # _client_ip was missing
from ..audit_utils import write_audit
```

In `oidc_callback`, after the `response.set_cookie(...)` call and before `return response`:
```python
await write_audit(
    redis,
    actor_id=sub,
    actor_ip=_client_ip(request),
    action_type="sso.login",
    resource_type="session",
    role=role.value,
    after_value={"provider": "oidc"},
)
```

`write_audit` signature (from `management/api/audit_utils.py`):
```python
async def write_audit(redis, *, actor_id, actor_ip, action_type, resource_type,
                      resource_id=None, before_value=None, after_value=None,
                      session_id=None, role) -> None:
```
It never raises — failures are swallowed and logged internally.

**Acceptance criteria**:
- After a mocked SAML login, `GET /api/v1/audit` shows an entry with
  `action_type="sso.login"`, `actor_id` equal to the SAML NameID, and the
  correct `actor_ip`.
- Same for OIDC — `actor_id` equals the `sub` claim.
- Tests assert the audit entry exists by checking the fake Redis `management:audit_log`
  key after a successful mock login.

---

## Gap 3 — No DELETE Endpoint for WebAuthn Credentials

**File**: `management/api/routes/webauthn.py`

**Problem**: Users can register multiple WebAuthn credentials but cannot remove
individual ones.  A lost or compromised hardware key cannot be revoked.

**Fix** — add two new routes to `webauthn.py`:

**GET `/auth/mfa/webauthn/credentials`** — list all credential IDs for the caller:

```python
@router.get("/auth/mfa/webauthn/credentials")
async def webauthn_list_credentials(
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> JSONResponse:
    identity, role = current_user
    user_id = identity.removeprefix("token:")
    credential_ids = await redis.smembers(_user_credentials_key(user_id))
    result = []
    for cid in credential_ids:
        fields = await redis.hgetall(_credential_key(cid))
        result.append({
            "credential_id": cid,
            "created_at": fields.get("created_at"),
        })
    return JSONResponse(content={"credentials": result})
```

**DELETE `/auth/mfa/webauthn/credentials/{credential_id_b64}`** — remove one credential:

```python
@router.delete("/auth/mfa/webauthn/credentials/{credential_id_b64}", status_code=204)
async def webauthn_delete_credential(
    credential_id_b64: str,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> Response:
    identity, role = current_user
    user_id = identity.removeprefix("token:")
    cred = await redis.hgetall(_credential_key(credential_id_b64))
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    if cred.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Credential does not belong to this user")
    pipe = redis.pipeline()
    pipe.delete(_credential_key(credential_id_b64))
    pipe.srem(_user_credentials_key(user_id), credential_id_b64)
    await pipe.execute()
    logger.info(
        "mfa | event=webauthn_credential_deleted | user=%s | credential_id=%s",
        user_id, credential_id_b64,
    )
    from fastapi.responses import Response as _Resp
    return _Resp(status_code=204)
```

Helper functions already available: `_credential_key(credential_id_b64)` and
`_user_credentials_key(user_id)`.  Redis keys written:
- `mgmt:webauthn:credential:{id}` (Hash) — deleted
- `mgmt:webauthn:user:{user_id}:credentials` (SET) — member removed via `SREM`

**Acceptance criteria**:
- DELETE returns 204 and removes both the Hash key and the SET entry.
- DELETE on a non-existent credential returns 404.
- DELETE on another user's credential returns 403 (test: seed credential for user B,
  authenticate as user A, attempt delete).
- GET lists all credential IDs + `created_at` for the authenticated user.
- Tests cover all paths using `fakeredis`.

---

## Gap 4 — SSO-Delegated MFA Not Implemented

**Files**: `management/api/routes/saml.py`, `management/api/routes/oidc.py`

**Problem**: When a user authenticates via SAML or OIDC, the IdP may have already
enforced MFA.  The current implementation still requires the user to complete TOTP
or WebAuthn after SSO login, even when the IdP has asserted MFA.

**Important implementation note**: `_set_mfa_verified` is defined in
`management/api/routes/mfa_totp.py` (line 76) but is a module-private function
(underscore-prefixed, not exported).  Do NOT import it cross-module.  Instead,
implement the MFA session mark inline using the exported `mfa_session_key` function
from `management.api.auth`:

```python
# In saml.py and oidc.py — add to existing auth import:
from ..auth import _create_access_token, _client_ip, mfa_session_key
```

**Fix**:

1. Add env var guard (check at top of `saml_acs` / `oidc_callback`, after role mapping):

   ```python
   trust_idp_mfa = os.environ.get("MANAGEMENT_SSO_TRUST_IDP_MFA", "false").lower() == "true"
   ```

2. In `saml_acs`, detect IdP-asserted MFA using `auth.get_last_authn_contexts()` after
   `auth.is_authenticated()` returns True:

   ```python
   idp_asserted_mfa = False
   if trust_idp_mfa:
       authn_contexts = auth.get_last_authn_contexts() or []
       MFA_CONTEXTS = {
           "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract",
           "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken",
           # Note: PasswordProtectedTransport is single-factor — do NOT include it
       }
       idp_asserted_mfa = bool(set(authn_contexts) & MFA_CONTEXTS)
   ```

3. In `oidc_callback`, detect IdP-asserted MFA from the ID token `amr` claim:

   ```python
   idp_asserted_mfa = False
   if trust_idp_mfa:
       amr = claims.get("amr") or []
       if isinstance(amr, str):
           amr = [amr]
       idp_asserted_mfa = bool(set(amr) & {"mfa", "otp", "hwk", "swk"})
   ```

4. After `token = _create_access_token(...)` and before the cookie is set, mark MFA
   verified if the IdP asserted it:

   ```python
   _MFA_SESSION_TTL = 8 * 3600
   if idp_asserted_mfa:
       await redis.set(mfa_session_key(token), "verified", ex=_MFA_SESSION_TTL)
       logger.info("sso | event=idp_mfa_trusted | user=%s | provider=saml|oidc", sub_or_nameid)
   ```

   `token` here is the string returned by `_create_access_token(...)` — it is
   available locally in both `saml_acs` and `oidc_callback` before the cookie is set.

**Acceptance criteria**:
- With `MANAGEMENT_SSO_TRUST_IDP_MFA=true` and a SAML response containing an MFA
  authn context, `mgmt:mfa:session:{sha256(token)}` exists in Redis after login.
- With the flag `false` (default), the key is not set.
- Same for OIDC with `amr` claim containing `"mfa"`.
- Tests mock the authn context / `amr` claim and assert Redis state.

---

## Gap 5 — SAML / OIDC Integration Test Markers Missing

**Files**:
- `/home/sean/LLM/JA4proxy4/pyproject.toml` (root-level, NOT under `management/`)
- `management/tests/test_saml.py`
- `management/tests/test_oidc.py`

**Problem**: The `integration` pytest marker is not registered, so future live-IdP
tests would produce `PytestUnknownMarkWarning`.

**Fix**:

1. In `pyproject.toml`, append to the existing `markers` list under
   `[tool.pytest.ini_options]` (the list already contains `"live_services: ..."`):

   ```toml
   markers = [
       "live_services: requires live Go/Python proxy and Redis; excluded from make test (use make test-live)",
       "integration: requires live external IdP (Okta, Entra ID, Keycloak); set OKTA_METADATA_URL or ENTRA_OIDC_DISCOVERY_URL",
   ]
   ```

2. Add placeholder integration tests at the **bottom** of `management/tests/test_saml.py`:

   ```python
   import os
   import pytest

   @pytest.mark.integration
   @pytest.mark.skipif(
       not os.environ.get("OKTA_METADATA_URL"),
       reason="OKTA_METADATA_URL not set — live Okta test skipped",
   )
   async def test_saml_live_okta_login():
       """Placeholder: end-to-end login against live Okta SAML IdP.

       To run: OKTA_METADATA_URL=https://... pytest -m integration
       """
       pytest.skip("Not yet implemented — stub for future live-IdP test")
   ```

3. Add placeholder integration tests at the **bottom** of `management/tests/test_oidc.py`:

   ```python
   @pytest.mark.integration
   @pytest.mark.skipif(
       not os.environ.get("ENTRA_OIDC_DISCOVERY_URL"),
       reason="ENTRA_OIDC_DISCOVERY_URL not set — live Entra ID test skipped",
   )
   async def test_oidc_live_entra_login():
       """Placeholder: end-to-end login against live Microsoft Entra ID OIDC.

       To run: ENTRA_OIDC_DISCOVERY_URL=https://login.microsoftonline.com/... pytest -m integration
       """
       pytest.skip("Not yet implemented — stub for future live-IdP test")
   ```

**Acceptance criteria**:
- `pytest -m "not integration"` produces no `PytestUnknownMarkWarning` and skips both
  placeholder tests.
- `pytest -m integration` without `OKTA_METADATA_URL` / `ENTRA_OIDC_DISCOVERY_URL`
  skips both tests (not fails).

---

## Gap 6 — Group-to-Role Mapping via config/proxy.yml Not Wired

**Files**: `management/api/routes/saml.py`, `management/api/routes/oidc.py`

**Problem**: Role mapping is read only from env vars (`MANAGEMENT_SAML_ROLE_MAPPING`,
`MANAGEMENT_OIDC_ROLE_MAPPING`).  The Phase 79 spec also requires honouring the
`sso.role_mapping` section of `config/proxy.yml`.

**Important context**: The management service currently has NO reader for
`config/proxy.yml`.  There is no shared config-loader module.  The proxy config
file is mounted read-only inside Docker at `/config/proxy.yml`.  This is the only
path the management container will ever see it at.

**Fix**:

1. Add `pyyaml` to `management/requirements.txt`:
   ```
   pyyaml>=6.0.0  # phase-100: proxy.yml SSO role mapping
   ```

2. Add a module-level config reader to a new file
   `management/api/proxy_config.py`:

   ```python
   """Read-only accessor for config/proxy.yml (mounted at /config/proxy.yml in Docker)."""
   import logging
   import os
   import time
   from typing import Any

   try:
       import yaml
   except ImportError:
       yaml = None  # type: ignore

   logger = logging.getLogger(__name__)

   _CONFIG_PATH = os.environ.get("MANAGEMENT_PROXY_CONFIG_PATH", "/config/proxy.yml")
   _cache: tuple[dict, float] | None = None
   _CACHE_TTL = 60.0  # reload at most once per minute


   def _load_proxy_config() -> dict:
       """Load proxy.yml with 60s caching.  Returns {} if file missing or unreadable."""
       global _cache
       now = time.monotonic()
       if _cache is not None and now - _cache[1] < _CACHE_TTL:
           return _cache[0]
       if yaml is None:
           return {}
       try:
           with open(_CONFIG_PATH) as f:
               data = yaml.safe_load(f) or {}
           _cache = (data, now)
           return data
       except FileNotFoundError:
           logger.debug("proxy_config | config not found at %s", _CONFIG_PATH)
           return {}
       except Exception as exc:
           logger.warning("proxy_config | load_failed | path=%s | error=%s", _CONFIG_PATH, exc)
           return {}


   def get_sso_role_mapping() -> dict[str, str]:
       """Return merged SSO role mapping: config.yml base + env var overrides.

       Env var (JSON) takes precedence over config.yml entries for the same group.
       This function is used by both saml.py and oidc.py.
       """
       config = _load_proxy_config()
       base: dict[str, Any] = (config.get("sso") or {}).get("role_mapping") or {}
       return {str(k): str(v) for k, v in base.items()}
   ```

3. In `_map_role` in **both** `saml.py` and `oidc.py`, load the config-file mapping
   and merge with the env var mapping (env var wins):

   ```python
   from ..proxy_config import get_sso_role_mapping

   def _map_role(groups: list[str]) -> Optional[Role]:
       # Env var mapping (JSON)
       env_raw = os.environ.get("MANAGEMENT_SAML_ROLE_MAPPING", "{}")  # or OIDC variant
       try:
           env_mapping: dict = json.loads(env_raw)
       except json.JSONDecodeError:
           env_mapping = {}

       # Config-file base; env var overrides
       role_mapping: dict = {**get_sso_role_mapping(), **env_mapping}
       # ... rest of function unchanged
   ```

   Config structure in `config/proxy.yml` (`# phase-100` comment required):
   ```yaml
   sso:                       # phase-100
     role_mapping:            # phase-100
       "SOC-Analysts": analyst       # phase-100
       "Security-Admins": admin      # phase-100
   ```

**Hot-reload**: `get_sso_role_mapping()` caches for 60s and reloads on next call after
expiry.  No explicit SIGHUP wiring is needed at this stage — the proxy.yml hot-reload
path in the proxy itself does not affect the management container.

**Acceptance criteria**:
- Role mapping in `config/proxy.yml` is honoured when env var is absent.
- Env var entry for the same group overrides config file entry.
- Missing or malformed `config/proxy.yml` silently falls back to env-var-only mapping.
- Tests set `MANAGEMENT_PROXY_CONFIG_PATH` to a temp file with a known mapping and
  assert the correct role is returned.

---

## Gap 7 — OpenAPI 3.1 Spec (`docs/api/openapi.yaml`) ✓ DONE

**Status**: Completed in Phase 79 C10.

**Why this matters**: The Terraform provider (Phase 83) and SDK generation tooling
consume this spec.  FastAPI auto-generates OpenAPI 3.0.x at `/api/docs`; the
requirement is a committed, static 3.1 file.

**Fix**:

1. Create `management/scripts/export_openapi.py`:

   ```python
   #!/usr/bin/env python3
   """Export the management API OpenAPI 3.1 spec to docs/api/openapi.yaml.

   Usage:
       MANAGEMENT_TEST_MODE=1 python management/scripts/export_openapi.py
   """
   import json
   import sys
   import os
   import yaml

   # Ensure management package is importable
   sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
   os.environ.setdefault("MANAGEMENT_TEST_MODE", "1")

   from management.api.main import app

   schema = app.openapi()
   # FastAPI generates OpenAPI 3.0.x — bump to 3.1.0
   schema["openapi"] = "3.1.0"

   output_path = os.path.join(
       os.path.dirname(__file__), "../../docs/api/openapi.yaml"
   )
   os.makedirs(os.path.dirname(output_path), exist_ok=True)
   with open(output_path, "w") as f:
       yaml.dump(schema, f, allow_unicode=True, sort_keys=False)

   print(f"Written: {output_path}")
   ```

2. Create `docs/api/` directory if it does not exist.

3. Run the script and commit the generated file:
   ```bash
   MANAGEMENT_TEST_MODE=1 python management/scripts/export_openapi.py
   git add docs/api/openapi.yaml management/scripts/export_openapi.py
   ```

4. Add a Makefile target at the bottom of `Makefile`:
   ```makefile
   ## Phase 100 targets
   openapi-spec:
   	MANAGEMENT_TEST_MODE=1 python management/scripts/export_openapi.py
   ```

**Note on 3.0 → 3.1 differences**: The main schema change is the `openapi` version
field.  For strict 3.1 compliance, `nullable: true` fields should become
`type: ["string", "null"]` — but this is an optional cleanup; the version bump alone
satisfies the downstream tooling requirement for Phase 83/84.

**Acceptance criteria**:
- `docs/api/openapi.yaml` exists and contains `openapi: 3.1.0`.
- All Phase 79 routes are present: verify these paths appear in the spec:
  - `/auth/login`, `/auth/logout`
  - `/auth/mfa/totp/setup`, `/auth/mfa/totp/verify`
  - `/auth/mfa/webauthn/register/begin`, `/auth/mfa/webauthn/register/complete`
  - `/auth/mfa/webauthn/auth/begin`, `/auth/mfa/webauthn/auth/complete`
  - `/auth/sso/saml/login`, `/auth/sso/saml/acs`, `/auth/sso/metadata`
  - `/auth/sso/oidc/login`, `/auth/sso/oidc/callback`
- File is valid YAML (parseable with `yaml.safe_load`).
- `make openapi-spec` regenerates the file without errors.

---

## Implementation Order

| Priority | Gap | Effort | Blocker |
|----------|-----|--------|---------|
| P0 | Gap 2 — SSO audit events | ~30 min | None |
| P0 | Gap 1 — OIDC JWKS signature | ~2–3h | Need `cryptography` for test key gen |
| P1 | Gap 3 — WebAuthn credential DELETE | ~1h | None |
| P1 | Gap 4 — SSO-delegated MFA | ~2h | None |
| P2 | Gap 5 — Integration test markers | ~20 min | None |
| P3 | Gap 6 — config.yml role mapping | ~3–4h | Requires `pyyaml` dep |
| ~~P2~~ | ~~Gap 7 — OpenAPI spec~~ | ~~Done~~ | ~~Completed in Phase 79 C10~~ |

---

## New Test File Locations

| Gap | Test additions |
|-----|----------------|
| Gap 1 | `management/tests/test_oidc.py` — new section for JWKS tests |
| Gap 2 | `management/tests/test_saml.py` and `test_oidc.py` — assert audit entry |
| Gap 3 | `management/tests/test_webauthn.py` — new section for list/delete |
| Gap 4 | `management/tests/test_saml.py` and `test_oidc.py` — MFA trust flag tests |
| Gap 5 | Bottom of `test_saml.py` and `test_oidc.py` |
| Gap 6 | `management/tests/test_proxy_config.py` (new file) |
| Gap 7 | No test; run `make openapi-spec` and inspect output |

---

## Dependencies

- Phase 79 (must be COMPLETE first — this phase closes its gaps)
- Phase 83 (Terraform provider) benefits from Gap 7 (OpenAPI spec)
- Phase 84 (Compliance Reporting) benefits from Gap 2 (audit events)

---

## Close-Out Checklist

- [ ] All 7 gaps implemented (or explicitly re-deferred with justification in notes)
- [ ] `make test-unit` passes
- [ ] `CHANGELOG.md` prepended
- [ ] `docs/phases/manifest.yaml` status set to `COMPLETE`
- [ ] `python3 scripts/sync-roadmap.py` run — commit TODO.md + PROJECT_STATUS.md
- [ ] Branch pushed: `git push origin claude/phase-100-sso-mfa-gap-closure`

---

*Created: 2026-04-07*
*Source: Phase 79 C7–C9 critical review*
*Revised: 2026-04-07 — added per-function detail, correct import paths, test patterns*