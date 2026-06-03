# Phase 100: Cross-Phase Gap Closure

> **Status: PARTLY COMPLETE — 8 closed, 14 remaining.**
>
> Phase 100 was opened 2026-04-07 as a rolling register for non-blocking
> gaps from completed phases. A focused push on 2026-04-07 closed the
> six Phase 79 SSO/MFA gaps (100-O–T). Phase 100 was briefly marked
> COMPLETE at that point, but the other 16 items (100-A–N, 100-U, 100-V)
> were silently dropped from the tracker. This document reopens them,
> verifies each against the current codebase as of **2026-04-11**, and
> files updated scoping suitable for a junior engineer to pick up cold.
>
> One additional item — 100-K — has since landed in Phase 79 and is
> moved to Closed. 100-A and 100-F are downgraded to PARTIAL after
> verification. 100-G closed 2026-04-11 after full triage of all 27
> SECURITY_REVIEW_PHASE1.md findings (3 RESOLVED, 1 partially, 12 OPEN,
> 11 INVALID).

---

## 1. How this phase works

When you pick up an item:
1. Read the **Context** block — it explains why the gap exists and what
   traps to avoid.
2. Confirm the **Verified state** note still matches the code — line
   numbers drift. If the code has moved, update the line refs as part
   of the fix commit.
3. Follow the **Exact changes** block — precise file, line, and diff.
4. Run the **Verify** command to confirm it passes.
5. Move the item to the **Closed Items** section with the commit SHA.

Items are independent unless the **Blocker** field says otherwise.
Work them in any order.

---

## Status summary (verified 2026-04-11)

| Item | Area | Status | Effort | Blocker |
|------|------|--------|--------|---------|
| 100-A | Go proxy ECS fields | **PARTIAL** — `destination.ip` done, `source.port` still absent | ~30 min | None |
| 100-B | Go proxy `dual_output` | OPEN | ~2 h | None |
| 100-C | Webhook per-endpoint retry/timeout | OPEN | ~1.5 h | None |
| 100-D | Splunk/Sentinel vs Phase 79 API | OPEN — **unblocked**, script URL/body mismatch | ~1 h | None |
| 100-E | Splunk TA / Sentinel live test | **BLOCKED** — no Splunk/Sentinel platform access available | Unknown | Platform access |
| 100-F | `security/validation.py` coverage | **PARTIAL** — imported by `tests/security/test_owasp_top10.py`; dedicated tests + lint scope still missing | ~1 h | None |
| 100-G | `SECURITY_REVIEW_PHASE1.md` triage | **CLOSED** — all 27 findings triaged (3 RESOLVED, 1 partial, 12 OPEN, 11 INVALID) | ~3 h | — |
| 100-H | `sync-roadmap.py` basename bug | OPEN | ~30 min | None |
| 100-I | `quick-start`, `perf-test-basic` Makefile targets | OPEN | ~15 min | None |
| 100-J | `PATCH /api/v1/bans/{ip}` | OPEN — **unblocked**, endpoint absent; must be implemented not just verified | ~1 h | None |
| ~~100-K~~ | ~~`POST /api/v1/tokens/{id}/rotate`~~ | **CLOSED** — present at `management/api/routes/tokens.py:163` | — | — |
| 100-L | Phase 82: 7 missing endpoints/values | OPEN — **split into 100-L1 through 100-L7** (see item detail) | ~3 days total | None |
| 100-M | Phase 82: signal_retention + simulation_runner | OPEN | ~2 d | 100-L |
| 100-N | Phase 82: platform-dependent ACs | BLOCKED | ~1 d | 100-L, 100-M |
| 100-O–T | Phase 79 SSO/MFA gaps | **CLOSED** 2026-04-07 (commit `6ffdbc5`) | — | — |
| 100-U | Phase 83 CLI keychain storage | OPEN | ~2–3 h | None |
| 100-V | Phase 83 CLI `confirm_mutating` flag | OPEN | ~1 h | None |

**Unblocked, small, pick these up first:** 100-H, 100-I, 100-V, 100-A (finish), 100-F (finish).
**Recently closed:** 100-G (security triage), 100-K (admin close-out).

**Unblocked, medium:** 100-B, 100-C, 100-D, 100-J, 100-U.

**Unblocked, large:** 100-L, 100-M.

**Blocked:** 100-E (platform), 100-N (on 100-L + 100-M).

---

## 2. Open Items

---

### Item 100-A: `source.port` absent from ECS events (destination.ip done)

**Origin:** Phase 80 Critical Review (Gap N1)
**Status:** **PARTIAL** — `destination.ip` landed; `source.port` still missing
**Effort:** ~30 minutes
**Verified:** 2026-04-11

#### Verified state

- `destination.ip` is emitted both in the decision log
  (`cmd/proxy/main.go:389` — `"dst_ip": backendHost`) and in the ECS
  stream payload (`cmd/proxy/main.go:401` — `"destination.ip": backendHost`).
  **Done.**
- `source.port` is **not** emitted. `internal/logging/ecs_formatter.go:88`
  maps a `src_port` log field to `source.port` if it is present, and unit
  tests in `internal/logging/ecs_formatter_test.go:616-632` cover the
  mapping — but nothing in `cmd/proxy/main.go` ever writes `src_port`
  into a `logrus.Fields{}` map, so the field is always absent at runtime.
- `ConnectionContext.ClientPort` does not exist
  (`internal/security/models.go:20` — only `ClientIP string`).
- `remoteIP()` is now at `cmd/proxy/main.go:731` (was 570). Its sibling
  `remotePort()` was never added.

#### Context

The ECS spec mandates `source.port` (the client's ephemeral TCP port).
The port is available from `conn.RemoteAddr().(*net.TCPAddr).Port` — the
same cast `remoteIP()` already does — but discarded.

**Trap:** When PROXY protocol is active (`cfg.Proxy.ProxyProtocol = true`),
the real client IP is overwritten from the PROXY header at
`cmd/proxy/main.go:281`. The client port in that case is NOT available from
the PROXY protocol v1 header (it doesn't carry port information in the
standard implementation here). So when PROXY protocol is enabled, log
`src_port: 0` or omit it — do not panic trying to parse a port from the
PROXY header.

#### Trap

When PROXY protocol is active (`cfg.Proxy.ProxyProtocol = true`), the
real client IP is overwritten from the PROXY header. The PROXY protocol
v1 reader at `internal/proxy/proxy_protocol.go:67` parses src port from
the header, but the current wiring in `cmd/proxy/main.go` only surfaces
the IP. Safest behaviour for this fix: log `src_port: 0` when behind
PROXY protocol and do **not** parse the header's port value. A follow-up
item can wire through the PROXY-reported port once a dedicated field
exists.

#### Exact changes

**1. `internal/security/models.go` — add `ClientPort int` to `ConnectionContext`**

After the `ClientIP string` field at line 20, add:
```go
// ClientPort is the source TCP port. Zero when behind PROXY protocol
// or when the source address is not a *net.TCPAddr.
ClientPort int
```

**2. `cmd/proxy/main.go` — add `remotePort()` helper**

Immediately after `remoteIP()` (currently at line 731), add:
```go
func remotePort(conn net.Conn) int {
    if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
        return addr.Port
    }
    return 0
}
```

**3. `cmd/proxy/main.go` — populate `ClientPort` in `handleConn`**

The `ConnectionContext` is built at line 302:
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
When PROXY protocol overwrites `ClientIP` a few lines later, leave
`ClientPort` at its current value (zero — intentional until the reader
surfaces the v1 port).

**4. `cmd/proxy/main.go` — emit `src_port` in the decision log**

The decision log `logrus.Fields{}` map is at lines 375-390. Add one
field alongside the existing `dst_ip`:
```go
"src_port": connCtx.ClientPort,
```

**5. `cmd/proxy/main.go` — emit `source.port` in the ECS stream payload**

The ECS fields block is at lines 396-409. Add:
```go
"source.port": connCtx.ClientPort,
```
(alongside the existing `"source.ip"` entry).

**6. `internal/logging/ecs_formatter.go` — no change needed**

The `src_port → source.port` mapping already exists at line 88. Adding
the log field in step 4 is enough to activate it.

**7. `config/integrations/ecs-sample-event.json` — add `source.port`**

If the file does not already contain the field, add:
```json
"source.port": 54321
```
(`destination.ip` was added in the earlier partial fix — confirm it's
there first.)

#### Verify

```bash
GOROOT=/snap/go/current go build ./... 2>&1 && echo OK
GOROOT=/snap/go/current go test ./internal/logging/... ./internal/security/... -v 2>&1 | grep -E "PASS|FAIL"
make validate-ecs-schema
```

The `source.port` mapping is already unit-tested in
`internal/logging/ecs_formatter_test.go:616-632`. What's not covered is
the integration path — adding `src_port` to the decision-log fields.

Add one test to `internal/logging/ecs_formatter_test.go`:
- `TestECSFormatter_SourcePort_AbsentWhenZero` — log entry with
  `src_port: 0`, assert `source.port` is **absent** from output
  (zero port = unknown, don't emit). Today the formatter emits it as 0;
  that's wrong for PROXY-protocol connections. Either fix the formatter
  to skip zero, or fix `handleConn` to omit the field when zero — the
  former is simpler.

#### Acceptance criteria

- [ ] `ConnectionContext.ClientPort` field present
- [ ] `source.port` emitted in ECS JSON for non-PROXY-protocol connections
- [ ] `source.port` absent (not present as 0) for PROXY-protocol connections
- [ ] `destination.ip` still emitted (regression guard)
- [ ] `make validate-ecs-schema` passes

---

### Item 100-B: Go proxy `dual_output` logging mode not implemented

**Origin:** Phase 80 Critical Review (Gap N3)
**Status:** OPEN
**Effort:** ~2 hours
**Verified:** 2026-04-11

#### Verified state

- `DualOutput bool` field exists at `internal/config/loader.go:454`.
- `cmd/proxy/main.go:753-755` still only emits a `Warn` and discards
  the setting:
  ```go
  if cfg.Logging.DualOutput && cfg.Logging.Format == "ecs" {
      log.Warn("proxy: logging.dual_output=true is a Python-only feature; Go proxy emits ECS-only format")
  }
  ```
- No `DualFormatter` struct exists in `internal/logging/`.

#### Context

The Python `JSONFormatter` (at `src/utils/logging_config.py:101-103`) supports
`dual_output=True`: it emits two newline-separated JSON strings per log
call — legacy format first, then ECS. This is the documented migration path
for operators switching to ECS without breaking existing Loki dashboards.

The Go proxy has the config field but no implementation.

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

Replace the warning block at lines 753-755 with:
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
This block must run **after** the existing ECS-only formatter is set
(search for `NewECSLogrusFormatter` earlier in `newLogger()`) so the
dual formatter overrides it when `dual_output=true`. Confirm the
`jalogger` import alias matches what `cmd/proxy/main.go` already uses
for `internal/logging` — if it's a different alias, use that.

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
**Status:** OPEN
**Effort:** ~1.5 hours
**Verified:** 2026-04-11

#### Verified state

- `WebhookEndpoint` struct at `internal/webhook/delivery.go:21-26` has
  only `ID/URL/Secret/Events` — no retry/timeout fields.
- `DispatcherConfig` at `internal/webhook/delivery.go:37-50` holds
  single global `RetryAttempts`, `RetryBackoff`, `TimeoutSeconds`.
- `deliverToEndpoint()` at `internal/webhook/delivery.go:112-170` reads
  `d.cfg.RetryAttempts` at line 113 and `d.cfg.RetryBackoff` at line 142.
- Wiring in `cmd/proxy/main.go:165-200` still has the "first endpoint
  wins" logic (lines 173-191). Comment at line 167 still calls it out
  as a known limitation.

#### Context

`WebhookEndpointConfig` (`internal/config/loader.go`) has three per-endpoint
fields: `RetryAttempts int`, `RetryBackoffSeconds float64`, `TimeoutSeconds float64`.
The wiring reads them but only applies the first endpoint's values as
global defaults; all endpoints share the same retry/timeout.

The fix requires changes at three levels:
1. `WebhookEndpoint` struct — add per-endpoint retry/timeout fields
2. `deliverToEndpoint()` — use per-endpoint values, falling back to the
   global `DispatcherConfig` defaults when zero
3. Wiring in `newProxy()` — populate per-endpoint fields from config

#### Exact changes

**1. `internal/webhook/delivery.go` — add fields to `WebhookEndpoint` (lines 21-26)**

```go
type WebhookEndpoint struct {
    ID     string
    URL    string
    Secret string
    Events []string // nil or empty means deliver all event types
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

**2. `internal/webhook/delivery.go` — `deliverToEndpoint()` uses per-endpoint values (line 112)**

It currently reads:
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

Replace the current wiring block at lines 165-200 (the loop with
`if i == 0` first-endpoint-wins logic and the comment
`// phase-80: build per-endpoint config`) with:
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

### Item 100-D: Splunk alert action and Sentinel playbooks do not match Phase 79 API shape

**Origin:** Phase 80 scoping (Phase 79 in progress at time of Phase 80)
**Status:** OPEN — **Phase 79 merged, integration broken**
**Effort:** ~1 hour
**Verified:** 2026-04-11

#### Verified state — the integration is broken

Phase 79 has merged. Spot-check confirms the Splunk alert action script
will fail against the real API because its request shape is wrong:

| Aspect | Splunk script (`ja4proxy_ban_action.py`) | Phase 79 route (`management/api/routes/bans.py`) |
|---|---|---|
| URL | `POST /api/v1/bans` (line 89) | `POST /api/v1/bans/{ip:path}` (line 89) |
| Body | `{"ip": src_ip, "ttl_seconds": …, "reason": …}` (lines 91-95) | `BanCreateRequest{ttl, reason}` — IP is in the path, not body |
| Expected status | 200 or 201 | 200 with `BanCreateResponse` |

Posting to `/api/v1/bans` (no IP in path) will return 404 or 405, and
even if it didn't, `ip` and `ttl_seconds` in the body don't match the
`BanCreateRequest` pydantic model — would 422 on validation.

#### Context

Two Phase 80 deliverables call the Management API:
- `integrations/splunk-ta/ja4proxy-ta/bin/ja4proxy_ban_action.py` —
  calls `POST /api/v1/bans` (wrong shape, see above)
- `integrations/sentinel/playbooks/Block-IP-Playbook.json` —
  Logic App that calls the same endpoint (confirm its ARM template
  HTTP action URL as part of this fix)

#### Exact changes

**1. `integrations/splunk-ta/ja4proxy-ta/bin/ja4proxy_ban_action.py`**

Change `_post_ban()` (lines 87-119). The URL must include the IP as a
path segment (URL-encoded for IPv6 safety), and the body must match
`BanCreateRequest`:
```python
import urllib.parse

endpoint = f"{mgmt_url}/api/v1/bans/{urllib.parse.quote(src_ip, safe='')}"

body = json.dumps({
    "ttl": ttl_seconds,
    "reason": reason,
}).encode("utf-8")
```
Confirm the field name by reading `management/api/models.py` —
`BanCreateRequest` defines the canonical names. If it uses `ttl_seconds`,
keep that; if it uses `ttl`, switch. (The fix here assumes `ttl`.)

**2. `integrations/sentinel/playbooks/Block-IP-Playbook.json`**

Find the HTTP action whose URI references `/api/v1/bans` and rewrite
it to `/api/v1/bans/@{triggerBody()?['src_ip']}`. Confirm the request
body JSON shape matches the model. Logic App templates escape `{}`
carefully — test the ARM template parses before deploying.

#### Original plan — verify steps after the fix

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
**Status:** BLOCKED on platform access
**Effort:** Unknown — requires external access
**Verified:** 2026-04-11 (no change; still no Splunk/Sentinel trial instance available)

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

### Item 100-F: `security/validation.py` lacks dedicated unit tests and is outside lint scope

**Origin:** cherry-pick from security/fix-tests branch (2026-04-07)
**Status:** **PARTIAL** — imported by OWASP test, still lacks dedicated unit tests and pylint coverage
**Effort:** ~1 hour
**Verified:** 2026-04-11

#### Verified state

- `security/validation.py` (411 lines) exists.
- **Is imported** by `tests/security/test_owasp_top10.py:18` (and five
  inline imports on lines 55, 134, 199, 217) — pulls in
  `SecurityError`, `SecurityValidator`, `ValidationError`, `MTLSManager`,
  `SecureHeadersManager`, `AuditLogger`. The original tracker claim
  "not imported" is stale and must be retracted.
- **Is not imported** by `proxy.py` or any `src/` runtime module — the
  class set is still dead from the proxy pipeline's perspective.
- No `tests/unit/test_security_validation.py` exists.
- `Makefile:1057-1060` has `lint-pylint` scoped to `src/ proxy.py` only,
  not `security/`.

#### Context

The original item claimed the file was both uncovered and dead code.
The OWASP top-10 test does exercise some entry points, but coverage is
incidental. What's still missing is:

1. A dedicated unit test file that pins the documented contracts
   (CSRF token roundtrip, session binding, expiry, IP validation).
2. `security/` inside the pylint scope so stale code (undefined names,
   unreachable blocks) is caught on every CI run.

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
**Status:** **CLOSED** — triage completed 2026-04-11
**Effort:** ~3 hours
**Verified:** 2026-04-11

#### Triage results

Full audit of `docs/security/SECURITY_REVIEW_PHASE1.md` against current codebase.
The document lists 27 findings but only 16 are actually described; the remaining
11 (VULN-017–027) are phantom items counted in the executive summary but never
written up (the document says "omitted for brevity").

| # | Finding | Severity | Status | Notes |
|---|---------|----------|--------|-------|
| VULN-001 | Unpinned Dependencies | Critical | OPEN | Dependencies still use ranges (`aiohttp>=3.9,<4`), no `--require-hashes`. Filed as Phase 101 gap (supply chain hardening). |
| VULN-002 | Insecure Redis Auth in Dev Mode | Critical | OPEN | Dev mode still allows empty password; management compose lacks `:?` enforcement. Filed as Phase 202 gap. |
| VULN-003 | Information Disclosure via Error Messages | Critical | OPEN | YAML parsing errors and Redis auth errors still leak internals. Needs SecureErrorHandler. |
| VULN-004 | Missing Input Validation on Network Data | Critical | OPEN | `MAX_REQUEST_SIZE` defined but never enforced in read path. |
| VULN-005 | Race Condition in Rate Limiting | Critical | OPEN | Still uses non-atomic `INCR` + `EXPIRE` (no Lua script). Go proxy uses atomic ops; Python does not. |
| VULN-006 | Insufficient TLS Validation — MITM Risk | Critical | OPEN | Backend connections use `asyncio.open_connection()` with no `ssl=` parameter. |
| VULN-007 | Docker Container Running as Root | High | **RESOLVED** | All containers have `cap_drop: ALL`, `no-new-privileges`, `read_only: true`, `USER` directives. |
| VULN-008 | Metrics Endpoint Without Auth | High | OPEN | `HealthServer.handle_metrics()` has no auth check. Config has `authentication.enabled: false`. |
| VULN-009 | Insufficient Logging of Security Events | High | **PARTIALLY RESOLVED** | `JSONFormatter` and `SensitiveDataFilter` exist, but `StructuredLogger`/`SIEMExporter` do not. |
| VULN-010 | No Automated Dependency Scanning | High | **RESOLVED** | CI now includes pip-audit, govulncheck, Semgrep, TruffleHog, dependency-review. |
| VULN-011 | Missing Request Size Limits | High | OPEN | Same as VULN-004 — constant defined but never enforced. |
| VULN-012 | No Connection Limit per IP | High | OPEN | No `ConnectionLimiter` class; global counter only. |
| VULN-013 | Incomplete Error Handling in Critical Paths | High | OPEN | `_forward_data()` still has bare `except Exception` with no timeout handling. |
| VULN-014 | Weak Random Number Generation | Medium | OPEN | `quick-start.sh` fallback still uses `date +%s`. |
| VULN-015 | Missing Security Headers | Medium | OPEN | Proxy operates at TCP/TLS layer; HTTP headers not applicable to most traffic. Partial INVALID. |
| VULN-016 | No Geo-Blocking Implementation | Medium | **RESOLVED** | GeoIP fully implemented with country whitelist/blacklist and metrics labels. |
| VULN-017–027 | (Not documented) | Medium/Low | **INVALID** | Document explicitly states "omitted for brevity". No findings to triage. |

#### Summary

| Status | Count | Findings |
|--------|-------|----------|
| RESOLVED | 3 | VULN-007, VULN-010, VULN-016 |
| PARTIALLY RESOLVED | 1 | VULN-009 |
| OPEN | 12 | VULN-001–006, VULN-008, VULN-011–015 |
| INVALID | 11 | VULN-017–027 (not documented) |

#### OPEN finding remediation plan

The 12 OPEN findings are filed into existing or future phases:

| Finding | Filed under | Rationale |
|---------|------------|-----------|
| VULN-001 (Unpinned deps) | Phase 202a | SHA-pin GitHub Actions + dependency auditing |
| VULN-002 (Redis auth) | Phase 202b | Remove default credential fallbacks |
| VULN-003 (Info disclosure) | Phase 101 (deferred) | Needs SecureErrorHandler — not scoped in current phases |
| VULN-004 (Input validation) | Phase 101 (deferred) | Needs network data validation layer |
| VULN-005 (Rate limit race) | Phase 101 (deferred) | Needs Lua script for atomic rate limiting |
| VULN-006 (TLS MITM) | Phase 101 (deferred) | Needs BackendConnector with TLS validation |
| VULN-008 (Metrics auth) | Phase 101 (deferred) | Needs metrics endpoint authentication |
| VULN-011 (Request size) | Same as VULN-004 | |
| VULN-012 (Conn limit) | Phase 101 (deferred) | Needs ConnectionLimiter class |
| VULN-013 (Error handling) | Phase 101 (deferred) | Needs explicit exception handling in _forward_data |
| VULN-014 (Weak random) | Phase 101 (deferred) | Minor — script-only, not runtime |
| VULN-015 (Security headers) | Phase 101 (deferred, likely INVALID) | TCP/TLS proxy — HTTP headers largely inapplicable |

---

### Item 100-H: `sync-roadmap.py` uses `os.path.basename()` — breaks links for archive/ paths

**Origin:** doc-housekeeping branch review (2026-04-07)
**Status:** OPEN
**Effort:** ~30 minutes
**Verified:** 2026-04-11

#### Verified state

The two offending lines have moved (the original spec said 79 and 95):
- `scripts/sync-roadmap.py:100`
- `scripts/sync-roadmap.py:116`

Both still call:
```python
plan_file = os.path.basename(data["action_plan"])
```

#### Context

Strips directory components so `docs/phases/archive/PHASE_28_WORK_PLAN.md`
becomes the bare filename. The generated markdown link resolves relative
to `docs/phases/`, pointing to a non-existent file.

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

**`scripts/sync-roadmap.py` lines 100 and 116 — replace `os.path.basename()` with a relative path helper**

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
**Status:** OPEN
**Effort:** ~15 minutes
**Verified:** 2026-04-11 — both scripts exist at the paths below; no `quick-start` or `perf-test-basic` target in Makefile

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

### Item 100-J: Implement `PATCH /api/v1/bans/{ip}` (Extend Ban)

**Origin:** Phase 81 Critical Review
**Status:** OPEN — **unblocked; endpoint confirmed absent**, must be implemented
**Effort:** ~1 hour
**Verified:** 2026-04-11

#### Verified state

`management/api/routes/bans.py` defines three routes:
- `GET /api/v1/bans` (line 46)
- `POST /api/v1/bans/{ip:path}` (line 89)
- `DELETE /api/v1/bans/{ip:path}` (line 138)

There is **no** `PATCH` route. Phase 81's xMatters "Extend Ban"
response option (§6.2) will fail with 405 Method Not Allowed.

#### Context

Phase 81's xMatters connector calls `PATCH /api/v1/bans/{ip}` to
extend an active ban's TTL by 24 h. Must be implemented as an Operator-
scoped endpoint, audit-logged via `write_audit()` like the create/delete
routes above it, and round-trip against the existing `ban:{ip}` Redis key.

#### Exact changes

**1. `management/api/models.py` — add the request/response models**

Next to `BanCreateRequest`:
```python
class BanExtendRequest(BaseModel):
    extend_ttl_seconds: int = Field(..., gt=0, le=86400 * 30)
    reason: Optional[str] = None  # optional note; does not overwrite existing reason

class BanExtendResponse(BaseModel):
    ip: str
    new_expires_at: str   # ISO-8601 UTC
    previous_ttl: int
    new_ttl: int
```

**2. `management/api/routes/bans.py` — add the handler**

After the `DELETE` handler (line 138+), add:
```python
@router.patch("/api/v1/bans/{ip:path}", response_model=BanExtendResponse)
async def extend_ban(
    ip: str,
    request: Request,
    body: BanExtendRequest,
    current_user=Depends(require_role(Role.operator)),
    redis=Depends(get_redis),
) -> BanExtendResponse:
    identity, role = current_user
    ip = urllib.parse.unquote(ip)
    key = f"{_BAN_KEY_PREFIX}{ip}"

    existing_ttl = await redis.ttl(key)
    if existing_ttl < 0:
        raise HTTPException(status_code=404, detail=f"no active ban for {ip}")

    reason = await redis.get(key) or b""
    if isinstance(reason, bytes):
        reason = reason.decode("utf-8", errors="replace")

    new_ttl = existing_ttl + body.extend_ttl_seconds
    await redis.set(key, reason, ex=new_ttl)

    new_expires_at = (datetime.utcnow() + timedelta(seconds=new_ttl)).isoformat() + "Z"

    await write_audit(
        redis,
        actor_id=identity,
        actor_ip=_client_ip(request),
        action_type="ban.extended",
        resource_type="ban",
        resource_id=ip,
        before_value={"ttl": existing_ttl},
        after_value={"ttl": new_ttl, "extended_by": body.extend_ttl_seconds},
        role=role.value,
    )

    return BanExtendResponse(
        ip=ip,
        new_expires_at=new_expires_at,
        previous_ttl=existing_ttl,
        new_ttl=new_ttl,
    )
```

Imports to add at the top of `bans.py` if not already present:
```python
from datetime import datetime, timedelta
from fastapi import HTTPException
from ..models import BanExtendRequest, BanExtendResponse
```

**3. Tests — `management/tests/test_bans.py`**

- `test_patch_extends_ttl` — create a ban with ttl=100, PATCH with
  extend_ttl_seconds=50, assert response `new_ttl == 150` and Redis
  `ttl(key)` is close to 150.
- `test_patch_nonexistent_returns_404`
- `test_patch_requires_operator_role` — Analyst role returns 403.
- `test_patch_writes_audit_entry` — assert `management:audit_log` has
  a `ban.extended` entry with correct `before_value`/`after_value`.
- `test_patch_rejects_extend_over_30_days` — 422 via Pydantic gt/le.

#### Acceptance criteria
- [ ] `PATCH /api/v1/bans/{ip}` handler implemented and routed
- [ ] Returns 200 with `BanExtendResponse` on success
- [ ] Returns 404 when no active ban exists for the IP
- [ ] Returns 403 for Analyst role
- [ ] Writes a `ban.extended` audit entry
- [ ] xMatters "Extend Ban" test command returns 200 end-to-end

---

### Item 100-L: Phase 82 — Phase 79 coordination: 7 missing endpoints and values

**Origin:** Phase 82 Critical Review (§9 Phase 79 Coordination Requirements)
**Status:** OPEN — **Phase 79 merged; verified all 7 items still absent**
**Effort:** ~3 days total (split into 7 sub-items below)
**Verified:** 2026-04-11

> **⚠️ This item has been split into 7 sub-items for junior engineer handoff.**
> Pick up one sub-item at a time. All share the same mock server contract in
> `tests/mocks/management_api_mock.py`.

#### Sub-items

| Sub-item | Endpoint / change | Files to create/modify | Effort |
|----------|------------------|----------------------|--------|
| **100-L1** | `POST /api/v1/simulation/run` | `management/api/routes/simulation.py` (new), `management/api/main.py` (register), `management/api/models.py` (SimulationRun schema) | ~4 h |
| **100-L2** | `GET /api/v1/simulation/{id}/report` | `management/api/routes/simulation.py` (add GET handler) | ~2 h |
| **100-L3** | `GET /api/v1/decisions` | `management/api/routes/decisions.py` (new), `management/api/main.py` (register), `management/api/models.py` (Decision schema) | ~2 h |
| **100-L4** | `POST /api/v1/decisions/{id}/approve` | `management/api/routes/decisions.py` (add approve handler) | ~2 h |
| **100-L5** | `POST /api/v1/decisions/{id}/reject` | `management/api/routes/decisions.py` (add reject handler) | ~2 h |
| **100-L6** | `managed_by=policy` enum value | `management/api/models.py:237-246` (add `policy` to ManagedBy enum) | ~15 min |
| **100-L7** | Approval-gating middleware (202 on mutation) | `management/api/middleware/approval_gate.py` (new), wire into routes that mutate | ~4 h |

#### Context (shared across all sub-items)

Phase 82's policy-as-code tooling (`scripts/ja4proxy-policy.py apply/diff`),
four-eyes workflow, and shadow mode simulation all depend on this API
surface. Phase 82's offline tests mock the endpoints. What's missing
is the real API backing them in Phase 79's management service.

#### Shared verify steps

After implementing each sub-item, verify against the OpenAPI spec:

```bash
SPEC=$(curl -s http://localhost:8090/openapi.json)
# Check each endpoint is present:
echo "$SPEC" | python3 -c "import sys,json; s=json.load(sys.stdin); print('simulation/run POST:', 'post' in s['paths'].get('/api/v1/simulation/run', {}))"
echo "$SPEC" | python3 -c "import sys,json; s=json.load(sys.stdin); print('decisions GET:', 'get' in s['paths'].get('/api/v1/decisions', {}))"
```

#### 100-L1: `POST /api/v1/simulation/run`

**Files:** Create `management/api/routes/simulation.py`, add route registration in `management/api/main.py`, add `SimulationRun` model in `management/api/models.py`.

**Expected contract:** 202 Accepted + `{"simulation_id": "...", "status": "running", "estimated_completion": "..."}`

**Implementation:**
1. Add `SimulationRun` model to `management/api/models.py`:
   ```python
   class SimulationRun(BaseModel):
       simulation_id: str
       status: str  # "running" | "complete" | "failed"
       hypothetical_dial: int
       from_ts: str
       to_ts: str
       estimated_completion: str
   ```
2. Create `management/api/routes/simulation.py` with a `router = APIRouter()` and POST handler that:
   - Validates request body (hypothetical_dial, from_ts, to_ts)
   - Generates a UUID for simulation_id
   - Stores job state in Redis at `sim:job:{sim_id}` (Hash, 7-day TTL)
   - Returns 202 with the response body above
3. Register the router in `management/api/main.py`: `app.include_router(simulation.router, prefix="/api/v1/simulation")`

**Acceptance criteria:**
- [ ] `POST /api/v1/simulation/run` returns 202 with correct body
- [ ] Redis key `sim:job:{sim_id}` created with TTL 604800 (7 days)
- [ ] Invalid request body returns 422
- [ ] OpenAPI spec includes the endpoint

#### 100-L2: `GET /api/v1/simulation/{id}/report`

**Files:** Add GET handler to `management/api/routes/simulation.py` (created in 100-L1).

**Expected contract:** 200 OK + full simulation report JSON (see PHASE_82.md §3.2)

**Implementation:**
1. Add GET handler that reads `sim:job:{sim_id}` from Redis
2. If status is "complete", return the full report from `result_json` field
3. If status is "running", return 202 with `{"simulation_id": "...", "status": "running", "progress_pct": ...}`
4. If not found, return 404

**Acceptance criteria:**
- [ ] Returns full report when simulation complete
- [ ] Returns 202 with progress when running
- [ ] Returns 404 for unknown simulation_id

#### 100-L3: `GET /api/v1/decisions`

**Files:** Create `management/api/routes/decisions.py` (new), add `Decision` model in `management/api/models.py`, register in `management/api/main.py`.

**Expected contract:** 200 OK + list of pending decision objects

**Implementation:**
1. Add `Decision` model to `management/api/models.py`:
   ```python
   class Decision(BaseModel):
       decision_id: str
       change_type: str  # "dial_increase" | "bypass_toggle" | "cidr_ban"
       requested_value: Any
       current_value: Any
       requested_by: str
       requested_at: str
       status: str  # "pending" | "approved" | "rejected"
   ```
2. Create GET handler that scans Redis for pending decisions (key pattern `decision:*`) and returns the list
3. Register router in `management/api/main.py`

**Acceptance criteria:**
- [ ] Returns empty list when no pending decisions
- [ ] Returns list of decision objects when pending
- [ ] Each object has decision_id, change_type, status fields

#### 100-L4: `POST /api/v1/decisions/{id}/approve`

**Files:** Add POST approve handler to `management/api/routes/decisions.py`.

**Expected contract:** 200 OK + updated decision; triggers deferred change

**Implementation:**
1. POST handler reads `decision:{id}` from Redis
2. Updates status from "pending" to "approved"
3. Applies the deferred change (e.g., PATCH dial, POST to allowlist)
4. Writes `decision.approved` audit entry
5. Returns 200 with updated decision object

**Acceptance criteria:**
- [ ] Approving a pending decision triggers the deferred change
- [ ] Returns 404 for unknown decision_id
- [ ] Returns 409 if decision already approved/rejected
- [ ] Audit entry written with `approved_by` field

#### 100-L5: `POST /api/v1/decisions/{id}/reject`

**Files:** Add POST reject handler to `management/api/routes/decisions.py`.

**Expected contract:** 200 OK + updated decision; discards change

**Implementation:**
1. POST handler reads `decision:{id}` from Redis
2. Updates status from "pending" to "rejected"
3. Writes `decision.rejected` audit entry
4. Returns 200 with updated decision object

**Acceptance criteria:**
- [ ] Rejecting a pending decision does NOT apply the change
- [ ] Returns 404 for unknown decision_id
- [ ] Returns 409 if decision already approved/rejected

#### 100-L6: `managed_by=policy` enum value

**Files:** `management/api/models.py:237-246`

**Implementation:**
1. Open `management/api/models.py` and find the `ManagedBy` enum
2. Add `policy = "policy"` to the enum (alphabetical order: after `operator`, before `terraform`)
3. Verify the enum is used in `?managed_by=` filter in `management/api/routes/canonical_lists.py` — it already is (line 211 uses the filter)

**Acceptance criteria:**
- [ ] `POST /api/v1/allowlist` with `managed_by=policy` returns 201
- [ ] `GET /api/v1/allowlist?managed_by=policy` returns only policy-managed entries
- [ ] No other phase's tests fail from the enum addition

#### 100-L7: Approval-gating middleware (202 on mutation)

**Files:** Create `management/api/middleware/approval_gate.py` (new), wire into mutation routes.

**Expected contract:** When `governance.approval_required.{change_type}` is true, mutation returns 202 instead of applying immediately.

**Implementation:**
1. Create middleware that intercepts mutation requests (PATCH dial, POST ban, POST bypass_toggle)
2. Reads `governance.approval_required` from config (Redis key `config:governance`)
3. If approval is required for the change type:
   - Generate a `decision_id` UUID
   - Store decision in Redis at `decision:{id}` with status "pending"
   - Return 202 with `{"decision_id": "...", "status": "pending_approval"}`
4. If approval is NOT required, pass through to the normal handler
5. Wire the middleware into the relevant routes

**Acceptance criteria:**
- [ ] PATCH dial with `approval_required.dial_increase: true` returns 202
- [ ] Same PATCH dial with `approval_required.dial_increase: false` applies immediately (200)
- [ ] 202 response includes `decision_id` and `status: "pending_approval"`
- [ ] Decision appears in `GET /api/v1/decisions`

---

### Item 100-M: Phase 82 — analytics node pre-conditions for shadow mode

**Origin:** Phase 82 §3.4 (Analytics Node Pre-Conditions)
**Status:** OPEN
**Effort:** ~2 days
**Blocked on:** 100-L (simulation API must back the runner)
**Verified:** 2026-04-11 — neither `analytics/signal_retention.py` nor `analytics/simulation_runner.py` exists anywhere in the repo

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

```python
"""Replay stored signal snapshots at a hypothetical dial value.

Reads sim:conn:{hour_epoch}:* keys via SCAN (never KEYS),
re-runs ActionDecider.decide(score) with the hypothetical dial,
accumulates results, and flags FP candidates via FCrDNS lookup.
"""
import asyncio
import json
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import redis.asyncio as aioredis

# Known-good PTR patterns — if FCrDNS matches these, flag as FP candidate.
_FP_PATTERNS = (".partner.com", "monitoring", ".internal.", ".corp.")


async def run_simulation(
    redis_client: "aioredis.Redis",
    sim_id: str,
    hypothetical_dial: int,
    from_ts: int,
    to_ts: int,
) -> dict:
    """Execute a shadow-mode simulation. Writes result to Redis sim:job:{sim_id}."""
    # Mark as running
    await redis_client.hset(f"sim:job:{sim_id}", mapping={
        "status": "running",
        "hypothetical_dial": hypothetical_dial,
        "from_ts": from_ts,
        "to_ts": to_ts,
        "started_at": int(time.time()),
    })
    await redis_client.expire(f"sim:job:{sim_id}", 604800)  # 7 days

    from_epoch = from_ts // 3600
    to_epoch = to_ts // 3600

    total = 0
    would_have_blocked = 0
    would_have_tarpitted = 0
    would_have_allowed = 0
    fp_candidates = []

    # SCAN through each hour in the range
    for hour_epoch in range(from_epoch, to_epoch + 1):
        cursor = 0
        while True:
            cursor, keys = await redis_client.scan(
                cursor, match=f"sim:conn:{hour_epoch}:*", count=500
            )
            for key in keys:
                total += 1
                fields = await redis_client.hgetall(key)
                score = int(fields.get(b"score", b"0"))

                # Re-run the decision at the hypothetical dial
                action = _decide_action(score, hypothetical_dial)
                if action == "block":
                    would_have_blocked += 1
                elif action == "tarpit":
                    would_have_tarpitted += 1
                else:
                    would_have_allowed += 1

                # Check FP candidacy for blocked connections
                if action == "block":
                    ip = fields.get(b"source_ip", b"").decode()
                    fp = await _check_fp_candidate(redis_client, ip)
                    if fp:
                        fp_candidates.append({"ip": ip, "reason": fp})

            if cursor == 0:
                break

    report = {
        "simulation_id": sim_id,
        "status": "complete",
        "hypothetical_dial": hypothetical_dial,
        "total_connections": total,
        "would_have_blocked": would_have_blocked,
        "would_have_tarpitted": would_have_tarpitted,
        "would_have_allowed": would_have_allowed,
        "fp_candidates": fp_candidates[:100],  # cap at 100
        "completed_at": int(time.time()),
    }

    # Write result to Redis
    await redis_client.hset(f"sim:job:{sim_id}", mapping={
        "status": "complete",
        "result_json": json.dumps(report),
    })
    return report


def _decide_action(score: int, dial: int) -> str:
    """Re-run the ActionDecider logic at the hypothetical dial."""
    if score >= 100:
        return "block"
    elif score >= dial:
        return "tarpit"
    return "allow"


async def _check_fp_candidate(
    redis_client: "aioredis.Redis", ip: str
) -> str | None:
    """Check if the IP has FCrDNS data matching known-good patterns."""
    ptr_data = await redis_client.get(f"rdns:{ip}")
    if not ptr_data:
        return None
    ptr_name = ptr_data.decode() if isinstance(ptr_data, bytes) else ptr_data
    for pattern in _FP_PATTERNS:
        if pattern in ptr_name.lower():
            return f"FCrDNS matches known-good pattern: {pattern}"
    return None
```

**Implementation steps for test scaffolding:**
1. In `tests/unit/test_simulation_runner.py`, use `fakeredis` to create synthetic `sim:conn:{epoch}:*` keys with `HSET` before running `run_simulation()`.
2. For the FP candidate test, pre-populate `rdns:10.0.0.1` with `"monitoring.partner.com"` and assert it appears in `report["fp_candidates"]`.
3. For the SCAN-not-KEYS test, mock `redis_client.keys` to raise `RuntimeError("KEYS * not allowed")` and confirm the test still passes (proves the implementation uses SCAN).

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
**Status:** BLOCKED
**Effort:** ~1 day (after 100-L, 100-M complete)
**Blocked on:** 100-L (Phase 79 API), 100-M (analytics node), Management UI phases
**Verified:** 2026-04-11 — still blocked; cannot start until 100-L and 100-M land

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

### Item 100-U: Phase 83 — keychain token storage not implemented

**Origin:** Phase 83 Critical Review (2026-04-07)
**Status:** OPEN
**Effort:** ~2–3 hours
**Blocker:** None (env var and config file fallback work fine)
**Verified:** 2026-04-11

#### Verified state

- `internal/cli/auth/auth.go:9` defines `ResolveToken(flagValue string) string`
  — handles `flag > env` only. No keyring import in the file.
- `cmd/ja4proxy-cli/main.go` call sites at lines 54, 578, 580, 619, 621
  all use the plain `auth.ResolveToken(...)`.
- No `github.com/99designs/keyring` or `github.com/zalando/go-keyring`
  in `go.mod`.
- No `login` or `config set-token` subcommand in `cmd/ja4proxy-cli/main.go`.

#### Context

The spec (`PHASE_83.md §4`) defines a four-level auth resolution order:
`flag > env > config file > keychain`. The first three levels work;
the keychain level is the only gap.

#### Exact changes needed

1. Add `github.com/zalando/go-keyring` to `go.mod`:
   ```
   go get github.com/zalando/go-keyring@latest
   ```
   **Decision:** We use `zalando/go-keyring` (not `99designs/keyring`) because:
   - It is simpler with fewer transitive dependencies
   - It has active maintenance and fewer open issues
   - Cross-platform support (Linux Secret Service, macOS Keychain, Windows Credential Locker)
   - Already used by several CLI tools in the CNCF ecosystem

2. In `internal/cli/auth/auth.go`, add:
   ```go
   import "github.com/zalando/go-keyring"

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

   // StoreTokenInKeychain stores a token in the system keychain.
   func StoreTokenInKeychain(token string) error {
       return keyring.Set("ja4proxy-cli", "token", token)
   }
   ```

3. Update `newClient()` in `cmd/ja4proxy-cli/main.go` to call
   `auth.ResolveTokenWithKeychain(gf.token)` instead of `auth.ResolveToken(gf.token)`.

4. Add `config set-token` subcommand in `cmd/ja4proxy-cli/main.go`:
   ```go
   // In the init() function where subcommands are registered:
   configCmd.AddCommand(setTokenCmd)

   var setTokenCmd = &cobra.Command{
       Use:   "set-token <token>",
       Short: "Store API token in system keychain",
       Args:  cobra.ExactArgs(1),
       RunE: func(cmd *cobra.Command, args []string) error {
           if err := auth.StoreTokenInKeychain(args[0]); err != nil {
               return fmt.Errorf("failed to store token in keychain: %w", err)
           }
           fmt.Println("Token stored in system keychain successfully.")
           return nil
       },
   }
   ```

5. Write tests in `internal/cli/auth/auth_test.go` using `github.com/zalando/go-keyring`'s
   built-in mock:
   ```go
   func TestResolveTokenWithKeychain_FlagWins(t *testing.T) {
       // Set keyring value, then call with flag — flag should win
       keyring.Set("ja4proxy-cli", "token", "keyring-token")
       defer keyring.Delete("ja4proxy-cli", "token")
       result := ResolveTokenWithKeychain("flag-token")
       assert.Equal(t, "flag-token", result)
   }

   func TestResolveTokenWithKeychain_KeychainFallback(t *testing.T) {
       // No flag, no env — keyring should be used
       keyring.Set("ja4proxy-cli", "token", "keyring-token")
       defer keyring.Delete("ja4proxy-cli", "token")
       result := ResolveTokenWithKeychain("")
       assert.Equal(t, "keyring-token", result)
   }

   func TestResolveTokenWithKeychain_Empty(t *testing.T) {
       // Nothing set — should return empty
       result := ResolveTokenWithKeychain("")
       assert.Equal(t, "", result)
   }
   ```

#### Acceptance criteria

- [ ] `TestResolveTokenWithKeychain_FlagWins` passes — flag beats keychain
- [ ] `TestResolveTokenWithKeychain_KeychainFallback` passes — keyring used when no flag/env
- [ ] `TestResolveTokenWithKeychain_Empty` passes — returns "" when nothing set
- [ ] `ja4proxy-cli config set-token <token>` stores the token and subsequent commands pick it up without any flag or env var
- [ ] `go vet ./internal/cli/auth/...` passes with zero warnings

---

### Item 100-V: Phase 83 — `confirm_mutating: false` config flag not honoured

**Origin:** Phase 83 Critical Review (2026-04-07)
**Status:** OPEN
**Effort:** ~1 hour
**Blocker:** None
**Verified:** 2026-04-11

#### Verified state

- `internal/cli/config/config.go:14-24` `CLIConfig` struct has only
  `URL`, `Token`, and `DefaultOutput` fields. **No `ConfirmMutating`.**
  The original tracker claim "parsed by `config.go`" is incorrect —
  it is not even parsed today; the YAML key silently decodes to nothing.
- `cmd/ja4proxy-cli/main.go:75-77` `requireConfirm()` exists but does
  not consult the config. It is called from ~10 sites (lines 219, 240,
  279, 323, 378, 430, 681, 705, …).

#### Context

`PHASE_83.md §4` specifies a `confirm_mutating: true` key in the CLI config
file. When set to `false`, mutating commands should not require `--confirm`
(useful for non-interactive scripts).

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

### 100-K: `POST /api/v1/tokens/{id}/rotate` present in Phase 79

**Closed:** 2026-04-11 (admin close-out — no code change required)
**Verified:** `management/api/routes/tokens.py:163` —
`@router.post("/api/v1/tokens/{token_id}/rotate", response_model=TokenRotateResponse)`.
Response body matches the acceptance criteria (new token value +
`expires_at`). Old-token invalidation must be re-confirmed in a
dedicated test when Phase 81's rotation script lands.

### 100-O through 100-T: Phase 79 SSO/MFA gap closure

**Closed:** 2026-04-07 in commit `6ffdbc5` ("phase-100: implement all 6
SSO/MFA gaps"), merged via `2848d11`. Detailed per-gap reference
material is preserved in the sections below (Gap 1 through Gap 7).

| Item | Gap | Landed behaviour |
|------|-----|------------------|
| 100-O | SSO login events not audited | `saml_acs` and `oidc_callback` now call `write_audit()` with `action_type="sso.login"` |
| 100-P | OIDC ID token signature not verified | `_extract_claims()` fetches JWKS, caches with double-checked `asyncio.Lock`, verifies via `authlib.jose`; `MANAGEMENT_TEST_MODE=1` bypass for unit tests |
| 100-Q | No DELETE for WebAuthn credentials | `GET` and `DELETE /auth/mfa/webauthn/credentials/{id}` present with ownership check |
| 100-R | SSO-delegated MFA trust | `MANAGEMENT_SSO_TRUST_IDP_MFA=true` sets `mgmt:mfa:session` when SAML `authn_context` or OIDC `amr` indicates MFA |
| 100-S | SAML/OIDC integration test markers | `pytest.mark.integration` registered in `pyproject.toml` |
| 100-T | Group-to-role mapping | Honoured from `config/proxy.yml sso.role_mapping` with 60 s cache and env-var override |

---

## 4. Phase completion criteria

Phase 100 is COMPLETE when all remaining 15 items are either:
- **Closed** — fix implemented, tests pass, commit SHA recorded, or
- **Explicitly deferred** — moved to a named future phase (e.g. 101)
  with written rationale. No silent drops.

The Closed Items section must list the commit SHA (or PR) for every
closed item.

**Unblocked, small (pick up now):** 100-A (finish), 100-F (finish),
  100-H, 100-I, 100-V
**Unblocked, medium:** 100-B, 100-C, 100-D, 100-J, 100-U
**Unblocked, large:** 100-G, 100-L, 100-M
**Blocked on 100-L + 100-M:** 100-N
**Blocked on platform access:** 100-E

---

## Phase 79 SSO/MFA Gaps (100-O through 100-T)

> These items were identified during Phase 79 C7–C9 critical review (2026-04-07).
> See `docs/phases/complete/PHASE_100.md` original Phase 79 section for detailed implementation
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

> The **Implementation Order**, **New Test File Locations**, **Dependencies**
> and **Close-Out Checklist** tables that used to live here were scoped to
> the six Phase 79 SSO/MFA gaps only. Those items are now closed
> (see §3 Closed Items) and the tables have been retired to avoid
> misleading a junior engineer into thinking Phase 100 is narrower than
> it actually is. The authoritative work list for the reopened phase is
> the **Status summary** table at the top of this document.

---

*Created: 2026-04-07 (rolling gap tracker)*
*Rescoped: 2026-04-07 — narrowed to Phase 79 SSO/MFA, 6 gaps closed*
*Reopened and re-verified: 2026-04-11 — 15 items remain, full codebase verification pass*