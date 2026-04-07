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

## 3. Closed Items

*(None yet — phase opened 2026-04-07)*

---

## 4. Phase completion criteria

Phase 100 is COMPLETE when all five items above are either:
- **Closed** — fix implemented, tests pass, commit SHA recorded, or
- **Explicitly deferred** — moved to a named future phase with written
  rationale (not silently dropped)

Items 100-D and 100-E are blocked on external dependencies. Close 100-A,
100-B, and 100-C first. Revisit 100-D when Phase 79 merges. Revisit 100-E
when platform access is arranged.
