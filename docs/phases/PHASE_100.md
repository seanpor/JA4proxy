# Phase 100: Cross-Phase Gap Closure

> **Rolling phase.** This phase is a formal tracker for non-blocking gaps
> identified during completed phases that don't individually justify a
> dedicated phase. Items are closed here as part of normal development
> rather than reopening a finished phase.

---

## 1. Purpose

When a phase completes, the Critical Reviewer may identify gaps classified
as "non-blocking" — correct enough to ship, but not ideal. Rather than
losing these in commit message footnotes, Phase 100 collects them in one
place with clear ownership and acceptance criteria.

New items may be added here any time a gap is identified in a completed
phase. The phase is marked COMPLETE when all registered items are closed.

---

## 2. Open Items

### 2.1 `source.port` and `destination.ip` absent from ECS connection events

**Origin:** Phase 80 Critical Review (Gap N1)
**File:** `cmd/proxy/main.go`, `internal/security/models.go`

The ECS spec mandates `source.port` (client port) and `destination.ip`
(backend IP). Neither is currently available at logging time:

- `ConnectionContext` has no `ClientPort` field — the port is available
  on the `net.Conn` at accept time but is not stored.
- `destination.ip` is the configured backend host, available from config
  but not passed into `handleConn`.

**Fix:**
1. Add `ClientPort int` to `ConnectionContext` in `internal/security/models.go`.
2. Populate it in `handleConn` from `clientConn.RemoteAddr().(*net.TCPAddr).Port`
   before the pipeline runs.
3. Add `"src_port": connCtx.ClientPort` and `"dst_ip": p.cfg.Proxy.BackendHost`
   to the `logrus.Fields{}` map in `handleConn`.
4. Add `source.port` and `destination.ip` to the ECS formatter's field
   mapping in `internal/logging/ecs_formatter.go`.
5. Update the ECS sample event at `config/integrations/ecs-sample-event.json`
   to include both fields.

**Acceptance criteria:**
- [ ] `ConnectionContext.ClientPort` field exists and is populated
- [ ] `source.port` present in ECS log output
- [ ] `destination.ip` present in ECS log output
- [ ] `ecs_formatter_test.go` tests for both fields pass

---

### 2.2 Go proxy does not support `dual_output` logging mode

**Origin:** Phase 80 Critical Review (Gap N3)
**File:** `cmd/proxy/main.go`, `internal/logging/ecs_formatter.go`

The Python `JSONFormatter` supports `dual_output=True` to emit both legacy
and ECS formats simultaneously — the intended migration path for operators
switching from legacy to ECS without breaking existing Grafana/Loki consumers.
The Go proxy has `DualOutput bool` in `LoggingConfig` but `newLogger()` only
logs a warning and does not implement it.

**Fix:**
1. Add a `DualFormatter` type to `internal/logging/` that wraps two
   `logrus.Formatter` instances and concatenates their outputs with `\n`.
2. When `cfg.Logging.DualOutput && cfg.Logging.Format == "ecs"`, use
   `DualFormatter{Legacy: &logrus.JSONFormatter{...}, ECS: &ECSFormatter{Mode: "ecs"}}`.
3. Add tests in `internal/logging/dual_formatter_test.go`.

**Acceptance criteria:**
- [ ] `logging.format: ecs` + `logging.dual_output: true` emits two JSON
  lines per log event — one legacy, one ECS
- [ ] Legacy line has `timestamp`, `level`, `message` (not `@timestamp`)
- [ ] ECS line has `@timestamp`, `event.action`, `source.ip`
- [ ] `dual_formatter_test.go` tests pass

---

### 2.3 Per-endpoint retry/timeout config not respected by webhook dispatcher

**Origin:** Phase 80 implementation (code worker note)
**File:** `internal/webhook/delivery.go`, `cmd/proxy/main.go`

The `WebhookEndpointConfig` struct has per-endpoint `retry_attempts`,
`retry_backoff_seconds`, and `timeout_seconds`. The wiring in `newProxy()`
uses the first endpoint's values as globals for the whole `DispatcherConfig`,
meaning all endpoints share the same retry/timeout settings instead of
each having its own.

**Fix:**
Move retry/timeout config inside `WebhookEndpoint` (it already has those
fields). In `deliverToEndpoint()`, use `endpoint.RetryAttempts`,
`endpoint.RetryBackoffSeconds`, and `endpoint.TimeoutSeconds` directly
rather than reading from a single `DispatcherConfig` default.

**Acceptance criteria:**
- [ ] Two endpoints with different `retry_attempts` values are each
  retried independently the correct number of times (verified by test)
- [ ] `TestDispatcher_PerEndpointRetryConfig` passes

---

### 2.4 Splunk TA and Sentinel content pack not live-tested

**Origin:** Phase 80 scoping decision (no platform access)

The Splunk TA dashboards, correlation searches, and Sentinel KQL analytics
rules are structurally correct but cannot be verified without live platform
instances.

**Fix (when access becomes available):**
- Install the TA in a Splunk trial instance, generate synthetic events
  matching `ja4proxy:telemetry` sourcetype, verify all 5 dashboards render
  and all 5 correlation searches return results.
- Deploy the Sentinel content pack to a trial Sentinel workspace, ingest
  test events via the `JA4proxy_CL` custom table, verify all 5 analytics
  rules fire.
- Document any field name mismatches found and fix them in the artifacts.

**Acceptance criteria:**
- [ ] Splunk TA installs without errors in Splunk Enterprise 9.x trial
- [ ] All 5 Splunk dashboards render with synthetic data
- [ ] At least 3 of 5 correlation searches return results against synthetic events
- [ ] Sentinel data connector ingests to `JA4proxy_CL` table
- [ ] At least one Sentinel analytics rule fires on a synthetic test event

*Note: This item requires external resource access. Track separately from
engineering items above.*

---

### 2.5 Phase 79 API-dependent Phase 80 features unverified

**Origin:** Phase 80 scoping decision (Phase 79 in progress at time of Phase 80)

Two Phase 80 acceptance criteria depend on the Phase 79 Management API:
- Splunk alert action (`bin/ja4proxy_ban_action.py`) calls `POST /api/v1/bans`
  with an Operator-scoped API token
- Sentinel `Block-IP-Playbook.json` calls the same endpoint

**Fix:**
Once Phase 79 is merged, run the Splunk alert action script against a
local test instance of the management API:
```bash
echo '{"result": {"src_ip": "198.51.100.4"}}' | \
  JA4PROXY_MGMT_URL=http://localhost:8090 \
  JA4PROXY_API_TOKEN=<test-token> \
  python3 integrations/splunk-ta/ja4proxy-ta/bin/ja4proxy_ban_action.py
```

**Acceptance criteria:**
- [ ] Alert action script POSTs successfully to Phase 79 bans endpoint
- [ ] Returns exit code 0 on success, 1 on auth failure
- [ ] Sentinel playbook JSON reviewed against Phase 79 API token format

---

## 3. Closed Items

*(None yet — phase just opened)*

---

## 4. Acceptance Criteria (Phase Complete)

All items in section 2 are either:
- Closed (fix implemented, tests pass), OR
- Explicitly deferred to a named future phase with rationale

Phase 100 is a rolling tracker and should not block other work.
