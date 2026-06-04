---
phase: 216
title: "Penetration Test Remediation — All Phase 215 Findings"
status: PROPOSED
size: LARGE
created: 2026-06-03
audience: [developer, security]
---

# Penetration Test Remediation — All Phase 215 Findings

## Goal

Remediate all 7 security findings discovered during the Phase 215 white-box penetration test of the Go production proxy. The fixes span panic recovery in the connection handler, bounding the beaconing goroutine, correcting the inverted `BlacklistBypass` toggle, hardening TLS record reassembly allocation, standardising log levels, fixing the active-connection metric under panic, and wiring `MaxConnectionLimit` into the accept semaphore. Each fix includes a regression test that confirms both the fix and its continued presence under future refactoring.

## Scope

### Files to modify

| File | Change |
|------|--------|
| `cmd/proxy/main.go` | Add `defer/recover()` to handler goroutine at line 418; add `defer atomic.AddInt64(&p.activeConns, -1)` after recover; remove unused `MaxConnectionLimit` field path or wire into `acceptSem`; fix log level at reassembly purge. |
| `internal/security/pipeline.go` | Replace unbounded `go p.beaconing.MaybeRecord(...)` with bounded worker-pool / semaphore pattern. |
| `cmd/proxy/main.go` (line 525) | Rename/invert `BlacklistBypass` to match actual semantics (e.g., `HardBlockEnabled`). |
| `cmd/proxy/main.go` (TLS reassembly) | Add per-fragment allocation cap to prevent OOM under fragmentation attack. |
| `internal/config/config.go` | Remove `MaxConnectionLimit` if unused, or wire into `acceptSem` capacity. |
| `cmd/proxy/pentest_panic_recovery_test.go` | Update regression test — change `t.Logf` for F-001 to `t.Errorf` once recover is added (test must fail on regress). |
| `tests/pentest/` (new files) | Add regression tests for F-002 through F-007. |

### Out of scope

- Python proxy (`proxy.py`, `src/`) — deprecated
- Management API — separate service
- Terraform provider / K8s operator — separate repos
- Any finding not listed in the Phase 215 pentest report

## Implementation Plan

### A — F-001 (CRITICAL): Add panic recovery to handler goroutine

1. In `cmd/proxy/main.go` at line 418, wrap the handler goroutine body with:
   ```go
   defer func() {
       if r := recover(); r != nil {
           p.log.WithField("panic", r).Error("handler recovered from panic")
           p.metrics.PanicsTotal.WithLabelValues("handler").Inc()
       }
   }()
   ```
2. Add `defer p.metrics.ActiveConns.Dec()` (or `defer atomic.AddInt64(&p.activeConns, -1)`) after the recover to fix the gauge-drift issue from F-006 as well.
3. Update `cmd/proxy/pentest_panic_recovery_test.go` — change `t.Logf` for F-001 to `t.Errorf` (the test must fail if recover is ever reverted).

### B — F-002 (HIGH): Bound beaconing goroutine per connection

1. In `internal/security/pipeline.go` at line 410, replace `go p.beaconing.MaybeRecord(...)` with a call through a bounded worker pool (buffered channel + N worker goroutines, pattern already established in `JA4PROXY-2026-0031` fix).
2. Configure pool size via `PipelineConfig` (default: `runtime.GOMAXPROCS(0) * 2`).
3. Add regression test that verifies `MaybeRecord` is called via bounded path and blocks when pool is saturated.

### C — F-003 (MEDIUM): Fix `BlacklistBypass` naming semantics

1. In `cmd/proxy/main.go` at line 525, rename the config field and its usages.
   - If the flag `true` means "enable hard blocking", rename from `BlacklistBypass` to `HardBlockEnabled` or `BlocklistEnabled`.
   - If the flag `false` means "allow all", rename to `DisableBlocking`.
2. Update all references in `internal/config/`, `internal/security/`, and test files.
3. Add a brief inline comment explaining the semantics at the config definition.

### D — F-004 (MEDIUM): Cap TLS record reassembly allocation

1. In `cmd/proxy/main.go` TLS reassembly path (lines 654–741), add a per-connection cap on the total bytes allocated for fragment reassembly (e.g., `MaxReassemblyBytes = 65536`).
2. If the cap is exceeded, close the connection with a log warning and release resources.
3. Add regression test that sends many small TLS records and verifies the connection is terminated before exceeding the cap.

### E — F-005 (LOW): Standardise reassembly log level

1. In `cmd/proxy/main.go` at line 741 (reassembly buffer purge log), change `p.log.Info(...)` to `p.log.Debug(...)`.
2. Verify no other `Info`-level logs exist in the reassembly path that should be `Debug`.

### F — F-006 (LOW): Fix active connection gauge under panic

1. Fixed as part of A — the `defer` added for activeConns decrement in the handler goroutine ensures the gauge is decremented even on panic.
2. Add explicit assertion in the F-001 regression test that verifies `activeConns` returns to baseline after a panic scenario.

### G — F-007 (LOW): Wire or remove `MaxConnectionLimit`

1. Check if `MaxConnectionLimit` is used anywhere in the Go proxy codebase.
2. If unused entirely: remove the field from `internal/config/config.go`.
3. If the intent was to set `acceptSem` capacity: wire it: `acceptSem: make(chan struct{}, cfg.Proxy.MaxConnectionLimit)`.
4. If the intent is deferred: add a comment explaining why it's not wired and link to the finding.

### H — Regression test maintenance

1. For each finding (F-001 through F-007), confirm there is a Go regression test in `cmd/proxy/` or a new file.
2. Each test must:
   - Be self-contained (no external Redis, no network calls).
   - Pass with the fix applied, fail without the fix.
   - Use `t.Error` (not `t.Fatal` or `t.Skip`) to report the regression.

## Test Strategy

| Check | What to verify |
|-------|---------------|
| `GOROOT=/snap/go/current go vet ./cmd/proxy/...` | No static-analysis violations |
| `GOROOT=/snap/go/current go test -run 'TestHandlerGoroutine' ./cmd/proxy/` | F-001 regression test: must now use `t.Errorf` (recover IS present) |
| New regression tests for F-002–F-007 | Every finding has a passing test that fails on regress |
| `make lint-phases` | Must exit 0 |
| `python3 scripts/sync-roadmap.py` | Must not fail |
| `python3 scripts/findings_register.py validate` | Finding register is consistent |
| `GOROOT=/snap/go/current go build ./cmd/proxy/` | Proxy compiles with zero warnings |

## Acceptance Criteria

1. **F-001**: Handler goroutine at `main.go:418` has `defer/recover()`. Static regression test uses `t.Errorf` and passes.
2. **F-002**: `pipeline.go:410` spawns `MaybeRecord` through a bounded worker pool. Regression test confirms blocking under saturation.
3. **F-003**: `BlacklistBypass` config field renamed to match actual semantics. All references updated.
4. **F-004**: TLS reassembly has a per-connection byte cap. Connection is terminated if cap exceeded.
5. **F-005**: Buffer purge log at reassembly path uses `Debug` level.
6. **F-006**: `activeConns` gauge returns to baseline after handler panic (verified by test).
7. **F-007**: `MaxConnectionLimit` field is either wired into `acceptSem` capacity or removed with documentation.
8. **All**: `go vet ./cmd/proxy/...` — 0 violations. `go build ./cmd/proxy/` — 0 warnings.

## Out of Scope

- Python proxy (`proxy.py`, `src/`) — deprecated, not touched
- Management API / UI — separate service
- Terraform provider / K8s operator — separate repos
- Infrastructure-as-code — not affected by these changes
- CI/CD pipeline changes — covered by earlier phases
- Any finding not listed in the Phase 215 pentest report
