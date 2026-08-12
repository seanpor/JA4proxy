<!--
title: "Phase 251a — ReplaceConfig Enrichment Worker Restart (JA4PROXY-2026-0089)"
audience: developer
last_reviewed: 2026-08-12
phase: 251a
-->

# Phase 251a — ReplaceConfig Enrichment Worker Restart

## Goal

Fix `JA4PROXY-2026-0089` (status OPEN): a hot config reload (SIGHUP →
`ReplaceConfig`) silently kills DNS/AbuseIPDB/RDAP/feed enrichment for the
remaining process lifetime.

## Context

This is the sole surviving finding of the superseded Phase 251
(`docs/phases/complete/PHASE_251.md`). Its sibling findings are already
fixed on main:

- 251.1 nil-rangerBox guard — `internal/security/blocklists.go:198`
- 251.2 unstoppable beaconing/audit workers — Phase 515 bound all workers to
  a context (`JA4PROXY-2026-0090`, commit `accdfff0`)

The original WIP implementation is preserved as
`docs/phases/complete/PHASE_251_WIP.patch` — **design reference only**; it
predates the Phase 515 restructure and does not apply to current code.

## The Bug (against current main)

`StartBackgroundWorkers(ctx)` (`internal/security/pipeline.go`, ~line 460)
calls `.Start(ctx)` exactly once, at process startup, on the enrichment
instances created by `NewPipeline`:

```go
p.dnsEnrichment.Start(ctx)
p.abuseipdb.Start(ctx)
p.rdap.Start(ctx)
p.feedDownloader.Start(ctx)
```

`ReplaceConfig()` (`pipeline.go:316`, holds `p.mu.Lock()`) then replaces
those pointers on every SIGHUP:

```go
p.dnsEnrichment = NewDNSEnrichment(buildDNSEnrichmentConfig(cfg), p.redis, p.log)
p.feedDownloader = NewFeedDownloader(cfg.BlocklistFeeds, p.blocklists, p.log)
p.abuseipdb = NewAbuseIPDB(buildAbuseIPDBConfig(cfg), p.redis, p.log)
p.rdap = NewRDAPEnricher(buildRDAPConfig(cfg), p.redis, p.log)
```

The **new** instances never get `.Start(ctx)` — their queue channels are
never drained, so post-reload enrichment jobs pile up unprocessed. The
**old** instances' workers keep running on the startup context, draining
queues that nothing sends to anymore, pinning stale config. No log, no
metric — enrichment signals just stop.

## Implementation Plan

All changes in `internal/security/pipeline.go`; all under the existing
`p.mu` (already held by `ReplaceConfig`, taken read-side by
`processInternal`).

1. **Add lifecycle fields to `Pipeline`:**
   ```go
   bgCtx       context.Context    // parent ctx for background workers; nil until StartBackgroundWorkers
   dnsCancel   context.CancelFunc
   abuseCancel context.CancelFunc
   rdapCancel  context.CancelFunc
   feedCancel  context.CancelFunc
   ```
2. **`StartBackgroundWorkers`:** store `p.bgCtx = ctx`; for each enrichment
   component create a child via `context.WithCancel(ctx)`, store its cancel
   func, and `Start` the component with the child. Behaviour unchanged when
   called once at startup.
3. **`ReplaceConfig`:** for each of the four components, in order — cancel
   the old worker (if a cancel func exists), construct the replacement, and
   if `p.bgCtx != nil` start it with a fresh child context, storing the new
   cancel func. The nil check preserves today's behaviour for Pipelines that
   never call `StartBackgroundWorkers` (unit tests, `ja4p` CLI).
4. **Observability:** one `log.Info` line per enrichment restart
   (`"enrichment worker restarted after config reload"` with component
   field) — the finding's core complaint is that the failure was silent.
5. **Shutdown semantics: unchanged.** `main()` cancels the root context on
   SIGTERM/SIGINT; all child contexts cascade. No `Stop()` method is added —
   the Phase 515 ctx-binding makes it unnecessary.

Not touched: the 32 `runAsyncScoringLoop` workers and the beaconing/audit
workers — `ReplaceConfig` does not replace their channels, and Phase 515
already made `beaconingWorker` re-read `p.beaconing` under the lock per job,
so they correctly follow the new config.

## Test Strategy

New tests in `internal/security/pipeline_test.go`:

| Test | Asserts |
|---|---|
| `TestPipeline_ReplaceConfig_RestartsEnrichmentWorkers` | After `ReplaceConfig`, the old worker has exited and a job sent to the **new** instance's queue is consumed (poll with deadline, no fixed sleeps). Must FAIL if the fix is reverted. |
| `TestPipeline_ReplaceConfig_NoGoroutineGrowth` | 10× `ReplaceConfig` with alternating enrichment configs; after root cancel, `runtime.NumGoroutine()` returns to baseline ±5 via a 3 s retry-loop helper. |
| `TestPipeline_ReplaceConfig_WithoutBackgroundWorkers` | `ReplaceConfig` on a Pipeline that never started workers does not panic and does not start goroutines (bgCtx nil path). |
| `go test -race ./internal/security/` | No races between `ReplaceConfig` and in-flight `processInternal` reads. |

## Acceptance Criteria

- [ ] Post-SIGHUP enrichment jobs are processed by the new instances (test 1)
- [ ] Repeated reloads do not leak goroutines (test 2)
- [ ] No behaviour change when background workers were never started (test 3)
- [ ] `go test -race ./internal/security/` clean
- [ ] `make test`, `make lint`, `make preflight` exit 0
- [ ] `findings.yaml`: 0089 → `status: FIXED`, `regression_test` populated,
      `closed_commit` filled after merge; `python3 scripts/findings_register.py
      validate` exits 0

## Out of Scope

- Anything fixed already: 251.1 (nil guard), 251.2 (worker ctx-binding).
- A general `Pipeline.Stop()` method (unnecessary post-515).
- Applying the old WIP patch directly (reference only).
- Python code.
