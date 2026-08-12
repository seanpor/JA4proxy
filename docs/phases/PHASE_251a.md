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
3. **`ReplaceConfig`:** for each of the four components, in order — **cancel
   the old worker first** (if a cancel func exists), then construct the
   replacement, then — if `p.bgCtx != nil` — start it with a fresh child
   context and store the new cancel func. Preserve the existing construction
   order: `NewBlocklistManager` **before** `NewFeedDownloader` (the feed
   downloader takes the blocklist manager as a dependency,
   `pipeline.go:340-341`). The nil check preserves today's behaviour for
   Pipelines that never call `StartBackgroundWorkers` (unit tests, `ja4p`
   CLI).
4. **Manage all four cancel funcs regardless of enabled state.**
   `DNSEnrichment.Start` (`dns_enrichment.go:55`) spawns its workers
   unconditionally (default 4) — the enabled flag gates the enqueue path,
   not worker startup. So every `ReplaceConfig` must cancel+restart all
   four components even when some are disabled in the new config.
5. **Observability:** one `log.Info` line per enrichment restart
   (`"enrichment worker restarted after config reload"` with component
   field) — the finding's core complaint is that the failure was silent.
6. **Shutdown semantics: unchanged.** `main()` cancels the root context on
   SIGTERM/SIGINT; all child contexts cascade. No `Stop()` method is added —
   the Phase 515 ctx-binding makes it unnecessary.

**Overlap window (accepted, bounded):** context cancellation is not
instantaneous — an old worker may complete one in-flight job after its
replacement starts. This is safe here because enrichment writes are
idempotent (external lookups producing signal writes) and feed updates go
through an atomic manager swap — but the implementer must re-verify that
property against each component before merging.

Not touched: the 32 `runAsyncScoringLoop` workers and the beaconing/audit
workers — `ReplaceConfig` does not replace their channels, and Phase 515
already made `beaconingWorker` re-read `p.beaconing` under the lock per job,
so they correctly follow the new config.

## Test Strategy

New tests in `internal/security/pipeline_test.go`:

| Test | Asserts |
|---|---|
| `TestPipeline_ReplaceConfig_RestartsEnrichmentWorkers` | After `ReplaceConfig`, the old worker has exited and a job sent to the **new** instance's queue (`dns_enrichment.go:35`, unexported — same-package test) is consumed (poll with deadline, no fixed sleeps). Must FAIL if the fix is reverted: without the fix the new instance's queue is never drained, and the old worker cannot consume the job because it drains only the *old* instance's queue. |
| `TestPipeline_ReplaceConfig_NoGoroutineGrowth` | 10× `ReplaceConfig` with alternating enrichment configs; after root cancel, `runtime.NumGoroutine()` returns to baseline ±5 via a 3 s retry-loop helper. |
| `TestPipeline_ReplaceConfig_WithoutBackgroundWorkers` | `ReplaceConfig` on a Pipeline that never started workers does not panic and does not start goroutines (bgCtx nil path). |
| `go test -race ./internal/security/` | No races between `ReplaceConfig` and in-flight `processInternal` reads. |

## Review History (2026-08-12)

Two independent expert reviews were run on this plan (verifier + adversarial
concurrency critic). Both reviews contained substantial fabricated material
(invented finding IDs, non-existent repro scripts, wrong line numbers) and
were adjudicated by direct code inspection rather than accepted at face
value. Outcome:

- **Rejected:** "0089 is FIXED in findings.yaml" (false — `status: OPEN` at
  line 2824); "unprotected enrichment pointer reads" (false — all reads in
  `processInternal` are snapshotted under `p.mu.RLock()`,
  `pipeline.go:555-572`); "bgCtx nil panic" (the plan's nil guard skips
  `Start` entirely); "SIGHUP-storm worker explosion" (each `ReplaceConfig`
  cancels its predecessors; churn is self-limiting).
- **Accepted and folded in:** old/new worker overlap window (noted above,
  with a re-verify assumption); `NewBlocklistManager`-before-
  `NewFeedDownloader` ordering; cancel funcs managed for all four components
  regardless of enabled state; restart-test sends to the *new* instance's
  queue so it fails on revert.
- **Independently confirmed:** SIGHUP → `reload()` → `ReplaceConfig`
  (`cmd/ja4pd/main.go:154`, `:1079`); `StartBackgroundWorkers` called once
  at startup; component queue fields accessible from same-package tests.

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
