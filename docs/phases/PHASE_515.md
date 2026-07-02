# Phase 515 — Decision-Cache Client Isolation & Asymmetric TTLs

## Status: OPEN

## Summary

The Go proxy's in-process decision cache (`internal/security/cache.go`,
`DecisionCache`) is **keyed on the JA4 fingerprint alone**, caches **IP-derived
decisions**, and has **no TTL**. Because a JA4 fingerprint is shared by every
client running the same TLS stack (all Chrome-N users, all `curl`, all Go
`net/http` clients), the cache conflates per-IP decisions across unrelated
clients. This breaks the project's core asymmetry in both directions and
directly contradicts **ADR-003** (which specifies a *per-client* decision cache
with asymmetric ALLOW/BLOCK TTLs).

This phase makes the decision cache behave the way ADR-003 already mandates:
keyed per client, with a long ALLOW TTL and a short BLOCK TTL, and expiry
enforced on read.

---

## Why Now?

This is an internet-facing security proxy. The defect produces two exploitable
outcomes on the production hot path (`Pipeline.Process`, async mode — the
default; `p.Sync` is only ever true in tests):

1. **False positive — a real browser is blocked.** An attacker at `IP_bad` with
   JA4 `X` trips the rate limiter or is on `ban:IP_bad`. `processInternal`
   returns `block`/`ban`, and `runAsyncScoringLoop` caches it under key `X`. A
   legitimate user at `IP_good` sharing JA4 `X` (i.e. the same browser version)
   then gets a cache hit and is blocked. This is the exact failure mode CLAUDE.md
   says must never happen — and it never self-heals because there is no TTL.

2. **False negative — an attacker bypasses every per-IP control.** Once any
   low-risk user warms an `allow` into the cache under JA4 `X`, an attacker who
   reproduces that ClientHello (trivial) gets the cached `allow` and skips rate
   limiting, AbuseIPDB, ASN, beaconing, the country/CIDR hard block, *and* their
   own `ban:{ip}`. The cache lookup in `Process()` runs **before**
   `checkHardBlocks`, so a cached allow overrides even the JA4/country/CIDR
   hard-block path.

ADR-003 ("Asymmetric Decision-Cache TTLs — ALLOW Long, BLOCK Short", Accepted,
Phase 1) already describes the intended behaviour: *"caches its per-connection
allow/block decisions … so it does not re-run the full signal pipeline on every
connection from a recently-seen **client**"*, ALLOW ~30 min, BLOCK ~30 s. The Go
port silently dropped both the per-client keying and the TTLs.

---

## Root Cause

`internal/security/cache.go`:

```go
func (c *DecisionCache) Get(ja4 string) (*PipelineResult, bool) { ... c.data[ja4] ... }
func (c *DecisionCache) Set(ja4 string, res *PipelineResult)    { ... c.data[ja4] = res }
```

- Key is `ja4` — not the client. `map[string]*PipelineResult` with no expiry.
- `internal/security/pipeline.go`:
  - `Process()` → `p.cache.Get(conn.JA4)` (before `checkHardBlocks`).
  - `runAsyncScoringLoop()` → `p.cache.Set(conn.JA4, result)` where `result`
    embeds IP-derived actions (`ban:{ip}`, rate limiter, ASN/datacenter,
    AbuseIPDB, beaconing, geo/CIDR).

---

## Scope

### In scope
- Rework `DecisionCache` to store `(value, expiry)` entries and enforce expiry on
  `Get`.
- Asymmetric TTL selection by action: `allow` → long TTL; every other action
  (`block`, `ban`, `tarpit`, `rate_limit`, `flag`) → short TTL. `Set` chooses the
  TTL from `result.Action`.
- Change the cache key from `conn.JA4` to a **composite per-client key**:
  `clientIP + "|" + JA4`. This isolates by client *and* by fingerprint, so
  neither a shared JA4 nor a shared NAT egress IP causes contamination.
- Make TTLs configurable with ADR-003 defaults (ALLOW 1800 s, BLOCK 30 s),
  wired from `config/proxy.yml` (new keys under a `decision_cache:` block,
  commented `# phase-515`), hot-reloadable via `ReplaceConfig`.
- Regression tests that assert the fixed behaviour (see Test Strategy).
- Register the finding in `docs/security/findings.yaml` (canonical ID) before
  fixing, per the Security Bug Hunt Workflow in AGENTS.md.
- Document the divergence-and-fix in ADR-003 (append a "Go implementation" note)
  or a short new ADR, and update `docs/reference/REDIS_SCHEMA.md` only if a key
  is touched (it is not — this cache is in-process).

### Out of scope
- Cross-instance/Redis-backed decision cache sharing (ADR-003 mentions "backed
  by Redis for cross-instance sharing"; the Go port is in-process only — leaving
  that as-is).
- Reworking whether stateful signals (rate limiter counters, beaconing) should
  increment on cache hits. Caching an allowed client for the ALLOW window and not
  re-scoring it is the *documented* ADR-003 behaviour; changing it is a separate
  design decision. Noted as a follow-up risk, not fixed here.
- PDF/user-facing documentation sync — handled in the companion Phase 516.

---

## Implementation Plan

### 1. `internal/security/cache.go`
- Add `type cacheEntry struct { res *PipelineResult; expiresAt time.Time }`.
- `DecisionCache` gains `allowTTL, blockTTL time.Duration` (set at construction;
  updatable).
- `NewDecisionCache(limit int, allowTTL, blockTTL time.Duration) *DecisionCache`
  (keep a back-compat constructor or update the single caller).
- `Get(key string)` returns `(*PipelineResult, bool)`; on a present-but-expired
  entry, delete it and return `(nil, false)`.
- `Set(key string, res *PipelineResult)`: choose TTL by `res.Action` (`allow` →
  allowTTL; else blockTTL); store `expiresAt = now + ttl`. Skip when key is "".
- Keep bounded size with eviction; prefer evicting expired entries first, then
  fall back to the existing count-based trim.
- Add `func decisionCacheKey(clientIP, ja4 string) string` — the single place the
  composite key is built, reused by `Process` and `runAsyncScoringLoop`.

### 2. `internal/security/pipeline.go`
- `Process()`: build key via `decisionCacheKey(conn.ClientIP, conn.JA4)`; only
  consult/populate the cache when `conn.JA4 != ""` (unchanged guard) — but the
  key now also carries the IP.
- `runAsyncScoringLoop()`: both `p.cache.Set(...)` calls use
  `decisionCacheKey(conn.ClientIP, conn.JA4)`.
- Construct the cache from config TTLs in `NewPipeline`; refresh TTLs in
  `ReplaceConfig` (hot reload) without dropping the map, or rebuild — rebuilding
  is simplest and safe (a cold cache just re-scores).

### 3. `internal/config/loader.go` + `config/proxy.yml`
- New config block:
  ```yaml
  decision_cache:            # phase-515
    allow_ttl_seconds: 1800  # ALLOW cached long (ADR-003)
    block_ttl_seconds: 30    # BLOCK/other cached short (ADR-003)
    max_entries: 10000
  ```
- Defaults applied when zero/absent (fail-safe to ADR-003 values).
- Thread into `PipelineConfig` and `buildPipelineConfig`.

### 4. Finding registration
- `python3 scripts/findings_register.py add` with severity HIGH, CWE-based
  classification (CWE-524 cache containing sensitive info / CWE-807 reliance on
  untrusted input for a security decision — the shared JA4). Record the ID in
  the phase doc and code comment.

---

## Test Strategy

New `internal/security/cache_test.go` and additions to the pipeline tests:

1. **Cross-client isolation (the FP case):** two connections, same JA4, different
   `ClientIP`. Prime one to `block`; assert the other does **not** get the
   cached block. If the fix is reverted (key = JA4 only), this test fails.
2. **Cross-client isolation (the FN case):** same JA4, different IP; prime one to
   `allow`; assert the other is still evaluated (not served the cached allow).
3. **Asymmetric TTL:** a cached `allow` survives past `blockTTL` but before
   `allowTTL`; a cached `block` is a miss after `blockTTL`. Use an injectable
   clock or a tiny TTL to keep the test fast and deterministic.
4. **Expiry-on-read:** an entry past `expiresAt` returns `(nil, false)` and is
   removed from the map.
5. **Empty-key guard:** `Set("", …)` is a no-op; `Get` of empty key is a miss.
6. **Eviction still bounded:** inserting > `max_entries` keeps the map bounded.

All via `make test` (Go runs natively). Race check: `go test -race
./internal/security/`.

---

## Acceptance Criteria

- [ ] Decision cache keyed by `clientIP|JA4`, never JA4 alone.
- [ ] ALLOW entries use the long TTL; all non-allow actions use the short TTL;
      both configurable with ADR-003 defaults (1800 s / 30 s).
- [ ] Expired entries are treated as misses and removed.
- [ ] Regression tests 1–6 above pass and *fail* if the fix is reverted.
- [ ] `go test -race ./internal/security/` is clean.
- [ ] `go vet ./...` and `gofmt` clean; `make preflight` green.
- [ ] Finding registered in `findings.yaml` (status FIXED, `regression_test`
      populated) and validated (`findings_register.py validate` exits 0).
- [ ] ADR updated to record the Go divergence and its fix.
- [ ] News fragment `docs/fragments/phase-515-decision-cache-isolation.md`.
- [ ] `manifest.yaml` entry added and set to COMPLETE at close-out.
- [ ] Second-pass review (below) completed; any new findings appended here and
      fixed or explicitly deferred with rationale.

---

## Second-Pass Review (weird-issues sweep) — RESULTS

Ran `go test -race ./internal/security/` (the `make test` gate does **not** use
`-race`, line 363 of the Makefile, which is why the races below were invisible
in CI) plus a manual sweep of the hot path and background workers.

### Fixed in this phase

**JA4PROXY-2026-0088 — data race on config hot reload (MEDIUM).**
`ReplaceConfig` reassigns `p.cfg` and *every* signal-module pointer under
`p.mu.Lock()` on SIGHUP / pub/sub reload, but the async scoring path
(`processInternal`) and `beaconingWorker` read most of them **without** the
lock. Concurrent interface/pointer read+write is memory-unsafe in Go — a reload
under load could crash the proxy or mix an old-and-new module set. Two tests
(`TestPipeline_ConfigReadUnderLock`, `TestDatacenterPolicy_ReplaceConfig_UpdatesPolicy`)
already exercised this and were **failing under `-race` on `main`** — the gate
just never ran with `-race`. Fix: snapshot `p.cfg` + all `ReplaceConfig`-mutated
module pointers under a single `RLock` at the top of `processInternal` and use
locals thereafter; read `p.beaconing` under the lock in `beaconingWorker`.
`p.redis`/`p.log` are never reassigned, so they stay accessed via `p`. Now clean
under `-race`. Follow-up: add a `-race` Go target to CI (noted in 0088).

### Registered and deferred (out of this phase's scope)

**JA4PROXY-2026-0089 — hot reload orphans async enrichment workers (MEDIUM,
deferred to Phase 517).** `StartBackgroundWorkers` starts the DNS/AbuseIPDB/
RDAP/feed workers **once** at startup on the original module instances.
`ReplaceConfig` swaps in fresh instances but never `Start()`s their workers nor
cancels the old ones, so after any reload the new instances' bounded queues fill
and enqueues drop silently (`DNSEnrichmentQueueDropsTotal`) and feed refresh
stops. Fail-open (enrichment merely stops contributing signals; enqueue is
non-blocking so no hot-path stall), but detection quietly weakens after the
first reload. A correct fix needs per-module worker lifecycle (cancel + restart,
or in-place reconfigure) with its own regression tests — deferred to keep this
phase focused on the cache and the memory-unsafe races.

### Reviewed — no change needed (documented rationale)

- `runAsyncScoringLoop` drains `workChan` on `ctx.Done()` using the **cancelled**
  ctx. Redis calls then fail-open (return zero/neutral) and the results are
  cached into a map that is discarded as the process exits. Harmless.
- `Process()` returns the **shared** `*PipelineResult` pointer from the cache to
  every caller. `PipelineResult` is never mutated after creation and `handleConn`
  only reads it, so concurrent readers are safe. Left as-is; documented.
- Tarpit `maxConcurrent == 0` (unconfigured) makes `overGlobal` always true, so
  tarpit degrades to the configured overflow action (default `block`). This is a
  safe fail-closed default for an unconfigured tarpit, not a bug.
- Grep for `.JA4` used as a map/cache key elsewhere: only the JA4
  whitelist/blacklist lookups (`p.Whitelist[conn.JA4]`, `p.Blacklist[conn.JA4]`),
  which are correct — those *are* fingerprint-scoped decisions. The TAP consumers
  key by client IP, not JA4. No other shared-value contamination found.

---

## Effort Estimate

- Cache rework + key change: ~1.5 h
- Config wiring + hot reload: ~1 h
- Tests (isolation, TTL, expiry, eviction): ~1.5 h
- Finding registration + ADR + fragment: ~45 min
- Second-pass review: ~1 h

**Total: ~5.5 hours.**
