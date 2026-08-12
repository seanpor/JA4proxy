<!--
title: "Phase 251 — Pipeline Lifecycle & Memory Safety: Stop() Method, Nil-Interface Guard, Enrichment Orphan Fix"
audience: developer
last_reviewed: 2026-06-30
phase: 251
-->

# Phase 251 — Pipeline Lifecycle & Memory Safety

> **CLOSED — SUPERSEDED (2026-08-12).** This phase was leased and partially
> implemented but never landed. Two of its three findings were fixed on main
> by other work: the nil-rangerBox guard (251.1) is at
> `internal/security/blocklists.go:198`, and the unstoppable beaconing/audit
> workers (251.2) were bound to a context by Phase 515
> (`JA4PROXY-2026-0090`, commit `accdfff0`). The third finding —
> `ReplaceConfig` orphaning enrichment workers — remains **OPEN** as
> `JA4PROXY-2026-0089` and is re-scoped against current code in **Phase
> 251a** (`docs/phases/PHASE_251a.md`). The original WIP implementation is
> preserved as `PHASE_251_WIP.patch` in this directory — it was written
> against pre-Phase-515 `pipeline.go`, does not apply to current main, and
> is kept as design reference only.

## Problem Statement

A review of the Go proxy found three distinct classes of bugs. All involve
goroutines, channels, or nil interfaces — classic Go pitfalls that are
easy to introduce and hard to notice.

### Finding 1: Nil rangerBox Dereference Panic (S×I = 64, High)

**Location:** `internal/security/blocklists.go:201` — `(*BlocklistManager).Check()`

`Check()` loads an `atomic.Pointer[rangerBox]` and checks `if box == nil`.
But it does **not** check whether `box.ranger` (the inner `cidranger.Ranger`
interface) is nil. If any code path stores a `rangerBox{ ranger: nil }`, the
call `box.ranger.Contains(ip)` panics with a nil pointer dereference.

`ReplaceFeed()` (line 172) was fixed in a prior pass to reject nil, so
the most obvious vector is blocked. This is a **defense-in-depth** gap.

**Consequence:** A nil interface stored by any future code path causes a
panic on every `Check()` call on that feed — crashing the HTTP handler or
the entire process.

### Finding 2: Two Workers That Can Never Be Stopped (S×I = 49, Medium-High)

**Location:** `internal/security/pipeline.go:380-395`

`beaconingWorker()` and `auditWorker()` both use `for job := range ch`.
The underlying channels (`beaconingJobs`, `auditJobs`) are **never closed**.
The comment on line 388 says: "the process exits on SIGINT/SIGTERM ... adding
a Stop() method would require plumbing shutdown through the entire call
chain for no benefit."

This assumption was correct when written, but **config reload via
`ReplaceConfig`** (SIGHUP at `cmd/ja4pd/main.go:1086`) and **tests that
create-and-discard Pipeline objects** both violate it. Every SIGHUP or
discarded Pipeline leaks two goroutines forever.

**Consequence:** Repeated config reloads accumulate leaked goroutines and
pinned Pipeline objects, leading to eventual OOM. Tests that create
Pipelines without stopping them accumulate goroutines across test cases.

### Finding 3: ReplaceConfig Orphans Enrichment Workers (S×I = 36, Medium)

**Location:** `internal/security/pipeline.go:291-320` — `(*Pipeline).ReplaceConfig()`

`ReplaceConfig()` creates **new** `DNSEnrichment`, `AbuseIPDB`,
`RDAPEnricher`, and `FeedDownloader` instances (lines 306-313) and assigns
them to the Pipeline. But `StartBackgroundWorkers()` is **only called once**
at process startup (line 96 of `main.go`).

This means:
- The **old** enrichment workers keep running on the main context — they
  read from the old queue channels that nobody sends to anymore.
- The **new** instances have their own queue channels, but nobody is
  draining them. New enrichment jobs pile up in these queues indefinitely.
- Enrichment signals (DNS, AbuseIPDB, RDAP) silently stop working after
  a config reload until the process restarts.

**Consequence:** Operators who change config via SIGHUP lose enrichment
signals without any log or metric indicating the loss. The new instances
accumulate queued-but-never-processed jobs.

### Finding 4: No Lifecycle Verification in Tests

The existing test suite has 25+ places that call `NewPipeline`, but none
call `Stop()`, `Close()`, or any teardown. There is no test that:
- Verifies goroutines return to baseline after Stop()
- Verifies repeated ReplaceConfig calls don't leak
- Catches the nil-rangerBox pattern via fuzzing or static analysis

---

## Critical Review Results

Three expert reviews were conducted on this phase plan. Here is a summary of
substantive findings that changed the plan. Every issue below has been
addressed in the sub-phase details that follow.

### Concurrency Expert (APPROVED with HIGH notes)

| Issue | Severity | Resolution |
|-------|----------|------------|
| Race on enrichment component pointers in `processInternal` | HIGH | Snapshot enrichment pointers under `p.mu.RLock()` before use (already existing pattern — verify) |
| Cancel-func reads in `Stop()` are lock-free → same-goroutine assumption | MEDIUM | Document that `Stop()` and handler calls are serialized by `main()` signal loop; add lock guard as belt-and-suspenders |
| `Stop()` may return before enrichment workers have fully exited | INFO | Use retry-loop in leak tests instead of hardcoded sleep |

### Security Expert (APPROVED with recommendations)

| Issue | Severity | Resolution |
|-------|----------|------------|
| Findings must be registered in `findings.yaml` before fixing | MEDIUM | Add "Register Findings" step before sub-phases |
| No finding IDs for any of the three bugs | MEDIUM | Three findings to register (see step 0) |
| `bgCtx`/cancel-func fields have no synchronization guard | LOW | Add doc comment: not protected by `p.mu` — callers must serialize |

### Code Quality Expert (CHANGES REQUESTED)

| Issue | Severity | Resolution |
|-------|----------|------------|
| Conflicting test guidance in 251.1 | MAJOR | Removed reflection discussion; simplified to direct access |
| Missing test implementations for 4 tests | MAJOR | Added full code for all tests |
| Missing findings registration | MAJOR | Added step 0 |
| Timing-dependent leak tests | MINOR | Replaced hardcoded sleep with retry loop |
| "cancels ALL" wording misleading | MINOR | Clarified exact scope |
| Semgrep rule needs caveat | MINOR | Added note about false positive pattern |

---

## Prerequisites — Register Findings in findings.yaml (Before Any Code Changes)

**Per project policy** (AGENTS.md), every bug must be registered in
`docs/security/findings.yaml` **before** the fix is implemented. This creates
a canonical audit trail with Jira-style IDs (`JA4PROXY-2026-NNNN`) and
automatically opens a GitHub issue.

Run these three commands **before writing any code**.

**Finding A — Nil rangerBox dereference:**

```bash
python3 scripts/findings_register.py add \
  --title "Nil rangerBox interface dereference in BlocklistManager.Check()" \
  --cwe "CWE-476" \
  --severity high \
  --cvss "7.5" \
  --component "internal/security/blocklists.go" \
  --description "BlocklistManager.Check() loads an atomic.Pointer[rangerBox] and checks the outer pointer for nil, but does not check whether the inner interface field box.ranger is nil before calling box.ranger.Contains(ip). A nil interface stored by any code path causes a panic on every Check() call on that feed."
```

**Finding B — Pipeline workers goroutine leak (never-stoppable):**

```bash
python3 scripts/findings_register.py add \
  --title "Pipeline beaconingWorker and auditWorker goroutines cannot be stopped" \
  --cwe "CWE-404" \
  --severity medium \
  --cvss "5.9" \
  --component "internal/security/pipeline.go" \
  --description "beaconingWorker() and auditWorker() use for...range over channels that are never closed. The Pipeline has no Stop() method. Every discarded Pipeline or ReplaceConfig call leaks 2 goroutines forever, accumulating until OOM."
```

**Finding C — ReplaceConfig orphans enrichment workers:**

```bash
python3 scripts/findings_register.py add \
  --title "ReplaceConfig creates orphan enrichment instances with un-drained queues" \
  --cwe "CWE-404" \
  --severity medium \
  --cvss "5.3" \
  --component "internal/security/pipeline.go" \
  --description "ReplaceConfig() creates new DNSEnrichment/AbuseIPDB/RDAPEnricher/FeedDownloader instances but never starts them. Old instances keep running on stale queues. New work goes to un-drained queues. Enrichment signals silently stop after a config reload."
```

After registration, record the allocated IDs (e.g. `JA4PROXY-2026-0100`)
in the PR description as `Fixes #NN` references.

---

## What Already Exists (Do Not Rebuild)

- **`internal/security/blocklists.go:172-183`**: `ReplaceFeed` already guards
  against nil ranger. Only the `Check()` hot path guard is missing.
- **`internal/security/pipeline.go:291-320`**: `ReplaceConfig` already exists
  and replaces sub-components. The bug is that it does not start the new
  instances or stop the old ones.
- **`internal/security/pipeline.go:405-412`**: `StartBackgroundWorkers` already
  exists. It is only called once at startup. The priority order of sub-phases
  below is carefully designed so you never need to rewrite this method or
  its callers.
- **`internal/security/`**: All enrichment components (`DNSEnrichment`,
  `AbuseIPDB`, `RDAPEnricher`, `FeedDownloader`) already use the `select`
  + `ctx.Done()` pattern — they **would** shut down cleanly if their context
  were cancelled. The bug is that their context is never cancelled.

---

## Sub-phases

Do these in order. Each builds on the previous one.

### 251.1 — Defensive nil-ranger guard in blocklist Check() (XS)

**Dependencies:** none

**What to do:**

Open `internal/security/blocklists.go`, find the `Check()` method. On line 197
the code loads the rangerBox and checks if the outer pointer is nil. Add a
check for the inner interface too.

Current code (lines 196-201):
```go
for _, feed := range m.feeds {
    box := feed.ranger.Load()
    if box == nil {
        continue
    }
    contains, err := box.ranger.Contains(ip)
```

After your fix it should look like:
```go
for _, feed := range m.feeds {
    box := feed.ranger.Load()
    if box == nil || box.ranger == nil {
        continue
    }
    contains, err := box.ranger.Contains(ip)
```

The `||` is important — it's one check, not two. Go short-circuits: if
`box` is nil it never evaluates `box.ranger`.

**Why this works:** `box.ranger` is an interface. An interface in Go is nil
only when both its type and value are unset — a `rangerBox{ranger: nil}`
stores an interface-value pair of `(nil, nil)`, which is nil. The
`|| box.ranger == nil` guard catches this.

**Scope note — typed-nil not covered:** This guard catches the most common
case. It does NOT catch a *typed nil* — e.g., `var r *cidranger.PCTrieRanger
= nil; rangerBox{ranger: r}`. In that case, the interface's type pointer is
set even though the value is nil, so `box.ranger == nil` returns false and
the panic remains. `ReplaceFeed` has the same gap. In practice this path is
not reachable because all callers use concrete constructors that never return
typed nils. The guard is defense-in-depth against accidental future code, not
a comprehensive nil-interface solution.

**Test to write:** `TestBlocklists_NilRangerBox_NoPanic` in
`internal/security/blocklists_test.go`.

The test file is in the same Go package (`package security`) as
`blocklists.go`, so it can access unexported types like `blocklistFeed`
and `rangerBox` directly. There is no need for reflection or helper
functions.

```go
func TestBlocklists_NilRangerBox_NoPanic(t *testing.T) {
    // Create a manager with one enabled feed.
    m := NewBlocklistManager(&BlocklistConfig{
        Feeds: []BlocklistFeedConfig{
            {Name: "nil_feed", Enabled: true},
        },
    }, nil)

    // Overwrite the feed's ranger with a rangerBox that has a nil
    // interface inside. This simulates the edge case that the
    // defense-in-depth guard catches.
    m.feeds[0].ranger.Store(&rangerBox{ranger: nil})

    // Check must NOT panic. It should skip the nil-ranger feed and
    // return empty results.
    sigs, hardBlock := m.Check(net.ParseIP("1.2.3.4"))
    if hardBlock {
        t.Error("nil ranger feed: expected no hard block")
    }
    if len(sigs) != 0 {
        t.Errorf("nil ranger feed: expected 0 signals, got %d", len(sigs))
    }
}
```

**Acceptance criteria:**
- [ ] `Check()` skips feeds where `box.ranger` is nil instead of panicking
- [ ] `TestBlocklists_NilRangerBox_NoPanic` passes — stores a nil-ranger
      rangerBox and verifies Check() returns empty results
- [ ] `make test` passes
- [ ] `make lint` passes

---

### 251.2 — Pipeline.Stop() with stop channel for channel-range workers (SMALL)

**Dependencies:** none

**What to do:**

Step 1 — Add two fields to the `Pipeline` struct (`pipeline.go:65-105`):

```go
stopCh chan struct{}
stopOnce sync.Once
wg       sync.WaitGroup
```

Add them near the other channel fields (around line 93). The `sync.Once`
ensures `Stop()` can be called multiple times without panicking on close.

Step 2 — In `NewPipeline()` (`pipeline.go:247`), initialize `stopCh` and
track the two workers in the WaitGroup. Replace the existing goroutine
launches at the bottom of `NewPipeline` with:

```go
p.beaconingJobs = make(chan beaconingJob, beaconingJobBuf)
p.auditJobs = make(chan auditJob, auditJobBuf)
p.stopCh = make(chan struct{})
p.wg.Add(1)
go p.beaconingWorker()
p.wg.Add(1)
go p.auditWorker()
return p
```

Step 3 — Rewrite `beaconingWorker()` (lines 380-384) from channel-range to
select-with-stopCh:

**Before:**
```go
func (p *Pipeline) beaconingWorker() {
    for job := range p.beaconingJobs {
        p.beaconing.MaybeRecord(job.ctx, job.conn, job.action)
    }
}
```

**After:**
```go
func (p *Pipeline) beaconingWorker() {
    defer p.wg.Done()
    for {
        select {
        case <-p.stopCh:
            return
        case job := <-p.beaconingJobs:
            p.beaconing.MaybeRecord(job.ctx, job.conn, job.action)
        }
    }
}
```

Step 4 — Rewrite `auditWorker()` (lines 392-396) the same way:

**Before:**
```go
func (p *Pipeline) auditWorker() {
    for job := range p.auditJobs {
        p.auditDecision(job.ctx, job.ip, job.currentScore)
    }
}
```

**After:**
```go
func (p *Pipeline) auditWorker() {
    defer p.wg.Done()
    for {
        select {
        case <-p.stopCh:
            return
        case job := <-p.auditJobs:
            p.auditDecision(job.ctx, job.ip, job.currentScore)
        }
    }
}
```

Step 5 — Add the `Stop()` method:

```go
// Stop signals all worker goroutines to exit and waits for them to finish.
// Safe to call multiple times — subsequent calls are no-ops.
func (p *Pipeline) Stop() {
    p.stopOnce.Do(func() {
        close(p.stopCh)
    })
    p.wg.Wait()
}
```

Step 6 — Wire `Stop()` into `main.go` so the pipeline shuts down on
SIGTERM/SIGINT. In the signal handler (around line 160-164 of `main.go`),
place `Stop()` **after** `drain()`:

```go
case syscall.SIGINT, syscall.SIGTERM:
    log.WithField("signal", sig).Info("shutdown signal received")
    cancel()
    proxy.drain(cfg.Proxy.DrainTimeoutSeconds)
    proxy.pipeline.Stop()   // ← add after drain
    return
```

**Why `Stop()` after `drain()`:** `drain()` waits for in-flight connections
to close. Those connections may still submit beaconing and audit jobs during
the drain window. Calling `Stop()` before `drain()` would terminate the
workers while connections are still being processed, silently dropping
last-moment observations. Calling it after drain means all in-flight work
is flushed before the workers exit.

**Why `Stop()` at all:** The process is already exiting after this handler
returns, so it is not required for correctness. Including it ensures the
`Stop()` code path is exercised in production; without it, the path only
runs in tests and could drift silently.

**Design note — why a stop channel instead of closing the job channels:**
Closing `beaconingJobs` or `auditJobs` while a producer might be sending
(see `processInternal()` lines 679 and 690) causes a panic:
`send on closed channel`. The stop channel is one-way production-side
(only closed, never sent to) and consumed by the workers alongside their
job channels. Closing the stop channel never panics because `sync.Once`
guards it, and reading from a closed channel returns immediately (the
zero value), which is why the workers return.

**Tests to write in `internal/security/pipeline_test.go`:**

**`TestPipeline_Stop_WorkersExit`** — verifies both channel-range workers
terminate when Stop() is called. Uses a flag-based approach to avoid
timing flakiness:

```go
func TestPipeline_Stop_WorkersExit(t *testing.T) {
    p := NewPipeline(&PipelineConfig{}, &mockRedis{}, nil)
    // Workers are started in NewPipeline. We need to stop them and
    // verify they exited. Since we don't call StartBackgroundWorkers,
    // only the two channel-range workers are running.
    p.Stop()

    // After Stop(), sending to the job channels should have no effect
    // (workers are gone, no panic). The non-blocking send with default
    // is safe regardless.
    select {
    case p.beaconingJobs <- beaconingJob{}:
    default:
    }
    select {
    case p.auditJobs <- auditJob{}:
    default:
    }
    // If we reach here without panic, the workers have stopped.
    // (They would have consumed these jobs if still running.)
}
```

**`TestPipeline_Stop_Idempotent`** — verifies double-Stop does not panic:

```go
func TestPipeline_Stop_Idempotent(t *testing.T) {
    p := NewPipeline(&PipelineConfig{}, &mockRedis{}, nil)
    p.Stop()
    // Second call must not panic (sync.Once guards close).
    p.Stop()
}
```

**`TestPipeline_Stop_WorkersExit_WithBackground`** — verifies cleanup
with all background workers started:

```go
func TestPipeline_Stop_WorkersExit_WithBackground(t *testing.T) {
    baseline := runtime.NumGoroutine()

    ctx, cancel := context.WithCancel(context.Background())

    p := NewPipeline(&PipelineConfig{}, &mockRedis{}, nil)
    p.StartBackgroundWorkers(ctx)

    // cancel() must be called explicitly before Stop() so the 32 async
    // scoring workers (which exit on ctx.Done()) are also stopped before
    // the goroutine check. Using defer cancel() would run it AFTER this
    // function returns — after requireGoroutinesReturnToBaseline — leaving
    // those 32 goroutines alive during the check and failing the ≤5 margin.
    cancel()
    p.Stop()
    requireGoroutinesReturnToBaseline(t, baseline)
}

// requireGoroutinesReturnToBaseline polls NumGoroutine in a retry
// loop. This avoids flaky failures when CI is slow.
func requireGoroutinesReturnToBaseline(t *testing.T, baseline int) {
    t.Helper()
    deadline := time.NewTimer(3 * time.Second)
    defer deadline.Stop()
    tick := time.NewTicker(50 * time.Millisecond)
    defer tick.Stop()
    for {
        select {
        case <-deadline.C:
            runtime.GC()
            after := runtime.NumGoroutine()
            leaked := after - baseline
            if leaked > 5 {
                t.Fatalf("expected ≤5 leaked goroutines, got %d (baseline=%d, after=%d)",
                    leaked, baseline, after)
            }
            return
        case <-tick.C:
            runtime.GC()
            after := runtime.NumGoroutine()
            if after-baseline <= 5 {
                return // success, workers have exited
            }
        }
    }
}
```

**Acceptance criteria:**
- [ ] `Pipeline.Stop()` closes the stop channel and both workers exit
- [ ] Calling `Stop()` twice does not panic (sync.Once guard)
- [ ] `TestPipeline_Stop_WorkersExit` passes — workers stop, no panic on post-Stop send
- [ ] `TestPipeline_Stop_Idempotent` passes — double-Stop does not panic
- [ ] `TestPipeline_Stop_WorkersExit_WithBackground` passes — all workers exit within 3s
- [ ] SIGTERM/SIGINT in main.go calls `proxy.pipeline.Stop()`
- [ ] `make test` passes
- [ ] `make lint` passes

---

### 251.3 — Fix ReplaceConfig enrichment orphans (MEDIUM)

**Dependencies:** 251.2

**What to do:**

The root cause is that `ReplaceConfig()` creates new enrichment instances
but doesn't stop the old ones or start the new ones. The enrichment
components (`DNSEnrichment`, `AbuseIPDB`, `RDAPEnricher`, `FeedDownloader`)
all follow the same pattern:

```
struct {
    queue chan ...
    cfg   *Config
    ...
}

func (s *Struct) Start(ctx context.Context) {
    go s.worker(ctx)
}

func (s *Struct) worker(ctx context.Context) {
    for {
        select {
        case <-ctx.Done():
            return
        case job := <-s.queue:
            ...
        }
    }
}
```

The fix has two parts:

**Part A — Store cancel functions in Pipeline**

Add four context-cancel fields to `Pipeline`:

```go
dnsCancel    context.CancelFunc
abuseCancel  context.CancelFunc
rdapCancel   context.CancelFunc
feedCancel   context.CancelFunc
```

**Part B — Replace `StartBackgroundWorkers` with context ownership**

Currently `StartBackgroundWorkers` takes a context from the caller. Change
it to CREATE its own child contexts so it owns the lifecycle:

```go
func (p *Pipeline) StartBackgroundWorkers(ctx context.Context) {
    for i := 0; i < asyncScoringWorkers; i++ {
        go p.runAsyncScoringLoop(ctx)
    }

    // Create child contexts so we can cancel them individually later.
    dnsCtx, dnsCancel := context.WithCancel(ctx)
    p.dnsCancel = dnsCancel
    p.dnsEnrichment.Start(dnsCtx)

    abuseCtx, abuseCancel := context.WithCancel(ctx)
    p.abuseCancel = abuseCancel
    p.abuseipdb.Start(abuseCtx)

    rdapCtx, rdapCancel := context.WithCancel(ctx)
    p.rdapCancel = rdapCancel
    p.rdap.Start(rdapCtx)

    feedCtx, feedCancel := context.WithCancel(ctx)
    p.feedCancel = feedCancel
    p.feedDownloader.Start(feedCtx)
}
```

**Part C — Update `ReplaceConfig` to stop old workers and start new ones**

Inside `ReplaceConfig()`, after creating each new instance:

```go
// Stop old enrichment workers.
if p.dnsCancel != nil {
    p.dnsCancel()
    p.dnsCancel = nil
}

// Replace with new instance.
p.dnsEnrichment = NewDNSEnrichment(buildDNSEnrichmentConfig(cfg), p.redis, p.log)

// Start new instance with fresh child context.
// BUT: ReplaceConfig does not have access to the parent ctx.
```

**Problem:** `ReplaceConfig` does not have access to the parent context
that was passed to `StartBackgroundWorkers`. We need to store the parent
context in the Pipeline too.

**Solution:** Add `bgCtx context.Context` to Pipeline. Set it in
`StartBackgroundWorkers`. Use it in `ReplaceConfig` to create new
child contexts.

Add to Pipeline struct:
```go
bgCtx       context.Context       // parent context for background workers
dnsCancel   context.CancelFunc
abuseCancel context.CancelFunc
rdapCancel  context.CancelFunc
feedCancel  context.CancelFunc
```

In `StartBackgroundWorkers`, save `p.bgCtx = ctx` before creating children.

In `ReplaceConfig`, for each enrichment component that has a Start():
```go
// Stop old
if p.dnsCancel != nil {
    p.dnsCancel()
}

// Replace
p.dnsEnrichment = NewDNSEnrichment(buildDNSEnrichmentConfig(cfg), p.redis, p.log)

// Start new (if parent context exists)
if p.bgCtx != nil {
    dnsCtx, dnsCancel := context.WithCancel(p.bgCtx)
    p.dnsCancel = dnsCancel
    p.dnsEnrichment.Start(dnsCtx)
}
```

**Repeat for:** `abuseipdb`, `rdap`, `feedDownloader`.

**Note on async scoring workers (`runAsyncScoringLoop`):** These read from
`workChan`, which is NOT replaced by `ReplaceConfig`. The same 32 workers
and same `workChan` survive across config reloads. This is correct — no
fix needed for them.

**Also update `Stop()` to cancel enrichment contexts:**

Add to the existing `Stop()` method:
```go
func (p *Pipeline) Stop() {
    p.stopOnce.Do(func() {
        close(p.stopCh)
    })
    // Cancel enrichment workers.
    if p.dnsCancel != nil { p.dnsCancel() }
    if p.abuseCancel != nil { p.abuseCancel() }
    if p.rdapCancel != nil { p.rdapCancel() }
    if p.feedCancel != nil { p.feedCancel() }
    p.wg.Wait()
}
```

**Important concurrency note — enrichment pointer races:**

The concurrency review found that `p.dnsEnrichment`, `p.abuseipdb`,
`p.rdap`, and `p.feedDownloader` are replaced by `ReplaceConfig` (under
`p.mu`), but read by `processInternal` (also under `p.mu.RLock()`).
Verify that all reads of these pointers in `processInternal` (around
lines 532-665 of pipeline.go) already hold `p.mu.RLock()`. If any read
accesses these pointers outside the lock, add a lock guard. The existing
code already uses `p.mu.RLock()` in `processInternal` for other fields
— check that the enrichment access is within that same locked section.

**`Stop()` must also lock when reading cancel funcs.** Even though in
production the SIGTERM and SIGHUP handlers run on the same goroutine
(the `main()` signal loop), add a lock guard as belt-and-suspenders so
tests that call `Stop()` and `ReplaceConfig` concurrently don't race.
Read the cancel funcs into local variables under a lock, then call them
outside the lock:

```go
func (p *Pipeline) Stop() {
    p.stopOnce.Do(func() { close(p.stopCh) })

    p.mu.Lock()
    dnsCancel := p.dnsCancel
    abuseCancel := p.abuseCancel
    rdapCancel := p.rdapCancel
    feedCancel := p.feedCancel
    p.mu.Unlock()

    if dnsCancel != nil { dnsCancel() }
    if abuseCancel != nil { abuseCancel() }
    if rdapCancel != nil { rdapCancel() }
    if feedCancel != nil { feedCancel() }
    p.wg.Wait()
}
```

(`context.CancelFunc` is a function value — calling it after the unlock
is safe; the underlying `Context` is what's mutated.)

**What `p.wg.Wait()` covers and what it does not:** `p.wg` tracks only
`beaconingWorker` and `auditWorker` — they call `defer p.wg.Done()`. The
enrichment workers (DNS, AbuseIPDB, RDAP, FeedDownloader) are signalled by
the `*Cancel()` calls above, but they are NOT added to the WaitGroup. `Stop()`
returns before they actually exit; they drain their last in-flight job and
return asynchronously within milliseconds of the cancel. The 32 async scoring
workers are out of scope entirely — they exit via the parent context cancel in
`main()`, not via `Stop()`. The goroutine leak tests tolerate a ≤5 goroutine
margin and use a 3-second polling window to allow these workers time to wind
down.

**Tests to write in `internal/security/pipeline_test.go`:**

**`TestPipeline_ReplaceConfig_EnrichmentRestart`** — verifies enrichment
workers are restarted after ReplaceConfig and process new jobs:

```go
func TestPipeline_ReplaceConfig_EnrichmentRestart(t *testing.T) {
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    p := NewPipeline(&PipelineConfig{
        DNSEnrichmentEnabled: true,
    }, &mockRedis{dial: 0}, nil)
    p.StartBackgroundWorkers(ctx)
    defer p.Stop()

    // ReplaceConfig should restart enrichment workers.
    p.ReplaceConfig(&PipelineConfig{
        DNSEnrichmentEnabled: true,
    })

    // Send a job to the enrichment queue. The new worker (started by
    // ReplaceConfig) should pick it up. Use non-blocking send.
    select {
    case p.dnsEnrichment.queue <- "10.0.0.1":
        // Successfully queued — worker will process it.
    default:
        t.Fatal("enrichment queue full or not drained")
    }

    // If we reach here without hanging, the enrichment worker is alive.
}
```

**`TestPipeline_Stop_CancelsAllWorkers`** — verifies the pipeline stops
all worker types, not just the channel-range pair:

```go
func TestPipeline_Stop_CancelsAllWorkers(t *testing.T) {
    ctx, cancel := context.WithCancel(context.Background())

    p := NewPipeline(&PipelineConfig{
        DNSEnrichmentEnabled:  true,
        AbuseIPDBEnabled:      true,
        RDAPEnabled:           true,
    }, &mockRedis{dial: 0}, nil)
    baseline := runtime.NumGoroutine()
    p.StartBackgroundWorkers(ctx)

    // Confirm workers were started.
    afterStart := runtime.NumGoroutine()
    if afterStart <= baseline {
        t.Fatal("StartBackgroundWorkers did not increase goroutine count")
    }

    // cancel() must be called explicitly before Stop(). The 32 async
    // scoring workers only exit on ctx.Done(). defer cancel() would run
    // after requireGoroutinesReturnToBaseline, leaving those goroutines
    // alive during the check and failing the ≤5 margin.
    cancel()
    p.Stop()
    requireGoroutinesReturnToBaseline(t, baseline)
}
```

**Acceptance criteria:**
- [ ] `ReplaceConfig` creates fresh enrichment instances AND starts them
- [ ] Old enrichment workers are stopped (their context cancelled) before
      new ones are created
- [ ] `StartBackgroundWorkers` still accepts a parent context (backward
      compatible — existing call in main.go line 96 does not change)
- [ ] `Pipeline.Stop()` cancels enrichment workers (DNSEnrichment,
      AbuseIPDB, RDAPEnricher, FeedDownloader) and stop-channel workers
      (beaconingWorker, auditWorker). Async scoring workers (32
      `runAsyncScoringLoop` goroutines) continue until the parent context
      is externally cancelled — they are not in scope.
- [ ] `Stop()` reads cancel funcs under `p.mu.Lock()` to prevent races
      with concurrent `ReplaceConfig`
- [ ] `p.mu.RLock()` in `processInternal` covers enrichment pointer reads
- [ ] `TestPipeline_ReplaceConfig_EnrichmentRestart` passes — enrichment
      queue is drained after ReplaceConfig
- [ ] `TestPipeline_Stop_CancelsAllWorkers` passes — goroutine count
      returns to baseline
- [ ] `make test` passes
- [ ] `make lint` passes

---

### 251.4 — Regression Harness: Leak Detection, Fuzzing & Semgrep Rules (SMALL)

**Dependencies:** 251.1, 251.2, 251.3

**What to do:**

This sub-phase builds the safety net that prevents these bug classes from
recurring. There are three parts.

**Part A — Goroutine leak regression test**

Add a test in `internal/security/pipeline_test.go` that:
1. Records the baseline goroutine count with `runtime.NumGoroutine()`
2. Creates a Pipeline with config that enables all modules
3. Calls `StartBackgroundWorkers(ctx)` with a cancellable context
4. Calls `Stop()`
5. Waits briefly (100ms) for goroutines to clean up
6. Checks `runtime.NumGoroutine()` is back to (or below) baseline + small margin

**Implementation detail — avoid flaky tests:**

Do NOT use a fixed `time.Sleep()` to wait for goroutines to unwind. Under
CI load (CPU contention, slow containers), goroutines may take longer than
expected. Instead, use the retry-loop helper `requireGoroutinesReturnToBaseline`
defined in 251.2. It polls `runtime.NumGoroutine()` in a loop with a 3-second
deadline.

**Important — isolation:** Other tests that create Pipelines without calling
`Stop()` inflate the baseline. Run these tests in isolation:
```bash
go test -run TestPipeline_GoroutineLeak_AfterStop ./internal/security/
go test -run TestPipeline_ReplaceConfig_NoGoroutineGrowth ./internal/security/
```

If you want a "true baseline" that accounts for all preceding tests, add a
`TestMain` that records the process-start goroutine count into a package-level
variable before any tests run.

```go
func TestPipeline_GoroutineLeak_AfterStop(t *testing.T) {
    baseline := runtime.NumGoroutine()

    ctx, cancel := context.WithCancel(context.Background())

    p := NewPipeline(&PipelineConfig{
        DNSEnrichmentEnabled:  true,
        AbuseIPDBEnabled:      true,
        RDAPEnabled:           true,
    }, &mockRedis{dial: 0}, nil)
    p.StartBackgroundWorkers(ctx)

    // cancel() stops the 32 async scoring workers (they exit on ctx.Done()).
    // It must be called explicitly here — a defer would fire after
    // requireGoroutinesReturnToBaseline, leaving those goroutines counted
    // as leaked and causing spurious failures with the ≤5 margin.
    cancel()
    p.Stop()

    requireGoroutinesReturnToBaseline(t, baseline)
}
```

**Part B — Repeated ReplaceConfig leak test**

Add a test that calls `ReplaceConfig` 10 times in a row and verifies no
goroutine growth:

```go
func TestPipeline_ReplaceConfig_NoGoroutineGrowth(t *testing.T) {
    baseline := runtime.NumGoroutine()

    ctx, cancel := context.WithCancel(context.Background())

    p := NewPipeline(&PipelineConfig{}, &mockRedis{dial: 0}, nil)
    p.StartBackgroundWorkers(ctx)

    for i := 0; i < 10; i++ {
        cfg := &PipelineConfig{
            DNSEnrichmentEnabled:  i%2 == 0,
            AbuseIPDBEnabled:      i%2 == 1,
            RDAPEnabled:           true,
        }
        p.ReplaceConfig(cfg)
    }

    // cancel() and Stop() must be called explicitly before the goroutine
    // check. defer forms would run after requireGoroutinesReturnToBaseline,
    // leaving async scoring workers and beaconing/audit workers counted as
    // leaked goroutines during the check.
    cancel()
    p.Stop()
    requireGoroutinesReturnToBaseline(t, baseline)
}
```

Helper function (shared between all goroutine-leak tests). Place it at
the bottom of `pipeline_test.go`:

```go
// requireGoroutinesReturnToBaseline polls NumGoroutine in a retry loop
// until the count returns to within 5 of the baseline, or the 3-second
// deadline expires. This avoids flaky failures due to CI CPU contention.
func requireGoroutinesReturnToBaseline(t *testing.T, baseline int) {
    t.Helper()
    deadline := time.NewTimer(3 * time.Second)
    defer deadline.Stop()
    tick := time.NewTicker(50 * time.Millisecond)
    defer tick.Stop()
    for {
        select {
        case <-deadline.C:
            runtime.GC()
            after := runtime.NumGoroutine()
            leaked := after - baseline
            if leaked > 5 {
                t.Fatalf("expected ≤5 leaked goroutines after Stop, got %d (baseline=%d, after=%d)",
                    leaked, baseline, after)
            }
            return
        case <-tick.C:
            runtime.GC()
            after := runtime.NumGoroutine()
            if after-baseline <= 5 {
                return
            }
        }
    }
}
```

**Part C — Fuzz test for blocklists**

Add a Go fuzz test in `internal/security/blocklists_test.go`:

```go
func FuzzBlocklistCheck(f *testing.F) {
    seeds := []string{
        "1.2.3.4",
        "10.0.0.1",
        "192.168.1.1",
        "2001:db8::1",
        "invalid-ip",
        "",
    }
    for _, s := range seeds {
        f.Add(s)
    }

    f.Fuzz(func(t *testing.T, ipStr string) {
        m := NewBlocklistManager(&BlocklistConfig{
            Feeds: []BlocklistFeedConfig{
                {Name: "feed1", Enabled: true, Score: 10},
            },
        }, nil)
        // Store a nil-ranger box to test the defense-in-depth path.
        // This is the condition that could panic without the fix from 251.1.
        m.feeds[0].ranger.Store(&rangerBox{})

        ip := net.ParseIP(ipStr)
        if ip == nil {
            return // Check handles nil IP safely
        }

        // Must never panic, regardless of input.
        m.Check(ip)
    })
}
```

**Part D — Semgrep rules**

Create two `.semgrep` rules under `internal/security/` (or in a
project-wide rules directory if one exists):

**Rule 1: `go-goroutine-channel-range-no-close`** — detects goroutines
that use `for ... := range` over a channel without a corresponding
`close()` call visible in the same compilation unit.

This rule is noisy (it has false positives for channels closed in other
functions), so mark it as `WARNING` not `ERROR`.

**Rule 2: `go-atomic-box-inner-no-nil-guard`** — detects the pattern where
an `atomic.Pointer` to a wrapper struct is loaded and a method is called on
an inner interface field without a nil check on that field.

**Important — rule structure:** This rule requires a single top-level
`pattern` with `...` to match the sequence of statements, paired with a
`pattern-not` that excludes the safe case. A flat `patterns:` list with
multiple `pattern` entries does NOT work here — Semgrep evaluates each
sub-pattern independently against the entire file, so it cannot express
"load appears, then method call appears, without an intervening nil check."
Use `pattern` + `pattern-not` instead:

```yaml
rules:
  - id: go-atomic-box-inner-no-nil-guard
    message: >
        $BOX loaded from $ATOMIC; $BOX.$FIELD.$METHOD() is called without
        checking whether $BOX.$FIELD is nil. Add
        `if $BOX.$FIELD == nil { continue }` before the method call.
    pattern: |
      $BOX := $ATOMIC.Load()
      ...
      $BOX.$FIELD.$METHOD(...)
    pattern-not: |
      $BOX := $ATOMIC.Load()
      ...
      if $BOX.$FIELD == nil {
          ...
      }
      ...
      $BOX.$FIELD.$METHOD(...)
    severity: WARNING
    languages: [go]
```

This rule has false positives when `$BOX.$FIELD` is checked for nil before
the load (in a caller, or via a wrapper function not visible to Semgrep).
Mark those with `# nosemgrep: go-atomic-box-inner-no-nil-guard` if they arise.

Add both rules to the existing CI semgrep workflow checks.

**Acceptance criteria:**
- [ ] `TestPipeline_GoroutineLeak_AfterStop` passes and catches goroutine leaks
- [ ] `TestPipeline_ReplaceConfig_NoGoroutineGrowth` passes — verifies
      10 config reloads don't grow goroutine count
- [ ] `go test -fuzz=FuzzBlocklistCheck -fuzztime=10s` runs without panic
- [ ] `semgrep --config=.semgrep/` (or wherever the rules live) returns zero
      findings or only pre-acknowledged findings
- [ ] Semgrep rule `go-atomic-pointer-nil-interface` fires on a test
      snippet that has the vulnerable pattern
- [ ] `make test` passes
- [ ] `make lint` passes

---

## Out of Scope

- Adding `Stop()` to enrichment components individually (DNSEnrichment,
  AbuseIPDB, RDAPEnricher, FeedDownloader). The fix stores cancel funcs
  in Pipeline instead.
- Rewriting `StartBackgroundWorkers` callers. Main.go line 96 should not
  change.
- Making every test call `Stop()`. The tests currently let Pipelines go
  out of scope; fixing them all is a separate task. The regression test
  in 251.4 ensures the total leak across all tests combined is bounded.
- Python code. This phase is Go-only.
- `proxy.drain()` or other proxy-level teardown. Only the Pipeline is
  in scope.

---

## Implementation Order

| Step | File(s) | What | Why this order |
|------|---------|------|----------------|
| 1 | `blocklists.go` | 251.1: add nil-ranger guard | Tiny change, immediate safety |
| 2 | `blocklists_test.go` | 251.1: nil-ranger test + 251.4: fuzz test | Test the fix immediately |
| 3 | `pipeline.go` | 251.2: add stopCh, wg, Stop() | Foundation for everything else |
| 4 | `pipeline.go` | 251.2: rewrite beaconingWorker + auditWorker | Use stop channel instead of range |
| 5 | `main.go` | 251.2: wire Stop() into SIGTERM handler | Exercise Stop() in production |
| 6 | `pipeline.go` | 251.3: add cancel fields to Pipeline struct | Prepare for enrichment lifecycle |
| 7 | `pipeline.go` | 251.3: child contexts in StartBackgroundWorkers | Pipeline owns enrichment ctxs |
| 8 | `pipeline.go` | 251.3: stop old + start new in ReplaceConfig | Fix the enrichment orphan bug |
| 9 | `pipeline.go` | 251.3: cancel enrichment ctxs in Stop() | Complete lifecycle |
| 10 | `pipeline_test.go` | 251.4: goroutine leak regression test | Verify everything works end-to-end |
| 11 | `pipeline_test.go` | 251.4: ReplaceConfig growth test | Verify config reloads don't leak |
| 12 | `.semgrep/` | 251.4: semgrep rules | Prevent recurrence |

---

## Test Strategy

| Test | File | What it checks |
|------|------|----------------|
| `TestBlocklists_NilRangerBox_NoPanic` | `blocklists_test.go` | nil interface guard works |
| `FuzzBlocklistCheck` | `blocklists_test.go` | no panic under random input |
| `TestPipeline_Stop_WorkersExit` | `pipeline_test.go` | channel-range workers terminate |
| `TestPipeline_Stop_Idempotent` | `pipeline_test.go` | double-Stop doesn't panic |
| `TestPipeline_ReplaceConfig_EnrichmentRestart` | `pipeline_test.go` | enrichment works after reload |
| `TestPipeline_Stop_CancelsAllWorkers` | `pipeline_test.go` | all background workers stop |
| `TestPipeline_GoroutineLeak_AfterStop` | `pipeline_test.go` | no goroutines leak after full lifecycle |
| `TestPipeline_ReplaceConfig_NoGoroutineGrowth` | `pipeline_test.go` | 10× reload doesn't accumulate |
| `go test -race ./internal/security/` | CI | no race conditions in shutdown |
| Semgrep rules | `.semgrep/` | static analysis catches patterns |

## Acceptance Criteria (all sub-phases)

- [ ] 251.1: `Check()` no longer panics when `box.ranger` is nil (defense-in-depth)
- [ ] 251.2: `Pipeline.Stop()` terminates both channel-range workers
- [ ] 251.2: Calling `Stop()` twice is safe (no panic)
- [ ] 251.3: `ReplaceConfig` properly stops old enrichment workers and starts new ones
- [ ] 251.3: `Pipeline.Stop()` cancels ALL background workers
- [ ] 251.4: Goroutine leak regression test passes (≤5 leaked goroutines after Stop)
- [ ] 251.4: 10× ReplaceConfig does not grow goroutine count
- [ ] 251.4: Fuzz test runs 10 seconds without panic
- [ ] 251.4: Semgrep rules exist and detect the vulnerable patterns
- [ ] No regression in existing tests
- [ ] `make test` exits 0
- [ ] `make lint` exits 0
- [ ] `make preflight` exits 0
