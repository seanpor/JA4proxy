# Phase 520 — Aggressive Bug Hunt: Go Proxy (Red-Team Pass)

> **For the implementing engineer:** this document is written to be actionable
> with **no prior knowledge of this codebase**. Every finding lists the exact
> file, the exact code, why it's wrong, the exact change to make, and the exact
> test to add. Read the "How to work this phase" section first. Do the findings
> in order. Ask before deviating.

## Status: OPEN

## Summary

A second, deliberately adversarial pass over the **remotely-reachable** Go proxy
(everything an unauthenticated internet client can drive). Phase 519 already
fuzzed the byte parsers to convergence (zero crashers) and fixed a pooled-buffer
aliasing bug (`JA4PROXY-2026-0092`). This pass thinks like an attacker who has
**read the source** and asks: "what does the proxy *stop* doing under stress, and
which security checks are not where I'd assume?"

It found **one real fail-open bypass** (`JA4PROXY-2026-0094`): the operator manual
ban and the Spamhaus blocklist — two *hard* blocks — are evaluated only on the
**async** scoring path, so when the scoring queue saturates under flood, a banned
or Spamhaus-listed IP is allowed through and forwarded to the backend.

Nothing else in the reviewed surface was exploitable; the "areas reviewed clean"
section records what was checked so this pass isn't silently repeated.

---

## How to work this phase (read first)

1. **Toolchain.** Go is required. `snap`-installed Go needs
   `export GOROOT=/snap/go/current` or `go build`/`go test` break (this repo's
   gotcha). Verify with `GOROOT=/snap/go/current go version`.
2. **Where the code is.** The proxy is Go only: entry point
   `cmd/ja4pd/main.go`; the security pipeline is `internal/security/pipeline.go`.
   There is no Python proxy.
3. **How to run the Go tests.** `GOROOT=/snap/go/current go test ./... -count=1`
   (native, no Docker). Race detector: `make test-race`.
4. **The golden rule of this codebase — the core asymmetry.** A blocked real user
   is far worse than a missed bad bot, so the proxy *fails open* by design. BUT
   "fail open on *scoring*" is not the same as "fail open on an operator's
   explicit *ban*." Finding 0094 is exactly that distinction. When you fix it,
   do **not** make the proxy start dropping legitimate traffic under load — read
   the fix note carefully.
5. **Definition of done.** Each finding is done when: the code change is made,
   the specified regression test is added **and fails if your fix is reverted**
   (verify this by reverting your own change and re-running), `go test ./...` and
   `make test-race` are green, and the finding's `status` in
   `docs/security/findings.yaml` is set to `FIXED` with `regression_test`
   populated. Run `python3 scripts/findings_register.py validate` (must exit 0).

---

## Finding 1 — `JA4PROXY-2026-0094` (MEDIUM): hard blocks bypassed under scoring-queue saturation

### What's wrong

`internal/security/pipeline.go`, function `Process` (the per-connection entry
point). In the default **async** mode it does, in order:

```go
func (p *Pipeline) Process(ctx, conn) *PipelineResult {
    if conn.JA4 != "" { if res, hit := p.cache.Get(decisionCacheKey(conn.ClientIP, conn.JA4)); hit { return res } }
    if block, reason := p.checkHardBlocks(conn); block {           // (A) synchronous hard blocks
        return &PipelineResult{Action: "block", Score: 100, BypassReason: reason}
    }
    if p.Sync { return p.processInternal(ctx, conn) }
    select {
    case p.workChan <- conn:                                       // (B) enqueue for async scoring
    default:
        metrics.WorkChanDroppedTotal.Inc()                         // (C) queue full → drop
    }
    return &PipelineResult{Action: "allow", Score: 0}              // (D) …and ALLOW
}
```

`checkHardBlocks` (A) checks the **JA4 blacklist, JA4X blacklist, country
blacklist, and dynamic CIDR blocklist**. But two other *hard* blocks live only
inside `processInternal` (the async path, B):

- the **operator manual ban**: `if p.redis.Exists(ctx, "ban:"+conn.ClientIP)` → block;
- the **Spamhaus DROP/EDROP blocklist**: `p.blocklists.Check(conn.ParsedIP)` → hard block.

So when `workChan` is full (it has a 20000 buffer drained by 32 workers), the
`select` hits `default` (C), the connection is **not scored**, and `Process`
returns `allow` (D). Back in `cmd/ja4pd/main.go` `handleConn`, `action == "allow"`
means `p.forward(...)` — the connection is proxied to the backend. A client on a
`ban:{ip}` list or in a Spamhaus DROP netblock **gets through**.

### Why it matters (attacker's view)

An attacker sustains enough connection volume to keep the queue saturated (32
workers × per-connection scoring latency is the drain rate; exceeding it fills
the buffer). While saturated, *their own* banned/blocklisted IP is forwarded.
These are the two blocks an operator most expects to be absolute — "I banned that
IP" and "Spamhaus says this is a hijacked netblock." Fail-open scoring is
intended; fail-open on an explicit ban is not.

### The fix (junior: do exactly this)

Move the manual-ban and blocklist **hard-block** checks into the synchronous path
so they run *before* the async enqueue, exactly like the other hard blocks.

1. In `internal/security/pipeline.go`, add these checks to `Process` (or to a
   helper called from `Process`) **after** `checkHardBlocks` and **before** the
   `p.Sync` branch — so they run on every connection regardless of async/sync:
   - manual ban: `if p.redis != nil && conn.ClientIP != "" && p.redis.Exists(ctx, "ban:"+conn.ClientIP) { return block, reason "manual_ban" }`
   - blocklist: `if _, hard := p.blocklists.Check(conn.ParsedIP); hard { return block, reason "blocklist" }`
2. **Avoid double evaluation.** `processInternal` also runs these. Two options,
   pick one and note it in the PR:
   - (preferred) keep them in `Process` only for the **hard-block** decision, and
     have `processInternal` reuse the already-computed blocklist signals. Note
     `JA4PROXY-2026-0037` already made `blocklists.Check` a single-call site
     inside `processInternal` — be careful not to reintroduce the double-check
     TOCTOU it fixed. The safest shape: compute `blSigs, blHard := p.blocklists.Check(...)`
     once in `Process`, act on `blHard` synchronously, and pass `blSigs` into the
     async job so scoring still sees the soft signal.
   - (simpler, acceptable) leave `processInternal` as is and accept that
     blocklist/ban are checked twice — once synchronously (authoritative) and once
     async (harmless, same result). Redis `Exists` is O(1); `blocklists.Check` is
     an in-process trie lookup. The cost is negligible and there is no correctness
     risk because both reads are point-in-time and a banned IP stays banned.
   The simpler option is recommended for a first implementation.
3. **Do not change the fail-open behaviour for *scoring*.** A connection that is
   not on a hard block must still return `allow` when the queue is full — that is
   correct and must not change. You are only adding the two hard-block checks to
   the synchronous path.

### The test (junior: add this — it is the acceptance criterion)

Add `internal/security/pipeline_saturation_hardblock_test.go`:

- Build a pipeline in **async** mode (do **not** set `p.Sync = true`) with a
  `mockRedis` whose `Exists("ban:9.9.9.9")` returns true (see
  `pipeline_manual_ban_test.go` for the `banRedis` pattern to copy).
- **Fill `workChan`** so the next `Process` hits the `default` drop: the channel
  is unexported but the test is in `package security`, so
  `for i := 0; i < cap(p.workChan); i++ { p.workChan <- &ConnectionContext{} }`.
- Call `res := p.Process(ctx, &ConnectionContext{ClientIP: "9.9.9.9", ParsedIP: net.ParseIP("9.9.9.9")})`.
- Assert `res.Action == "block"` (before the fix it is `"allow"`).
- Add a second case with a Spamhaus-style blocklist feed matching the IP (copy
  the feed setup from `pentest_blocklist_single_check_regression_test.go`) and
  assert the saturated `Process` still blocks it.
- **Verify revert-sensitivity:** temporarily undo your `Process` change and
  confirm this test fails (`action == "allow"`), then restore.

### Acceptance criteria for Finding 1
- [ ] `ban:{ip}` and Spamhaus blocklist are enforced even when `workChan` is full.
- [ ] Non-hard-block traffic still returns `allow` under saturation (fail-open for
      scoring preserved) — add/keep a test asserting this.
- [ ] `pipeline_saturation_hardblock_test.go` passes and fails on revert.
- [ ] No reintroduction of the `JA4PROXY-2026-0037` double-check TOCTOU (single
      authoritative `blocklists.Check` result per connection).
- [ ] `go test ./...` + `make test-race` green; `findings.yaml` 0094 → FIXED.

---

## Areas reviewed and found clean (do not re-hunt without new information)

- **ClientHello / JA4 parser** (`internal/tls/parser.go`, `ja4.go`): fuzzed to
  convergence in Phase 519 (`FuzzParseClientHello` 10.7M execs, plus
  `FuzzClientHello`, `FuzzFragmentation`, `FuzzProtocolSmuggling`,
  `FuzzReadProxyProtocol[V2]`) — **zero crashers**. Re-run:
  `GOROOT=/snap/go/current go test ./internal/tls/ -run '^$' -fuzz FuzzParseClientHello -fuzztime 60s`.
- **Attacker-controlled allocations**: every `make([]byte, n)` / `append` driven
  by a length field is capped — TLS record ≤ 16384, reassembly ≤ 65536. No
  amplification found.
- **Pooled-buffer aliasing**: SNI/ALPN escape fixed in Phase 519 (0092); the rule
  "clone any parsed value before it escapes the synchronous parse frame" is
  documented on `populateTLSFingerprints`.
- **Connection accounting**: `acceptSem` acquire (`admitConn`) / release
  (handler `defer <-p.acceptSem`) and `activeConns` inc/dec are symmetric; no
  leak or double-release found.
- **PROXY-protocol spoof/smuggle**: header always stripped; chained-header
  smuggling closes the connection (0001/0002). Fuzzed clean.

---

## Critical review of this phase doc (self-audit)

**Is it suitable for a junior with little codebase knowledge?** Mostly yes: the
one finding has exact file/function, the buggy code inline, a step-by-step fix
with a recommended (simpler) option, a concrete test with the exact pattern files
to copy, and a revert-check. Gaps a junior may hit, addressed here:
- *"How do I fill an unexported channel from a test?"* — the test is in
  `package security` (same package), so `p.workChan` is accessible. Stated above.
- *"Won't adding a synchronous Redis `Exists` on every connection add hot-path
  latency?"* — `Exists` is already called per-connection in `processInternal`;
  moving/duplicating it does not add a *new* round trip in the common path, and
  it fails open (returns false) on Redis error, so it cannot start blocking real
  users during a Redis outage. Note this in the PR.
- *"What if `p.redis` is nil (unit tests)?"* — guard with `p.redis != nil`, as the
  existing `processInternal` check does.

**Did the requester miss anything? / other similar bugs elsewhere?**
- **Same class, check next:** any *hard* security decision that lives only in
  `processInternal` shares this fail-open-under-saturation risk. Audit
  `processInternal` for other early `return block/ban` paths that are not also in
  `checkHardBlocks` — e.g. the **auto-escalation ban** (Phase 248) and the
  **datacenter policy** block also return terminal actions from the async path.
  Decide per-control whether it must be synchronous. Document the decision.
- **Related knob:** `workChan` capacity (20000) and `asyncScoringWorkers` (32) set
  how easily the queue saturates. Consider a metric alert on
  `WorkChanDroppedTotal > 0` so operators *see* the fail-open happening. (Doc/PR
  note, not code for this phase.)
- **Not in scope but worth a ticket:** the `cmd/ja4pd` `TestClientHelloFragmentation`
  / `TestForward_ConfigLocalCapture` `-race` fragility was fixed in Phase 518; if
  that PR is not yet merged when you start, rebase onto it so `make test-race` is
  green.

---

## Out of scope
- Implementation of the fix (this phase documents; a separate implementation PR
  makes the change).
- The management API / infrastructure — that is **Phase 521**.
