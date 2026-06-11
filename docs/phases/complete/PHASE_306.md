---
phase: 306
title: Take Over PR #95 — Land the Go Performance Wins Without the Regressions
status: COMPLETE
size: MEDIUM
created: 2026-06-10
completed: 2026-06-10
audience: [developer, security]
---

# Take Over PR #95 — Land the Performance Wins Without the Regressions

> **Outcome (as executed).** Implemented on `phase-306-pr95-takeover`, branched
> from `main` (so PR #95's regressions were never inherited — we re-added only
> the good parts). Two things turned out to be *worse* than the plan assumed,
> and one *better*:
>
> - **`docs/ATTACK_MAPPING.md` was stale on `main`, not just mangled by PR #95.**
>   The Python prototype files (`src/security/*.py`) were removed in v2.0.0, so
>   the doc's prototype rows pointed at files that no longer exist — and the
>   CI-gate test (`tests/test_attack_mapping.py`) was *already failing on main*
>   (it still pointed at the moved `docs/for-architects/` path **and** would then
>   have failed on the dead source paths). PR #95's blind `*.py → *.go` sed was a
>   clumsy attempt to paper over this and created self-contradictions. The honest
>   fix: drop the retired-prototype rows entirely and point the two genuine
>   rate-tracker rows at the real Go module (`internal/security/rate_limiter.go`).
>   The gate now passes for the first time.
> - **The `>10,000 CPS/core` claim lived in *new* files** the PR adds
>   (`docs/BENCHMARKING_GUIDE.md`, `docs/phases/complete/PHASE_161.md`). Simplest
>   correct action: don't import those two marketing docs at all. The honest
>   hyperbole tone-downs the PR made to *existing* docs (Elite→Verified/High,
>   "beast/traffic jam"→"highly optimized/bottleneck") were applied.
> - **The forward-path fix is a regression test now.**
>   `TestForward_IdleConnectionIsReaped` proves an idle client+backend pair is
>   torn down at `read_timeout`; it would hang (and fail) if the deadlines are
>   ever removed again.

> **One-line summary for the junior engineer picking this up:** an external
> contributor's PR (#95, "unleash Go performance") contains several *genuinely
> good* speed improvements, but it also quietly removes a security control,
> corrupts a compliance document, and over-states our benchmark numbers. We are
> going to **keep every good part, fix every bad part, and prove it with tests**
> — then land it through a clean PR. We are not going to merge it as-is, and we
> are not going to throw the good work away either.

## 0. Background — why this phase exists (read this first)

A pull request is a *proposal*, not a fact. Someone (here, a mix of the original
author and an AI coding assistant) changed 28 files across the Go proxy, the
docs, and some scripts. The headline — "make the proxy faster" — is something we
genuinely want. JA4proxy sits in front of real traffic; throughput matters.

But "faster" is never the only goal. This project has four goals **at the same
time**, and they sometimes pull against each other:

1. **Secure** — we are a security proxy. A speed-up that removes a defence is a
   net loss, not a win.
2. **Fast** — lower latency and higher connections-per-second (CPS) are real
   features for our users.
3. **Flexible in config** — operators tune us through `config/build.yml`
   (timeouts, buffer sizes, pool sizes). A change that *ignores* a config knob
   silently takes that flexibility away.
4. **Not reckless** — we don't ship unproven claims, we don't break the audit
   trail, and we don't merge anything we can't defend in code review.

The skill this phase teaches is **separating the wheat from the chaff in someone
else's change**. You will learn to read a diff critically: praise what's right,
refuse what's wrong, and — crucially — be able to *say why* for each line. That
last part is the whole job. "I don't like it" is not a review; "this removes the
idle-connection timeout, here is the exact line, here is the attack it re-opens"
is a review.

> **The core asymmetry (from `CLAUDE.md`, applies here too):** a missed bad
> request is cheap and recoverable; a self-inflicted vulnerability or a blocked
> real user is expensive. When a perf change trades away safety, the safety wins.

## 1. Goal

Produce a **clean branch** that:
- preserves all of PR #95's legitimate performance improvements,
- restores the security control it removed,
- repairs the document it corrupted,
- corrects the over-stated benchmark claim,
- and passes the full required-check gate (Meta-Validation, Full Lint, Full
  Test, Security Scan) on a current rebase.

Then close PR #95 in favour of our branch (with a courteous review comment
explaining what we kept and what we changed and why), and land ours by PR.

## 2. The verdict, item by item

This is the heart of the phase. Each item says **what the PR did**, **is it good
or bad**, and **what we do about it**. Read every row — the point is to learn the
reasoning, not just the conclusion.

### 🟢 KEEP — the genuinely good parts

These are real improvements. We keep them, ideally byte-for-byte.

| Change | File | Why it's good |
|---|---|---|
| `io.CopyBuffer` + `sync.Pool` 32 KB buffer reuse in `forward()` | `cmd/ja4pd/main.go` | The old copy loop did `make([]byte, BufferSize)` **per connection** — that's garbage-collector pressure at scale. Reusing a pooled buffer is a textbook Go optimisation. The new code also keeps the **JA4PROXY-2026-0009 invariant** (both copy goroutines finish before `forward()` returns) via `sync.WaitGroup` + closing both conns — so no goroutine/buffer leak. |
| Redis pool tuning: `PoolSize: 100`, `MinIdleConns: 10` | `internal/redis/client.go` | Under load, a tiny connection pool serialises Redis calls and adds latency. Pre-warming idle connections removes cold-start stalls on the hot path. Sensible, conservative numbers. |
| Async scoring: 1 → 32 scoring workers; `workChan` 10 000 → 20 000 | `internal/security/pipeline.go` | A single scoring goroutine is a throughput bottleneck on a multi-core box. Fan-out to 32 workers with a deeper queue lets scoring keep up with accepts. (We should *sanity-check* 32 is bounded sensibly — see §3 task 3.) |
| Backend port `443 → 8443` | `cmd/ja4p/main.go`, `scripts/start-poc.sh` | Correct bug fix. Our POC backend listens on **8443** (443 is HAProxy). This matches reality and matches the project memory note about the integration-test port. |
| Tarpit logging: f-string → lazy `%s` | `src/tarpit/tarpit-server.py` | Lazy logging means the string is only formatted if the log level is active. Tiny, correct, idiomatic. |
| Toning down marketing language ("Elite/beast" → "High/Verified") in some docs | various docs | We *want* sober, defensible language. This part is an improvement. |
| Test path fix: `docs/for-architects/ATTACK_MAPPING.md` → `docs/ATTACK_MAPPING.md` | `tests/test_attack_mapping.py` | **This is a real fix and we MUST keep it.** The doc was moved to `docs/` earlier but the CI-gate test still pointed at the old path. The test is *currently failing on `main`* with `FileNotFoundError` (verified). PR #95 inadvertently repairs it. See §2.1 below — this finding is important. |

### 🔴 FIX — the parts that must not ship as written

| Change | File | Why it's a problem | What we do |
|---|---|---|---|
| **Removes the per-read idle timeout from the forward path** | `cmd/ja4pd/main.go` `forward()` | The old loop called `SetReadDeadline(ReadTimeout)` before every read and `SetWriteDeadline(WriteTimeout)` before every write. That is our **idle-connection reaper**. `io.CopyBuffer` sets **no deadlines at all** — so once a connection is established, `proxy.read_timeout` / `write_timeout` are silently *unenforced*. A slowloris / idle-hold client now ties up a goroutine **and a pooled 32 KB buffer forever**. This is both a resource-exhaustion vector and a config knob that no longer does anything. **This is the most important fix in the phase.** | Restore the deadlines **inside** the new pooled-buffer copy (see §3 task 1). We keep the buffer-pool win *and* the timeouts — they are not in conflict. |
| **Corrupts `docs/ATTACK_MAPPING.md`** | `docs/ATTACK_MAPPING.md` | A blind `src/security/*.py → internal/security/*.go` find-replace was run over a doc that *deliberately* lists both the Go module and its Python prototype. Result: rows literally read "Python prototype … `internal/security/tcp_analyzer.go`" (self-contradictory); reverse-map rows have duplicate Go paths (`asn_classifier.go, asn_classifier.go`); and it references a `tests/test_attack_mapping.go` that does not exist (the test is `.py`). This is a security/compliance artefact — it must be accurate. | Revert the doc *content* to its correct form (keep the original Go-plus-Python references), while **keeping** the test-path fix from the KEEP list. See §3 task 2. |
| **`> 10,000 CPS per core` unsubstantiated claim** | `docs/BENCHMARKING_GUIDE.md` | This number is extrapolated, not measured. Our verified host-native figure is ~3,500 CPS; the same doc honestly reports ~2,600 CPS in Docker with `network_mode: host`. Shipping a 10k claim we can't reproduce is exactly the "reckless" we're avoiding — and it contradicts the PR's *own* "Verified" language elsewhere. | Replace with the measured numbers and label them as measured, with the test command that produces them. See §3 task 4. |

### 🟠 RECONSIDER — defensible, but not as a silent drive-by

| Change | File | The tension | Decision |
|---|---|---|---|
| `"proxy: connection decision"` log demoted **Info → Debug** | `cmd/ja4pd/main.go` | This is the per-connection allow/block/score line. At very high CPS, logging every decision at Info *is* a real cost. But that line is **audit-relevant** — demoting it to Debug means decisions vanish from default logs and SIEM. Slipping that into a perf PR unannounced is the problem, not the idea itself. | **Keep it at Info for now** (preserve the audit trail; that's the conservative, security-first default). If decision-log volume is a measured bottleneck, address it deliberately in its own change — e.g. sampling, or a config toggle — so operators *opt in* to less logging rather than losing it silently. Flexibility = a knob, not a hardcode. |

## 2.1 A real bug we found while reviewing — the broken ATT&CK test

While checking PR #95 we ran `tests/test_attack_mapping.py` and it **fails on
`main`** today:

```
FileNotFoundError: .../docs/for-architects/ATTACK_MAPPING.md
```

The mapping doc was relocated to `docs/ATTACK_MAPPING.md` in an earlier phase,
but this CI-gate test was never updated. PR #95's path change is the correct fix.
**Lesson:** a good review doesn't just judge the diff — it runs the affected
tests and sometimes uncovers latent breakage the diff happens to touch. Note
this in the PHASE notes; it explains *why* we keep the test-path change even
though most of the doc change is a revert.

> If `tests/test_attack_mapping.py` is not currently in a required CI check,
> flag that separately — a CI gate that can silently fail is itself a gap.

## 3. The work, step by step

> Branch: `git checkout main && git pull && git checkout -b phase-306-pr95-takeover`
> Remember the project memory note: **never background a branch-mutating git
> command**, and there is unrelated Go WIP that lives in a stash — do not disturb
> other people's stashes.

### Task 1 — Restore the forward-path idle timeout (the security fix) 🔴

Goal: keep the pooled-buffer speed-up **and** re-enforce `read_timeout` /
`write_timeout` during forwarding. These do not conflict — the deadline is a
syscall on the connection; the buffer is just memory we copy through.

Replace the PR's deadline-free `cp` closure with a copy loop that (a) borrows a
buffer from `bufferPool`, and (b) refreshes the read/write deadline each
iteration — i.e. the *old* reaper logic, but using the pooled buffer:

```go
cp := func(dst, src net.Conn) {
    defer wg.Done()
    bp := bufferPool.Get().(*[]byte)
    defer bufferPool.Put(bp)
    buf := *bp
    for {
        // Idle-connection reaper: enforce the configured read timeout on every
        // read so a stalled/slowloris client cannot pin a goroutine + buffer.
        _ = src.SetReadDeadline(time.Now().Add(time.Duration(p.cfg.Proxy.ReadTimeout) * time.Second))
        n, rerr := src.Read(buf)
        if n > 0 {
            _ = dst.SetWriteDeadline(time.Now().Add(time.Duration(p.cfg.Proxy.WriteTimeout) * time.Second))
            if _, werr := dst.Write(buf[:n]); werr != nil {
                break
            }
        }
        if rerr != nil {
            break
        }
    }
    // JA4PROXY-2026-0009: closing both ends unblocks the peer goroutine's Read
    // promptly so forward() can return without a lingering goroutine/buffer.
    _ = dst.Close()
    _ = src.Close()
}
```

> **Why not keep `io.CopyBuffer` and add a watchdog timer?** You *could* — a
> separate `time.AfterFunc` that closes idle conns. But it's more moving parts
> for the same outcome, and the per-read deadline is the pattern already proven
> in this codebase. Prefer the simplest change that restores the guarantee.
> (If a future phase shows the per-read `SetReadDeadline` syscall is itself a
> measurable bottleneck, *that's* the time to consider a coarser idle watchdog —
> with a benchmark to justify it.)

Keep the rest of the PR's `forward()` clean-ups (the `sync.WaitGroup`, the tidy
forensic-trace block, the `t3/t6` timing). Only the copy body changes.

**Acceptance:** an integration/chaos test proves an idle client connection is
closed after ~`read_timeout` seconds (see §4).

### Task 2 — Repair `docs/ATTACK_MAPPING.md` (the compliance fix) 🔴

Take the doc **content** from `main` (the correct version, which lists each Go
module *and* its Python prototype), and apply **only** the legitimate path fix to
the test:

1. `git checkout main -- docs/ATTACK_MAPPING.md` to restore the correct content.
2. Keep PR #95's `tests/test_attack_mapping.py` path change
   (`docs/for-architects/…` → `docs/…`).
3. Run `python3 -m pytest tests/test_attack_mapping.py -o addopts="" -q` and
   confirm it now **passes** (it fails on `main` today — see §2.1).
4. Sanity-read the doc: no row should say "Python prototype" next to a `.go`
   path; no reverse-map cell should list the same file twice; no reference to a
   non-existent `.go` test.

### Task 3 — Keep the perf wins, with a sanity check 🟢

- `internal/redis/client.go`: keep `PoolSize: 100`, `MinIdleConns: 10`.
- `internal/security/pipeline.go`: keep the 32 scoring workers and
  `workChan` 20 000. **Sanity-check:** confirm 32 is a fixed, bounded fan-out
  (it is — a literal `for i := 0; i < 32; i++`), not something that scales with
  request volume. A fixed worker pool is correct; an unbounded one would be the
  reckless version. If you want it *flexible*, consider sourcing the count from
  config with a safe default — optional, not required for this phase.
- `cmd/ja4p/main.go`, `scripts/start-poc.sh`: keep the `443 → 8443` fix.
- `src/tarpit/tarpit-server.py`: keep lazy logging.
- Keep the buffer-pool reuse in `forward()` (now combined with Task 1's
  deadlines).

### Task 4 — Honest benchmark numbers 🔴→🟢

In `docs/BENCHMARKING_GUIDE.md` (and `docs/phases/complete/PHASE_161.md` if it
carries the same line):
- Remove `> 10,000 CPS per core in a distributed production environment`.
- State the **measured** figures with the command that produced them, e.g.
  "~3,500 CPS host-native; ~2,600 CPS in Docker with `network_mode: host`
  (measured via `./bin/ja4p test benchmark …`)". If a higher number is ever
  wanted, it must come with a reproducible run, not an extrapolation.
- Keep the PR's honest down-grading of hyperbole elsewhere.

### Task 5 — Decide on the decision-log level 🟠

Revert `"proxy: connection decision"` back to **`.Info`** (preserve the audit
trail). If you believe high-CPS decision logging is worth optimising, write a
one-paragraph follow-up note proposing a *config-driven* sampling/toggle so
operators opt in — do not hardcode the loss of visibility here.

## 4. Tests (this is how we prove "not reckless")

Add/keep tests so the regressions can never silently come back:

1. **Idle-timeout regression test (Go).** A test that opens a client→proxy
   connection, completes forwarding, then goes idle, and asserts the connection
   is torn down within roughly `read_timeout`. This is the test that would have
   caught the PR's removal. Put it alongside the existing proxy/forward tests in
   `cmd/ja4pd/` or `internal/security/` (match where forward-path tests already
   live).
2. **ATT&CK mapping gate green.** `tests/test_attack_mapping.py` passes against
   the repaired `docs/ATTACK_MAPPING.md`.
3. **No new Go test regressions.** `GOROOT=/snap/go/current go test ./...`
   stays green (remember the snap-Go GOROOT note).
4. **Full suite.** `make test` green; `make lint-phases` clean.

## 5. Acceptance Criteria

1. Forward path uses the pooled buffer **and** re-enforces `read_timeout` /
   `write_timeout`; a regression test proves idle connections are reaped.
2. `docs/ATTACK_MAPPING.md` content is correct (Go + Python references intact,
   no duplicates, no phantom `.go` test) **and** `tests/test_attack_mapping.py`
   passes (it currently fails on `main`).
3. Redis pool tuning, 32 scoring workers / 20 000 queue, `443→8443`, and lazy
   tarpit logging are all preserved.
4. `BENCHMARKING_GUIDE.md` states measured numbers only; the `>10,000 CPS`
   claim is gone.
5. The connection-decision log is back at Info (or a config-driven toggle is
   added with a safe default of "log at Info").
6. `make test` and `make lint-phases` pass; branch rebased so the four required
   checks run green; landed via PR; PR #95 closed with a review comment crediting
   the kept work and explaining the changes.

## 6. Out of Scope (follow-ups, don't scope-creep this phase)

- Making the scoring-worker count and Redis pool sizes config-driven (nice
  flexibility, but the fixed defaults are safe — separate phase if wanted).
- A measured re-benchmark to establish a *defensible* high-CPS headline number.
- Confirming `tests/test_attack_mapping.py` is wired into a **required** CI
  check (if it isn't, a gate that can silently fail is its own gap — track it).
- The carried-over items from earlier phases: `python-jose → PyJWT`
  ([[PHASE_304]]), and deleting/rewriting the dead
  `management/tests/test_phase_122_security_review.py` ([[PHASE_305]]).

> **The takeaway for next time you review a big PR:** read it as four questions,
> not one. *Is it secure? Is it actually faster? Does it keep our config knobs
> working? Is any claim or removal reckless?* Praise generously, refuse
> precisely, and make every "no" come with a line number and a reason.
