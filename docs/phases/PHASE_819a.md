---
phase: 819a
title: "Benchmark truthfulness — the throughput and false-positive numbers are both constants"
status: PROPOSED
size: MEDIUM
created: 2026-08-13
audience: [developer, operations]
---

# Benchmark truthfulness

> **STATUS: PROPOSED — plan for review. No code until approved.**
>
> Revision 2, after expert review. Three reviewers audited revision 1; the
> central finding was confirmed and strengthened, two of my claims were wrong
> in a dangerous direction, and two findings of equal severity were missed.
> Corrections are marked **[rev2]**. See "What review changed" at the end.
>
> Split from the original single phase on the unanimous recommendation of all
> three reviewers. **819a is the half that changes a published number and the
> half that is dangerous to leave.** The bit-rot half is [PHASE_819b](PHASE_819b.md).

## Goal (plain language)

Two numbers this project publishes are not measurements. They are constants
that the harness prints regardless of how the proxy behaves:

- **Throughput** — `bench-macro` reports ~96 conn/s because the load generator
  is configured to offer ~96 conn/s. Nothing about the proxy enters into it.
- **False-positive rate** — `benchmarks.md`'s "False positives: 0%" is
  structurally unreachable code. No production path can make it non-zero.

Fix both, make the harness incapable of silently printing a constant again,
and remove the container-destroying authority that `make bench-all` currently
carries. Then re-measure honestly.

### The headline

**There is no evidence that JA4proxy has lost performance.** There is strong
evidence that we have not been measuring it. Once the harness is honest we
will have a real ceiling to compare against the last known-good real number
(3,263 conn/s host-native, 2026-06-10, SHA `76504c8`, `benchmarks.md:38`).

---

## F1 — `bench-macro` measures the load generator, not the proxy — CRITICAL

### Mechanism

`internal/test/bench/ja4bench.go:279-291`:

```go
func runProfile(ctx context.Context, host string, isGood bool, rate, workers int, res *BenchResult) error {
	ratePerWorker := rate / workers          // 100 / 8 = 12
	...
		ticker := time.NewTicker(time.Second / time.Duration(ratePerWorker))  // 83.333ms
```

Defaults (`ja4bench.go:199,202`) are `--good-rate 100`, `--workers 8`. Integer
division gives 12 conn/s/worker; 8 × 12 = **96.000 conn/s offered**.
`Makefile:1209` passes neither flag (`$(ARGS)` is never assigned; it is only
documented in help text at `Makefile:231`), and `nightly-benchmark.yml:57`
inlines the same bare invocation.

Go's `Ticker` does not coalesce or catch up — it drops ticks for slow
receivers (`time/tick.go:24,41`), channel capacity 1 — and the dial is
**synchronous inside the tick handler** (`ja4bench.go:308-318`). So each
worker's rate is `1 / max(tickPeriod, latency)`: a pure closed loop.

### Proof

**[rev2 — lead with this; it is the strongest single line of evidence.]** From
the live CI artefact (`nightly-benchmark-latest/result.json`):

```json
"total_good": 2873, "errors": 0, "duration_total": 30005493030,
"throughput_cps": 95.74913490431655,
"avg_latency_ms": 12.498433693003829, "p95_latency_ms": 15.605
```

`8 workers × floor(30s / 83.333ms) = 8 × 360 = 2880` predicted; **2873
measured** — 0.24% short from tail truncation. No capacity model predicts an
integer that close to `workers × ticks`.

**Little's Law kills every capacity explanation.** 96 CPS × 12.498 ms =
**1.2 connections in flight** out of 8 available workers. A saturated system
would report `8 / 0.0125 = 640` CPS.

**[rev2 — corrected phrasing.]** My i9-9900K measures 95.73 and the CI runner
95.749. Those do *not* agree "to two decimal places" — they agree to **0.02%**.
And the decisive detail is the *decoupling*: mean latency differs 2× between
the two machines (6.26 ms vs 12.498 ms) while throughput agrees to 0.02%.
Throughput that ignores a 2× latency difference is not measuring the system.

Alternative explanations, and why each fails:

| Alternative | Survives? |
|---|---|
| docker-proxy bridge serialises at ~96 | **No.** `benchmarks.md:91` records ~600 CPS through that same bridge port. 96 is 6× below. |
| Redis/backend capacity limit | **No.** `errors: 0`, and Little's Law gives 1.2 in-flight of 8. A capacity limit shows queueing. |
| Proxy rate limit (`config/proxy.yml:94 max_requests_per_minute: 100`) | **No.** That is 1.67/s, and `good_blocked: 0`. |
| Coincidence across two machines | **No.** They are not equal — see the latency decoupling above. |

### Blind zone

**[rev2 — host-specific, and throughput-only.]** Break-even is
`tickPeriod / latency`: **13.3×** on my i9 (83.333 / 6.26), but only **6.7×**
on the CI runner (83.333 / 12.498). Below that, a slower proxy changes nothing
in the reported throughput.

**[rev2 — do not overreach.]** F1 invalidates the **throughput** number only.
`avg/p50/p95/p99_latency_ms` in the same output are genuine measurements — of
an essentially unloaded path at ~0.6 offered concurrency. The correct
description is "an unloaded-latency measurement mislabelled as capacity", not
"not a measurement of the proxy".

**[rev2 — correct the duty-cycle claim.]** 92.5% is the *generator's per-worker*
idle fraction, not proxy utilisation. Offered concurrency is 8 × 0.075 = **0.6
connections** on a 16-thread host; the proxy is far more idle than 92.5%.

### Second-order bug

`ratePerWorker == 0` collapses to 1 (`ja4bench.go:281-283`), so any `rate <
workers` silently offers `workers` conn/s. **[rev2 — a live instance I missed:]**
`Makefile:1642 loadtest` defaults `GOOD_RATE=10 WORKERS=16` → `10/16 = 0 → 1` →
offers **16/s when 10 was requested**; `BAD_RATE=190/16=11` → offers 176/s when
190 was requested. Same fix, needs its own test.

**[rev2 — deadline gap.]** `net.Dialer{Timeout: 2s}` (`ja4bench.go:310`) bounds
dial+handshake only. `io.Copy` at `:313` has no deadline, so a proxy that hangs
*after* handshake blocks a worker indefinitely and CPS collapses to ~0 rather
than degrading smoothly. This matters for choosing the fault-injection point in
the AC4 test.

---

## F2 — the false-positive rate is structurally zero, and Phase 800's gate on it is unreachable — CRITICAL

**[rev2 — new finding, missed in revision 1. Co-critical with F1.]**

`internal/test/bench/ja4bench.go:47-53`:

```go
func (r *BenchResult) Record(isGood, allowed bool, latency time.Duration, err error) {
	...
	if err != nil {
		r.Errors++
		r.LastError = err.Error()
		return          // ← returns BEFORE the allowed/blocked branch
	}
```

The only `allowed=false` call site is `:317`, which passes an error alongside
it. `Record` returns early on that error, so **`GoodBlocked` is never
incremented by any production path.** Therefore:

- `FalsePositiveRate()` (`:102`) always returns 0.00%.
- `Status()`'s `if fp := r.FalsePositiveRate(); fp > 0` (`:141`) — added by
  **Phase 800 as the correctness gate** — can never fire.
- A proxy RST is counted as an **error**, never as a **block**.
- `benchmarks.md`'s published "False positives: 0%" column is a printed
  constant, exactly like the 95.73 CPS.

**Why Phase 800's audit missed it:** `ja4bench_test.go:76,138` assign
`r.GoodBlocked = 1` / `= 10` **directly on the struct**. The tests exercise the
arithmetic of a field the generator cannot populate — the F1 pathology
reproduced inside the test suite.

Under `CLAUDE.md`'s core asymmetry (false positives are the expensive error),
this is arguably the worse of the two constants.

---

## F3 — Phase 818 misdiagnosed F1, and its proposed remedy would have entrenched it

`.github/workflows/nightly-benchmark.yml:109-114` **[rev2 — corrected line range]**
and `PHASE_818.md:38-43` attribute the anomaly to shared GitHub-hosted runners:

> The tell that this is an environment mismatch and not a code regression:
> throughput is ~6× lower while latency is ~17× better.

The paradox was spotted correctly; the cause was not. It is not runner
hardware — my idle i9 produces the same number. The paradox resolves under F1:
latency is better *because* the offered concurrency is 0.6, and throughput is
lower *because the generator never asks for more*.

**[rev2 — corrected diagnosis.]** Revision 1 said "comparing a 64-worker
saturating run against an 8-worker throttled run is the entire discrepancy."
That is wrong and actively misleading: because `ratePerWorker = rate/workers`,
**raising `--workers` alone makes it strictly worse** — `--good-rate 100
--workers 64` offers `100/64 = 1` → 64 conn/s. The load-bearing variable is
`--good-rate`, not `--workers`. The correct statement is **throttled vs
unthrottled offered rate**. (`benchmarks.md:49-52` independently notes the
bridge plateaus "~600 conn/s regardless of ... client worker count".)

Consequences now live in the repo:

- The gate is advisory. `nightly-benchmark.yml:116` **[rev2 — 116, not 117]**
  reads `if: steps.gate.outputs.regressed == 'true' && false`. The job prints
  `REGRESSION DETECTED` every night and stays green. Issue #395 was opened,
  then closed; filing is paused. The alarm is permanently silent on a
  permanently-broken metric.
- **[rev2 — partially rehabilitate 818, per reviewer.]** Phase 818's proposed
  "CI-representative baseline" will not work **while the number is a constant** —
  a self-hosted runner is *faster* and lands deeper in the tick-bound region, and
  a statistical baseline would converge on 95.75 ± 0.1 and gate on a constant.
  But once the harness saturates, a CI-accumulated baseline becomes exactly the
  right instrument, because the runner genuinely *is* slower than an i9 and no
  host-measured baseline will ever fit it. 818's diagnosis was wrong; its
  prescription becomes right after this phase. Say both.
- **[rev2 — the p95 gate is toothless for the same reason.]** Baseline p95 is
  290 ms (from a saturated run) versus 15.6 ms actual — 18× headroom. Even a
  20× slower proxy passes the 20% gate. Fixing throughput alone leaves latency
  ungated.
- **[rev2 — how it became invisible.]** `nightly_benchmark_baseline.json`'s
  `"method"` field reads `"make bench-macro (bridge port via docker-proxy, ja4p
  test benchmark --duration 30)"` — it **omits the workers/rate flags the 600
  CPS run actually used**. That omission is arguably the root cause of the
  apples-to-oranges comparison surviving review.

---

## F4 — `bench-all` counts silent skips as passes, and carries destructive authority

`Makefile:1606-1613` chains `$(MAKE)` calls and prints `✓ bench-all complete`,
but stages return 0 while measuring nothing. Same class as the `|| true` Phase
800 removed from `bench-micro` (`Makefile:1195-1199`); the lesson was not
generalised.

**[rev2 — the urgent part.]** `bench-all` invokes `measure-mttr`
(`Makefile:1612`), and `verify-all` (`Makefile:1615-1620`) — the release gate —
invokes `bench-all`. `scripts/measure_mttr.sh` runs `$COMPOSE stop redis`,
`$COMPOSE up -d`, and `docker volume rm`. Today it is stopped only by an
accidental pre-flight SKIP. **Anyone who "helpfully" unblocks that pre-flight
turns `make verify-all` into a command that destroys the developer's lane.**
This is why step 0 below is a one-line change made on day one.

The full `measure-mttr` analysis — and my two wrong claims about it — moved to
[PHASE_819b](PHASE_819b.md#f9). Only the removal from `bench-all` happens here.

---

## Design

### D-A: fix the harness before touching any baseline

No baseline file, doc, brochure, or Grafana panel changes until the harness is
honest. Re-baselining a broken measurement is how Phase 818's situation arose.

### D-B: the primary invariant is a boolean, not a plateau — **[rev2, rewritten]**

Revision 1 proposed a worker sweep asserting "CPS plateaus while latency
climbs". Reviewers correctly rejected this: a plateau identifies *a*
bottleneck, not *which* one, and there are at least three available — the
generator's own mutex-serialised `Record` and client-side TLS cost; the
`docker-proxy` userland relay (which `benchmarks.md:49-52` already documents as
plateauing ~600 CPS "regardless of ... client worker count"); and the proxy's.
`bench-macro` is *guaranteed* to satisfy a plateau assertion, and the plateau
it finds is the relay's. That is F1's error in a new costume. In CI the
predicate also needs a numeric threshold that is simultaneously robust to ±40%
runner variance and sensitive enough to catch F1 — no such threshold exists.

Instead, compare the run **against its own configuration**:

```
offered_rate_cps = workers × ratePerWorker      # after the truncation fix
rate_limited     = achieved_cps ≥ 0.9 × offered_rate_cps
```

Single run, no sweep, no threshold tuning, immune to machine speed and CI
noise. It catches F1 exactly: offered 96, achieved 95.73 → `rate_limited =
true` → **the harness refuses to publish the number.**

Then add a **saturation witness that is not the client**: scrape the proxy's
own `/metrics` and cgroup CPU at run start/end; assert proxy-side connection
count ≈ client-side. A "ceiling" claim requires either proxy CPU near a core
limit **or** a named documented downstream cap (`docker-proxy`). Keep the
8→16→32→64 sweep as a **reported curve in the artefact**, never as a CI
assertion.

### D-C: vocabulary — three different numbers, enforced in output strings

- `bench-macro` → **bridge-path CPS (docker-proxy-bound)**. A same-topology
  regression tripwire. Never quotable as capacity.
- `bench-hostnative` → **engine CPS**. This is the capacity number — and it is
  **not currently in `bench-all`** (`Makefile:1606-1613`), which is why a clean
  `bench-all` could not have produced an honest ceiling anyway. Add it.
- `test-go-perf` → **TCP accept rate, no ClientHello** (819b).

### D-D: a skip is not a pass

Every `bench-all` stage ends in **measured** or **loud failure**. Extend this
to *empty results*, not just absent environment — that is what F2 needs.

### D-E: the Phase 805 plumbing is in scope — **[rev2, was wrongly out of scope]**

Revision 1 excused it as "transports whatever number it is given". Untrue of a
schema change: `scripts/export_ci_benchmark_textfile.sh` uses bare subscripts
(`data["total_good"]`, `["total_bad"]`, `["errors"]`). A shape change raises
`KeyError` → fail-open leaves the old textfile → Prometheus serves stale data
for 36 h → `JA4ProxyNightlyBenchmarkStale` fires while CI is green. This is the
single most likely operational failure of the phase.

In scope: freeze the keys the puller reads; add `offered_rate_cps`, `workers`,
`rate_limited` to `result.json`; export `ja4proxy_loadtest_rate_limited`; make
`JA4ProxyNightlyBenchmarkRegression` require it to be 0. **That gauge is what
makes F1 permanently un-repeatable in production monitoring** — far more
durable than a Makefile flag.

---

## Decisions

| # | Decision | Rationale |
|---|---|---|
| **D1** | Fix the harness; never re-baseline onto the artefact | The metric is the generator's tick rate. Phase 818's self-hosted-runner remedy would entrench it (F3) |
| **D2** | Saturating flags live in **`ja4bench.go:199-202` defaults**, not the Makefile | **[rev2]** The nightly workflow *inlines* `ja4p test benchmark` (`nightly-benchmark.yml:57`) and never calls `make bench-macro` — Phase 805 copied the invocation deliberately (`PHASE_805.md:171`). A Makefile-only fix leaves CI measuring 96 forever while local runs report truth. Changing the defaults makes every caller inherit it. Add a workflow-lint assertion that no workflow invokes `ja4p test benchmark` directly |
| **D3** | `rate_limited` boolean is the gate; the sweep is a reported curve | D-B |
| **D4** | Add `bench-hostnative` to `bench-all` | It is the only stage that measures the engine (D-C) |
| **D5** | Remove `measure-mttr` from `bench-all` — **permanently, step 0** | It answers a DR question, not a capacity one; it is destructive by design; `verify-all` must not carry `docker volume rm` authority. Its isolated home is Phase 814a's `make pentest-range`, already IN_PROGRESS — build once, use twice |
| **D6** | Gate `rate_limited` and `error_rate` **enforcing immediately**; throughput/p95 advisory for 10 nightly runs, then re-seed from observed CI variance at `max(20%, 3σ)` | **[rev2]** Two gates, not one. `rate_limited` is zero-variance — it compares a run to its own config. Gating on it means F1 can never silently return |
| **D7** | Delete `&& false` (`nightly-benchmark.yml:116`); replace with repo variable `vars.NIGHTLY_PERF_GATE_ENFORCING` | A boolean literal hardcoded into a workflow condition outlives its comment. Keep issue filing paused until the gate is enforcing — a paused gate that files issues is what produced #395 |
| **D8** | `benchmarks.md` historical rows are **appended, never overwritten** | The 2026-06-10 / `76504c8` row is the only record of the last known-good real number and the seed of the baseline JSON |

---

## Implementation plan

**Step 0 must land on day one, as its own commit, before anything else.**

0. **Remove `measure-mttr` from `bench-all`** — delete `Makefile:1612`. One
   line. Removes `docker volume rm` authority from `verify-all` while the rest
   of this phase (and 819b) is under review and being re-run repeatedly.
1. **Generator truth (F1).** Fix the truncation and the `ratePerWorker == 0`
   collapse; extract a testable `offeredRate(rate, workers)` helper; emit
   `offered_rate_cps`, `workers`, `rate_limited` in `--output json` and text;
   change the defaults per D2. Fix `Makefile:1642 loadtest`'s corrupted rates.
2. **False-positive truth (F2).** Make `Record` distinguish a *block* (RST /
   connection refused after accept) from a *transport error*, so `GoodBlocked`
   is reachable and `Status()`'s FP gate becomes live. Rewrite
   `ja4bench_test.go:76,138` to drive `Record()` rather than assign the field.
3. **`bench-all` contract (D-D)** — **[rev2: moved ahead of the stage fixes]**.
   Land the invariant first so every later fix is verified *by the contract*
   rather than by eyeballing a terminal. It will turn `bench-all` red
   immediately, which is correct — it *is* red.
4. **`bench-macro` + `bench-hostnative` (D-C/D4).** Saturating defaults
   inherited from step 1; sweep reported, not asserted; add `go-build
   cli-build` prerequisites (`bench-macro` currently has none, so a clean
   checkout dies at stage 2); add `bench-hostnative` to `bench-all`.
5. **JSON contract + exporter (D-E).** Freeze the puller's keys; add the new
   fields; export `ja4proxy_loadtest_rate_limited`; update the alert rule. Add
   a contract test feeding real `--output json` through the puller's parser.
6. **Nightly workflow (F3/D6/D7).** Per the cutover sequence below. Correct the
   Phase 818 comments at `nightly-benchmark.yml:109-114` and `:165-178`.
7. **Re-measure and record (D-A/D8).** Honest bridge and engine numbers; append
   to `benchmarks.md`; re-seed `nightly_benchmark_baseline.json` including a
   `"method"` string that names the flags; re-derive `error_rate_gate`; close
   the Phase 524 D2 debt in `PERFORMANCE_BENCHMARK.md:139-150`; review
   `docs/pdf/brochure/brochure-body.tex:61` ("2,500 connections per second per
   node") and `scripts/capacity_calculator.py:62-68`.

### Cutover sequence (step 6, ordered so no false alert can fire)

1. Land steps 1-5 with the nightly workflow **untouched**. Nothing downstream moves.
2. Verify the JSON contract locally through the puller's parser **before**
   anything publishes. If it doesn't emit all ten gauges, stop.
3. Collect ≥5 fixed-harness data points via `workflow_dispatch` uploading to a
   **different** release tag (`nightly-benchmark-shadow`). Do **not** clobber
   `nightly-benchmark-latest` — `--clobber` is irreversible and it is the
   puller's only source.
4. Silence `JA4ProxyNightlyBenchmarkRegression` for ~48 h. Leave
   `JA4ProxyNightlyBenchmarkStale` **live** — during a cutover, staleness is
   exactly the signal you need.
5. **One atomic commit:** baseline JSON (`gated_metrics` + `error_rate_gate` +
   `source`/`method`), the workflow invocation, and the corrected 818 comments.
   Split commits are what create a false storm, because the alert reads
   `ja4proxy_loadtest_baseline_*` fed from the same `result.json`.
6. `workflow_dispatch` immediately; confirm gate report and release asset.
7. Force one puller run; confirm the textfile updated. If unchanged, the JSON
   contract broke — revert step 5 **before** the 36 h stale window elapses.
8. Two consecutive clean nightlies under the silence → lift the silence.
9. Only then flip `vars.NIGHTLY_PERF_GATE_ENFORCING`; issue filing on first,
   hard-fail after a week of clean runs.
10. Last: the human-facing numbers (step 7's doc list). Annotate the Grafana
    cutover date so the step discontinuity is not later triaged as an incident.

---

## Test plan

- **The F1 regression test, made hermetic and threshold-free.** `internal/test/bench`
  is a normal package with an existing `ja4bench_test.go`. Stand up an
  in-process `net.Listener` with a self-signed cert that sleeps *N* ms, and
  point `runProfile` at it. No Docker, no compose, no lane. Table-driven,
  asserting on the **derived flag**: `{delay 5ms → rate_limited=true}`,
  `{delay 20ms, workers 8, good-rate 100 → rate_limited=false AND cps within
  25% of workers÷latency}`.
  **[rev2 — revision 1's version was broken:]** it said "a delayed stub backend;
  CPS must fall — under today's code it would not." Wrong. Today's tick period
  is 83.3 ms, so any delay *above* that makes CPS fall **with the bug present**,
  and the test passes green on broken code. The delay must be *below* the tick
  period, which is why asserting `rate_limited` rather than raw CPS is the
  right call. **[rev2]** Pick the injection point deliberately given the
  `io.Copy` deadline gap.
- **The F2 regression test.** Drive `runProfile` against a listener that RSTs a
  fraction of connections; assert `GoodBlocked > 0` and `FalsePositiveRate() >
  0`. Fails today. Must go **through `Record()`**, not by assigning the struct
  field — that is precisely the defect in `ja4bench_test.go:76,138`.
- **Unit:** `offeredRate(rate, workers)` — `(100,8)→96`, `(4,8)→8`, `(0,8)→0`,
  plus `loadtest`'s `(10,16)` and `(190,16)`.
- **Contract test:** real `--output json` through `export_ci_benchmark_textfile.sh`'s
  parser; all ten gauges present.
- **Workflow lint:** no workflow invokes `ja4p test benchmark` directly (D2).
- **`bench-all` contract tests:** each stage exits **non-zero** on absent
  environment *and* on empty results.

## Acceptance criteria

1. `make bench-all` completes green with every stage having produced a real
   measurement — no skip and no empty result counted as a pass.
2. `bench-macro` and `bench-hostnative` report `rate_limited = false`, with
   `offered_rate_cps`, `workers`, and the saturation verdict in `result.json`.
3. **[rev2 — replaces the unfalsifiable "differs materially between machines".]**
   Revision 1's AC3 required two machines and a human comparing runs — no CI
   job could evaluate it, "materially" was undefined, and it could be *false
   even when the fix is correct*, since the docker-proxy-bound bridge path may
   legitimately land close on both. It used a symptom of the bug as the
   definition of the fix. Replaced by:
   - **3a.** The recorded run reports `rate_limited = false`.
   - **3b.** With a stub backend delayed 20 ms (below the current 83.3 ms tick,
     so today's code would not catch it), reported CPS falls to within ±25% of
     the closed-loop prediction `workers ÷ latency`. Under the pre-fix
     invocation this assertion fails.
   The two-machine comparison stays as a reported observation in
   `PHASE_819a_notes.md`, where an informative-but-unfalsifiable check belongs.
4. `FalsePositiveRate()` is reachable: the F2 test proves a blocked good
   connection produces a non-zero FP rate and trips `Status()`.
5. `ja4proxy_loadtest_rate_limited` is exported and the regression alert
   requires it to be 0.
6. `make verify-all` cannot stop a container or remove a volume.
7. Baseline JSON, `benchmarks.md` (appended), `PERFORMANCE_BENCHMARK.md`'s
   Phase 524 D2 note, and the brochure claim are all reconciled with the
   re-measured numbers.
8. `make lint-phases` exits 0; changelog fragment under `docs/fragments/`.

## Out of scope

- Proxy performance *optimisation*. If the honest ceiling lands below the
  2026-06-10 numbers, that is a follow-up with a real target — see Risks.
- Re-architecting the generator to open-loop. Closed-loop is fine; it just has
  to saturate.
- Everything in [PHASE_819b](PHASE_819b.md).

## Risks

| Risk | Mitigation |
|---|---|
| The honest ceiling is below 2026-06-10 — a real regression was hiding behind F1 | A finding, not a failure. Bisect against `76504c8` in a follow-up. **[rev2]** Note it has a published claim attached: `brochure-body.tex:61` states "2,500 connections per second per node" to customers |
| **[rev2]** Client-side TIME_WAIT/port exhaustion mistaken for the proxy's ceiling | This host has 28,232 ephemeral ports and `tcp_tw_reuse=2` (**loopback only**). Against a container IP, TIME_WAIT caps sustained rate at ~470 CPS — which would look exactly like a saturated proxy. Record `ss -s` TIME_WAIT counts and the port range alongside CPS, or assert loopback targeting. Otherwise the phase reproduces F1's error class in a new disguise |
| **[rev2]** `Status()` fails on FP>0 vs a single-IP saturating burst | Once F2 makes the FP path reachable, a 30k-rate burst from one IP is exactly what rate-limit/beaconing signals target. Pin `dial=0` or whitelist the generator's JA4 for benchmark runs, and document it |
| **[rev2]** A saturating run trips the 1% error-rate gate | `max_error_rate_percent: 1.0` was set when every run measured 0 errors at 7.5% duty cycle. Re-derive from the first honest runs. Also: the workflow's claim that "error-rate failures remain a real signal" is **already false** — the gate's exit code is collapsed into one advisory boolean. Fix the wiring or delete the comment |
| **[rev2]** Counters that are not counters | `ja4proxy_loadtest_connections_*_total` are `# TYPE counter` carrying a fresh absolute value nightly. Jumping ~2,900 → ~120,000 reads as a counter reset to any later `rate()`. Note in the fragment |
| Nightly runtime grows | Bound the sweep explicitly rather than leaving it to `$(ARGS)` |

---

## What review changed

Three reviewers audited revision 1 independently. F1 was **confirmed**, with
better evidence than I had (the `2873 ≈ 8 × 360` tick count, and Little's Law).
What they corrected:

**Wrong, and dangerous:**
1. I claimed bare `docker compose` from the repo root resolves to a *different*
   project than the live lane. **Inverted.** `.env` sets
   `COMPOSE_PROJECT_NAME=ja4proxy-lane23`, so it targets the **live lane** using
   the root 4-service file. There is no project-name separation. Full analysis
   moved to 819b; the mitigation is step 0 here.
2. I prescribed `docker volume ls` as the fix for the invalid `docker compose
   volume ls`. That is host-global: on this machine it selects
   `ja4_claude0_redis-sock` — **another agent's lane** — out of 21 matches, and
   the next line is `docker volume rm`. (`docker compose volumes`, plural,
   exists and is project-scoped.) 819b.

**Missed, of equal severity:** F2 (structural FP=0) — now co-critical here; and
`load-test` producing no metrics at all — 819b.

**Wrong in detail:** the "64-worker vs 8-worker" diagnosis (it is offered
*rate*, not workers — raising workers alone makes it worse); "two decimal
places" (0.02%); "the proxy is idle 92.5%" (that is the generator's duty cycle);
"not a measurement of the proxy" (throughput only — the latency figures are
real); "only `bench-macro` reads `HOST_PORT_DIRECT`" (`Makefile:1642` and
`nightly-benchmark.yml:55` do too — the claim holds only within `bench-all`);
three wrong line numbers; and a closed-loop quote attributed to two files when
it is verbatim from one.

**Design rejected:** the worker-sweep plateau assertion (D-B), and AC3.

Reviewer verdicts on revision 1: one *approve with eight must-haves*, one
*rework*, one *confirmed with corrections*. All eight must-haves and all three
Q-answers are folded in above.
