---
phase: 819
title: "Bench-all restoration — make the benchmark numbers real, then get a clean full run"
status: PROPOSED
size: LARGE
created: 2026-08-13
audience: [developer, operations]
---

# Bench-all restoration

> **STATUS: PROPOSED — plan for review. No code until approved.**
>
> Triggered by rerunning `make bench-all` on 2026-08-13 after the entrypoint
> shebang fix (#416) landed. The shebang fix worked; `bench-all` died one step
> later. Investigating that failure turned up six more, and one of them
> invalidates the headline performance number the project has been publishing
> nightly since Phase 805.

## Goal (plain language)

Two things, in this order:

1. **Make the measurements true.** Today `make bench-all` cannot complete, and
   the one stage that *does* complete reports a number that is not a
   measurement of the proxy. Fix the harness before drawing any conclusion
   about performance.
2. **Then get a clean, complete `make bench-all` run** end to end, and record
   the resulting numbers as the honest Go-proxy baseline — closing the Phase
   524 "D2" re-measurement debt that `docs/reports/PERFORMANCE_BENCHMARK.md`
   still carries.

### The headline, up front

**There is no evidence that JA4proxy has lost performance.** There is strong
evidence that we have not been measuring it. The number the nightly job has
published every night — ~96 conn/s — is the *load generator's own configured
tick rate*, not the proxy's capacity. The proxy is idle ~92.5% of the time
during that benchmark.

So "get back to high performance" is, on current evidence, mostly a
*measurement* problem rather than a *regression* problem. This phase is
written to prove that either way: once the harness saturates properly, we will
have a real ceiling to compare against the last known-good real number
(3,263 conn/s host-native, 2026-06-10, SHA 76504c8).

---

## Evidence: the run that started this

`make bench-all` on branch `fix-test-entrypoint-shebang`, host i9-9900K,
lane-23 stack (`COMPOSE_PROJECT_NAME=ja4proxy-lane23`, `HOST_PORT_DIRECT=10381`):

| Stage | Result | Detail |
|---|---|---|
| `bench-micro` | **PASS** | genuine numbers, see below |
| `bench-macro` | **PASS** | 95.73 CPS — but see F1; this is not a measurement |
| `perf-test` | **FAIL** (Error 1) | locust cannot import on Python 3.14 (F2) |
| `test-go-perf` | *never reached*; standalone: **4/4 SKIP, exit 0** | wrong port (F3) |
| `load-test` | *never reached*; standalone: **Error 2** | missing Makefile defaults (F4) |
| `measure-mttr` | *never reached*; standalone: **SKIP, exit 0** | three stacked blockers (F6) |

Micro-benchmarks are healthy and are the one part of this that needs nothing:

```
BenchmarkPipeline_Allow-16    407.9 ns/op   184 B/op   3 allocs/op
BenchmarkPipeline_Score-16    425.8 ns/op   160 B/op   3 allocs/op
BenchmarkClientHelloParse-16  330.5 ns/op   464 B/op   8 allocs/op
BenchmarkJA4Compute-16       3155   ns/op   864 B/op  41 allocs/op
BenchmarkExtractJA4X-16      5805   ns/op  4451 B/op  73 allocs/op
```

---

## The findings

### F1 — `bench-macro` measures the load generator, not the proxy — CRITICAL

**Symptom.** `make bench-macro` reports ~95.7 conn/s on an i9-9900K. The
nightly CI job on a shared GitHub-hosted runner reports **95.749** conn/s.
Two wildly different machines agreeing to two decimal places is not a
performance measurement — it is a constant.

**Root cause.** `internal/test/bench/ja4bench.go:279-291`:

```go
func runProfile(ctx context.Context, host string, isGood bool, rate, workers int, res *BenchResult) error {
	ratePerWorker := rate / workers          // 100 / 8 = 12
	...
		ticker := time.NewTicker(time.Second / time.Duration(ratePerWorker))  // 83.3ms
```

The generator is a **rate-limited, closed-loop** driver. Defaults
(`ja4bench.go:198-202`) are `--good-rate 100`, `--workers 8`. Integer division
gives 12 conn/s/worker; 8 workers × 12 = **96 conn/s offered**. Measured 95.73.
The proxy delivered exactly what was asked for and then sat idle.

`Makefile:1204-1209` invokes it with neither flag:

```make
./bin/ja4p test benchmark --host 127.0.0.1:$$PORT --duration 30 $(ARGS)
```

**Duty cycle.** Measured mean latency 6.26 ms against an 83.3 ms tick period —
the proxy is busy **7.5%** of the time. A proxy that got **13× slower** would
still report ~96 conn/s. Throughput only starts to fall once per-connection
latency exceeds 83.3 ms.

**A second-order bug:** the integer truncation means `--good-rate 100` silently
offers 96, and any `rate` below `workers` collapses to `ratePerWorker = 1`
(the `if ratePerWorker == 0` guard at `ja4bench.go:281`), silently offering
`workers` conn/s regardless of what was requested.

**The repo already knows how to do this correctly.** `scripts/bench-hostnative.sh:24-27`
drives the same binary with `--workers 32 --good-rate 30000` — 937 conn/s/worker,
i.e. effectively unthrottled, latency-bound, genuinely saturating. And
`scripts/bench-hostnative.sh:111` and `docs/performance/benchmarks.md:80` both
state the model explicitly: *"Closed-loop: CPS ≈ workers ÷ latency. If CPS
plateaus while latency climbs, the engine is saturated — that plateau is the
real ceiling."* `bench-macro` simply never applied it.

### F1a — Phase 818 misdiagnosed this, and the proposed follow-up is a dead end

`.github/workflows/nightly-benchmark.yml:165-178` currently says:

> The cause is not a code regression: the baseline in
> `nightly_benchmark_baseline.json` was measured on a real HOST (600 cps,
> 290ms p95), but this workflow runs on shared GitHub-hosted runners that
> measure ~96 cps / ~17ms p95. The tell that it's an environment mismatch, not
> a slowdown: throughput is ~6x LOWER while latency is ~17x BETTER — physically
> impossible for a real regression.

Phase 818 spotted the paradox correctly and drew the wrong conclusion from it.
It is not runner hardware. My host — an idle i9-9900K, not a shared runner —
produces **95.73**, the same number. The paradox resolves cleanly under F1:
latency is better *because* the proxy is 92.5% idle, and throughput is lower
*because the generator never asks for more*.

The real mismatch is **flags, not hardware**. `docs/performance/benchmarks.md:91`
records the 600 cps bridge baseline as measured **@ 64 workers**;
`nightly_benchmark_baseline.json` seeds from that row. The nightly workflow
and `make bench-macro` both run the **8-worker, 100 rate** defaults. Comparing
a 64-worker saturating run against an 8-worker throttled run is the entire
discrepancy.

**Consequences to fix here:**

- The nightly gate is **advisory only** (`if: ... == 'true' && false` at
  `nightly-benchmark.yml:117`, and the final step warns instead of failing).
  It reports `REGRESSION DETECTED (1 metric(s))` **every single night** while
  the job stays green. Issue #395 was opened, then closed; issue filing is
  paused. The alarm is now permanently silent on a permanently-broken metric.
- Phase 818's stated follow-up — "a CI-representative baseline (self-hosted
  runner, or a statistical baseline accumulated from CI runs)" — **will not
  work.** A self-hosted runner would also measure ~96, because ~96 is the
  generator's tick rate. Any baseline accumulated from these runs would bake
  the artefact in permanently. This must be fixed at the harness, not the
  baseline.

### F2 — `perf-test`: locust 2.17.0 cannot import on Python 3.14 — BLOCKER

```
File "/usr/local/lib/python3.14/site-packages/locust/event.py", line 200, in __init__
    for name, value in self.__annotations__.items():
AttributeError: 'Events' object has no attribute '__annotations__'.
                 Did you mean: '__annotate_func__'?
```

`requirements.txt:32` pins `locust==2.17.0` (Oct 2023).
`deploy/docker/Dockerfile.test` is based on `python:3.14.6-alpine3.24`.
Python 3.14 implements PEP 649/749 (deferred evaluation of annotations):
`__annotations__` is now materialised lazily via `__annotate_func__`, and an
*instance* attribute lookup for `self.__annotations__` no longer resolves the
way locust 2.17 assumes.

Locust 2.46.3 declares support for 3.14 and 3.15 in its trove classifiers.
`requirements.txt:66` also carries a now-stale comment referencing
"locust 2.17.0" for the msgpack pin.

**Note this was masked twice over:** the shebang bug (#416) failed this stage
with exit 255 before locust ever ran, and the `perf-test` failure in turn
prevented F3/F4/F6 from ever being reached. This is a queue of stacked
blockers, not a single fault.

### F2a — what `perf-test` actually exercises is questionable

Worth settling while we are here. `Makefile:1024` runs locust with
`--host http://proxy:8080` — **plain HTTP against the TLS passthrough port**.
`tests/performance/locust_tests.py:115` separately hardcodes
`TLSClient("localhost", 8080)` inside the container, where `localhost` is the
*test container*, not the proxy. Fixing the import will make this stage run;
it will not by itself make it meaningful. See Decision D4.

### F3 — `test-go-perf` skips itself and reports success

`tests/performance/test_bench_go_proxy.py:25` defaults `GO_PROXY_PORT` to
**18082**. Lane 23 publishes the proxy on `HOST_PORT_DIRECT=10381`
(`.env`); the compose default is 8081 (`docker-compose.poc.yml`
`${HOST_PORT_DIRECT:-8081}`). Port 18082 is not listening under any of these,
so every test hits `pytest.skip("Go proxy not reachable...")`, pytest exits 0,
and `bench-all` counts the stage as passed.

Pointed at the real port it works, and gives the only real end-to-end numbers
from this whole exercise:

```
GO_PROXY_PORT=10381 → 43375 connections in 10.2s = 4264.5 conn/s (10 threads)
                       latency mean 0.05ms / p50 0.05ms / p99 0.26ms
                       sustained: 1000 ok, 0 failed        → 3 passed, 1 skipped
```

Two caveats that keep this from being the answer on its own:

- `_one_connection` (`test_bench_go_proxy.py:59-65`) does a bare TCP
  connect-and-close — **no ClientHello, no bytes written**. This is accept-rate,
  not handshake throughput. It is not comparable to `bench-macro`'s full
  TLS+HTTP figure and must never be quoted as such.
- The assertion is a sanity floor of **≥ 1 conn/s**, not a regression gate.
- `test_go_vs_python_throughput_ratio` compares against the Python proxy that
  was deleted in the Go rewrite. It is a permanent skip — dead code.

### F4 — `load-test` cannot run at all

`Makefile:1271-1276` expands `$(LOAD_TEST_TARGET)`, `$(LOAD_TEST_DURATION)`,
`$(LOAD_TEST_RPS)`, `$(LOAD_TEST_SCENARIO)` — **none of which are defined
anywhere in the Makefile.** They are only ever set inline by the separate
`load-test-baseline` target. From `bench-all` the recipe becomes:

```
python3 scripts/load_test.py --target --duration --rps --scenario
load_test.py: error: argument --target: expected one argument
make: *** [Makefile:1272: load-test] Error 2
```

This has never worked from `bench-all`. It was invisible because `perf-test`
failed first.

### F5 — `load-test-baseline` is broken two ways as well

`Makefile:1278-1283` sets `LOAD_TEST_SCENARIO=baseline`. Phase 86i replaced the
scenario set; `scripts/load_test.py:391` uses
`choices=sorted(SCENARIOS.keys())` = `{attack-wave, bypass-only, full-signal,
mixed}`. `"baseline"` survives only in `_LEGACY_SCENARIOS`
(`load_test.py:81`), which is **not** in `choices` — argparse rejects it.

It also sets `LOAD_TEST_TARGET=localhost:8080`. Port 8080 is the proxy's
*container-internal* port; the host-published port is `HOST_PORT_DIRECT`
(10381 on lane 23, 8081 by compose default).

### F6 — `measure-mttr`: why `redis-cli` was not found, and the two blockers behind it

This is the one the user asked to have explained, so in full.

**Blocker 1 — the pre-flight.** `scripts/measure_mttr.sh:45-49`:

```bash
if ! command -v redis-cli &>/dev/null; then
    log "SKIP: redis-cli not found on PATH."
```

The script expects a **host-installed** Redis client. Nothing in this project
installs one, and nothing should: `AGENTS.md` "Container-Strict Execution"
forbids host tooling precisely to avoid version skew, and Redis only ever runs
as a container. So the check fails on every developer machine and CI runner
that has not had `redis-tools` hand-installed. It then does `exit 0` — a
**silent success**, which is why `bench-all` would have counted it as a pass.

**Blocker 2 — there is no host-reachable Redis anyway.** Even with
`redis-tools` installed, the next check (`redis-cli PING` → `localhost:6379`)
would fail: `deploy/docker/docker-compose.poc.yml` publishes **no host port
for the redis service** (verified — `services.redis.ports` is absent; only
`proxy` and `management` publish ports). There is no 6379 on the host for this
stack.

*This one is worse than a failure.* If the developer happens to have **some
other** Redis on 6379 — and on this machine the unrelated `ja4range` stack is
running — the script would connect to it and happily execute
`SET config:dial 100`, `PUBLISH config:reload`, and `SET ja4proxy:mttr_probe`
against **the wrong database**. The current SKIP is accidentally protecting us.

**Blocker 3 — an invalid Docker subcommand.** `scripts/measure_mttr.sh:~88`:

```bash
REDIS_VOLUME=$($COMPOSE volume ls --format '{{.Name}}' 2>/dev/null | grep -i redis | head -1)
```

**`docker compose` has no `volume` subcommand** (verified — it prints the usage
banner and exits non-zero). `REDIS_VOLUME` is therefore always empty and the
script takes its *next* silent `exit 0`: "SKIP: No Redis volume found." The
correct call is `docker volume ls`. So even fixing blockers 1 and 2 leaves the
script skipping.

**Blocker 4 — lane-unawareness and wrong-stack targeting.**
`HEALTH_URL` defaults to `http://localhost:8090/...` (`measure_mttr.sh:18`),
but lane 23's management API is on `HOST_PORT_MANAGEMENT=10390`. `COMPOSE`
defaults to a bare `docker compose` (`measure_mttr.sh:20`), which from the repo
root resolves the **root `docker-compose.yml`** — a different, 4-service
quick-start stack (`ja4proxy`, `management`, `management-tls`, `redis`) under a
different project name than `ja4proxy-lane23`.

**Blocker 5 — and this is why we must not simply "unblock" it.** Once the
pre-flights pass, the script runs `$COMPOSE stop redis`, `$COMPOSE up -d`, and
at scenario 5 `docker volume rm "$REDIS_VOLUME"`. Wiring that into
`make bench-all` means **running `make bench-all` destroys the developer's
running lane's Redis data mid-session.** A benchmark target must never do
that. See Decision D5.

### F7 — `bench-all`'s exit-code contract does not hold

`Makefile:1606-1613` chains `$(MAKE)` calls and prints `✓ bench-all complete`.
But two stages return 0 while measuring nothing (F3's 4 skips, F6's pre-flight
`exit 0`). A green `bench-all` today would prove very little.

This is the same class of defect Phase 800 removed from `bench-micro`, and the
Makefile comment at `Makefile:1195-1199` describes it exactly: a trailing
`|| true` had been masking three permanently-failing benchmarks. The lesson did
not get generalised to the other stages.

---

## The cross-cutting theme

Every one of F1, F3, F6, F7 is the same failure mode: **a stage that does not
measure what it claims, while reporting success.** F2/F4/F5 are ordinary bit-rot
(a stale pin, missing variables, a renamed enum) and are cheap. The expensive,
important half of this phase is making the benchmark suite *incapable of
silently measuring nothing*.

Two secondary themes worth naming:

- **Lane-unawareness** (F3, F5, F6) — the repo grew a lane system
  (`scripts/lane-env.sh`, `HOST_PORT_*` in `.env`) and the benchmark tooling
  never adopted it. `bench-macro` alone reads `HOST_PORT_DIRECT`
  (`Makefile:1206`); everything else hardcodes a port.
- **Stacked blockers** — six of these were invisible because the one in front
  of them failed first. Any fix order that does not re-run the whole chain
  after each fix will just uncover the next one late.

---

## Design

### D-A: fix the harness before touching any baseline

No baseline file, doc, or Grafana panel gets updated until `bench-macro`
saturates. Updating a baseline to match a broken measurement is how Phase 818's
situation arose.

### D-B: make saturation the default, and prove the plateau

`bench-macro` should drive the generator the way `bench-hostnative.sh` already
does — enough workers and a high enough offered rate that **latency**, not the
ticker, is the limit. Because the model is closed-loop (CPS ≈ workers ÷
latency), a single data point cannot distinguish "saturated" from "throttled".
The target must sweep workers and show the plateau, exactly as
`docs/performance/benchmarks.md:80` already instructs a human to do by hand.

Concretely: a sweep (e.g. 8 → 16 → 32 → 64 workers) at a `--good-rate` high
enough to be non-binding, asserting that CPS plateaus while latency climbs. If
CPS scales linearly with workers all the way to the top of the sweep, the run
is *still* throttled and the harness should say so rather than print a number.

### D-C: a skip is not a pass

Every `bench-all` stage must end in exactly one of: **measured**, or **loud
failure**. "Environment not present" is a failure of the *run*, not a quiet
success — `bench-all` is explicitly the "slow, runs alone" release gate, so
demanding its environment is reasonable. Where a stage genuinely cannot run
(no Docker, say), it must fail with an actionable message rather than exit 0.

### D-D: lane-awareness from one source

All stages derive host ports from `.env` / `scripts/lane-env.sh` the way
`Makefile:1206` already does, rather than each hardcoding a different default.

---

## Key decisions (for review)

| # | Decision | Rationale | Alternatives rejected |
|---|---|---|---|
| **D1** | Fix `bench-macro`'s invocation (saturating flags + worker sweep) rather than re-baselining | The metric is an artefact of the generator's tick rate; any baseline built on it is meaningless | Phase 818's proposed "CI-representative baseline" — would bake the artefact in permanently (see F1a) |
| **D2** | Bump `locust` to ≥2.46.3 | Only versions with declared 3.14 support can import at all | Pinning the test image back to Python 3.13 — reintroduces the CVE-laden base Phase 317 deliberately moved off |
| **D3** | Give `LOAD_TEST_*` real Makefile defaults, lane-derived | The target is referenced by `bench-all` and cannot run without them | Dropping `load-test` from `bench-all` — loses the only scenario-based (bypass/full-signal/attack-wave) coverage |
| **D4** | Decide `perf-test`'s fate explicitly (see open question Q1) | Fixing the import makes it *run*; F2a shows it may still not measure anything useful | Silently shipping a green-but-meaningless stage — the exact pattern this phase exists to end |
| **D5** | `measure-mttr` must run against a **dedicated ephemeral stack**, never the developer's live lane; and `redis-cli` comes from the redis container, not the host | It stops containers and `docker volume rm`s the Redis volume (F6 blocker 5). Container-strict execution (`AGENTS.md`) also forbids the host-tool assumption | Installing `redis-tools` on hosts/CI — violates container-strict rule and still targets the wrong DB (F6 blocker 2) |
| **D6** | Delete `test_go_vs_python_throughput_ratio` | Compares against a proxy deleted in the Go rewrite; permanent skip | Leaving it — inflates the skip count and hides real skips |
| **D7** | `bench-all` fails loudly on any stage that measures nothing | Restores the exit-code contract (F7) | Status quo — a green `bench-all` currently proves almost nothing |

---

## Open questions for the reviewer

- **Q1 (D4):** Is `perf-test`/locust worth keeping? It sends plain HTTP at the
  TLS passthrough port and duplicates coverage that `load-test`'s scenario set
  provides more meaningfully. Options: (a) fix the pin and the target so it
  measures something real; (b) fix the pin only, keep it as a smoke test;
  (c) retire the stage and drop the locust dependency entirely. (c) removes a
  large transitive dep tree from the test image; (a) is the most work.
- **Q2:** Should the nightly workflow move to the fixed saturating benchmark
  immediately, or should the gate stay advisory for a settling period while we
  accumulate variance data from GitHub-hosted runners? Runner noise is real —
  it is just not what F1 is about.
- **Q3:** Should `measure-mttr` stay in `bench-all` at all? It is a DR/recovery
  measurement, not a benchmark. A separate `make measure-mttr` invoked
  deliberately (D5's ephemeral stack) may be the honest home for it.

---

## Implementation plan (in order)

Each step ends with a re-run of the full chain, because of the stacked-blocker
problem.

1. **Harness truth (F1) — the load generator.** Fix the integer-truncation and
   the `ratePerWorker == 0` collapse in `internal/test/bench/ja4bench.go`; make
   the offered rate and worker count explicit in output so a throttled run is
   self-evident. Emit a saturation indicator.
2. **`bench-macro` (F1).** Drive with saturating flags and a worker sweep per
   D-B. Report the plateau, not a single point. Keep reading `HOST_PORT_DIRECT`.
3. **Re-measure and record.** Produce the honest bridge and host-native numbers;
   update `docs/performance/benchmarks.md`, `nightly_benchmark_baseline.json`,
   and close the Phase 524 D2 debt in `docs/reports/PERFORMANCE_BENCHMARK.md`.
   Only now is re-baselining legitimate.
4. **Nightly workflow (F1a).** Point it at the fixed target; correct the
   misdiagnosis comments at `nightly-benchmark.yml:112-118` and `:165-178`;
   resolve Q2 for the `&& false` gate and issue filing.
5. **`perf-test` (F2/F2a).** Per Q1's answer. If kept: bump `locust`, fix the
   stale msgpack comment at `requirements.txt:66`, fix the host/target confusion.
6. **`test-go-perf` (F3).** Lane-derived port; delete the dead Python-ratio
   test (D6); replace the ≥1 conn/s floor with a real threshold; label the
   metric clearly as TCP accept-rate so it is never confused with F1's number.
7. **`load-test` (F4/F5).** Add lane-derived `LOAD_TEST_*` defaults; fix
   `load-test-baseline`'s dead `baseline` scenario and container-port target.
8. **`measure-mttr` (F6).** `docker volume ls` fix; redis-cli via
   `docker compose exec redis`; lane-derived `HEALTH_URL` and explicit
   `-f ... --env-file .env`; ephemeral-stack isolation per D5; replace both
   silent `exit 0` paths with loud failures. Resolve Q3.
9. **`bench-all` contract (F7).** Fail on any stage that measured nothing.
10. **Full clean run.** `make bench-all` end to end, green, with every stage
    having produced a real number. Capture the output as the phase artefact.

---

## Test plan

- **Regression test for F1 (the important one).** A test that runs the
  generator at two worker counts and asserts the reported CPS actually responds
  to the proxy's speed — e.g. against a deliberately delayed stub backend,
  CPS must fall. Under today's code it would not. This test is what stops F1
  recurring.
- **Unit:** `ratePerWorker` arithmetic — truncation, `rate < workers`, and
  `rate == 0` cases.
- **Makefile-target smoke tests:** each `bench-all` stage invoked with a
  deliberately absent environment must exit **non-zero** with an actionable
  message (guards D-C/F7 and prevents regression to silent-skip).
- **`docker compose volume ls` guard:** a shell test asserting `measure_mttr.sh`
  resolves a real volume name against a live stack.
- **Lane-awareness test:** with a non-default `HOST_PORT_DIRECT`, every stage
  targets the right port (guards F3/F5/F6 blocker 4).
- **Import smoke test:** `locust --version` inside the built test image, so a
  Python-version bump can never silently re-break it (guards F2). Applies only
  if Q1 keeps locust.
- **Container config:** per `CLAUDE.md`'s web-service rule, assert the compose
  `test` service env passes what the stage needs.

## Acceptance criteria

1. `make bench-all` completes green, with **every** stage having produced a
   real measurement — no skips counted as passes.
2. `bench-macro` demonstrates saturation: a worker sweep showing a CPS plateau
   with rising latency, and a stated ceiling.
3. The reported bridge CPS **differs materially between an i9-9900K host and a
   GitHub-hosted runner** — the direct disproof of F1. Same-number-everywhere is
   the bug signature.
4. A deliberately slowed proxy causes the benchmark's reported throughput to
   fall (the F1 regression test passes).
5. Every stage derives its target from `.env`/lane config; no hardcoded ports.
6. `measure-mttr` either runs against an isolated ephemeral stack or is removed
   from `bench-all` (Q3) — and in no case can `make bench-all` destroy a
   running lane's data.
7. `nightly_benchmark_baseline.json`, `docs/performance/benchmarks.md`, and
   `docs/reports/PERFORMANCE_BENCHMARK.md` reflect the re-measured numbers, and
   the Phase 524 D2 debt is closed.
8. The incorrect "shared GitHub-hosted runners" explanation in
   `nightly-benchmark.yml` is corrected.
9. `make lint-phases` exits 0; changelog fragment added under `docs/fragments/`.

## Out of scope

- Actual proxy performance *optimisation*. This phase measures honestly; if the
  real ceiling then turns out to be below the 2026-06-10 numbers, that is a
  follow-up phase with a real target to aim at.
- Re-architecting the load generator into an open-loop system. Closed-loop is
  fine and is what the docs already describe; it just has to saturate.
- The Prometheus/Grafana textfile-collector plumbing from Phase 805 — it
  transports whatever number it is given, and is not implicated.
- Multi-instance scaling curves (1/2/4/8 proxies) mentioned as a wish in
  `PERFORMANCE_BENCHMARK.md`. Single-instance truth first.

## Risks

| Risk | Mitigation |
|---|---|
| The honest ceiling comes in below the 2026-06-10 numbers — i.e. there *is* a real regression hiding behind F1 | That is a finding, not a failure of this phase. Bisect against SHA 76504c8 in a follow-up; the point of the phase is to make it visible |
| A saturating `bench-macro` is much slower / noisier in CI, making the nightly job flaky | Q2's settling period; gate on the plateau rather than a single point |
| `measure-mttr` fixes accidentally destroy a developer's lane during review | D5 is a hard requirement, tested before the pre-flights are unblocked; do not unblock the pre-flights before the isolation exists |
| Scope sprawl — seven findings in one phase | The ordering is deliberate: F1 is the only one that changes any published number. F2/F4/F5 are small. If the phase must be split, F1+F1a+F7 is the valuable half |
| Locust bump drags in transitive CVEs and trips the security gate | Q1 option (c) removes the dependency entirely; otherwise scan before merging |
