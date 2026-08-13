---
phase: 819b
title: "Bench-all stage repair — bit-rot, lane-awareness, and safe MTTR isolation"
status: PROPOSED
size: LARGE
created: 2026-08-13
audience: [developer, operations]
---

# Bench-all stage repair

> **STATUS: PROPOSED — plan for review. No code until approved.**
>
> The second half of the `bench-all` restoration. [PHASE_819a](PHASE_819a.md)
> owns the two findings that change a published number (throughput and
> false-positive rate) plus the one-line removal of `measure-mttr` from
> `bench-all`. **819a lands first.** This phase repairs the individual stages.
>
> Revision 2, after expert review. Corrections to revision 1 are marked
> **[rev2]**; two of them reverse a prescription that would have destroyed
> another agent's lane.

**Dependency: 814a.** Phase 814a (IN_PROGRESS) is landing `make pentest-range`
— an isolated stack on an `internal: true` network with verified zero egress.
That *is* the ephemeral stack F9 needs. Build once, use twice; do not fund a
second one here.

---

## F5 — `perf-test` is dead four layers deep; a version bump does not fix it

Revision 1 framed this as a Python 3.14 import error (`locust==2.17.0`,
`requirements.txt:32`, against `python:3.14.6-alpine3.24`):

```
File "/usr/local/lib/python3.14/site-packages/locust/event.py", line 200, in __init__
    for name, value in self.__annotations__.items():
AttributeError: 'Events' object has no attribute '__annotations__'.
```

That is real (PEP 649/749 deferred annotations) and verified against the 2.17.0
wheel. But **[rev2]** bumping the pin only changes *how* it fails. Verified on
this host:

```
locust 2.17.0
request_success  False
request_failure  False
request          True
```

`tests/performance/locust_tests.py` fires `environment.events.request_success` /
`request_failure` at **eight sites** (lines 126, 133, 143, 162, 169, 194, 201,
211). Those events were **removed in locust 2.0**. Every task raises
`AttributeError` at runtime.

Two more layers beneath that:

- **The ClientHello it builds is structurally corrupt.** `locust_tests.py:83`
  does `struct.pack_into(">I", client_hello, 6, handshake_length)` — writing
  **4 bytes** into the **3-byte** handshake-length field at offsets 6-8. The
  length lands shifted and offset 9 (the first body byte, `0x03`) is clobbered
  with `len & 0xff`. And `:73` emits every extension with length 0, including
  `supported_versions` (43), `key_share` (51) and SNI (0).
- **It points plain HTTP at the TLS passthrough port.** `Makefile:1024` uses
  `--host http://proxy:8080`, while `locust_tests.py:115` separately hardcodes
  `TLSClient("localhost", 8080)` — `localhost` being the *test container*.

### Decision D9 — retire `perf-test`; delete `locust_tests.py` and the dependency

Not close once all four layers are visible. "Fix the pin and the target" is not
a version bump, it is *write a new load tool* — and `scripts/tls-traffic-generator.py`
already exists and already emits four real JA4 families. Keeping it as a smoke
test ships a stage that imports cleanly and throws on every task.

Bonus: dropping locust removes the `msgpack>=1.2.1` pin at `requirements.txt:66`
(which exists *solely* as a locust 2.17.0 transitive) and a large dep tree from
the test image — shrinking the CVE-exception surface Phase 818 just spent a
phase clearing, and removing a scan-regression risk for the in-flight Phase 800
loop. Delete outright; do not archive.

**[rev2]** This also removes a hazard revision 1 missed: `Makefile:1024` runs
`docker compose ... run --rm test locust ... --users 100 --run-time 5m` with
`--env-file .env`, i.e. project `ja4proxy-lane23` — **driving 100 concurrent
users at the developer's live lane for five minutes**, and starting its
`depends_on` services there.

---

## F6 — `test-go-perf` skips itself and reports success

`tests/performance/test_bench_go_proxy.py:25` defaults `GO_PROXY_PORT` to
**18082**. Lane 23 publishes `HOST_PORT_DIRECT=10381`; the compose default is
8081. Nothing listens on 18082, so all four tests `pytest.skip`, pytest exits
0, and `bench-all` counts the stage as passed.

At the real port it works:

```
GO_PROXY_PORT=10381 → 43375 connections in 10.2s = 4264.5 conn/s (10 threads)
                       mean 0.05ms / p50 0.05ms / p99 0.26ms
                       sustained: 1000 ok, 0 failed   → 3 passed, 1 skipped
```

Caveats that keep this from being a headline number:

- `_one_connection` (`:59-65`) does a bare TCP connect-and-close — **no
  ClientHello, no bytes**. Accept-rate, not handshake throughput.
- The assertion is a **≥1 conn/s** sanity floor, not a gate.
- **[rev2 — do not promote this figure.]** `:80-85` drives 10 **GIL-bound
  Python threads** doing blocking `socket.create_connection`. There is no
  evidence 4,264 CPS isn't the *harness's* ceiling rather than the proxy's.
  Revision 1 called it "the only real end-to-end numbers from this exercise" —
  that is 819a's F1 error repeated in the replacement number. Any use requires
  a harness-headroom check first.

### D10 — delete `test_go_vs_python_throughput_ratio`

It compares against the Python proxy deleted in the Go rewrite. **[rev2 — this
is load-bearing, not cosmetic:]** `:27` defaults `PYTHON_PROXY_PORT` to **8081**,
which is also `docker-compose.poc.yml`'s `${HOST_PORT_DIRECT:-8081}`. On a
non-lane machine, once F6's port fix lands, *both* `_check_port` calls succeed
against **the same Go proxy** and the test asserts a ≥2.0× ratio of a thing
against itself → **guaranteed failure, not a skip.**

Also fix while here: `:10` documents the default port as 8082 while `:25` uses
18082; `:38` directs the reader to `make test-live`, **which does not exist**;
`:70-72`'s docstring promises a 3-tuple and `:94` returns 2.

---

## F7 — `load-test` cannot run, and "fixing" it makes it silently green

`Makefile:1271-1276` expands four variables defined **nowhere** (`git log -S
"LOAD_TEST_TARGET ?=" -- Makefile` is empty; they are only set inline by
`load-test-baseline` at `:1279-1282`):

```
python3 scripts/load_test.py --target --duration --rps --scenario
load_test.py: error: argument --target: expected one argument
make: *** [Makefile:1272: load-test] Error 2
```

`load-test-baseline` is broken two further ways: it passes
`LOAD_TEST_SCENARIO=baseline`, but Phase 86i removed it —
`scripts/load_test.py:391` uses `choices=sorted(SCENARIOS.keys())` =
`{attack-wave, bypass-only, full-signal, mixed}`, and `"baseline"` survives only
in `_LEGACY_SCENARIOS` (`:81`), which is not in `choices`. And
`LOAD_TEST_TARGET=localhost:8080` — **[rev2]** worse than "the container-internal
port" as revision 1 said: on a default stack `docker-compose.poc.yml` publishes
**analytics** on `${HOST_PORT_ANALYTICS:-8080}`, so `load-test-baseline` would
load-test the analytics node.

### **[rev2]** F7a — the stage produces no measurement even when it runs

Revision 1's D3 kept `load-test` in `bench-all` for "the only scenario-based
coverage". It provides none:

- `scripts/load_test.py:287-296` builds `raw_data` from `{scenario,
  fingerprint_mix, fingerprint_mix_arg, cmd}`. **No throughput, no latency, no
  error count, no connection totals.**
- `:282` — `report_text = (proc.stdout or "")[-2000:]`. The only record of the
  run is the last 2000 characters of ANSI-coloured stdout.
  `tls-traffic-generator.py` prints `Connections/sec:` at `:421` then continues
  with per-profile tables (`:462-494`), so on a 4-profile mix **the throughput
  line is frequently truncated out of the artefact**.
- `:468` propagates the subprocess exit code, but `tls-traffic-generator.py:680`
  calls `generator.run()` and falls off the end of `main()`. **There is no
  non-zero exit for "0 successful connections"** — `load-test` exits 0 on a
  totally failed run.
- `:446-448` reads `rd.get("connections_attempted")` / `rd.get("throughput")`
  for the Pushgateway path — keys `run_benchmark` never sets. Always 0.
- `--rps` is inert by its own help text (`:382-386`: "documented; benchmark
  engine runs at native max throughput").

So adding `LOAD_TEST_*` defaults would turn `load-test` from *loudly broken*
into *silently green* — a regression against 819a's D-D, delivered by the phase
meant to enforce it.

### D11 — extract real metrics, or drop the stage

Either give `run_benchmark` structured output (parse the generator's results
rather than tailing stdout) **and** give `tls-traffic-generator.py` a non-zero
exit path for zero successful connections — or remove `load-test` from
`bench-all` entirely. Do not add defaults to a stage that cannot report a
number. Lane-derived defaults come only after it can.

---

## F8 — `bench-micro` misses a hot-path package, and `bench-all`'s help text has drifted

**[rev2 — new.]** `Makefile:1202` hardcodes `./cmd/ja4pd/ ./internal/tls/`.
`internal/security/tap_consumer_test.go:416,431` contains
`BenchmarkTapConsumer_GetSignal_CacheHit` and `_RedisHit` — hot-path signal
lookups — which **no target runs**. Revision 1 said micro-benchmarks "need
nothing". Same hardcoded-list drift Phase 815 exists to eliminate; derive the
package list or add the package.

`Makefile:1606`'s help text says "(perf, load, go-perf, MTTR)" but `:1608` also
runs `bench` (micro + macro). If Phase 815 generates `MAKEFILE_TARGETS.md` from
`##` comments, this drift propagates into the generated doc.

---

## F9 — `measure-mttr`: why `redis-cli` was not found, and the five blockers behind it

819a removes this stage from `bench-all` on day one. This phase makes it
correct and safe as a standalone target.

### Blocker 1 — the pre-flight assumes a host-installed client

`scripts/measure_mttr.sh:45-49` checks `command -v redis-cli` on the **host**.
Nothing in this project installs one and nothing should: `AGENTS.md`
"Container-Strict Execution" forbids host tooling, and Redis only runs as a
container. It then `exit 0`s — a **silent success**, which is why `bench-all`
counted it as a pass.

### Blocker 2 — there is no host-reachable Redis for this stack

`docker-compose.poc.yml:127-129` carries the comment `# No host port exposure —
internal to ja4proxy-data only.` and no `ports:` key. `ss -ltn` confirms nothing
listens on 6379.

**[rev2 — two corrections to revision 1 here.]** I wrote that "only `proxy` and
`management` publish ports" — false; `haproxy` publishes at `:29-31` and
`analytics` at `:323-324`. And I asserted the script would connect to the
running `ja4range` stack — also false: `ja4range-redis-1` exposes `6379/tcp`
but publishes no host port, and **nothing is listening on host 6379 at all**.

The generic hazard is real and the *specific* target is inside this repo:
`docker-compose.yml:57-58` publishes `127.0.0.1:6379:6379` with
`--requirepass ${REDIS_PASSWORD:-changeme}` read from the same `.env` the script
reads. So the quick-start stack is the one Redis that would both answer *and*
accept `REDISCLI_AUTH` — and Blocker 4's `$COMPOSE up -d` is what would create
it. The only thing preventing the loop from closing is statement ordering: the
PING at `:51` runs before the `up` at `:95`.

Consequence if it did close: `SET config:dial 100`, `PUBLISH config:reload`,
`SET ja4proxy:mttr_probe` against an unintended database — a **live
security-policy change** delivered over the same pub/sub channel the Management
UI uses. Against a production Redis reached through an SSH tunnel, that is a
self-inflicted "real browsers blocked" outage of exactly the kind `CLAUDE.md`'s
core asymmetry exists to prevent.

**[rev2]** Also drop `export REDISCLI_AUTH` (`:30`): it sends the lane's Redis
password to whatever host answers on 6379.

### Blocker 3 — an invalid Docker subcommand, and a fix that is worse than the bug

`scripts/measure_mttr.sh:86`:

```bash
REDIS_VOLUME=$($COMPOSE volume ls --format '{{.Name}}' 2>/dev/null | grep -i redis | head -1)
```

`docker compose volume ls` does not exist (it prints the usage banner and exits
1), so `REDIS_VOLUME` is always empty and the script takes its *second* silent
`exit 0`.

**[rev2 — revision 1's prescription was the single most dangerous line in the
plan.]** I wrote "the correct call is `docker volume ls`". That is host-global.
Verified on this machine:

```
$ docker volume ls --format '{{.Name}}' | grep -i redis | head -1
ja4_claude0_redis-sock
```

That is **another agent's lane**, one of 21 redis-matching volumes across ~10
projects. It is not in use, so `docker volume rm` at `:176` would **succeed**,
and `2>/dev/null || true` means nothing is reported. `head -1` is a lottery.

The correct call is `docker compose volumes` — **plural, it exists, and it is
project-scoped** — or `docker volume ls --filter
label=com.docker.compose.project="$PROJECT" --filter name=redis-data`, with a
hard failure on 0 or >1 matches and no `|| true`.

### Blocker 4 — the script targets the developer's live lane

**[rev2 — revision 1 had this exactly backwards, and the truth is worse.]** I
wrote that bare `docker compose` resolves the root `docker-compose.yml` "under a
different project name than `ja4proxy-lane23`". Verified:

```
$ docker compose config | grep '^name:'      →  name: ja4proxy-lane23
$ docker compose config --services           →  redis ja4proxy management management-tls
```

Compose auto-loads `./.env`, which sets `COMPOSE_PROJECT_NAME=ja4proxy-lane23`.
So bare `docker compose` uses the **root 4-service file against the live lane
project**. There is no project-name separation protecting anything.

`$COMPOSE up -d` at `:95` therefore reconciles the live lane against the
quick-start file:

- `redis` exists in both with completely different definitions (lane:
  `redis:7.4.9-alpine`, `redis-entrypoint.sh`, seven secret mounts, named
  data + socket volumes; root: `redis:7-alpine`, `--requirepass`, `tmpfs:
  /data`). Different config hash → **Compose recreates the lane's Redis**,
  detaching both volumes and dropping the unix socket lane services connect over.
- **Auth breaks fleet-wide.** `redis-entrypoint.sh` renders an ACL file where
  `user default off`; lane services authenticate as named ACL users
  (`analytics`, `management`, `ja4tap`, `exporter`). The root `--requirepass`
  Redis has no such users. Total lane outage.
- Three new containers (`ja4proxy`, `management`, `management-tls`) are created
  **in the lane project**. `docker-compose.yml:121` publishes
  `"${PROXY_PORT:-8443}:8443"` — **`0.0.0.0`, not loopback** — so a benchmark
  target would silently expose a proxy on every interface.
- The other 14 lane containers become **orphans**. Compose only warns today —
  but the repo already uses `--remove-orphans` elsewhere
  (`nightly-benchmark.yml` teardown), so the single most likely "cleanup
  improvement" someone adds deletes the entire dev lane.

`HEALTH_URL` is also lane-unaware: `:18` defaults to `localhost:8090` while
lane 23's management API is `HOST_PORT_MANAGEMENT=10390`.

### Blocker 5 — it measures the wrong container

**[rev2 — new, found in review.]** `:60-72` pipes `$COMPOSE ps --format json`
into `json.load`. Compose v2 emits **NDJSON**:

```
PARSE FAILED: JSONDecodeError Extra data: line 2 column 1 (char 1407)
```

So the primary path always throws and the fallback at `:76` runs:

```
$ docker compose ps --services | grep -i proxy | head -1
docker-socket-proxy
```

Scenario 2 stops and starts the **Docker-socket proxy sidecar** and publishes
that as "Single node failure" MTTR. A third silent-wrong-measurement of exactly
the class 819a exists to eliminate.

### Blocker 6 — no cleanup handler

**[rev2]** `set -euo pipefail` at `:16` with **no `trap`**. Interrupted between
`:155` and `:157` leaves the target Redis at `config:dial 100` with a
`config:reload` already published and nothing to revert it. Interrupted between
`:173` and `:178` leaves Redis stopped with its volume already removed.

### D12 — the isolation contract

Testable requirements, all of which must hold before the pre-flights at
`:45-55` are touched:

- **Explicit project name, never inherited.** `-p` on every invocation, derived
  from 814a's range. **Hard assert** it differs from `.env`'s
  `COMPOSE_PROJECT_NAME` and is not an existing project in `docker compose ls`.
- **Explicit `-f ... --env-file ...` on every call.** Never let Compose
  file-discover the root `docker-compose.yml`.
- **Volume selection project-scoped**, single-match asserted, no `head -1`, no
  `|| true` on the `rm`.
- **Ephemeral host ports**, asserted free before `up`; never `HOST_PORT_*` from
  `.env` nor the root file's 8443/8090/8444/6379.
- **Never `--remove-orphans`.** An orphan in an ephemeral project is a bug to
  fail on.
- **`trap … EXIT INT TERM`** tearing down the ephemeral project and restoring
  the dial.
- **Redis auth via an explicit ACL user** resolved from compose secrets — not
  `REDISCLI_AUTH`, which cannot authenticate against `user default off`. **[rev2]**
  Without this the implementer hits an auth wall mid-work and the tempting
  shortcut is the root compose file, landing straight back in Blocker 4.
- **Identity assert before the first write** — prove the target is the stack
  this script started, e.g. by reading back a seeded sentinel. "I started it,
  therefore it is mine" must be provable.
- **Resolve the proxy container by compose service label**, asserting `== proxy`.
- **Both silent `exit 0` paths (`:49`, `:89`) become `exit 1`.**

**[rev2]** `tests/test_phase64h_mttr.py` asserts the script's *current*
structure ("Derives Redis volume name dynamically", "Uses COMPOSE variable for
all compose commands"). Rewriting per D12 breaks these text-matching tests; they
must be updated in the same commit or `make test` fails.

---

## F10 — container-strict violations inside `bench-all`

**[rev2 — new.]** `Makefile:2` sets `PYTHON ?= $(shell command -v python ||
command -v python3)` → **host Python 3.10.12** here versus **3.14** in the
pinned image. `test-go-perf` (`Makefile:1165`) and `load-test` (`:1272`) both
use it, and `measure_mttr.sh` shells out to bare `python3` at `:61, :112, :128,
:160`. Revision 1 invoked container-strict to justify D12 without noticing that
a third of `bench-all` is already in breach. Route through `$(TOOLS_RUN)` or
document the exemption explicitly.

## F11 — `bench-all` dirties the working tree

**[rev2 — new.]** `measure_mttr.sh:19` writes `MTTR_BASELINE.md` to the repo
root; `git check-ignore` returns 1 and it is not in `git ls-files`. So a
successful `bench-all` leaves an untracked file at the root — and **Phase 800's
gate-runner (IN_PROGRESS) refuses a dirty tree on an all-gates run, exit 64
REFUSED.** Write to `test-results/` or gitignore it.

## F12 — missing build prerequisites

**[rev2 — new.]** `bench-macro` (`Makefile:1204`) has no `go-build cli-build`
prerequisite, unlike `bench-hostnative` (`:1622`). On a clean checkout
`bench-all` dies at stage 2 with `No such file or directory`. (Fixed in 819a
step 4 as part of the `bench-macro` work; recorded here for completeness.)

---

## Implementation plan

Sequenced so nothing destructive is reachable while the rest is in flux. 819a's
step 0 (`measure-mttr` out of `bench-all`) is a hard prerequisite.

1. **F5 / D9** — delete `perf-test`, `locust_tests.py`, the locust pin, and the
   now-orphaned `msgpack` pin comment. Removes the 5-minute live-lane load too.
2. **F6 / D10** — lane-derived `GO_PROXY_PORT`; delete the Python-ratio test;
   replace the ≥1 conn/s floor with a real threshold; label the metric **TCP
   accept-rate**; fix the docstring/`make test-live` errors.
3. **F7 / D11** — decide extract-metrics vs drop. If extracting: structured
   output plus a non-zero exit path in `tls-traffic-generator.py`, *then*
   lane-derived defaults. Fix `load-test-baseline`'s dead scenario and its
   accidental analytics target.
4. **F8** — add `internal/security` to `bench-micro` (or derive the list); fix
   `bench-all`'s help text.
5. **F10 / F11** — route host-Python stages through `$(TOOLS_RUN)`; relocate
   `MTTR_BASELINE.md`.
6. **F9 / D12** — only after 814a's range exists. Isolation contract first, as
   its own commit with a test proving a run cannot reference the lane project;
   the pre-flights at `:45-55` are unblocked **last**. Update
   `tests/test_phase64h_mttr.py` in the same commit. Add `measure-mttr` to a
   scheduled workflow, not to `bench-all`.

## Test plan

- **Lane-awareness:** with a non-default `HOST_PORT_DIRECT`, every stage targets
  the right port.
- **Isolation proof (D12):** a test asserting `measure_mttr.sh` cannot resolve
  the lane project name or a volume outside its own project; and that an
  interrupted run leaves no stopped container, no removed volume, and the dial
  restored.
- **Empty-result contract:** each stage exits non-zero on absent environment
  *and* on zero measured connections (this is what F7a needs).
- **Exit-path test** for `tls-traffic-generator.py` with 0 successful connections.
- **Harness-headroom check** for `test-go-perf` before its number is quoted
  anywhere (F6 caveat).
- Per `CLAUDE.md`'s web-service rule, `test_container_config.py` coverage for
  any compose env the surviving stages need.

## Acceptance criteria

1. Every surviving `bench-all` stage produces a real measurement or fails
   loudly — including on empty results.
2. No stage hardcodes a port; all derive from `.env`/lane config.
3. `perf-test` and the locust dependency are gone; `make scan`'s surface shrinks.
4. `measure-mttr` runs only against an isolated ephemeral stack, is absent from
   `bench-all` and `verify-all`, and cannot reference the lane project — proven
   by test, including under interruption.
5. `bench-all` leaves the working tree clean.
6. No `bench-all` stage runs host Python, or the exemption is documented.
7. A full `make bench-all` completes green with every stage measuring.
8. `make lint-phases` exits 0; changelog fragment under `docs/fragments/`.

## Out of scope

- Everything in [PHASE_819a](PHASE_819a.md).
- Building a new ephemeral-stack harness — consume 814a's.
- Multi-instance scaling curves (1/2/4/8 proxies). Single-instance truth first.

## Risks

| Risk | Mitigation |
|---|---|
| F9 work destroys a lane during implementation or review | 819a step 0 removes it from `bench-all` first; D12's isolation lands before the pre-flights are unblocked; no reviewer needs to run it |
| 814a slips, blocking F9 | F9 is last in the sequence and independently deferrable — steps 1-5 deliver value without it |
| Retiring locust is later regretted | `tls-traffic-generator.py` already covers four JA4 families with real fingerprints; F7's D11 work is where scenario coverage belongs |
| Collision with Phase 815 (generated `MAKEFILE_TARGETS.md`) | Give every new/changed target a `##` description; never hand-edit the generated docs. Land 819a/b first or re-snapshot 815's count |
| Collision with Phase 800 (gate-runner) | F11 fixes the dirty-tree break; D9 removes the locust scan-regression risk |
| Collision with Phase 814k (Redis/backup pentest) | Its range volumes are exactly what revision 1's `docker volume ls` prescription would have deleted. D12's project-scoped selector is the fix |
