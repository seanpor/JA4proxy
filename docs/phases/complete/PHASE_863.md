<!--
title: Go Proxy Build Hardening — Security & Throughput Optimization
audience: developer
last_reviewed: 2026-11-04
phase: 863
-->

# Go Proxy Build Hardening — Security & Throughput Optimization

> **Size:** LARGE
> **Dependencies:** [862]
> **Branch:** `phase-863-go-build-hardening`
> **Work packages:** 863a → 863b → 863c → 863d (sequenced; 863b gates 863c)

---

## Goal

Harden the production Go proxy binary and container image:

- **Security:** PIE/ASLR, GNU_RELRO, minimal runtime image (no package manager; a shell only when justified), no unnecessary packages (`curl`) in the runtime. **BIND_NOW is a compliance checkbox here, not a pillar** — Go performs no lazy PLT binding and static-PIE self-relocates eagerly, so the substantive mitigations are PIE + RELRO.
- **Throughput:** Profile-Guided Optimization (PGO), correct memory-limit/GC tuning.
- **Reproducibility:** `-buildid=`, `-trimpath`, pinned digests. (`-buildid=` is **necessary but not sufficient** for reproducible output — same toolchain + `-trimpath` + no timestamps are also required. Do not overclaim.)

Target: an internet-facing, high-throughput, inline network security proxy — regressions here are fail-open traffic-path incidents, so every step is gated and independently revertable.

---

## Critical Prerequisites & Design Corrections (from Principal Systems Review)

1. **Native `_FILE` secret resolution in Go (`internal/config/loader.go`):**
   - Current `deploy/docker/docker-compose.prod.yml` relies on `/bin/sh -c 'export REDIS_PASSWORD=$(cat /run/secrets/redis_password); exec /usr/local/bin/ja4pd'`.
   - Distroless minimal runtimes (`gcr.io/distroless/static`) have **no `/bin/sh`**.
   - **Fix:** In `internal/config/loader.go`, teach `expandEnvVars` native `_FILE` fallback: if `${VAR}` is requested and `$VAR` is unset/empty, check if `${VAR}_FILE` is set. If `${VAR}_FILE` exists and points to a readable file, read and trim its contents. Also support direct `${VAR_FILE}` expansion.
   - This eliminates the `/bin/sh` entrypoint wrapper in `docker-compose.prod.yml`, allowing the container to use direct exec form `ENTRYPOINT ["/usr/local/bin/ja4pd"]` with `environment: [REDIS_PASSWORD_FILE=/run/secrets/redis_password]`.
2. **Native zero-dependency health check probe (`cmd/ja4pd`):**
   - Distroless minimal runtimes contain neither `curl` nor `wget`.
   - **Fix:** Add a lightweight `ja4pd --health-check` (or `ja4pd healthcheck [--url=...]`) command to `cmd/ja4pd/main.go` that performs a direct HTTP GET with timeout and exits 0 on 200 OK, 1 otherwise.
   - This makes `HEALTHCHECK CMD ["/usr/local/bin/ja4pd", "--health-check"]` completely self-contained and immune to base image utility differences.
3. **CGO Musl Static PIE Validation (F2 vs V1):**
   - Empirical test confirmed: `CGO_ENABLED=1 -buildmode=pie -linkmode external -extldflags "-static -z relro -z now" -tags netgo,osusergo` successfully produces a `static-pie linked` executable with `BIND_NOW` and `GNU_RELRO` that executes cleanly in distroless static.
   - To guard against musl static thread stack / cgo traps, the spike in 863b must include `make test-race` and high-concurrency soak testing (`make test-soak`).
4. **Memory and GC Tuning Calibration:**
   - Instead of aggressive `GOGC=50`, default to `GOGC=100` and `GOMEMLIMIT=400MiB` (leaving 112MiB headroom under the 512MiB cgroup limit for off-heap buffers, OS threads, and connection tables). Benchmark before/after.
5. **Representative Macro-Workload PGO:**
   - Profile collection must use representative TLS pipeline workloads (mixed handshakes, extensions, JA4 fingerprints), not synthetic single-function tight loops.

---

## Verified design constraints (read before touching anything)

These were **empirically verified on 2026-11-04** in the actual builder image (`golang:1.27.3-alpine`) and runtime candidates (`gcr.io/distroless/static:nonroot`, `:debug`). Do not re-derive them; re-run the probes only to confirm the toolchain hasn't changed.

### The flag matrix (all rows tested)

| # | Configuration | BIND_NOW | GNU_RELRO | Runs in `distroless/static` | Notes |
|---|---------------|----------|-----------|------------------------------|-------|
| V4 | `CGO_ENABLED=0`, no pie, `-extldflags "-static"` **(current production)** | no | **no** | yes | `ET_EXEC`, no RELRO at all today |
| V1 | `CGO_ENABLED=0 -buildmode=pie` | no | yes (Go adds it for pie) | **no** — `exec: no such file or directory` (exit 255), needs `/lib/ld-musl` | `-extldflags` **silently ignored** — no gcc in builder → internal linking |
| F1 | `CGO_ENABLED=1 -buildmode=pie -linkmode external -extldflags "-z relro -z now"` | **yes** | **yes** | **no** — dynamic musl loader missing | |
| **F2** | **`CGO_ENABLED=1 -buildmode=pie -linkmode external -extldflags "-static -z relro -z now"`** | **yes** | **yes** | **yes** (verified: binary runs, prints output) | **← chosen configuration** |

### Other verified facts

1. **`-linkmode` and `-buildid=` are linker flags — they go INSIDE `-ldflags=`**, not as bare `go build` flags (`go build -buildid=` errors: `flag provided but not defined`).
2. **`-linkmode external` requires `CGO_ENABLED=1`** — Go rejects it otherwise: `linkmode requires external (cgo) linking, but cgo is not enabled`.
3. **`-pgo=auto` is already the default** (per `go help build`). Adding it changes nothing. It looks for `default.pgo` **in the main package's directory** — i.e. **`cmd/ja4pd/default.pgo`**, *not* the repo root. A profile at the repo root is silently ignored.
4. **`GOEXPERIMENT=loopvar` is a no-op** — `go.mod` floors at `go 1.26.10`; loop-variable semantics have been default since Go 1.22. Do not add it.
5. **The proxy container is limited to `memory: 512M`** in *both* `docker-compose.poc.yml` and `docker-compose.prod.yml`. `GOMEMLIMIT` must sit **below** that limit (use `440MiB`); a value above it (e.g. `800MiB`) lets the heap grow past the cgroup limit so the limiter never engages and the kernel OOM-kills the proxy instead.
6. **First-party code has zero `import "C"`**, and the only gopacket imports are `layers` + `pcapgo` (pure Go) — `internal/tap/capture.go` does **not** need libpcap. `CGO_ENABLED=1` therefore compiles without adding libpcap to the builder. (`make test` must still prove this.)
7. **Size impact of F2:** ~+14% on a hello-world (1.51 MB → 1.73 MB). Record the real `ja4pd` delta in 863b.
8. **The Dockerfile `HEALTHCHECK` is load-bearing:** `deploy/docker/docker-compose.test.yml` builds `go-proxy` from `Dockerfile.go-proxy`, and other test services wait on it with `condition: service_healthy`. Breaking the healthcheck breaks the integration stack.
9. **`gcr.io/distroless/static:debug` exists and ships busybox** (incl. `wget`) at `/busybox`, which **is on its default `PATH`**. Its default `ENTRYPOINT` is `/busybox/sh` and default `USER=0` — our Dockerfile overrides both (`ENTRYPOINT ["/usr/local/bin/ja4pd"]`, `USER 1000:1000` — required by Pod Security Admission `restricted`, see ADR-202c).
10. **Alpine's busybox `wget` works** (`wget -q -O /dev/null <url>`), and the monitoring compose already uses `wget --spider` for other services. The `apk add curl` in the runtime image is removable in favour of busybox wget.
11. **`CGO_ENABLED=1` can activate the cgo DNS resolver.** Verified: the F2-shaped build links `cgoLookupHost`/`_cgo_getaddrinfo`, and `GODEBUG=netdns=2` reports *"dynamic selection of DNS resolver"* (in one probe `netCgo=false`, but that is environment-dependent). The cgo resolver blocks an OS thread per lookup and **cannot be cancelled via `context`** — a DoS vector for this proxy's DNS work (`internal/security/dns_enrichment.go` FCrDNS, backend resolution, webhook/TI). **F2 therefore requires `-tags netgo,osusergo`** to keep the async, cancellable pure-Go resolver (verified: builds with external linking, `netGo=true`).
12. **`go version -m` does NOT print `-ldflags` or `-buildid`** (verified: it shows `-buildmode`, `-trimpath=true`, `CGO_ENABLED` only). To prove `-buildid=` took effect, use **`go tool buildid ./ja4pd` → empty output** (verified).
13. **`go tool pgo` does not exist** (`go: no such tool "pgo"`). `go tool preprofile` does exist, **but the build invokes it automatically** — `default.pgo` must be a raw pprof CPU profile (verified: build runs `preprofile -i default.pgo` and passes `-pgoprofile=…` to `compile`). Writing the *output* of `go tool preprofile` into `default.pgo` double-processes it and fails with `preprofile: error parsing profile: unknown wire type: 7` (verified). Also `-pgo=instrument` is **not** a special value — Go treats it as a file path.

---

## Design decision (decide in 863b with both options costed)

**Provisional choice: F2** — RELRO + PIE + BIND_NOW, statically linked so it runs on distroless. **This is not settled.** 863b must run the V1-vs-F2 spike below before 863c is allowed to start, and the chosen option is recorded here.

| Option | Mitigations | Cost / risk |
|--------|-------------|-------------|
| Keep current (V4) | none (ET_EXEC, no RELRO) | status quo |
| **V1:** `CGO=0 -buildmode=pie`, **Alpine runtime** | PIE + GNU_RELRO | **zero C code**; no BIND_NOW; keeps `apk`/shell |
| F1: `CGO=1` dynamic pie | PIE + RELRO + BIND_NOW | needs musl loader → **fails distroless** |
| **F2:** `CGO=1 -linkmode external -extldflags "-static -z relro -z now"` | PIE + RELRO + BIND_NOW | **statically links musl C code**; needs gcc/musl-dev; needs `netgo,osusergo` to keep the safe resolver |
| Full RELRO **without** CGO | — | **impossible** — `-extldflags` is discarded by internal linking (V1) |

**Why V1 is co-equal, not a mere fallback:** for a memory-safety-sensitive security product, adding a statically-linked C library to buy mitigations *against C-code exploitation* is a genuine trade-off, not a clean win. And `distroless/static:debug` **retains busybox**, so the "no shell" benefit is not realized — the remaining distroless gain is "no package manager + fewer packages". BIND_NOW adds little for Go (see Goal). If the F2 spike shows any resolver/`make test` instability, **V1 + Alpine is the preferred outcome** — PIE + RELRO with zero C code.

**Decision spike (must run in 863b):** build both V1 and F2 from the real `ja4pd`, run `make test` + `make test-race` + `readelf`/`ldd`, and record the table above with measured results. Pick F2 only if the DNS pinning (fact 11) and race tests are clean; otherwise pick V1 and skip 863c's distroless migration (keep Alpine).

**Accepted trade-off if F2 stands:** `CGO_ENABLED=1` statically links musl and enables the cgo runtime. Mitigations: first-party code has no `import "C"` (fact 6); the binary stays fully static (`-static`); **`-tags netgo,osusergo` pins the pure-Go resolver** (fact 11); `make test` + `make test-race` gate the change.

---

## Work package 863a — Safe hardening wins & Zero-Dependency Foundations

Independent of the F2 decision. Ship first; revertable on its own.

### Scope

1. **`Makefile` `LDFLAGS` (lines 17–19):**
   - Add `-buildid=` **inside** the existing `-ldflags="..."` string. Pair it with `-trimpath` and pinned toolchain/base images; `-buildid=` alone does **not** guarantee reproducibility.
   - Add `-trimpath` explicitly to the `go-build`/`cli-build`/`go-build-foss` invocations.
   - Do **not** add `-pgo=auto` (already default), `GOEXPERIMENT=loopvar` (no-op), or bare `-buildid=` (errors).
2. **Native `_FILE` secret reading in Go (`internal/config/loader.go`):**
   - When expanding `${VAR}` or `${VAR:-default}`, if `VAR` is unset/empty, check if `${VAR}_FILE` exists in the environment. If so, read and strip whitespace from the file.
   - Eliminates `/bin/sh` wrapper requirement for Docker/Kubernetes secrets in production compose!
   - Update `deploy/docker/docker-compose.prod.yml` to set `REDIS_PASSWORD_FILE=/run/secrets/redis_password` and use native exec form entrypoint without `/bin/sh`.
3. **Native zero-dependency healthcheck subcommand (`cmd/ja4pd`):**
   - Implement `ja4pd --health-check` (or `ja4pd healthcheck [--url=...]`) in `cmd/ja4pd/main.go`.
   - Update `Dockerfile.go-proxy` to `HEALTHCHECK CMD ["/usr/local/bin/ja4pd", "--health-check"]`.
   - Completely removes dependency on `curl` or `wget` from runtime images!
4. **Runtime memory limits & GC tuning** (Dockerfile `ENV`, overridable by compose):
   - `GOMEMLIMIT=400MiB` (leaves 112MiB headroom under 512M cgroup limit).
   - `GOGC=100` (evaluate `GOGC=50` bench-gated; keep `100` if GC CPU overhead increases).

### Acceptance criteria (863a)

- [ ] `go tool buildid bin/ja4pd` prints **empty** (proves `-buildid=` took effect — fact 12; `go version -m` cannot show ldflags, so it must not be used for this). `go version -m bin/ja4pd | grep -- '-trimpath=true'` still succeeds.
- [ ] `readelf -d bin/ja4pd` **still shows no BIND_NOW** at this stage (expected — F2 comes in 863b; this criterion exists so nobody "fixes" it early with CGO).
- [ ] `docker inspect ja4proxy:2.0.0 --format '{{.Config.Healthcheck.Test}}'` shows the wget exec-form command; no `curl` in `docker history`.
- [ ] `docker exec <proxy> env` (or `docker inspect`) shows `GOMEMLIMIT=440MiB`; value is strictly below the compose `memory: 512M` limit.
- [ ] `make bench-macro` before/after: no throughput regression >2% with `GOGC=50` (or GOGC dropped, with note).
- [ ] `make test` and `make lint` green.

---

## Work package 863b — Hardened link flags (F2 validation against the real binary)

Gates 863c. Everything here must be proven on **`ja4pd` itself**, not a toy.

### Scope

0. **Run the V1-vs-F2 decision spike first** (Design decision section): build both from the real `ja4pd`, run `make test`/`make test-race`, compare `readelf`/`ldd`/size, and record the outcome in this file. **Do not continue to 863c on F2 unless the spike is clean.**
1. **Builder image** (`Dockerfile.go-proxy` build stage): add `gcc` and `musl-dev` to `apk add` (needed for external linking).
2. **Build command** — apply F2 **with `netgo,osusergo`** (keep the existing `-X` version-stamp flags):
   ```dockerfile
   RUN CGO_ENABLED=1 GOOS=linux go build \
       -buildmode=pie -trimpath \
       -tags netgo,osusergo \
       -ldflags="-s -w -buildid= \
         -linkmode external \
         -extldflags \"-static -z relro -z now\" \
         -X github.com/seanpor/ja4proxy/internal/config.Version=${VERSION} \
         -X github.com/seanpor/ja4proxy/internal/config.GitCommit=${GIT_COMMIT} \
         -X github.com/seanpor/ja4proxy/internal/config.BuildDate=${BUILD_DATE}" \
       -o /ja4pd ./cmd/ja4pd
   ```
   Note the nested quoting: the two `-extldflags` sub-flags are **space-separated inside one quoted string**; the comma form (`-z,now,-z,relro`) was verified as a no-op. `-tags netgo,osusergo` is **mandatory** — without it the cgo resolver can be selected at runtime (fact 11).
3. **`Makefile` `go-build` / `cli-build` / `go-build-foss`:** apply the same hardened recipe (`CGO_ENABLED=1`, pie, `-tags netgo,osusergo`, linkmode external, static+relro+now) so the host binary matches production shape. **Host C toolchain is now a hard requirement** for these targets (it already is for `make test-race`, which needs cgo): `make doctor` must **fail** (non-advisory) when `gcc` is absent, with the exact remediation; `go-build` prints the same message and exits non-zero rather than silently building a different-shaped binary.
4. **Single flag source, enforced (required, not optional):** extract the recipe into `scripts/go_build_hardened.sh` (or a shared `.mk` include) and have `Makefile` + every Go `Dockerfile` call it. Add **`tests/unit/test_go_build_flags_sync.py`** that enumerates **all** Go build recipes — `Makefile` (`go-build`, `cli-build`, `go-build-foss`), `deploy/docker/Dockerfile.go-proxy`, `Dockerfile.go-proxy.foss`, `Dockerfile.cli`, `Dockerfile.ja4-tap`, `.goreleaser.yml` — and asserts each either matches the hardened recipe/shared script or appears in an explicit, commented deferral allowlist naming the follow-up phase. Silent divergence must fail CI.
   - `.goreleaser.yml` is **stale**: it points at `./cmd/ja4proxy-cli/`, which does not exist in-tree (`cmd/` only has `ja4p`, `ja4pd`, `ja4-tap`), yet `release-cli.yml` still runs goreleaser. Do not harden a broken recipe here — record it as a separate finding and add an explicit allowlist entry with a follow-up reference. (Also verify whether the release job currently fails; that is a pre-existing issue, not this phase's.)
5. **Keep a comment in both files:** `# Keep in sync: F2 hardened flags — see docs/phases/PHASE_863.md flag matrix`.

### Acceptance criteria (863b)

- [ ] `docker run --rm --entrypoint /usr/local/bin/ja4pd ja4proxy:2.0.0 --help` (or equivalent) starts without loader errors — proves the F2 binary executes.
- [ ] Inside the built image (or from the artifact): `readelf -d ja4pd | grep BIND_NOW` → **present**; `readelf -l ja4pd | grep GNU_RELRO` → **present**; `file ja4pd` → `pie executable`.
- [ ] Binary is fully static despite PIE: `ldd ja4pd` → `not a dynamic executable` (or no musl interpreter in `readelf -l`).
- [ ] `CGO_ENABLED=1` does not break the build: `make build` green; `make go-build` green on a host with gcc. `make doctor` fails with actionable text when gcc is absent (hard requirement).
- [ ] **DNS resolver is the pure-Go one (fact 11):** `GODEBUG=netdns=2 ./bin/ja4pd ... 2>&1 | grep -i "using the Go DNS resolver"` on the **production (stripped) binary**; and on an **unstripped sibling build** (same flags minus `-s -w`), `go tool nm | grep -c cgoLookupHost` → `0` (symbol inspection is impossible on `-s -w` output). **If the cgo resolver is still selected, the F2 spike fails → choose V1.**
- [ ] `make test` green (proves fact 6 — no libpcap/cgo fallout in `internal/tap`).
- [ ] `make test-race` green (race detector requires cgo — confirms CGO=1 is race-compatible).
- [ ] `tests/unit/test_go_build_flags_sync.py` added and green — it enumerates every Go build recipe (Makefile ×3, the four Go Dockerfiles) and fails on silent divergence (863b scope 4).
- [ ] Binary size delta vs pre-863b recorded in this file (expect ≈ +14%, hello-world reference).
- [ ] **V1-vs-F2 spike result recorded** in the Design decision table with measured `readelf`/`ldd`/size/test results.
- [ ] **If any criterion above cannot be met (especially the resolver check):** stop, record the failure in this file, and adopt **V1 + Alpine runtime** (per Design decision) — then 863c's distroless migration is cancelled/recorded as not applicable.

---

## Work package 863c — Runtime image migration (distroless)

**Start only when 863b is fully green.**

### Scope

1. Runtime stage: `alpine:3.24.3@sha256:...` → **`gcr.io/distroless/static:debug@sha256:<pin-digest>`** (fact 9: busybox `wget` on `PATH`, incident-response shell retained — deliberate trade-off: a shell without capabilities/with `cap_drop: ALL`, `read_only`, `no-new-privileges` is low attacker value and high operator value).
2. Keep in the Dockerfile: `USER 1000:1000`, `ENTRYPOINT ["/usr/local/bin/ja4pd"]`, CA certs copy, `HEALTHCHECK` exec form (`wget` resolves via `/busybox` on PATH).
3. **Delete** the `apk upgrade` / `apk add` / `addgroup`/`adduser` lines — distroless has no package manager; the user is created via numeric `USER` only (no passwd entry needed; numeric UID satisfies PSA `restricted`).
4. Pin by digest; record the digest in this file.

### Acceptance criteria (863c)

- [ ] `docker run --rm ja4proxy:2.0.0` starts the proxy (no `no such file or directory` loader failure — the F1 failure mode).
- [ ] `docker inspect ja4proxy:2.0.0` healthcheck status transitions to `healthy` (busybox wget works in-image).
- [ ] `docker compose -f deploy/docker/docker-compose.test.yml up` — `go-proxy` reaches `healthy` and dependent services pass their `condition: service_healthy` gates (fact 8).
- [ ] `docker exec <proxy> /busybox/sh -c 'apk --version'` → fails (no package manager — the point).
- [ ] Image size recorded vs Alpine baseline (expect a reduction; `curl` alone is ~1 MB).
- [ ] `make scan-first-party` green (no HIGH/CRITICAL in distroless).
- [ ] `make test` green (container-config tests in `tests/unit/test_container_config.py` may assert on the base image — update them in the same commit if so, never skip).

---

## Work package 863d — Profile-Guided Optimization (PGO)

Independent of 863b/863c; can run in parallel after 863a.

### Scope

1. **Profile location — `cmd/ja4pd/default.pgo`** (fact 3: the main package's directory, *not* the repo root). `-pgo=auto` is already the default — no Makefile flag needed.
2. **Regeneration script — `scripts/gen_pgo_profile.sh`** (the old doc's reference to `scripts/bench_macro.sh` was wrong; the real entry point is `make bench-macro`, client `./bin/ja4p test benchmark`, results compared by `scripts/benchmark_comparison.py`):
   ```bash
   #!/usr/bin/env bash
   # Regenerate cmd/ja4pd/default.pgo from a representative load run.
   # Usage: scripts/gen_pgo_profile.sh [duration-seconds]
   set -euo pipefail
   DUR="${1:-60}"
   # 1. Baseline profile from the real pipeline benchmarks (these exist:
   #    cmd/ja4pd/bench_test.go -> BenchmarkPipeline_Allow / _Score).
   go test -run '^$' -bench 'BenchmarkPipeline' -benchtime 10x \
     -cpuprofile /tmp/pipeline.pprof ./cmd/ja4pd
   # 2. default.pgo is a RAW pprof CPU profile. Do NOT run `go tool preprofile`
   #    yourself — the build runs it (fact 13; doing it manually corrupts the file).
   cp /tmp/pipeline.pprof cmd/ja4pd/default.pgo
   ```
   (Invariant: the profile comes from **representative proxy load** — prefer a pprof capture from a real `make bench-macro` run once a capture path exists; `ja4pd` currently exposes no `/debug/pprof` endpoint, so the pipeline benchmarks are the fallback. It must land at **`cmd/ja4pd/default.pgo`**, and the script must exit non-zero if no profile is produced.)
3. **Regeneration runbook — `docs/runbooks/pgo_regeneration.md`**: when to regenerate (hot-path changes, Go version bumps), how to verify, how to A/B with `scripts/benchmark_comparison.py`.
4. **`.dockerignore`:** ensure `cmd/ja4pd/default.pgo` is **not** excluded (current file does not exclude `*.pgo` — add a test if someone adds a broad glob later).

### Acceptance criteria (863d)

- [ ] `cmd/ja4pd/default.pgo` committed; **no** `default.pgo` at repo root (root one would be silently ignored — fact 3).
- [ ] Profile is actually consumed: `go build -x -o /dev/null ./cmd/ja4pd 2>&1 | grep -E 'preprofile .*default\.pgo|-pgoprofile='` matches (verified output shape). (Fallback proof: temporarily replace the file with garbage → build must **fail** with a profile-parse error; restore it.)
- [ ] `make bench-macro` (container) and/or `make bench-hostnative` (host binary) before/after: **no regression**; ≥3% improvement is the target — if <3%, record the measured delta in this file and keep the profile only if it is non-negative (PGO is kept only if it demonstrably does no harm).
- [ ] `scripts/gen_pgo_profile.sh` exits 0 on a clean tree and exits non-zero when profiling fails.
- [ ] `docs/runbooks/pgo_regeneration.md` exists and its commands were executed verbatim during this phase.
- [ ] `make test` green (profile must not break `go test` — tests don't consume it, but verify).

---

## Global acceptance criteria (whole phase)

- [ ] All four work packages' acceptance criteria checked off, or the documented fallback (V1 + Alpine) recorded in this file with rationale.
- [ ] `make preflight` green (lint + scan + test) on the final tree.
- [ ] `make bench-macro` final numbers recorded in this file: throughput before/after, image size before/after, binary size before/after.
- [ ] The flag matrix in this file matches reality — re-run the V4/V1/F1/F2 probes if the Go or base-image version changed, and update the table.
- [ ] `docs/reference/BUILD_HARDENING.md` documents the final chosen configuration, every flag, and *why* (including the rejected options) — aimed at the next operator, not at the implementer.
- [ ] CHANGELOG fragment dropped in `docs/fragments/phase-863-*.md` (never edit `CHANGELOG.md` directly).

## Test strategy

| Layer | Command | Gate |
|-------|---------|------|
| Unit/Go | `make test`, `make test-race` | required |
| Lint | `make lint` | required |
| Pre-PR | `make preflight` | required |
| Binary shape | `readelf -d/-l`, `file`, `ldd` per acceptance criteria | required (863b) |
| Container boot | `docker run` + healthcheck → `healthy` | required (863c) |
| Integration | `docker compose -f deploy/docker/docker-compose.test.yml up` (`service_healthy` chain) | required (863c) |
| Throughput | `make bench-macro` + `scripts/benchmark_comparison.py` | required (863a GOGC, 863d PGO) |
| CVE | `make scan-first-party` | required (863c) |

## Rollback plan

Each work package reverts independently:

- **863a:** revert `LDFLAGS`/healthcheck/`ENV` lines; `curl` returns.
- **863b:** revert build command + `apk add gcc musl-dev` + Makefile flags; production returns to V4 (current static non-PIE).
- **863c:** revert the `FROM` line to `alpine:3.24.3@sha256:...`; healthcheck/entrypoint unchanged since 863a.
- **863d:** `git rm cmd/ja4pd/default.pgo` — `-pgo=auto` finds nothing and is inert by design.

After any rollback: `make build && make test` must be green before push.

## Files to modify

| File | Work packages |
|------|---------------|
| `Makefile` (`LDFLAGS`, `go-build`, `cli-build`, `go-build-foss`, `doctor`) | 863a, 863b |
| `scripts/go_build_hardened.sh` (new — single flag source) | 863b |
| `deploy/docker/Dockerfile.go-proxy` | 863a, 863b, 863c |
| `deploy/docker/Dockerfile.go-proxy.foss` (call shared recipe or allowlist) | 863b |
| `deploy/docker/Dockerfile.cli` (call shared recipe or allowlist) | 863b |
| `deploy/docker/Dockerfile.ja4-tap` (call shared recipe or allowlist) | 863b |
| `.goreleaser.yml` (stale recipe — verify/defer via allowlist) | 863b |
| `cmd/ja4pd/default.pgo` (new) | 863d |
| `scripts/gen_pgo_profile.sh` (new) | 863d |
| `docs/runbooks/pgo_regeneration.md` (new) | 863d |
| `docs/reference/BUILD_HARDENING.md` (new) | global |
| `docs/fragments/phase-863-*.md` (new) | global |
| `tests/unit/test_container_config.py` (if base-image assertions need updating) | 863c |
| `tests/unit/test_go_build_flags_sync.py` (new — **required** guard, enumerates every Go build recipe) | 863b |

## Out of scope

- **Migrating** `ja4p`/`ja4-tap` images and release artifacts to F2/distroless (separate phases). Their **flag divergence must still be recorded** by the 863b guard test, either by adopting the shared recipe or by an explicit allowlist entry naming the follow-up phase.
- FIPS 140-3 mode (`GOFIPS140`), ARM64 build pipeline.
- Migrating non-proxy images (`ja4p`/`ja4-tap`) to distroless in this phase (separate phases).
- Changing proxy runtime logic, compose resource limits (the 512M limit is the *input* to GOMEMLIMIT, not changed here).
- Re-generating the PGO profile in CI (manual/runbook-driven; CI consumes the committed profile only).