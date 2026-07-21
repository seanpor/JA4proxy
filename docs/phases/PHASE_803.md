---
phase: 803
title: "Go TAP/SPAN Sensor Remediation — Fix Phase 334's Findings"
status: PROPOSED
created: 2026-07-21
audience: [developer]
---

# Go TAP/SPAN Sensor Remediation

> **STATUS: PROPOSED — plan for review. No code until approved.**
> Executes the fixes [[PHASE_334]] (316\* series code review) recommended but
> explicitly did not implement — that phase's scope was review-only by design.
> This phase is the follow-up its own Section 5 acceptance criteria and every
> finding's "Recommendation" field call for.

## Goal (plain language)

Fix the 40+ findings PHASE_334 catalogued in the Go TAP/SPAN passive sensor
(`cmd/ja4-tap`, `internal/tap/`), in priority order, so the sensor is safe to
deploy, observable when it's running, and doesn't quietly violate GDPR. Do
**not** re-review — PHASE_334's findings are the input; read them (they cite
exact file:line evidence) rather than re-deriving them here.

## Why this phase exists

PHASE_334 found the sensor currently has **zero panic recovery** (one crafted
packet permanently hangs it — a packet-of-death DoS that passes liveness
checks while dead), runs with **full `CAP_NET_RAW`** throughout its lifetime
(capability drop was planned, never wired), and **can't be built** by the
project's own `make build` (no Makefile target exists for it at all). None of
this was known before phase-800's manifest audit surfaced the review by
accident — it had sat, complete and unactioned, for a month.

## Priority tiers

PHASE_334 rated each finding CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL. This
phase groups them into four waves so the fixes that matter most for safety
ship first and independently of the larger cleanup.

### Wave 1 — CRITICAL (block production deployment until fixed)

| Finding | Summary | Fix |
|---|---|---|
| F-022 | No panic recovery anywhere; a panic hangs the process forever (deferred `close(s.events)` never runs, main goroutine blocks on the range loop forever) | Wrap the sensor goroutine with `defer recover()` that closes `s.events`, logs the stack, and signals `done` with an error |
| F-002 | Capability drop + seccomp planned, never wired; binary runs with `CAP_NET_RAW` for its entire life | Implement post-bind `setreuid`/`setregid` to a non-root UID/GID (fail closed on error) and load a real seccomp profile scoped to the Go binary's actual syscall set (not the stale Phase-20-Python one at `config/seccomp_tap.json`) |
| R-001 | `ReadPacketData` has no poll timeout; `SIGTERM` is invisible until a packet arrives, so shutdown on an idle sensor requires `SIGKILL` | Add `afpacket.OptPollTimeout(1s)` so `ctx.Done()` is rechecked at least once per second even with no traffic |

### Wave 2 — HIGH (fix before any real deployment)

| Finding | Summary | Fix |
|---|---|---|
| F-014 | Busyloop on persistent read error — 100% CPU burn with no backoff | Add exponential backoff (capped ~1s) on the read-error path; count consecutive errors and fail safe (stop + loud WARN) past a threshold |
| F-023 | Metrics are defined but never registered; no HTTP server; no `/health` — operator cannot tell "idle" from "dead" | `prometheus.MustRegister(tap.Collectors()...)`; add `--metrics-addr` with `promhttp.Handler()` + `/health` |
| O-001 | No Makefile target builds `cmd/ja4-tap` at all | Add `tap-build` target; wire into the `build` chain |
| O-002 | 5 of 7 Alertmanager rules (`deploy/monitoring/alertmanager/rules/tap.yml`) reference metrics that don't exist or are never assigned — those alerts can never fire | Fix each rule's metric name (table of exact wrong→right names is in F-023/O-002's evidence) or remove rules for unimplemented subsystems |
| O-003 | 8 of 11 Grafana dashboard panels (`deploy/monitoring/grafana/dashboards/tap_sensor.json`) show "No data" — same root cause as O-002 | Fix panel metric references or mark unimplemented panels as removed/planned |
| R-002 | Single 100ms deadline shared across 3 sequential Redis writes per event; a Redis hiccup collapses throughput from thousands/sec to ~10/sec for minutes | Add a circuit breaker (skip Redis writes after N consecutive failures, cooldown, resume); stop sharing one deadline across three operations |
| R-004 | Event buffer hardcoded at 1024, no flag, no sizing guidance | Add `--event-buffer int` flag (default 1024), document the memory/drop-rate tradeoff |

### Wave 3 — MEDIUM (privacy/compliance and hardening)

Group by theme rather than fixing 20 individual findings as isolated tasks:

- **Redis security** (F-017, F-018): add `--redis-password`/`REDIS_PASSWORD` env support (get the password off the command line / `ps aux`); add `--redis-tls` to force TLS regardless of URL scheme.
- **Concurrency safety** (F-016, G-001): guard `JA4TBlocklist` with a `sync.RWMutex` (latent panic risk once any writer exists); deep-copy `StackFeatures.OptionOrder` at emit time to match the handshake-bytes pattern.
- **Operability** (R-005, R-007, R-008, R-009, R-010): periodic heartbeat log (not gated by `--quiet`); `SIGHUP`/`SIGUSR1` handlers; `--log-format json` + `--log-level`; config file / env var support; `GOMEMLIMIT` guidance.
- **Ban provenance** (D-001): sensor-written bans currently show as `"manual_ban"` in the audit log and can silently overwrite an operator's 24h ban with a 5-minute TTL. Tag provenance in the bypass reason; have the sensor check for an existing operator ban before overwriting.
- **Cache correctness** (D-002): `TapConsumer`/`JA4TConsumer` cache "not found" the same as "cached empty" — a transient Redis miss poisons the signal for a full 60s TTL. Use a sentinel for negative caching, or a much shorter negative-cache TTL.
- **Privacy/GDPR** (P-001, P-002, P-003): write `docs/PRIVACY.md` (what's captured, what's persisted, retention periods, what is explicitly *not* persisted); document that `fp:*`/`ban:*` key names contain IPs (PII) so any `~fp:*` Redis ACL grantee can enumerate the tracked-client corpus; add an `--exclude-ips` mechanism and a documented manual-erasure runbook section for GDPR Article 17 requests.
- **Deployment infra** (O-004, O-005, O-006): Prometheus scrape target for the sensor; a real `Dockerfile.ja4-tap` + compose service + resource limits + HEALTHCHECK; a `ja4tap` Redis ACL user in `config/redis_acl.conf` (the runbook already documents the ACL commands — the canonical config file just doesn't have them).
- **Reassembler correctness** (T-001): `HelloRetryRequest`/`HelloRequest` in the server direction currently causes the real `ServerHello` to be silently dropped — fix `appendDir` to only mark a direction "done" on the expected handshake type.

### Wave 4 — LOW / INFORMATIONAL (cleanup, opportunistic)

Batch into a single pass rather than individual tickets: `sync.Pool` for
reassembly buffers (F-003) and `assemblerCtx` (G-002); kernel BPF filter
(F-004); the never-implemented `watchdog.go` (F-005) — a supervision loop or
at minimum `recover()`-based restart; missing `tap:` config section (F-006);
missing `dropEventOverflow` metric constant (F-007); TLS non-handshake-record
skip-not-break fix (F-008); stale Phase-20 doc-comment references (F-009,
F-010, F-011); duplicate `canonicalIP` + Redis key-prefix constants across
writer/consumer with no sync test (F-019, D-003 — same unguarded-duplicate
class as the `sliding_window.lua` finding from this session's earlier
duplicate-file audit; **add a test enforcing the two copies stay identical**,
per that same fix pattern, or better, delete the duplicate); read-error metric
(F-020); payload-privacy test (F-021); supervisor/restart docs (F-024);
gopacket CVE-audit entry (F-025); `Fetch()` buffer-size documentation (F-026);
`--frame-size` bounds check (F-027); TLS-version-field validation (T-002);
`extractFirstHandshake` O(n²) re-parse (T-003); TTL-boundary doc comment
(T-004); ChromeOS/Android OS-mismatch doc gap (T-005); `GOMAXPROCS`/resource
isolation (G-003); dead-metric removal (R-011 is listed under Wave 3's
concurrency theme above but its "remove or implement" choice belongs here
once decided); rate-limiting/sampling flags (R-014); `REDIS_SCHEMA.md` entry
for `fp:ban_intent:ip` (D-004); SNI/privacy doc comment (P-004, P-005);
upstream dependency health check on startup (R-012); drain-to-file on
SIGKILL documentation (R-013); connection-scoped histograms (R-006).

## Key decisions (for review)

| # | Decision | Why |
|---|---|---|
| D1 | **Wave 1 blocks any production deployment of `cmd/ja4-tap`.** If the sensor is already deployed anywhere, treat this as an incident, not a backlog item. | F-022 (permanent hang passing liveness checks) and F-002 (full `CAP_NET_RAW` with no sandboxing) are the two findings PHASE_334 itself called the most severe. |
| D2 | **Waves 1-2 are one PR-sized unit of work; Waves 3-4 may ship as separate, smaller PRs** over subsequent sessions rather than one giant change. | Matches this repo's "smallest correct change, verified before claiming" discipline — a 40-finding single PR is unreviewable. |
| D3 | **Seccomp profile is rewritten for the Go binary, not reused from Phase 20's Python one.** `config/seccomp_tap.json`'s syscall allowlist was written for `src/tap/security.py` (deleted). Go's runtime needs a different syscall surface. | F-002 evidence: the file's own comment names the deleted Python module. Reusing it as-is would either be a no-op or block syscalls the Go runtime actually needs. |
| D4 | **Metric/alert/dashboard name fixes (O-002, O-003) are verified against the real, currently-emitted metric names** — re-run `cmd/ja4-tap --metrics-addr` locally and `curl` it, don't just pattern-match the tables in PHASE_334. | The tables in the finding are accurate as of 2026-06-19; confirm nothing renamed since. |

## Implementation plan

1. **Wave 1** (Crash safety + shutdown): F-022, F-002, R-001. Add tests: a
   crafted-packet-triggers-panic-and-recovers test; a SIGTERM-while-idle
   shutdown test; verify capability drop actually happens (check `/proc/self/status`
   `CapEff` post-drop in a test, or an integration test under a real
   non-root check).
2. **Wave 2** (Operability): F-014, F-023, O-001, O-002, O-003, R-002, R-004.
   `make tap-build` must produce a working binary; `curl localhost:<port>/metrics`
   must return real data; fixed alert rules must be validated with `promtool
   check rules` (mentioned as available per this repo's tooling); Grafana
   dashboard JSON must be re-validated (a JSON schema check at minimum, ideally
   a real Grafana render check if the tooling exists).
3. **Wave 3** (Security/privacy hardening), grouped by theme as listed above.
   `docs/PRIVACY.md` is a genuinely new document — treat its accuracy as load-bearing,
   not boilerplate.
4. **Wave 4** (cleanup), batched opportunistically — do not let this wave block
   Waves 1-2 shipping.
5. **Close-out**: update `docs/phases/PHASE_334.md`'s findings to reference
   this phase's fix commits (don't delete the findings — they're the audit
   trail); mark this manifest entry COMPLETE only when Wave 1 AND Wave 2 are
   done (Waves 3-4 may be tracked as their own follow-up phase(s) if not
   finished in the same cycle — do not silently drop them, register whatever's
   left as a new phase per this session's own "keep the manifest honest" theme).

## Test plan

- Each Wave-1 fix needs a test that fails before the fix and passes after
  (a crafted-panic test, a shutdown-under-idle-SPAN test, a capability-drop
  verification).
- `make test` (existing `internal/tap` suite) must stay green throughout —
  this phase adds tests, it should not need to loosen any existing one.
- `promtool check rules` (or equivalent) on the corrected `tap.yml` alert
  rules.
- Manual smoke: run `ja4-tap` against a synthetic pcap, hit `/metrics` and
  `/health`, confirm real numbers.

## Acceptance criteria

- [ ] Wave 1: sensor survives a crafted panic-inducing packet without hanging;
      shuts down within a few seconds of `SIGTERM` even with no traffic;
      capability drop + a Go-appropriate seccomp profile are both wired and
      verified.
- [ ] Wave 2: `make build` (or a new `make tap-build`) produces the sensor
      binary; `/metrics` and `/health` return real data; every Alertmanager
      rule and Grafana panel for the sensor references a metric that actually
      exists and is populated.
- [ ] Waves 3-4: either completed in this phase or explicitly registered as
      a follow-up phase in the manifest — not silently dropped.
- [ ] `docs/phases/PHASE_334.md` findings updated with fix references (audit
      trail preserved, not deleted).
- [ ] Full CI green.

## Out of scope

- **Re-reviewing the 316\* series** — PHASE_334 already did this; this phase
  fixes what it found.
- **New TAP features** (additional fingerprint types, new export formats,
  etc.) — this is remediation, not roadmap.
- **Deciding whether the TAP sensor ships in a release at all** — that's a
  product call independent of these fixes; this phase makes it safe *if*
  deployed, not a decision to deploy it.

## Risks

- **Volume.** 40+ findings is a lot of surface area for regressions. D2's
  wave-splitting exists specifically to keep each shippable unit reviewable.
- **Seccomp profile correctness (D3).** An incorrectly-scoped syscall
  allowlist can break the sensor in subtle, hard-to-reproduce ways (a syscall
  used only on some code paths, e.g. an error branch, might not appear during
  testing). Test the profile against every code path exercised by the test
  suite, not just the happy path.
- **`docs/PRIVACY.md` accuracy.** This is the sensor's first privacy
  documentation ever (P-001) — get it reviewed by someone thinking about
  actual GDPR exposure, not just written to satisfy the finding.
