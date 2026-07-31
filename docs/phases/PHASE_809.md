---
phase: 809
title: "Go TAP/SPAN Sensor Remediation Waves 3-4 — Phase 334's Remaining Findings"
status: PROPOSED
created: 2026-07-24
audience: [developer]
---

# Go TAP/SPAN Sensor Remediation — Waves 3-4

> **STATUS: PROPOSED — plan for review. No code until approved.**
> Continues [[PHASE_803]] (Waves 1-2, COMPLETE) with the remainder of
> [[PHASE_334]]'s findings, per PHASE_803's own D2 decision: "Waves 1-2 are one
> PR-sized unit of work; Waves 3-4 may ship as separate, smaller PRs." Not a
> re-review — PHASE_334 is still the source of truth for what's wrong; verify
> each finding against current code before fixing it (PHASE_803 found 3 of its
> 10 Wave 1-2 findings had already been silently fixed by an untracked prior
> commit, so don't assume PHASE_334's June snapshot is still accurate).

## Goal (plain language)

Finish what PHASE_803 didn't: MEDIUM-priority security/privacy hardening
(Wave 3) and LOW/INFORMATIONAL cleanup (Wave 4) in the Go TAP/SPAN sensor
(`cmd/ja4-tap`, `internal/tap/`). The headline item is `docs/PRIVACY.md` —
this project has **zero privacy documentation** despite the sensor capturing
raw ClientHello bytes (including SNI) and writing IP-keyed Redis records with
no erasure mechanism.

## Why this phase exists

PHASE_803 shipped Wave 1 (CRITICAL) and Wave 2 (HIGH) as one reviewable PR and
explicitly deferred Waves 3-4 rather than bundling 40+ findings into a single
change. This phase is that deferred work, registered as its own manifest
entry per the "keep the manifest honest, don't silently drop scope" pattern
established across recent phases (see PHASE_806's discovery of an untracked
capability gap, PHASE_803 itself surfacing unlinked prior fixes).

## Wave 3 — MEDIUM (privacy/compliance and hardening)

Grouped by theme, matching PHASE_803's own grouping (copied forward so this
doc is self-contained — see PHASE_334.md for full evidence/line numbers):

- **Redis security** (F-017, F-018): `--redis-password`/`REDIS_PASSWORD` env
  support (a password on the command line is visible via `ps aux`);
  `--redis-tls` to force TLS regardless of URL scheme.
- **Concurrency safety** (F-016, G-001): guard `JA4TBlocklist` with a
  `sync.RWMutex` (latent panic risk once any writer exists); deep-copy
  `StackFeatures.OptionOrder` at emit time to match the handshake-bytes
  pattern already used elsewhere.
- **Resilience/startup verification** (F-005, F-015): `internal/tap/watchdog.go`
  appears to already exist (other PHASE_334 `RESOLVED` notes reference
  `Watchdog.Run`), but F-005 itself was never confirmed or annotated — verify
  it's real supervision (restart + rapid-crash-loop protection) and close the
  loop in `PHASE_334.md`, implementing it here if it turns out to be missing
  after all; add a startup check that the capture interface exists and is up
  (`net.InterfaceByName`) per F-015 (its frame-size-clamp half is already
  covered by Wave 4's F-027).
- **Operability** (R-005, R-007, R-008, R-009, R-010): periodic heartbeat log
  (not gated by `--quiet`); `SIGHUP`/`SIGUSR1` handlers; `--log-format json` +
  `--log-level`; config file / env var support; `GOMEMLIMIT` guidance.
- **Ban provenance** (D-001): sensor-written bans currently show as
  `"manual_ban"` in the audit log and can silently overwrite and shorten an
  operator's 24h ban with the sensor's own 5-minute TTL. Tag provenance in the
  bypass reason; check for an existing operator ban before overwriting.
- **Cache correctness** (D-002): `TapConsumer`/`JA4TConsumer` cache "not
  found" the same as "cached empty" — a transient Redis miss poisons the
  signal for a full 60s TTL. Use a sentinel for negative caching, or a much
  shorter negative-cache TTL.
- **Privacy/GDPR** (P-001, P-002, P-003): write `docs/PRIVACY.md` (what's
  captured, what's persisted, retention periods, what is explicitly *not*
  persisted); document that `fp:*`/`ban:*` key names contain IPs (PII) so any
  `~fp:*` Redis ACL grantee can enumerate the tracked-client corpus; add an
  `--exclude-ips` mechanism and a documented manual-erasure runbook section
  for GDPR Article 17 requests.
- **Deployment infra** (O-004, O-005, O-006): Prometheus scrape target for
  the sensor; a real `Dockerfile.ja4-tap` + compose service + resource limits
  + `HEALTHCHECK`; a `ja4tap` Redis ACL user in `config/redis_acl.conf` (the
  runbook already documents the ACL commands — the canonical config file just
  doesn't have them).
- **Reassembler correctness** (T-001): `HelloRetryRequest`/`HelloRequest` in
  the server direction currently causes the real `ServerHello` to be silently
  dropped — fix `appendDir` to only mark a direction "done" on the expected
  handshake type.

## Wave 4 — LOW / INFORMATIONAL (cleanup, opportunistic)

Batch into a single pass rather than individual tickets: `sync.Pool` for
reassembly buffers (F-003) and `assemblerCtx` (G-002); kernel BPF filter
(F-004); missing `tap:` config section (F-006); missing `dropEventOverflow`
metric constant (F-007); TLS non-handshake-record skip-not-break fix (F-008);
stale Phase-20 doc-comment references (F-009, F-010, F-011); duplicate
`canonicalIP` + Redis key-prefix constants across writer/consumer with no
sync test (F-019, D-003 — same unguarded-duplicate class as the
`sliding_window.lua` finding from an earlier phase's duplicate-file audit;
**add a test enforcing the two copies stay identical**, or better, delete the
duplicate); read-error metric (F-020); payload-privacy test (F-021);
supervisor/restart docs (F-024); gopacket CVE-audit entry (F-025); `Fetch()`
buffer-size documentation (F-026); `--frame-size` bounds check (F-027);
TLS-version-field validation (T-002); `extractFirstHandshake` O(n²) re-parse
(T-003); TTL-boundary doc comment (T-004); ChromeOS/Android OS-mismatch doc
gap (T-005); `GOMAXPROCS`/resource isolation (G-003); dead-metric removal
(R-011 — "remove or implement" choice deferred from Wave 3); rate-
limiting/sampling flags (R-014); `REDIS_SCHEMA.md` entry for
`fp:ban_intent:ip` (D-004); SNI/privacy doc comment (P-004, P-005); upstream
dependency health check on startup (R-012); drain-to-file on SIGKILL
documentation (R-013); connection-scoped histograms (R-006).

Note: PHASE_803's Wave 1-2 work already resolved F-002, F-014, F-022, F-023,
O-001, O-002, O-003, R-001, R-002, R-004 — do not re-open those; see
`docs/phases/complete/PHASE_334.md`'s `**RESOLVED**` annotations for what
each fix actually did before starting this phase, so Wave 3/4 work builds on
the real current state (e.g. R-002's new circuit breaker is a dependency for
any further Redis-security work here, not something to redesign).

## Key decisions (for review)

| # | Decision | Why |
|---|---|---|
| D1 | **`docs/PRIVACY.md` accuracy is load-bearing, not boilerplate.** Get it reviewed against the actual Redis key set (`docs/reference/REDIS_SCHEMA.md`) before treating it as done. | This is the project's first privacy documentation ever; a wrong or incomplete doc is worse than none because it creates false confidence. |
| D2 | **Verify every Wave 3/4 finding against current code before fixing it**, the same discipline PHASE_803 applied via its own D4. | PHASE_803 found 3 Wave 1-2 findings had already been silently fixed since PHASE_334 was written; Wave 3/4 findings are equally likely to have drifted given they're lower priority and further from recent attention. |
| D3 | **Wave 3 and Wave 4 may land as separate PRs**, matching PHASE_803's own Wave 1-2 split. | Wave 3 has real security/privacy weight (GDPR docs, Redis auth) and deserves independent review; Wave 4 is opportunistic cleanup that shouldn't gate it. |

## Implementation plan

1. **Re-verify scope**: for each Wave 3/4 finding, grep/read the current
   `internal/tap/`/`cmd/ja4-tap/` code before assuming PHASE_334's description
   still applies — do not port findings mechanically.
2. **Wave 3**, grouped by theme as listed above. `docs/PRIVACY.md` is a new
   document; write it against the real Redis key set in
   `docs/reference/REDIS_SCHEMA.md`, not from memory.
3. **Wave 4**, batched opportunistically — do not let it block Wave 3.
4. **Close-out**: annotate the remaining PHASE_334.md findings with resolution
   references (same non-destructive pattern PHASE_803 used); mark this
   manifest entry COMPLETE only when both waves are done, or split further and
   register what's left as yet another follow-up phase.

## Test plan

- Each fix needs a test that fails before and passes after, where the finding
  describes observable behavior (e.g. ban-provenance overwrite, cache
  negative-caching TTL, reassembler `HelloRetryRequest` handling).
- `make test` (existing `internal/tap` suite) stays green throughout.
- `docs/PRIVACY.md` reviewed against `docs/reference/REDIS_SCHEMA.md` for
  completeness (every IP-keyed or otherwise-PII-bearing key pattern named).

## Acceptance criteria

- [ ] Wave 3 items complete or explicitly re-scoped with reasoning if a
      finding turns out to no longer apply.
- [ ] `docs/PRIVACY.md` exists, reviewed, and accurate against the real Redis
      schema.
- [ ] Wave 4 cleanup complete, or explicitly deferred with a reason.
- [ ] `docs/phases/complete/PHASE_334.md` findings updated with fix
      references (audit trail preserved, not deleted).
- [ ] Full CI green.

## Out of scope

- **Re-reviewing the 316\* series or PHASE_803's Wave 1-2 work** — both
  already done; this phase only touches what's still open.
- **New TAP features** — this is remediation, not roadmap.

## Risks

- **Finding staleness.** Some Wave 3/4 findings may already be fixed or may
  no longer apply given how much the sensor changed under PHASE_803 — verify
  before implementing, per D2.
- **`docs/PRIVACY.md` scope creep or inaccuracy.** Keep it factual and scoped
  to what the TAP sensor actually does today; don't turn it into aspirational
  policy.
