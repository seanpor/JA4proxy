<!--
title: Go_1_27_3_Bump_And_CVE_2026_111943_Triage
audience: developer
last_reviewed: 2026-10-21
phase: 847g
-->

# Phase 847g — Go 1.27.3 bump and the CVE-2026-111943 triage

> **Status:** PROPOSED
> **Size:** SMALL
> **Dependencies:** []
> **Branch:** `phase-847g-go-1-27-3-cve-2026-111943`
> **Part of:** Phase 847 (umbrella) — see `docs/phases/PHASE_847.md`

---

## Goal

Clear **CVE-2026-111943** from every surface this repository controls, and
decide — explicitly, in writing — what happens to the surfaces it does not.

The CVE is a Go standard-library finding in `crypto/x509`, published
2026-10-21, affecting Go 1.27.2 (fixed in **1.26.10** and **1.27.3**). The
847c monitor filed nine issues for it within nine hours of publication, one
per affected surface; this phase is the work those issues are asking for.

Two parts, and they are not the same kind of work:

1. **Ours to fix.** Every first-party image is built on
   `golang:1.27.2-alpine`. Bumping the base image clears the CVE in the
   proxy, the mock backend, the tap, the CLI, Logtide and the FOSS proxy
   build — with a real fix, not a waiver.
2. **Not ours to fix.** Six pinned third-party images bundle a Go toolchain we
   do not control: `grafana/grafana`, `grafana/loki`, `grafana/alloy`,
   `prom/prometheus`, `prom/alertmanager`, `oliver006/redis_exporter`. Their
   Go version changes when upstream rebuilds them. Until then they need
   **dated, justified waivers** — or a bump to a tag that happens to bundle a
   patched toolchain, if one exists by then.

### Already done: the audit toolchain

The **audit** half of the CVE is already handled. Every Go toolchain CI pins
was moved to 1.27.3, and `go.mod`'s floor to 1.26.10, because the required
"Go dependency audit (govulncheck)" job pinned the *vulnerable* 1.27.2 and
`govulncheck` therefore exited 3 on `internal/security/mtls.go:50` — failing
every pull request in the repository. That landed with Phase 847d, with
`tests/unit/test_go_toolchain_pins.py` keeping it honest.

What is left here is the half that **ships**: the images.

---

## Why this is a phase and not a commit

`make scan` is a **zero-HIGH/CRITICAL** gate. It is red on CVE-2026-111943 on
`main`, for every branch, until this phase lands. It is also, since 847c, the
**de-required** job: the required PR gate is `Scan Regression (surfaces
touched)`, which judges a PR against `security/baseline.json` and so cannot
be reddened by an upstream CVE disclosed overnight.

So the honest position is:

- the CVE is **triaged** — nine issues, filed by the monitor, refreshed daily
  while it is unresolved;
- it is **not fixed**, and this phase is the fix;
- the full scan being red does not block unrelated PRs, by design, and that
  design is what let 847d land while this CVE was open.

The temptation is to fix it "in passing" inside an unrelated PR. Don't. A
base-image bump with refreshed digests is its own unit of work: it needs the
images rebuilt, the scan re-run, and the digests verified. It belongs to
whoever can watch that happen.

---

## Implementation plan

### 847g.1 Bump our own base image (a fix, not a waiver)

| File | Current | Change to |
|------|---------|-----------|
| `deploy/docker/Dockerfile.go-proxy` | `golang:1.27.2-alpine@sha256:…` | `golang:1.27.3-alpine@sha256:…` |
| `deploy/docker/Dockerfile.ja4-tap` | " | " |
| `deploy/docker/Dockerfile.mockbackend` | " | " |
| `deploy/docker/Dockerfile.cli` | " | " |
| `deploy/docker/Dockerfile.logtide` | " | " |
| `deploy/docker/Dockerfile.go-proxy.foss` | " | " |
| `deploy/docker/security-scan/Dockerfile` | `golang:1.26.6-alpine@sha256:…` | `golang:1.26.10-alpine@sha256:…` (1.26.10 carries the fix) |
| `tests/docker/Dockerfile.test-runner` | `golang:1.26-alpine@sha256:…` | check the pinned version; bump if it is below 1.26.10 |
| `deploy/docker/update-checker/Dockerfile` | `golang:1.25.10-alpine` (**unpinned**) | 1.25.x has no published fix for this CVE — but the *unpinned tag* is drift of its own, and is a separate finding |

**The digests must be pinned, and pinned to the same multi-arch manifest
digest** for every Dockerfile that uses the same tag, so one `FROM` line
cannot drift from another. Note that `Dockerfile.logtide` currently carries a
*different* digest for the same tag as the other five — find out why before
changing it, because an accidental platform-specific pin only shows up on an
arm64 runner.

Then: `make build && make scan-first-party` must come back clean.

### 847g.2 Decide the third-party surfaces, in writing

For each of the six third-party images, one of:

- **a bump**, if a published tag bundles Go ≥ 1.26.10 / ≥ 1.27.3 — check with
  `trivy image --format json <image>:<tag>` before proposing it;
- **a waiver** in `security/waivers.yaml`, with a justification that says
  *why the fix is not ours to make* and an `expires:` date — at which point
  847d's re-affirmation takes over and re-asks on the day it expires.

A waiver for a CVE whose fix exists upstream but has not been released yet is
a legitimate waiver: dated, justified, re-affirmed. A waiver with no date is
not.

**Watch the trap 822 documented:** a third-party waiver must not suppress the
same finding in the proxy we ship. That is what the first-party/third-party
ignorefile split exists for; do not merge the two files.

### 847g.3 Re-baseline

`make scan-baseline` — run from `main`, after the images are built — records
what the repository carries, so the regression gate judges the next PR against
a truth that includes this CVE's absence. Without it the gate keeps
reporting the CVE as "not in the baseline" for surfaces that have since been
fixed.

---

## Test strategy

- `make build` then `make scan-first-party` — zero HIGH/CRITICAL.
- `make scan-images` — zero HIGH/CRITICAL, or every remaining finding has a
  dated waiver in `security/waivers.yaml`.
- `make scan-regression` — green, **and** the surfaces this phase touches are
  actually scanned: the gate must not report "nothing to scan" for a branch
  that changed a Dockerfile.
- `make lint` — `render_waivers.py --check` passes, so the registry and the
  generated ignorefiles still agree.

---

## Acceptance criteria

- [ ] No first-party image carries CVE-2026-111943; the fix is a base-image
      bump, not a waiver.
- [ ] Every first-party `FROM golang:…` line is digest-pinned, to the same
      1.27.3 (or 1.26.10) manifest digest, and the digest is recorded in the
      commit message.
- [ ] Every third-party surface carrying the CVE has either a bump or a
      dated, justified waiver, and the decision is written down per surface.
- [ ] No third-party waiver suppresses a finding in a first-party image — the
      split stays split.
- [ ] `security/baseline.json` is re-recorded.
- [ ] `make preflight` is green.

---

## Out of scope

- The nine monitor issues stay open until the surfaces they name are clean.
  This phase does not close them by hand.
- MEDIUM gating (847e) and reachability evidence (847f).
- Any change to the waiver *mechanism* — 847d owns that.
- The unpinned `golang:1.25.10-alpine` tag in `update-checker`. It is real
  drift and it is its own finding; do not fold it in silently.

---

## Notes for implementer

- **Do not bump a third-party image version to "get a fix" without checking
  what changed.** A monitoring sidecar's major or minor bump is a behaviour
  change. The CVE is a Go toolchain patch, and a patch-level bump of the same
  project is usually the safe one.
- **If upstream ships the fix mid-phase, prefer the upstream tag over a
  waiver.** A waiver that is no longer needed is a waiver to delete, and
  847d's re-affirmation will not delete it for you while it is still live.
- **Watch the gate while you work.** 847d changed the waiver-set trigger to
  compare applied *entries* rather than file bytes, so adding a real waiver
  entry widens the gate to every surface — as it should — while a comment
  does not.
