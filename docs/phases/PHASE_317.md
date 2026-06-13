---
phase: 317
title: First-Party Image Base Hardening + first-party HIGH-gate flip
status: PROPOSED
created: 2026-06-13
audience: [developer]
---

# First-Party Image Base Hardening + first-party HIGH-gate flip

> **STATUS: PROPOSED — plan for review. No code until approved.**
> Direct follow-up to [[PHASE_314]]. 314 adopted a *differentiated* scan gate
> (hard HIGH+CRITICAL on Dockerfiles + our own Go toolchain; third-party HIGH
> tracked in a waiver register) but **deferred** the one piece that needs real
> image work: making `scan-first-party` gate on **HIGH**. This phase does that.

## Goal (plain language)

Get every **first-party** image we build to a HIGH/CRITICAL-clean base, then turn
`make scan-first-party` from "fails on CRITICAL, HIGH advisory" into "fails on
**HIGH or CRITICAL**" — so a real, hard CVE gate covers the code and containers we
actually own. Third-party images are out of scope here (they stay CRITICAL-gated +
waiver-tracked, per 314 — we don't build them).

## Why this phase exists (what 314's scan found)

The Phase 314 scan (2026-06-13) showed the first-party images split three ways:

| Image | Base | HIGH/CRITICAL status | Fix |
|---|---|---|---|
| `ja4proxy` (Go proxy) | `golang:1.26.4-alpine` → minimal | **clean** | none needed |
| `ja4proxy-mockbackend` (Go) | `golang:1.26.4-alpine` | **clean** | none needed |
| `ja4proxy-analytics` | alpine | 2× openssl HIGH (`CVE-2026-45447`) | **fixable**: rebuild on alpine with openssl `3.5.7-r0` |
| `ja4proxy-tarpit` | alpine | 2× openssl HIGH (`CVE-2026-45447`) | **fixable**: rebuild on alpine with openssl `3.5.7-r0` |
| `ja4proxy-test` | `python:3.14.0-slim` (Debian) | **no-fix** distro HIGH (curl, ncurses, libssh2, perl, linux-libc-dev, …) | **re-base** |
| `ja4proxy-trafficgen` | `python:3.14.0-slim` (Debian) | **no-fix** distro HIGH (same family) | **re-base** |

Two related but out-of-the-gated-set images carry the same Debian problem and
should get the same treatment opportunistically (they are **not** in
`FIRST_PARTY_IMAGES` today, so they don't gate, but they carry **CRITICAL** perl
CVEs with no fix):

- `ja4proxy-management` (`python:3.14-slim`) — 2× CRITICAL perl (`CVE-2026-42496`,
  `CVE-2026-8376`), many HIGH.
- `ja4proxy-admin` (`python:3.14-slim`).

The blocker for a first-party HIGH gate is the **Debian `python:3.14-slim`** base:
its `perl-base`, `ncurses`, `linux-libc-dev`, `libssh2`, `curl` CVEs have **no
upstream fix**, so they can't be `apt upgrade`-d away — the base itself must change.

## Key decisions (for review)

| # | Decision | Why |
|---|---|---|
| D1 | **Re-base the Debian Python images onto a slim, low-CVE Python base.** Candidates: `python:3.14-alpine` (musl), Chainguard/Wolfi `cgr.dev/chainguard/python` (distroless, near-zero CVE), or a distroless `gcr.io/distroless/python3`. Pick **one** and apply consistently. | The no-fix Debian CVEs come from the broad Debian userland (perl, ncurses, libssh2, kernel headers) that a slim/distroless base simply doesn't ship. Must be **re-verified** by building + scanning — alpine/musl can break Python wheels (manylinux vs musllinux), so validate the test/trafficgen/management stacks still build and run. |
| D2 | **Rebuild the alpine images (`analytics`, `tarpit`) on a base that has openssl ≥ `3.5.7-r0`.** Bump the pinned alpine base digest. | The single openssl HIGH is genuinely fixable today — just needs a current alpine base. |
| D3 | **Flip `scan-first-party` to gate on HIGH+CRITICAL** using the same finding-row match the dockerfile scan uses, **only after** D1+D2 land and a clean scan is proven in CI. | This is the actual deliverable. Do it last, gated on green. |
| D4 | **If any first-party HIGH remains genuinely unfixable** after re-basing, add a **dated, justified `.trivyignore`** entry per that file's 14-day policy — not a blanket suppression. The goal is zero, but the mechanism stays honest. | First-party is ours; residuals must be rare and time-boxed, unlike the third-party waiver register. |
| D5 | **Decide test/trafficgen's gate membership explicitly.** If they remain CI-only (not shipped), they still get re-based (so the gate is meaningful) — do **not** simply exclude them to make the gate pass. | Excluding images to green the gate is the dishonest path 314 explicitly rejected. |

## Implementation plan (in order)

1. **Re-base alpine images** (`src/analytics/Dockerfile`, `src/tarpit/Dockerfile`
   or wherever they build) to a current alpine with openssl ≥ `3.5.7-r0`; rebuild
   + scan → confirm HIGH-clean.
2. **Re-base the Debian Python images** (`Dockerfile.test`, `Dockerfile.trafficgen`,
   and `Dockerfile.management`/`Dockerfile.admin` opportunistically) onto the D1
   base; fix any musl/distroless build fallout (wheels, shell assumptions,
   healthchecks); rebuild + scan each → confirm HIGH/CRITICAL-clean (or D4 residual).
3. **Update `docs/DOCKER_IMAGES.md`** first-party + base rows to the new bases.
4. **Flip `scan-first-party`** to HIGH+CRITICAL (count HIGH finding rows,
   `--exit-code` path), and update its advisory echo wording.
5. **Update `tests/integration/test_ci_flow.py`** to assert `scan-first-party`
   gates on HIGH (mirror of the existing dockerfile-gate assertions).
6. **Tick the [[PHASE_313]] deferred HIGH-gate box** for the first-party half, with
   a note that third-party HIGH remains waiver-tracked (upstream-dependent).
7. Docs: CHANGELOG, ADR if the base choice is non-obvious, manifest `317` COMPLETE.

## Test plan

- **Build + scan each re-based image** in CI (the authoritative environment; local
  full builds are unreliable — learned in 314) → HIGH/CRITICAL-clean or a dated
  residual.
- **Functional smoke** of each re-based image: `test` runs the suite, `trafficgen`
  generates load, `management`/`admin` serve their endpoints — i.e. the base swap
  didn't break the Python runtime (musl wheel compatibility is the main risk).
- **`test_ci_flow.py`** asserts the first-party HIGH gate is active.
- **`make scan` exits 0** end to end with the new gate.

## Acceptance criteria

- [ ] All gated first-party images (`FIRST_PARTY_IMAGES`) are HIGH/CRITICAL-clean,
      or carry only dated/justified `.trivyignore` residuals.
- [ ] `scan-first-party` gates on **HIGH+CRITICAL**; `make scan` exits 0.
- [ ] `test_ci_flow.py` asserts the first-party HIGH gate.
- [ ] Re-based images still build **and** pass a functional smoke test.
- [ ] `docs/DOCKER_IMAGES.md` reflects the new bases; CHANGELOG + manifest updated.
- [ ] The [[PHASE_313]] first-party HIGH-gate box is ticked; third-party remains
      waiver-tracked.
- [ ] Full CI green.

## Out of scope

- **Third-party image HIGH-gating** — upstream-dependent; tracked by
  `docs/security/THIRD_PARTY_CVE_WAIVERS.md` (see [[PHASE_314]]), not a phase.
- The differentiated-gate decision itself (made in [[PHASE_314]]).
- MEDIUM/LOW CVEs (reporting-only).

## Risks

- **musl/distroless build fallout.** Moving Python images off Debian glibc can break
  wheels that ship only `manylinux` builds, or scripts assuming a Debian shell. This
  is the main effort sink — budget for per-image build debugging, and keep each
  image's re-base in its own commit so a regression is easy to bisect.
- **A distroless base has no shell**, which can break healthchecks/entrypoints that
  shell out; verify each image's `HEALTHCHECK`/entrypoint after the swap.
