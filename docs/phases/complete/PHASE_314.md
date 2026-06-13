---
phase: 314
title: Third-Party Image HIGH-CVE Remediation (differentiated HIGH-gating)
status: IN_PROGRESS
created: 2026-06-13
updated: 2026-06-13
audience: [developer]
---

# Third-Party Image HIGH-CVE Remediation

> **Goal (revised after a fresh authoritative scan).** Reduce the pinned-image
> HIGH-CVE exposure where we actually can, and replace the original "flip
> `make scan` to a blanket HIGH gate" plan with a **differentiated gate** that is
> honest about what we control. Completes the HIGH-gating intent recorded in
> [[PHASE_313]] *in the only way that doesn't red the required CI gate for every
> agent on CVEs we can't fix.*

## Why this plan changed (the re-review)

The original plan assumed "~13 HIGH, all with fixed upstream tags — just bump
each image." A fresh scan on **2026-06-13** (`aquasec/trivy:0.71.0`,
`--severity HIGH,CRITICAL`) showed that assumption is **false today**:

| Image (pinned) | HIGH findings | Bump-fixable? |
|---|---|---|
| `haproxy:2.8.24-alpine` | none | ✅ already clean |
| `prom/alertmanager:v0.32.1` | otel + 8× Go-stdlib | ✅ **v0.33.0 → CLEAN** |
| `oliver006/redis_exporter:v1.84.0` | 1× Go-stdlib | ✅ **v1.86.0 → CLEAN** |
| `prom/node-exporter:v1.11.1` | ~12× Go-stdlib | ❌ already newest stable |
| `prom/prometheus:v3.12.0` | 1× Go-stdlib | ❌ already newest stable |
| `grafana/loki:3.7.2` | thrift + prom-lib + stdlib | ❌ already newest stable |
| `grafana/promtail:3.6.11` | docker (2× **no fix at all**) + prom-lib + openssl + stdlib | ❌ already newest stable |
| `grafana/grafana:13.0.2-ubuntu` | tempo + prom-lib + openssl + stdlib | ❌ already newest major |
| `redis/redis-stack:7.4.0-v8` | gpgv + openssl (distro) | ❌ already newest tag |

**Only 2 of 9** third-party images can be bump-fixed. The other 6 are *already on
their newest stable tag*; their HIGH findings are brand-new Go-stdlib CVEs (fixed
only in Go **1.26.4**, days old — upstream hasn't rebuilt yet), distro openssl/gpgv
patches awaiting an upstream base rebuild, and 2 `docker/docker` CVEs with **no
upstream fix at any version**. We literally cannot bump or code our way out of
those — they clear only when each upstream project ships a rebuilt image.

A blanket HIGH gate would therefore need ~6 images of `.trivyignore` residuals,
but that file's policy caps entries at **14 days** — so the **required** Security
Scan gate would flap red and block every PR (for all parallel agents) to suppress
CVEs we can't fix. That directly violates the project's core asymmetry (don't
block legitimate work for a low-cost, un-actionable issue).

The first-party side is **not uniformly clean either** (newly discovered): the Go
images (`ja4proxy`, `ja4proxy-mockbackend`) are HIGH-clean (already built with Go
1.26.4), the **alpine** images (`ja4proxy-analytics`, `ja4proxy-tarpit`) have a
*fixable* openssl HIGH (apk `3.5.6-r0` → `3.5.7-r0` via a base rebuild), but the
**Debian `python:3.14-slim`** images (`ja4proxy-test`, `ja4proxy-trafficgen`, plus
the out-of-scope `management`/`admin`) carry **no-fix** distro HIGH **and CRITICAL**
CVEs (curl, ncurses, perl, linux-libc-dev, …). So even a first-party HIGH gate
needs a base-image strategy first.

## Decision (user-approved 2026-06-13): differentiated gate

```
scan-dockerfiles : HIGH+CRITICAL -> exit 1   (we own these files — unchanged)
scan-first-party : CRITICAL -> exit 1 ; HIGH -> advisory   (target: HIGH gate once
                   the alpine openssl rebuild + a slim/distroless base for the
                   Debian Python images land — see "Deferred" below)
scan-images (3rd): CRITICAL -> exit 1 ; HIGH -> reported + tracked in a dated
                   waiver register (docs/security/THIRD_PARTY_CVE_WAIVERS.md).
                   When upstream ships a fixed tag, bump it and drop the row.
```

Rationale: gate hard on what we control (Dockerfiles, our own Go toolchain),
track openly what we don't (upstream third-party rebuild lag), never silently
ignore, and keep the required gate green unless **we** regress.

## What this phase delivers NOW (verified, safe)

1. **Bump the 2 fixable third-party images** (both re-scanned CLEAN):
   - `prom/alertmanager` `v0.32.1` → `v0.33.0`
   - `oliver006/redis_exporter` `v1.84.0` → `v1.86.0`
   Mirrored across `Makefile` `TRIVY_IMAGES`, `deploy/docker/docker-compose.monitoring.yml`,
   `deploy/docker/docker-compose.prod.yml`, the `redis-secure` Ansible default,
   and `docs/DOCKER_IMAGES.md`.
2. **Refresh `docs/DOCKER_IMAGES.md`** — its third-party table had drifted by many
   releases; reconciled to the actually-pinned tags.
3. **Create `docs/security/THIRD_PARTY_CVE_WAIVERS.md`** — honest, dated register
   of every upstream-blocked third-party HIGH, with recheck dates and a bump-and-drop
   process. (Not a `.trivyignore`; these are advisory, not gating.)
4. **Clarify `make scan-images` output** to reference the register and explain the
   differentiated posture (no gate-logic change — third-party still gates on CRITICAL).

## Deferred (own follow-up; do NOT force into this PR)

These are blocked on work we can't safely verify locally / that exceeds a docs+bump PR:

- **First-party HIGH gate flip.** Requires: (a) rebuild `analytics`/`tarpit` on a
  patched alpine base to clear the openssl HIGH, and (b) move the Debian
  `python:3.14-slim` first-party images (`test`, `trafficgen`) to a slim/distroless
  base — or scope them out of the production HIGH gate — because they carry no-fix
  Debian HIGH/CRITICAL. Verify in CI (local full builds are unreliable here).
- **Third-party HIGH gate flip.** Re-attempt only once upstream images
  (`node-exporter`, `prometheus`, `loki`, `promtail`, `grafana`, `redis-stack`)
  ship rebuilds against Go 1.26.4 / patched bases. Tracked by the waiver register's
  fortnightly recheck + Dependabot + the weekly scheduled scan.
- **Out-of-scope CRITICALs surfaced by the scan:** the `python:3.14-slim`-based
  `ja4proxy-management` image carries 2 CRITICAL perl CVEs (no fix). It is **not**
  in the gated `FIRST_PARTY_IMAGES` set, so it does not red the gate today, but it
  should get the same base-image treatment. Flag for a hardening follow-up.

## Scope (files)

- **Edit:** `Makefile` — `TRIVY_IMAGES` (2 tag bumps) + `scan-images` advisory wording.
- **Edit:** `deploy/docker/docker-compose.monitoring.yml`, `deploy/docker/docker-compose.prod.yml` — matching tag bumps.
- **Edit:** `deploy/ansible/roles/redis-secure/defaults/main.yml` — `redis_exporter_version` default bump.
- **Edit:** `docs/DOCKER_IMAGES.md` — third-party inventory refresh.
- **New:** `docs/security/THIRD_PARTY_CVE_WAIVERS.md` — waiver register.
- **Edit:** `CHANGELOG.md`, `docs/phases/manifest.yaml`.

## Acceptance criteria (revised)

- [x] Fresh authoritative scan captured; plan reconciled to reality.
- [x] The 2 fixable third-party images bumped + mirrored in compose + Ansible +
      `DOCKER_IMAGES.md`; `make lint-docker` still passes.
- [x] `docs/security/THIRD_PARTY_CVE_WAIVERS.md` enumerates every upstream-blocked
      third-party HIGH with a recheck date and a bump-and-drop process.
- [x] `make scan` exits 0 (third-party gates on CRITICAL; HIGH reported + tracked).
- [x] Full CI green (Full Lint, Security Scan, Full Test, Meta-Validation) — merged in #144.
- [x] Follow-up for the first-party base-image work + gate flip is recorded as
      **[[PHASE_317]]**; the [[PHASE_313]] deferred HIGH-gate box stays open,
      annotated with the differentiated-gate decision and the remaining blockers.

## Status: COMPLETE (2026-06-13, merged in #144)

The scoped differentiated-gate deliverable shipped. The remaining work — re-basing
the Debian `python:3.14-slim` first-party images, rebuilding the alpine images, and
flipping `scan-first-party` to a HIGH gate — is carried by **[[PHASE_317]]**. The
third-party HIGH gate-flip remains upstream-dependent and is tracked by the waiver
register's fortnightly recheck, not a phase.

## Out of scope

- The lint toolchain containerisation (delivered in [[PHASE_313]]).
- Re-architecting the Debian Python images onto a slim/distroless base (follow-up).
- MEDIUM/LOW CVEs (remain reporting-only).

## Risks

- **Moving target.** New Go-stdlib CVEs land continually and hit every Go-based
  third-party image at once; the waiver register + fortnightly recheck keep this
  honest rather than pretending to a frozen-clean state.
- **Image bumps are behaviour changes.** The 2 bumps are minor monitoring-sidecar
  version steps; `make lint-docker` + the compose config check guard against
  structural breakage.
