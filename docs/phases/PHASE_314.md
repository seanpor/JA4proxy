---
phase: 314
title: Third-Party Image HIGH-CVE Remediation (re-enable HIGH-gating)
status: PROPOSED
created: 2026-06-13
audience: [developer]
---

# Third-Party Image HIGH-CVE Remediation

> **Goal.** Clear the pre-existing **HIGH**-severity CVE backlog in the pinned
> container images so `make scan` can be flipped back to **gate on HIGH** (not
> just CRITICAL) — completing the deferral recorded in [[PHASE_313]]. End state:
> `scan-images` (and `scan-first-party`) fail the build on HIGH **or** CRITICAL,
> with only justified, dated `.trivyignore` entries where no upstream fix exists.

## Background

[[PHASE_313]] containerised the lint toolchain and intended to harden
`scan-images` from CRITICAL-only to **HIGH+CRITICAL**. The first CI run showed
the pinned third-party images carry a substantial pre-existing HIGH backlog
(**13 HIGH, 0 CRITICAL** in one run), all DoS-/disclosure-class. Gating on HIGH
immediately would block every PR, and blanket-`.trivyignore`-ing real findings
would be dishonest — so HIGH-gating was **deferred** to this phase. `scan-images`
currently scans + reports HIGH but gates only on CRITICAL (same posture as `main`).

## Inventory (from the Phase 313 CI/local scan — re-confirm at implementation)

Trivy `--severity HIGH,CRITICAL` over `TRIVY_IMAGES` (haproxy, redis-stack,
redis_exporter, prometheus, alertmanager, node-exporter, grafana, loki, promtail)
surfaced these HIGH CVEs. All were reported by Trivy as **fixed** upstream:

| CVE | Package | Note |
|---|---|---|
| CVE-2025-68973 | `gpgv` (Debian/Ubuntu base) | GnuPG info-disclosure; fixed in base-image patch |
| CVE-2026-45447 | `libssl3t64` (OpenSSL) | Heap UAF in `PKCS7_verify()`; base-image patch |
| CVE-2026-42504 | Go `stdlib` (v1.26.3) | MIME header DoS; fixed in Go 1.26.4 |
| CVE-2026-32280 | Go `stdlib` | crypto/tls DoS; Go 1.26.2 |
| CVE-2026-33811 | Go `stdlib` | net DoS; Go 1.26.3 |
| CVE-2026-39883 | `go.opentelemetry.io/otel/sdk` v1.41.0 | fixed in otel 1.43.0 |
| CVE-2026-41602 | `github.com/apache/thrift` v0.22.0 | integer overflow; thrift 0.23.0 |
| CVE-2026-21728 | `github.com/grafana/tempo` | Tempo query DoS; 2.8.4+/2.9.2+/2.10.2+ |
| CVE-2026-34040 | `github.com/docker/docker` v28.5.0 | Moby authz bypass; 29.3.1 |

The Go-package CVEs (`stdlib`, `otel`, `thrift`, `docker`) come from the
third-party **Go-based** images (grafana/loki/tempo/promtail/prometheus etc.)
being built against older Go/deps — they are fixed by **bumping each image to a
newer pinned tag**, not by changing our code. Confirm the same set against
`scan-first-party` (our images) too — those Go CVEs *are* ours to fix via go.mod /
base-image bumps.

## Approach

1. **Re-scan to get the authoritative current list** (`make scan-images` +
   `make scan-first-party` after `make build`); CVE data drifts, so do not trust
   the table above verbatim.
2. **Bump pinned image tags** in `Makefile` `TRIVY_IMAGES` to versions whose
   release notes/Trivy output clear the HIGH findings. **Keep every bump in sync**
   with the compose files that deploy those images (`deploy/docker/docker-compose.monitoring.yml`,
   `*.prod.yml`, etc.) — the `lint-docker` compose-config check and
   `docs/DOCKER_IMAGES.md` must stay consistent.
3. **First-party images**: bump go.mod / toolchain (e.g. Go 1.26.3 → 1.26.4 to
   clear the stdlib CVEs) and the affected Go deps (otel sdk → 1.43.0,
   thrift → 0.23.0, docker → 29.3.1), rebuild, re-scan.
4. **Residuals**: where no fixed upstream tag exists yet, add a **dated, justified**
   `.trivyignore` entry (CVE, package, why-unfixable, review date) — never a
   blanket suppression.
5. **Flip the gate**: change `scan-images` (and confirm `scan-first-party`) to
   fail on HIGH+CRITICAL — i.e. count HIGH finding rows too, `--exit-code 1`
   (using the `^│.*<SEV>` finding-row match, **not** the totals line). Update the
   advisory wording removed from `scan-images` in Phase 313.
6. **Tests/docs**: update `tests/integration/test_ci_flow.py`
   (`test_scan_images_reports_high_gates_on_critical` → assert HIGH-gating),
   tick the deferred acceptance box in `PHASE_313.md`, CHANGELOG, REDIS/DOCKER
   image docs.

## Scope (files)

- **Edit:** `Makefile` — `TRIVY_IMAGES` tag bumps; flip `scan-images`
  (and verify `scan-first-party`) to HIGH+CRITICAL gating.
- **Edit:** `deploy/docker/docker-compose.*.yml` — matching image tag bumps.
- **Edit:** `go.mod` / `go.sum` — Go toolchain + dep bumps for first-party CVEs.
- **Edit:** `.trivyignore` — dated, justified entries for any genuinely-unfixed CVE.
- **Edit:** `tests/integration/test_ci_flow.py`, `docs/DOCKER_IMAGES.md`,
  `CHANGELOG.md`, `docs/phases/complete/PHASE_313.md` (tick deferred box).

## Acceptance criteria

- [ ] `make scan` exits 0 with `scan-images` **and** `scan-first-party` gating on
      **HIGH+CRITICAL** (no advisory carve-out for HIGH).
- [ ] Every pinned image bump is mirrored in the compose files and
      `docs/DOCKER_IMAGES.md`; `make lint-docker` still passes.
- [ ] First-party HIGH CVEs fixed at source (Go toolchain/deps), not ignored.
- [ ] `.trivyignore` contains only dated, individually-justified residuals (if any),
      each with a recheck date.
- [ ] `test_ci_flow.py` asserts the HIGH gate; the [[PHASE_313]] deferred box is ticked.
- [ ] Full CI green (Full Lint, Security Scan, Full Test, Meta-Validation).

## Out of scope

- The lint toolchain containerisation (delivered in [[PHASE_313]]).
- Non-CVE Trivy misconfiguration findings (`scan-dockerfiles`) beyond what a tag
  bump incidentally changes.
- MEDIUM/LOW CVEs (remain reporting-only).

## Risks

- **Image bumps are behaviour changes.** A newer haproxy/redis/grafana tag can
  shift config/behaviour; bump deliberately, run `make lint-docker` + the relevant
  compose smoke/E2E, and bump one image per commit where practical.
- **Moving target.** New HIGH CVEs land continually; the goal is "zero
  un-justified HIGH at merge", kept honest by the gate + Dependabot + the weekly
  scheduled scan — not a permanently frozen list.
- **Upstream lag.** Some third-party images may not yet ship a fixed tag; those
  become dated `.trivyignore` residuals with a recheck date, not silent passes.
