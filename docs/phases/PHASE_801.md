---
phase: 801
title: ja4proxy-management Base Hardening (Debian -> low-CVE base)
status: IN_PROGRESS
created: 2026-07-21
audience: [developer]
---

# ja4proxy-management Base Hardening

> **STATUS: IN_PROGRESS.** Stage 1 (Alpine rebase, steps 1-2-4-5-6-7 below)
> is complete — see `docs/phases/manifest.yaml` for the full writeup. Stage 2
> (step 3, the SAML adversarial test) is deliberately deferred until
> [[PHASE_806]]/[[PHASE_807]]/[[PHASE_808]] land a real, CI-verified safety
> net for `management/tests/` — found unregistered-from-CI while scoping this
> phase, and too load-bearing for this phase's own D2 risk assessment to skip.
>
> Picks up the piece [[PHASE_317]] explicitly deferred: `ja4proxy-management`
> and `ja4proxy-admin` stayed on Debian `python:3.14-slim`, "their no-fix
> distro CVEs waiver-tracked" — never actually wired into a waiver register,
> and never scanned by anything. This phase finishes that.

## Goal (plain language)

Get `ja4proxy-management` onto a base image with no unfixable distro CVEs,
the same way [[PHASE_317]] already did for `analytics`, `tarpit`, `test`, and
`trafficgen` (Debian slim -> `python:3.14.6-alpine3.24`) — then add it to
`scan-first-party` so it's actually gated, not silently exempt.

## Why this phase exists

A phase-800 code-health session (2026-07-21) ran a fresh, unfiltered Trivy
scan of `ja4proxy-management` — the first time anyone had, since Phase 317
deferred it five weeks earlier — and found **41 HIGH/CRITICAL findings**,
only 6 of which were previously documented anywhere:

| Category | Count | Fixable how |
|---|---|---|
| Debian OS packages (`perl-base` incl. 3x CRITICAL, `curl`, `libcurl4t64`, `util-linux` family, `ncurses`, `gzip`, `bsdutils`, `libacl1`) | 36 | **No upstream fix for this base** — same class Phase 317 already fixed for the other four images by changing base. This phase. |
| Python ecosystem (`starlette`, `pyasn1`, `ecdsa`) | 5 | 4 already fixed in a separate phase-800 commit (fastapi bump, pyasn1 override unblocked by a Dependabot python-jose bump). `ecdsa` CVE-2024-23342 is an upstream won't-fix, needs the PyJWT migration already tracked from phase-304 — **out of scope here**. |

`ja4proxy-management` is production code (the FastAPI Management API, per
`CLAUDE.md`) — this isn't a CI-only convenience image like `ja4proxy-test`.

## Why this wasn't just done in phase-800

Re-basing `analytics`/`tarpit`/`test`/`trafficgen` (Phase 317) was already
flagged as the effort sink of that phase: "musl/distroless build fallout...
can break wheels that ship only manylinux builds." Management carries a much
heavier and more sensitive dependency set than any of those four —
`cryptography`, `bcrypt`, `pyOpenSSL`, `lxml`, `xmlsec`, `python3-saml`,
`webauthn`, `authlib` — several of which (`xmlsec`, `python3-saml`) bind
against system C libraries (`libxml2`, `libxmlsec1`) whose Alpine/musl
packaging has historically been a common source of subtle SAML-signature
bugs. Getting this wrong doesn't fail loud in CI the way a broken `manylinux`
wheel does — it can fail quiet, as a SAML assertion that silently
verifies when it shouldn't. That risk profile means this needs its own
scoped, reviewed plan and a real functional smoke test of the auth flows,
not a bolt-on to an unrelated CVE-hygiene session.

## Key decisions (for review)

| # | Decision | Why |
|---|---|---|
| D1 | **Re-base onto `python:3.14.6-alpine3.24`** (the same digest-pinned base Phase 317 already chose for the other four first-party Python images), not distroless. | Consistency with the existing fleet (one base to patch, one Dependabot entry already tracks it — see `deploy/docker` in `.github/dependabot.yml`). Alpine also keeps a shell, which `Dockerfile.management`'s `HEALTHCHECK CMD curl ...` and `useradd`/`USER` steps rely on — distroless has none, and Phase 317's own risk notes call out entrypoint/healthcheck breakage as a real failure mode on shell-less bases. |
| D2 | **Full SAML auth-flow smoke test is mandatory before merge**, not just `tests/unit/management/` passing. | `tests/unit/management/` doesn't exercise `python3-saml`/`xmlsec` at all (grep confirms no SAML-specific test file exists yet) — a silent signature-verification regression would pass the existing suite. This phase must add at least one adversarial SAML test (tampered assertion rejected) before it can claim the base swap is safe. |
| D3 | **Add `ja4proxy-management` to `scan-first-party`'s `FIRST_PARTY_IMAGES`** only after a clean scan is proven in CI — mirrors [[PHASE_317]] D3 exactly. | Don't gate on red; prove green first, gate second. |
| D4 | **Any genuinely-unfixable residual gets a dated `.trivyignore` entry**, not silence. | Matches Phase 314/317 policy — first-party residuals must be rare and time-boxed. |
| D5 | ~~`ja4proxy-admin`'s Dockerfile gets the same base swap opportunistically~~ — **N/A, confirmed already decommissioned.** `docs/phases/manifest.yaml` records `Dockerfile.admin` was purged (Phase 232d/232e: legacy admin API decommission — "all management traffic now flows through the JWT-gated management service on port 8090"). | Verified 2026-07-21; nothing to do here. |

## Implementation plan (in order)

1. **Re-base `deploy/docker/Dockerfile.management`** to `python:3.14.6-alpine3.24@<digest>`, matching the `apk upgrade --no-cache` + package-install pattern already used in `src/analytics/Dockerfile` / `src/tarpit/Dockerfile`. Identify and install the Alpine equivalents of whatever Debian packages the current image pulls in beyond the Python wheels (check for any `apt-get install` beyond `curl libyaml-dev` — currently just those two, per the existing Dockerfile).
2. **Build and fix musl/wheel fallout** for each pinned dependency in `management/requirements.txt`, in particular: `cryptography`, `bcrypt`, `lxml`, `xmlsec`, `python3-saml`, `webauthn`, `pyOpenSSL`. Expect `xmlsec` to need `libxml2-dev libxmlsec1-dev pkgconfig` (or Alpine equivalents) at build time even if wheels exist for the others.
3. **Add a SAML adversarial test** (`tests/unit/management/test_saml_*.py` or extend an existing auth test file) — tampered assertion / bad signature must be rejected — as the functional proof the xmlsec/libxmlsec1 binding still works correctly post-rebase. This is the acceptance-critical test, not optional coverage.
4. **Full functional smoke**: `management-up` (or equivalent), confirm `/health` responds, confirm normal login (password + OIDC + SAML if a test IdP is available) still works end-to-end.
5. **Re-scan**: confirm 0 HIGH/CRITICAL, or a dated `.trivyignore` entry per D4 for anything genuinely unfixable.
6. **Add `ja4proxy-management` to `scan-first-party`'s `FIRST_PARTY_IMAGES`** in the Makefile once step 5 is green.
7. **Update `docs/reference/DOCKER_IMAGES.md`** (management isn't currently even listed there — add it) and `docs/phases/manifest.yaml`.
8. **Docs**: CHANGELOG fragment, ADR if the base choice needs justifying beyond D1's rationale, manifest `801` COMPLETE.

## Test plan

- **`tests/unit/management/` must still pass 43/43** post-rebase (today's phase-800 session established this baseline against the current Debian image + the fastapi/pyasn1 bumps — use it as the regression floor).
- **New SAML adversarial test** (step 4) — the actual proof this is safe, not a formality.
- **Build + scan in CI** — per Phase 317's own lesson ("local full builds are unreliable"), the authoritative result is a CI run, not a local one.
- **`make scan` exits 0** end to end with `ja4proxy-management` now included.

## Acceptance criteria

- [ ] `ja4proxy-management` scans 0 HIGH/CRITICAL, or carries only dated/justified `.trivyignore` residuals (expect `CVE-2024-23342`/ecdsa to remain here — that one is explicitly out of scope, see below).
- [ ] `ja4proxy-management` is in `scan-first-party`'s `FIRST_PARTY_IMAGES`; `make scan` exits 0.
- [ ] A SAML signature-tampering test exists and fails correctly (rejects the tampered assertion) on the re-based image.
- [ ] `tests/unit/management/` still passes in full.
- [ ] `docs/reference/DOCKER_IMAGES.md` lists `ja4proxy-management` with its new base.
- [ ] `ja4proxy-admin` status resolved (either also re-based, or confirmed dead and noted here).
- [ ] Full CI green.

## Out of scope

- **`CVE-2024-23342` (ecdsa)** — upstream won't-fix; the real remediation is the PyJWT migration off `python-jose` already tracked from phase-304. A base-image change cannot fix a pure-Python package's own algorithm choice.
- **The phase-304 PyJWT migration itself** — a separate, larger auth-library change; do not fold it into this phase.
- **`management-image.yml`'s persistent GHA build cache** — noted during the phase-800 session as carrying the same staleness risk `scan-first-party --no-cache` already fixed for local builds; worth its own small follow-up (add a Trivy step + either drop `cache-to: type=gha` or add a cache-busting mechanism) but not required for this phase's acceptance criteria.
- MEDIUM/LOW severity CVEs (reporting-only, per Phase 314/317 precedent).

## Risks

- **musl/wheel fallout**, per Phase 317's own risk note — budget for real build debugging, especially `xmlsec`/`python3-saml` (system C library bindings, not pure wheels).
- **Silent SAML breakage** is the risk that matters most here and the reason D2 is non-negotiable: a broken auth integration that still returns 200s is worse than a CVE with no known exploit path. Do not mark this phase complete on "the image builds and unit tests pass" alone.
- **`ja4proxy-admin` uncertainty** — Phase 317 refers to it in passing; confirm it still exists as a real, shipped artifact before spending effort on it (D5).
