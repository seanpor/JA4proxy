---
phase: 814a
title: "Notes — charter, test range, finding/verification harness"
status: IN_PROGRESS
created: 2026-08-05
audience: [security, developer]
---

# Phase 814a — working notes

Decisions taken, things learned by testing rather than assuming, and mistakes
made. Written for whoever picks this up next, including future-me.

## Delivered so far

| Artefact | What |
|---|---|
| `deploy/docker/docker-compose.pentest.yml` | Range override (isolation + attacker) |
| `deploy/docker/Dockerfile.attacker` | Attacker workstation image |
| `scripts/start-pentest-range.sh` | Bring-up + eight assertions + provenance |
| `scripts/check_finding_spec.py` | PROGRAMME.md §9 completeness gate (13 tests) |
| `scripts/verify_revert.sh` | Two-state proof automation |
| `docs/security/pentest/RANGE.md` | Range documentation |
| `Makefile` | `pentest-range`, `-down`, `-verify`, `pentest-shell` |

**Still open in 814a:** the RoE document; wiring `make verify-findings` into
CI; the `found_against` provenance field in the register schema; tests for
`verify_revert.sh`; a compose-config test asserting the range stays isolated.

## Decisions

### The range is an override on the PoC stack, not a parallel stack

The single load-bearing decision. `docker-compose.pentest.yml` layers on
`docker-compose.poc.yml`, so **the range is what actually ships**. Findings
transfer, and there is no "the range has drifted from production" failure mode
because there is nothing to drift.

This was only viable because of an empirical result (below): Docker silently
drops port publishing on internal networks, so the override never needed to
remove the PoC's `ports:` entries — which compose's list-concatenation
semantics would not have allowed anyway.

### The range runs in PRODUCTION posture by default

`scripts/start-poc.sh` writes `ENVIRONMENT=development`, which activates the
project's test-only escape hatches (relaxed cookie flags, API docs exposed,
boot guards that tolerate weak secrets).

For a pentest range that would **invalidate the results**: we would be
attacking a deliberately weakened build, producing false positives ("the escape
hatch works!") while leaving the hardening that actually ships untested. The
range therefore defaults to `ENVIRONMENT=production` with strong random fixture
secrets, so the fail-closed boot guards (`0093`/`0096`) are satisfied
legitimately rather than bypassed. `RANGE_ENVIRONMENT=development` overrides
deliberately.

### Networks are renamed, not just made internal

`docker-compose.poc.yml` pins **global** network names via `name:`. If a PoC
stack were already running, an unrenamed range would attach to *its*
`ja4proxy-dmz` — which is **not** internal — and would have full internet
access while appearing correctly configured. Renaming to `ja4range-*` makes the
collision impossible; asserting egress catches it anyway if this is ever undone.

### Assertions, not assumptions

Every bring-up proves eight properties (see `RANGE.md`). Assertions 7–8
(targets reachable, `redis`/`backend` *not* reachable) exist because the first
six only prove the range is **safe** — a stack that blocked everything would
pass them and be useless.

## Learned by testing

| Question | Answer | Consequence |
|---|---|---|
| Does `internal: true` block egress? | Yes — **both** IP and DNS | The isolation mechanism |
| Do published ports work on an internal network? | **No** — Docker creates no host listener at all | The override approach is viable |
| Is `helm` available? | Yes, host **and** tools image | 814b's Helm rendering is fine |
| Does the management app import without secrets? | **No** — 0096 guard raises at import | Any introspection needs fixture env |

## Mistakes made (all fixed)

Recorded because two of them are instances of the exact failure this project
treats as most expensive.

1. **Fail-closed guard, false positive.** The credential safety check grepped
   the compose file's raw text and tripped over its *own comments* explaining
   why `deploy/secrets` is off limits. Fixed by stripping comments before
   matching — check what compose will act on, not what the file says.
2. **Egress probe mis-parsed, also failing closed.** The probe merged `wget`'s
   stderr into stdout, so the result was two lines and the string compare
   failed *even though egress was correctly blocked*. Fixed with `2>/dev/null`
   plus `tail -n 1`.
3. **apk pins written from memory.** The attacker image pinned every package
   version; the values were invented, and Alpine 3.22 ships redis 8.x not 7.x,
   so the build failed immediately. Now follows house convention — digest-pinned
   base plus `apk upgrade`, no per-package pins. Lesson: resolve versions from
   the actual base image, or do not pin.

## Findings for later workstreams

- **`proxy:9090` (metrics) is loopback-bound inside its container** and is
  unreachable over the network even from an adjacent container. Correct
  hardening — but 814e/814j must know it before concluding the endpoint does
  not exist. Recorded in `RANGE.md` and in the script's output.
- **`redis` and `backend` do not even resolve** from the attacker position.
  Segmentation is real, and now asserted on every bring-up.

## Raised, not absorbed

**Phase 815 (PROPOSED).** Adding four `make` targets, three scripts and one
image should have meant rows in `MAKEFILE_TARGETS.md`, `SCRIPTS.md` and
`DOCKER_IMAGES.md`. Measuring them first showed all three had already drifted:
187 targets / 167 documented / 56 missing **and 36 documented that no longer
exist**; 45 of 119 scripts; and `DOCKER_IMAGES.md` — the "canonical registry of
all images" — missing `Dockerfile.go-proxy`, which builds the production proxy.
`lint-meta`'s doc-sync check is one-directional, so none of it was caught.
Adding three more hand-maintained rows to lists that are already 63% wrong
would be ceremony, not documentation. See `PHASE_815.md`.

## Pre-flight on 814b — why it was re-specced before starting

Probing 814b's central mechanism found it would have produced a confidently
wrong result:

| Route enumeration approach | Routes found |
|---|---|
| Naive `app.routes` iteration | **4** |
| Recursing into `.routes` | **4** |
| `app.openapi()` | **94** |

FastAPI 0.141.1 wraps included routers in `_IncludedRouter` objects that do not
expose `.routes`, so the natural traversal finds only the auto-docs endpoints.
An inventory built that way would report a 4-route attack surface — and would
**understate** it, the dangerous direction. `app.openapi()` flattens correctly
but does not carry the auth dependency or required role, which is exactly what
814b needs; that requires `_IncludedRouter.original_router` traversal plus
`dependant` inspection.

Five further issues, and the re-spec, are recorded in `PHASE_814.md` §5 (814b).
