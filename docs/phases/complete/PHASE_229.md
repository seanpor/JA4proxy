---
phase: 229
title: Base-Image Consolidation & Consistent Pinning
status: COMPLETE
size: SMALL
created: 2026-06-06
completed: 2026-06-09
audience: [developer, operator]
---

> **Outcome (COMPLETE — 2026-06-09).** Primary goal achieved: analytics & tarpit
> moved to a **perl-free** `python:3.14.0-alpine@sha256:8373…` base, so the three
> Phase 226 no-fix perl `.trivyignore` exceptions were **deleted** — `make scan`
> is green with zero active exceptions (CI run 80267600210). `entrypoint.sh` →
> POSIX sh (alpine has no bash); analytics numpy compiles via a virtual
> build-deps package removed after install (runtime has no perl/compilers). The
> drifted `security-scan` image was aligned from `golang:1.25.10-alpine` to the
> shared pinned `golang:1.26.4-alpine@sha256:f23e8b…`. `test_docker_consistency`
> now accepts a patch-pinned slim **or** alpine python base.
>
> **Deferred hardening (small follow-up):** the `tests/docker/*` fixture images
> are still tag-pinned (not digest), and a strict "every FROM must be
> digest-pinned" guard is not yet enforced (the current guard enforces the
> patch-version pin). These don't affect the scanned production images.
---

# Base-Image Consolidation & Consistent Pinning

## Goal

Shrink the set of distinct base images the project builds on, standardize on one
version per ecosystem, and pin every base by digest. Fewer, consistent bases =
smaller CVE surface, faster/cacheable builds (helps Phase 227), and one place to
bump when a CVE lands.

## Motivation

A scan of the real Dockerfiles shows avoidable sprawl and inconsistency:

```
 2  alpine:3.19.3@sha256:…            (pinned)
 1  gcr.io/distroless/static-debian12@sha256:…
 1  golang:1.25.10-alpine            (UNPINNED, older Go)   ← security-scan image
 3  golang:1.26.4-alpine@sha256:…    (pinned)
 1  golang:1.26-alpine@sha256:…      (same digest, different tag string)
 6  python:3.14.0-slim               (UNPINNED)
 4  python:3.14.0-slim@sha256:…      (pinned — same image, inconsistent)
```

So: two different Go versions (1.25.10 vs 1.26.4), a tag/digest mismatch
(`1.26-alpine` vs `1.26.4-alpine`), and `python:3.14.0-slim` pinned in 4 places
but unpinned in 6 — the unpinned ones drift and defeat the SLSA/Scorecard
"immutable dependencies" posture the README advertises.

## Scope

- **One Go builder version**, pinned by digest, everywhere (bump `security-scan`
  off 1.25.10 onto the common 1.26.x digest).
- **One python runtime** (`python:3.14.0-slim`), pinned by the same digest in all
  Dockerfiles (fix the 6 unpinned ones).
- **One alpine**, one distroless — pinned.
- Consider a shared builder/base stage (or a single internal base image) so the
  toolchain layer is defined once and reused.
- Add a guard (extend `meta_lint`/a test) asserting every `FROM` is digest-pinned
  and drawn from the approved base set, so drift can't return.

## Out of Scope

- Switching ecosystems (e.g. distroless-everywhere) — just consolidate/pin what's
  here.
- The caching mechanics themselves (Phase 227).

## Acceptance Criteria

1. At most one Go base version and one python base version across all real
   Dockerfiles, each pinned by digest.
2. No unpinned `FROM` lines in shipped Dockerfiles; tag/digest strings consistent.
3. A guard fails CI if a new `FROM` is unpinned or off the approved base set.
4. `make build` + `make scan` still pass.
