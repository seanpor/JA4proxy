---
phase: 227
title: Scan & Build Caching — Stop Re-Pulling the Same Layers and DBs
size: SMALL
created: 2026-06-06
audience: [developer, operator]
---

# Scan & Build Caching

## Goal

Make `make scan` (and the CI scan job) fast by caching the things it currently
re-fetches on every run: the Trivy vulnerability DB and the shared base-image
layers it pulls once per scanned image.

## Motivation

The de-suppressed scan (Phase 226) now does real work but takes **~5 minutes**.
Watching the log, the same costs repeat:
- the **Trivy DB** is downloaded fresh each invocation;
- the **same base layers** (e.g. `python:3.14-slim`, `alpine:3.19.3`) are pulled
  and re-scanned once for each of the ~6 first-party images;
- `trivy image` containers re-pull `aquasec/trivy:0.71.0` repeatedly.

## Scope

- **Trivy DB cache**: point trivy at a persistent `--cache-dir` and cache it in
  CI (`actions/cache`) with a short refresh window (the DB updates ~6-hourly;
  a 15-min–1-hour local TTL as suggested is fine for dev). Use `--skip-db-update`
  when a fresh-enough cache exists.
- **Build layer cache**: enable buildx layer caching (`--cache-from/--cache-to`
  or `actions/cache`) so base layers aren't rebuilt/re-pulled per image.
- **De-dup base scanning**: scan each distinct base image once, not once per
  derived image (pairs naturally with Phase 229's base consolidation).

## Out of Scope

- Changing what the scan gates on (Phase 226).
- Reducing the number of base images (Phase 229 — but this phase benefits from it).

## Acceptance Criteria

1. A warm-cache `make scan` is materially faster than cold (target: ≥40% wall-clock
   reduction), with the saving documented.
2. Trivy DB is cached with a defined TTL; CI restores it across runs.
3. No loss of scan coverage or severity gating versus Phase 226.
