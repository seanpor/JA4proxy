# PHASE 330 — Resolve Security Scan Vulnerability Failures

## Status: COMPLETE

---

## Goal

`make scan` fails because the first-party image vulnerability scan (`scan-first-party`) scans `ja4proxy:1.0.0`, which is a legacy Python-based container image with 231 vulnerabilities. This phase updates the production image tag to the Go-based `ja4proxy:2.0.0` in the Makefile, production docker-compose configuration, and documentation, ensuring security scans run against the clean Go/Alpine-based production image and succeed.

---

## 330a. Production Image Tag Update

### Finding

The production container image for the proxy in `deploy/docker/docker-compose.prod.yml` and `Makefile` (`FIRST_PARTY_IMAGES`, `scan-first-party`) is tagged `ja4proxy:1.0.0`. However, the Go rewrite of the proxy is v2.0.0, and `deploy/docker/docker-compose.poc.yml` builds it under the tag `ja4proxy:2.0.0`. As a result:
1. `make build` builds `ja4proxy:2.0.0` but not `ja4proxy:1.0.0`.
2. `make scan` runs `scan-first-party` which targets `ja4proxy:1.0.0`.
3. The image scan fails because `ja4proxy:1.0.0` matches a stale, vulnerable Python-based image.
4. `make check-image-versions` warns about version drift for `ja4proxy` between `docker-compose.prod.yml` and `docker-compose.poc.yml`.

### Fix

Update the proxy image version tag to `2.0.0` in:
- `deploy/docker/docker-compose.prod.yml`
- `Makefile` (under `FIRST_PARTY_IMAGES` and `scan-first-party` loop)

---

## 330b. Phase Documentation Hygiene

### Finding

`docs/phases/PHASE_230.md` describes the production Go proxy migration and lists `ja4proxy:1.0.0` as the production image. In addition, the phase document was not tracked in `docs/phases/manifest.yaml` despite being referenced as a dependency.

### Fix

1. Update the table in `docs/phases/PHASE_230.md` to reference `ja4proxy:2.0.0`.
2. Add the definition of Phase 230 (status: `PROPOSED`) to `docs/phases/manifest.yaml` and assign it to the `User Interface & Experience` epic.

---

## Acceptance Criteria

- [x] `make check-image-versions` passes with zero warnings about `ja4proxy` version drift.
- [x] `make build` successfully builds the Go proxy.
- [x] `make scan` (which runs `scan-first-party`) successfully executes and passes with exit code 0.
- [x] `make lint-phases` exits 0.

---

## Files to Modify

| File | Change |
|------|--------|
| `Makefile` | Update `ja4proxy:1.0.0` to `ja4proxy:2.0.0` in `FIRST_PARTY_IMAGES` and `scan-first-party` target |
| `deploy/docker/docker-compose.prod.yml` | Update `ja4proxy:1.0.0` to `ja4proxy:2.0.0` for the `proxy` service image tag |
| `docs/phases/PHASE_230.md` | Update table to reference `ja4proxy:2.0.0` |
| `docs/phases/manifest.yaml` | Add phase 230 and phase 330 entries and map to epics |
