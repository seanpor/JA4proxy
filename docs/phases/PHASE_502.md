---
phase: 502
title: "Phase 15 Gap Closure — Browser Fixtures and Container Smoke Test"
size: SMALL
created: 2026-06-26
audience: [developer, qa]
dependencies: [15]
---

# Phase 502 — Phase 15 Gap Closure

Closes the two remaining open items from the Phase 15 post-implementation review.
Neither item blocks production; both are test coverage gaps that leave regressions
invisible.

## Background

Phase 15's post-implementation review (see `docs/phases/complete/PHASE_15.md §Post-Implementation Review`)
identified four gaps. Gaps 2 and 3 were closed on branch `fix-phase-15-gaps`. This
phase closes Gaps 1 and the REQ-015-08 automation gap.

## Gap 1 — Browser-like ClientHello fixtures

**Problem:** `tests/fixtures/clienthello/` contains only synthetic minimal cases plus
curl and openssl captures. Real browsers produce richer ClientHellos — GREASE values
in both cipher and extension lists, `compress_certificate` (0x001b),
`post_handshake_auth` (0x0031), multiple ALPN values, and padding — that are the
edge cases most likely to expose JA4 computation bugs. The gap is not Go/Python
parity (the Python proxy is gone) but test coverage of code paths that only
browser-shaped input exercises.

**Approach:** Since capturing live browser traffic requires an interactive browser
session (non-reproducible in CI), we generate deterministic synthetic fixtures that
mimic Chrome and Firefox ClientHello patterns using the existing
`buildClientHelloBytes` helper in `internal/tls/ja4_test.go`. The fixtures are
generated once and committed; `TestJA4_FixturesParity` and
`TestFixtureReplay_StableDecisions` verify them on every run.

**Deliverables:**
- `tests/fixtures/clienthello/chrome_tls13_like.bin` — Chrome 120+ pattern: GREASE
  in cipher and extension lists, `compress_certificate`, `extended_master_secret`,
  `post_handshake_auth`, multi-ALPN (h2 + http/1.1)
- `tests/fixtures/clienthello/firefox_tls13_like.bin` — Firefox 122+ pattern: no
  GREASE, different cipher ordering, `post_handshake_auth`, `record_size_limit`
- `tests/fixtures/clienthello/known_ja4.json` updated with expected fingerprints
- `internal/tls/gen_browser_fixtures_test.go` — generator (build tag `generate`)
  that produces the above files; checked in so the generation is reproducible

## REQ-015-08 — Management + analytics container smoke test

**Problem:** "Python analytics and management UI containers run unchanged alongside
Go proxy" was verified only by `[MANUAL-REVIEW]` at Phase 15 closure. The Python
proxy has since been deleted. There is no automated test that verifies these services
are wired to the Go proxy correctly.

**Approach:** Extend `tests/integration/test_container_config.py` with assertions
that verify the docker-compose configuration wires management and analytics to the
Go proxy service (`ja4pd`) rather than to any deleted Python proxy service, and that
the shared Redis data network is present for all three services.

**Deliverables:**
- New test class/functions in `tests/integration/test_container_config.py` covering:
  - management service references `ja4pd` (or no `proxy` service) as its upstream
  - analytics service is on the Redis data network alongside the Go proxy
  - no reference to `proxy.py` or `python proxy` in compose service definitions

## Acceptance Criteria

- [ ] `tests/fixtures/clienthello/chrome_tls13_like.bin` exists and parses without error
- [ ] `tests/fixtures/clienthello/firefox_tls13_like.bin` exists and parses without error
- [ ] `known_ja4.json` has entries for `chrome_tls13_like` and `firefox_tls13_like`
- [ ] `TestJA4_FixturesParity` passes with the new fixtures included
- [ ] `TestFixtureReplay_StableDecisions` covers the new fixtures automatically (no changes needed — the test already walks all `.bin` files)
- [ ] New `test_container_config.py` assertions pass with `pytest -x` (no Docker daemon required — config-parsing only)
- [ ] REQ-015-08 updated to `[x]` in `PHASE_15.md` once the container test is in place
