<!--
title: Python Dependencies Reconciliation & Semgrep Pin Coupling
audience: developer
last_reviewed: 2026-11-02
phase: 860
-->

# Python Dependencies Reconciliation & Semgrep Pin Coupling

> **Size:** MEDIUM  
> **Dependencies:** [859]  
> **Branch:** `phase-860-python-deps-reconciliation`  
> **Related PR / Issues:** Dependabot PR #682, Phase 800 notes, Phase 833, Phase 838  

---

## Goal

Resolve the pip dependency resolution collision surfaced by Dependabot PR #682 (`ResolutionImpossible`), completely delete development/CI-only security scanners (`semgrep`) and unused transitive pins (`mcp`) from `requirements.txt`, retire five related waivers in `security/waivers.yaml`, triage the pending Python dependency updates, and safely validate version upgrades across all toolchain requirements files.

---

## Background & Problem Statement

Dependabot PR #682 attempted to bump 26 Python dependencies simultaneously in `requirements.txt`. The PR failed CI immediately with `pip._vendor.resolvelib.resolvers.ResolutionImpossible`.

Investigation revealed the root cause is tight transitive pin coupling introduced by `semgrep>=1.176.0`:
1. **The Semgrep Pin Wall:**
   - In `requirements.txt:21`, `semgrep>=1.176.0` was listed alongside testing and development dependencies.
   - When pip attempts to resolve `semgrep` (currently fetching semgrep 1.182.1+), semgrep's own wheel metadata strictly requires:
     - `jsonschema~=4.25.1` (which rejects `jsonschema>=4.26.0`)
     - `mcp==1.29.0` (which rejects `mcp>=2.3.0` proposed in PR #682)
     - `opentelemetry-proto<7.0,>=5.0` (which conflicts with protobuf 7.x)
   - Furthermore, `requirements.txt` contains direct pins:
     - `jsonschema==4.25.1` (line 41)
     - `mcp>=1.29.0` (line 55, added solely to manage semgrep's transitive CVEs)
     - `protobuf>=5.29.6` (line 51)
   - In addition, `requirements-analytics.txt:1` independently pins `jsonschema==4.25.1`.
2. **Tools vs. Runtime vs. Dev Contamination:**
   - `semgrep` is an offline static analysis tool run during `make lint` via its official Docker container (`semgrep/semgrep:1.166.0` in `Makefile:575`). `Dockerfile.tools:122` explicitly notes: *"semgrep and ansible-lint are NOT installed here — they don't yet run on 3.14, so the Makefile runs semgrep from its official container"*.
   - Keeping `semgrep` pinned in root `requirements.txt` polluted pip's dependency resolver for general development, test runners, and management images.
   - First-party code **never** imports `mcp` or `semgrep`. Removing `semgrep` allows immediate deletion of `mcp` and retirement of 5 HIGH CVE waivers in `security/waivers.yaml`.
3. **Major Version Upgrades & Stream Test Realities:**
   - `protobuf` 5.x -> 7.x: Note that JA4proxy has zero Python gRPC or OpenTelemetry runtime code. The only first-party dependency touching protobuf is `google-cloud-storage>=3.13.1` (via `proto-plus`). `proto-plus 1.29.0` requires `protobuf<8.0.0,>=6.33.5`.
   - `fakeredis` 2.38.0 -> 2.40.0: Phase 838 pinned `fakeredis==2.38.0` due to upstream 2.39.0 breaking `xtrim minid`. The component using `xtrim minid` is `management/compliance/purge.py` (line 168). A dedicated regression test must verify `xtrim minid` against 2.40.0.
   - `jsonschema` 4.25.1 -> 4.26+: Must be updated in both `requirements.txt` and `requirements-analytics.txt`, and verified against `src/analytics/stream_consumer.py`.

---

## Scope

### In Scope
1. **Requirements Architecture Cleanup:**
   - Completely delete `semgrep>=1.176.0` and `mcp>=1.29.0` from `requirements.txt`.
   - Retire the 5 `mcp` waivers in `security/waivers.yaml` (CVE-2026-59951, CVE-2026-116684..116686, CVE-2026-114603) and re-render waivers.
   - Update tests that mock waivers/reachability checks (`test_fix_forward.py`, `test_reachability_checks.py`).
2. **Triage the 26 Packages from PR #682 into Logical Groups:**
   - Group 1 (Linters & Dev): `pytest-mock`, `black`, `flake8`, `mypy`, `isort`, `hypothesis`.
   - Group 2 (Core HTTP & Frameworks): `aiohttp`, `urllib3`, `fastapi`, `uvicorn`, `sse-starlette`, `cryptography`.
   - Group 3 (Cloud SDKs): `boto3`, `moto[s3]`, `google-cloud-storage`.
   - Group 4 (Isolated High Risk): `protobuf` 7.x, `fakeredis` 2.40.0, `jsonschema` 4.26+. Landed in dedicated atomic commits.
3. **Multi-File Resolver Verification:**
   - Dry-run resolve all four toolchain files together: `requirements.txt`, `requirements-test.txt`, `requirements-analytics.txt`, `requirements-lint-management.txt`.
4. **Dependabot Configuration Hardening:**
   - Split `python-dependencies` group in `.github/dependabot.yml` to separate dev linters from core runtime dependencies.

### Out of Scope
- Python 3.15 base image upgrades (tracked exclusively in Phase 861).
- Go dependency updates (Phase 859 / #676).

---

## Implementation Plan

1. **Phase 1: Semgrep & MCP Elimination**
   - Delete `semgrep` and `mcp` lines from `requirements.txt`.
   - Retire waivers in `security/waivers.yaml` and run `python3 scripts/render_waivers.py`.
   - Update unit tests expecting `mcp` in waivers or reachability registries.

2. **Phase 2: Multi-File Resolver Dry-Run**
   - Execute combined dry-run inside `ja4proxy-tools`:
     ```bash
     pip install --dry-run \
       -r requirements.txt -r requirements-test.txt -r requirements-analytics.txt -r requirements-lint-management.txt
     ```

3. **Phase 3: Dedicated fakeredis & jsonschema Verification**
   - Add a concrete regression test `tests/unit/test_fakeredis_stream_xtrim.py` asserting `await redis.xtrim(stream, minid=...)` on `fakeredis==2.40.0`.
   - Bump `jsonschema` in both `requirements.txt` and `requirements-analytics.txt`.
   - Run `pytest tests/unit/test_event_validation.py tests/unit/test_stream_consumer.py management/tests/test_compliance_purge.py`.

4. **Phase 4: Protobuf 7.x Verification**
   - Verify `google-cloud-storage` resolves cleanly with `protobuf>=7.0.0` or pin `protobuf<7.0.0,>=5.29.6` if upstream constraints require it.

5. **Phase 5: Close / Supersede PR #682**
   - Close PR #682 and land changes via atomic commits on `phase-860-python-deps-reconciliation`.

---

## Test Strategy

- **Toolchain Resolver:** Full dry-run across all 4 requirements files in `ja4proxy-tools`.
- **Stream Regression:** Dedicated test for `XTRIM ... MINID` in fakeredis.
- **Analytics Schema Test:** Validation tests in `tests/unit/test_event_validation.py`.
- **Preflight Suite:** Complete `make preflight`.

---

## Acceptance Criteria

| # | Criterion | Verification |
|---|---|---|
| A1 | All 4 requirements files resolve together cleanly in `ja4proxy-tools` with zero backtrack / `ResolutionImpossible` within 180s | `pip install --dry-run` terminal log |
| A2 | `semgrep` and `mcp` eliminated from `requirements.txt` and 5 waivers retired | `git diff requirements.txt security/waivers.yaml` |
| A3 | `fakeredis` 2.40.0 `xtrim minid` regression test passes | `pytest tests/unit/test_fakeredis_stream_xtrim.py` |
| A4 | `jsonschema` updated in both `requirements.txt` and `requirements-analytics.txt` | File diffs & analytics tests pass |
| A5 | `make preflight` exits 0 (100% green lint, test, scan) | Terminal run |
| A6 | PR #682 closed and superseded | GitHub PR state |

---

## Rollback & Risk Analysis

- **Risk:** `fakeredis` 2.40.0 exhibits subtle stream consumer group or minid corruption.
  - **Mitigation:** Revert `fakeredis` to 2.38.0 immediately in an isolated commit.
- **Risk:** `protobuf>=7.0.0` breaks `google-api-core`.
  - **Mitigation:** Constrain `protobuf<7.0.0,>=5.29.6`.
