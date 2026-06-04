# Phase 37 — Lint & Static Analysis Cleanup

**Priority:** HIGH — blocks `make lint` and `make lint-static`
**Scope:** Code quality only. No logic changes, no new features.

---

## Problem Statement

`make lint` fails because 79 files need `black` reformatting.
`make lint-static` fails with 15 mypy errors across 7 files.
~65 flake8 F401 (unused imports) and 4 F821 (undefined names) are present.
All 2718 tests pass; 21 skips are expected (Go binary / live Redis / PCAP corpus).

---

## Acceptance Criteria

- [x] `make lint` exits 0 (black + flake8 + mypy + bandit all pass in Docker)
- [x] `make lint-static` exits 0 (mypy, bandit, ruff, pip-audit)
- [x] `make test` still passes with 2718 tests, 21 expected skips
- [x] No logic changes — diffs are formatting, import removals, and `# type: ignore` annotations only

---

## Issue Inventory

### A. Black formatting (79 files)

`black --check proxy.py security/ src/` reports 79 files need reformatting.
Fix: `black proxy.py security/ src/`

### B. Flake8 / Ruff errors

| Code | Count | Description |
|------|-------|-------------|
| F401 | ~65 | Unused imports across ~30 files |
| F811 | 1 | `signal` imported at module level (proxy.py:36) and re-imported locally (proxy.py:2425) — remove top-level |
| F821 | 4 | Undefined `x509`, `datetime`, `timezone` in `security/validation.py` (missing imports) |
| F841 | 5 | Unused local variables in `h2_fingerprint.py` and `tap_pipeline.py` |

### C. Mypy errors (15 across 7 files)

| File | Line | Error | Fix |
|------|------|-------|-----|
| `src/tap/watchdog.py` | 22 | `TAP_WORKER_RESTARTS` does not exist; should be `TAP_WORKER_RESTARTS_TOTAL` | Rename import |
| `src/tap/security.py` | 231 | Cannot infer lambda type (redis typed as `object`) | `# type: ignore[misc]` |
| `src/tap/export/taxii_server.py` | 133 | List item type mismatch (mypy locks dict type from first `body` assignment) | `# type: ignore[list-item]` |
| `src/security/write_buffer.py` | 219, 227 | `object` has no `.pipeline` (redis typed as `object` — Phase 16g fix) | `# type: ignore[attr-defined]` |
| `src/security/rate_tracker.py` | 294 | Missing type annotation for `results` dict | Add `Dict[str, Any]` annotation |
| `src/security/rate_tracker.py` | 362, 362 | `redis.Pipeline` lacks `__aenter__`/`__aexit__` (sync pipeline used as async) | `# type: ignore[attr-defined]` |
| `src/tap/capture.py` | 448 | `bytes` in f-string produces `b'...'` repr | `.hex()` on slice |
| `src/tap/tap_pipeline.py` | 113, 119, 128, 134, 137, 138 | `result` reused across different fingerprint types (JA4SResult, JA4HResult, etc.) | Rename per-section: `ja4s_r`, `ja4h_r`, `ja4ssh_r`, `h2_r` |

---

## File-by-File F401 Removal Plan

### proxy.py
- Remove top-level `import signal` (line 36) — local re-import at line 2425 is the actual use

### security/validation.py
- Remove `typing.List`, `typing.Optional`, `typing.Set`
- Remove `urllib.parse.quote`, `urllib.parse.unquote`
- **Add** `from cryptography import x509` (F821 fix)
- **Add** `from datetime import datetime, timezone` (F821 fix)

### src/analytics/drift_detector.py — remove `import math`
### src/analytics/ml_detector.py — remove `import json`, `typing.Optional`
### src/analytics/shadow_scoring.py — remove `datetime.datetime`, `datetime.timedelta`
### src/backup/restorer.py — remove `typing.Optional`
### src/backup/scheduler.py — remove local `import time` (unused inside `_parse_schedule`)
### src/cache/bloom.py — remove `import asyncio`
### src/cli/main.py — remove `pathlib.Path`
### src/security/action_enforcer.py — remove `import time`
### src/security/asn_classifier.py — remove `pathlib.Path`, `redis`
### src/security/blocklists.py — remove `dataclasses.field`
### src/security/mtls.py — remove `cryptography.hazmat.primitives.hashes`
### src/security/pipeline.py — remove `dataclasses.dataclass`, `dataclasses.field`, `.abuseipdb.AbuseIPDBConfig`, `.rate_strategy.RateLimitStrategy`, `.rate_strategy.StrategyConfig`
### src/security/rate_strategy.py — remove `import time`
### src/security/rate_tracker.py — remove `import asyncio`, `typing.Optional`
### src/security/rdap_enrichment.py — remove `typing.Any`
### src/security/risk_scorer.py — remove `dataclasses.field`
### src/security/security_manager.py — remove `.action_types.ActionType`, `.threat_evaluator.MultiStrategyPolicy`
### src/security/threat_evaluator.py — remove `typing.List`
### src/security/tls_enforcer.py — remove `dataclasses.dataclass`, `dataclasses.field`
### src/security/write_buffer.py — remove `import time`, `typing.Callable`
### src/tap/capture.py — remove `dataclasses.field`
### src/tap/enforcement_bridge.py — remove `import time`
### src/tap/export/export_manager.py — remove `typing.Optional`
### src/tap/export/syslog_exporter.py — remove `import time`
### src/tap/fingerprints/h2_fingerprint.py — remove `dataclasses.field`
### src/tap/fingerprints/ja4h.py — remove `dataclasses.field`
### src/tap/fingerprints/ja4ssh.py — remove `dataclasses.field`
### src/tap/fingerprints/ja4x.py — remove `cryptography.hazmat.primitives.serialization`
### src/tap/fingerprints/os_fingerprint.py — remove `dataclasses.field`; remove 6 unused `_OPT_*` imports from `ja4t`
### src/tap/fingerprints/tls_ext_values.py — remove `dataclasses.field`, `src.tap.fingerprints.ja4._GREASE`
### src/tap/fingerprint_store.py — remove `typing.Optional`
### src/tap/security.py — remove `typing.Optional`
### src/tap/tap_pipeline.py — remove `import json`, `import time`, `extract_quic_fingerprint`; also fix F841 unused locals
### src/tap/watchdog.py — remove `typing.Optional`
### src/utils/ip.py — remove `ipaddress.IPv4Address`
### src/utils/logging_config.py — remove `import time`

---

## Implementation Order

1. `black proxy.py security/ src/` — no manual edits needed
2. Fix F821 in `security/validation.py` (add 2 imports, remove 5)
3. Fix `watchdog.py` metric name
4. Fix `tap_pipeline.py` variable reuse
5. Fix `capture.py` bytes f-string
6. Add `# type: ignore` in `write_buffer.py`, `rate_tracker.py`, `security.py`, `taxii_server.py`
7. Add type annotation in `rate_tracker.py:294`
8. Remove all F401 unused imports (file by file)
9. `make test` — must pass
10. `make lint-static` — must pass
11. `make lint` — must pass

---

## Non-Goals

- No logic changes
- No new tests (existing tests validate unchanged behaviour)
- No mypy strict mode (tracked in Phase 16g)
- Do not fix E402 module-level-import-not-at-top (intentional conditional imports)
