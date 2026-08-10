- **Fix `.trivyignore` expiry off-by-one (Phase 800)**: `scripts/scan_exceptions.py`
  treated an entry whose `exp:` date is *today* as still valid (`d < 0`), but Trivy
  suppresses a finding only while `today < exp` — so `make scan-exceptions` printed
  "✓ all within their time window" and exited 0 while `make scan` was already red.
  Verified against `aquasec/trivy:0.71.0`: `exp:today` is reported, `exp:tomorrow`
  is suppressed. Now flags `d == 0` as EXPIRED (caught 42 live entries on
  2026-08-10) with boundary tests in `tests/unit/test_scan_exceptions.py`.
