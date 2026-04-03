# Phase 66 — Python 3.14 Compatibility Assessment

## Overview

All JA4proxy containers run Python 3.11.11. Python 3.14 (released October 2025) offers
meaningful performance gains — the tail-call interpreter alone gives ~15% on all Python
code with zero code changes, and the JIT compiler benefits the JA4/scoring hot path.

Before touching any Dockerfile, this phase answers three questions:

1. **Do all dependencies have Python 3.14 wheels?** If not, which ones need source builds?
2. **Does the test suite pass on 3.14 locally?** Surface any deprecation-promoted-to-error
   issues before they block a Dockerfile change.
3. **What is the current 3.11 performance baseline?** Required as the before/after reference
   for Phase 67 (the actual upgrade).

This is a zero-risk, zero-production-change phase. It produces a compatibility report and
a benchmark baseline. All upgrade work happens in Phase 67 onwards.

---

## Background: Python 3.14 Performance Levers

| Feature | Available | Effect |
|---------|-----------|--------|
| Tail-call interpreter (PEP 764) | 3.14 default (Clang build) | ~5–15% all Python code |
| Copy-and-patch JIT | 3.14 default on supported platforms | ~10–25% hot loops (JA4, scoring) |
| Faster `asyncio` task scheduling | 3.14 (progressive since 3.12) | ~10–20% per-connection overhead |
| PEP 749 deferred annotations | 3.14 default | Faster module import |
| Improved free-threading | 3.14t build (separate image tag) | True GIL-free parallelism (Phase 69) |

Cumulative estimate for standard build upgrade (no code changes): **~25–35% on
CPU-bound paths** (JA4 computation, risk scoring, TLS parsing).

---

## Work Plan

### A — Dependency Wheel Checker

Write `scripts/check-python314-compat.py`:

```python
#!/usr/bin/env python3
"""
Check all requirements*.txt packages for Python 3.14 wheel availability.
Uses PyPI JSON API (stdlib only: urllib, json). No additional installs required.
Outputs a table: package | current version | 3.14 wheel | action needed.
Exit 0 if all packages have wheels or are pure-Python.
Exit 1 if any C-extension package lacks a 3.14 wheel.
"""
```

The script must:
- Parse `requirements.txt`, `requirements-test.txt`, `requirements-analytics.txt`
- For each package, fetch `https://pypi.org/pypi/{package}/json` and check `urls[].python_requires`
  for `cp314` or `py3` compatibility tags
- Flag C-extension packages (those with compiled wheels but no 3.14 wheel) as `BUILD_FROM_SOURCE`
- Output a markdown-compatible table to stdout
- Write the table to `reports/python314-compat.md` for commit

Known expected outcomes based on April 2026 PyPI state:

| Package | Expected status |
|---------|----------------|
| `pytricia 1.3.0` | May lack wheel — C extension, infrequently updated |
| `aiohttp` | ✅ Has 3.14 wheel |
| `redis` | ✅ Pure Python |
| `cryptography` | ✅ Rust-based, broad wheel coverage |
| `scapy` | ✅ Pure Python |
| `numpy` (analytics) | ✅ Has 3.14 wheel from 2.0+ |
| `scipy` (analytics) | ✅ Has 3.14 wheel |

If `pytricia` lacks a wheel, the fix is one Dockerfile line:
```dockerfile
RUN apt-get install -y --no-install-recommends gcc && pip install pytricia==1.3.0
```

### B — Local 3.14 Test Run

Run the full test suite against Python 3.14 locally (not in Docker, not in CI yet):

```bash
# Install Python 3.14 via pyenv if not present
pyenv install 3.14.0
pyenv local 3.14.0

# Run the suite
python3 -m pytest tests/ --ignore=tests/integration/test_docker_stack.py -x -q 2>&1 \
  | tee reports/python314-test-run.txt
```

Expected: all 2687+ tests pass. Any failure is a deprecation issue to fix in Phase 67.

Document any failures in `reports/python314-compat.md` with the fix needed.

### C — Benchmark Baseline Capture

Run the existing benchmark suite on Python 3.11 and record the baseline. This is the
reference point for Phase 67's acceptance criteria.

```bash
make bench 2>&1 | tee reports/benchmark/python311-baseline.md
```

If `make bench` is not available, run:
```bash
python3 -m pytest tests/performance/ -v 2>&1 | tee reports/benchmark/python311-baseline.md
```

Record at minimum:
- Scoring path mean latency (ms)
- Bypass path mean latency (ms)
- Full ALLOW connection mean (ms)
- Throughput ceiling (conn/s) if measurable

---

## Files to Create / Modify

| File | Change |
|------|--------|
| `scripts/check-python314-compat.py` (new) | PyPI wheel availability checker |
| `reports/python314-compat.md` (new) | Compatibility table output |
| `reports/benchmark/python311-baseline.md` (new) | Pre-upgrade benchmark baseline |
| `docs/phases/manifest.yaml` | Add Phase 66 |
| `CLAUDE.md` | Add Phase 66 to phase index |
| `CHANGELOG.md` | Phase 66 entry |

---

## Acceptance Criteria

- [ ] `scripts/check-python314-compat.py` runs on Python 3.11 with no extra installs
- [ ] `reports/python314-compat.md` committed with a row for every package in requirements*.txt
- [ ] All packages either have a 3.14 wheel or are marked `BUILD_FROM_SOURCE` with the
      required Dockerfile fix documented
- [ ] Full test suite run attempted on Python 3.14 — result (pass/fail/count) documented
- [ ] `reports/benchmark/python311-baseline.md` committed with scoring path and bypass
      path mean latencies
- [ ] `CHANGELOG.md` entry for Phase 66

---

## What This Does Not Cover

- Actual Dockerfile changes — that is Phase 67.
- Any code changes — Phase 66 is read-only except for the new script and reports.
- Free-threading assessment — Phase 69.
- Analytics container — Phase 70.
