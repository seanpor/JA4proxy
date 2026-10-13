---
phase: 819b
title: "Retire Locust & Clean Performance Dependencies"
status: PROPOSED
size: SMALL
created: 2026-08-13
audience: [developer, operations]
---

# Retire Locust & Clean Performance Dependencies

> **STATUS: PROPOSED — plan for junior developer execution.**
>
> Split from original Phase 819b. This phase addresses **F5** (Locust bit-rot & unneeded dependencies) cleanly in isolation.

## Goal

Remove dead `locust` dependencies and the bit-rotten `locust_tests.py` suite.
In Python 3.14 (`ja4proxy-tools`), `locust==2.17.0` cannot import due to PEP 649/749 deferred annotations, relies on removed event hooks, builds structurally corrupt ClientHellos, and drives unisolated load against dev lanes. Retiring this dead suite eliminates scan CVE surface and cleans Makefile performance targets.

## Scope of Work (Junior Dev Checklist)

1. **Delete Dead Test File**:
   - Remove `tests/performance/locust_tests.py`.
2. **Clean Dependencies**:
   - Remove `locust==2.17.0` and `msgpack>=1.2.1` from `requirements.txt`.
3. **Clean Makefile**:
   - Remove or retire the `perf-test` target in `Makefile` (replace with message or point to modern benchmark suite `bench-macro`).
4. **Verification**:
   - Run `make test-unit` to ensure no remaining tests import locust.
   - Run `make lint` to verify clean imports.

## Acceptance Criteria
- `requirements.txt` has no `locust` or `msgpack`.
- `tests/performance/locust_tests.py` is removed.
- `make lint` passes cleanly.
