# Phase 999 — Traceability Fixture (TAGGED)

## Goal

A minimal phase doc used by `tests/unit/test_traceability.py` to exercise
the REQ-tagged extraction path.

## Acceptance Criteria

- [ ] REQ-999-01: Demo file exists in the fixtures tree. Verified by:
      `tests/unit/test_traceability.py::test_extracts_req_ids_from_tagged_phase`
- [ ] REQ-999-02: Manual review marker is honoured. Verified by: `[MANUAL-REVIEW]`
- [ ] REQ-999-03: Multi-line `Verified by:` clauses parse cleanly.
      Verified by:
      `tests/unit/test_traceability.py::test_handles_multiline_verified_by`
