<!--
title: Dynamic Threat-Intelligence Feed Ingestion Contract & Malformed Feed Defense
audience: developer
last_reviewed: 2026-10-29
phase: 857
-->

# Dynamic Threat-Intelligence Feed Ingestion Contract & Malformed Feed Defense

> **Size:** SMALL
> **Dependencies:** [856]
> **Branch:** `phase-857-ti-feed-hardening`

---

## Goal

Harden threat intelligence feed parsing and transport ingestion (`src/analytics/ti_feeds/stix_ja4.py` and `src/analytics/ti_feeds/taxii.py`) against malformed STIX 2.1 indicators, invalid or boundary CIDRs, nested dictionary recursion, ReDoS patterns, and unbounded HTTP response sizes.

---

## Junior Dev Feasibility & Sizing

- **Verdict:** **SMALL & Straightforward**.
- **Junior Dev Friendliness:** High. Pure Python property-based testing and input sanitation with Hypothesis and pytest. Runs 100% in the containerized `ja4proxy-tools` environment.
- **Clear Bounds:** Targets `parse_stix_indicator` in `src/analytics/ti_feeds/stix_ja4.py` and payload limit protections in `src/analytics/ti_feeds/taxii.py`.

---

## Scope

### In Scope
1. **Property-Based Fuzzing & Invariant Suite (`tests/unit/analytics/ti_feeds/test_stix_fuzz.py`)**:
   - Fuzz `parse_stix_indicator` with corrupted CIDR notations (e.g., `/0`, `/129`, `999.999.999.999`, non-standard colons) and verify safe validation failure without exceptions.
   - Assert regex extractors (`_PATTERN_IPV4_RE`, `_PATTERN_JA4_RE`) reject adversarial pathological strings within bounded time (no catastrophic backtracking / ReDoS).
   - Assert handling of deeply nested, malformed, or cyclic indicator structures.
2. **Payload Size Guarding**:
   - Ensure `TAXIIClient` enforces a strict response payload limit before full JSON decoding to guard against memory exhaustion.
3. **Containerized Execution**:
   - Verified via `docker run --rm -v "$PWD":/src -w /src ja4proxy-tools pytest tests/unit/analytics/ti_feeds/`.

### Out of Scope
- Changes to external threat intelligence vendors or live external API calls.

---

## Acceptance Criteria
- [ ] Hypothesis tests in `tests/unit/analytics/ti_feeds/test_stix_fuzz.py` verify robust parsing across malformed CIDRs and indicator formats.
- [ ] ReDoS safety and bounded regex execution verified on pathological inputs.
- [ ] Payload size bounding protects feed clients from memory exhaustion.
- [ ] `make test-unit` and `make preflight` pass 100% green.
