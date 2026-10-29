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

Harden the threat intelligence feed ingestion script (`scripts/ti_feed_ingest.py`) against malformed STIX/TAXII JSON payloads, invalid CIDRs, connection timeouts, and memory exhaustion during feed parsing.

---

## Junior Dev Feasibility & Sizing

- **Verdict:** **SMALL & Straightforward**.
- **Junior Dev Friendliness:** High. Pure Python script hardening with pytest and Hypothesis mock tests. Runs 100% in `ja4proxy-tools`.

---

## Scope

### In Scope
1. **Feed Ingestion Resilience (`tests/unit/security/test_ti_feed_ingest.py`)**:
   - Fuzz STIX/TAXII feed parsing with corrupted JSON, non-RFC IP notations, and empty indicators.
   - Assert graceful error logging and metric increments (`TI_FEED_ERRORS.inc()`), never crashing the feed daemon.
2. **Atomic Redis Write Invariant**:
   - Verify threat intel indicator sets are written atomically (via Redis pipeline / multi-exec) to prevent partial indicator states during feed reloads.

### Out of Scope
- Direct upstream threat intelligence subscription integration.

---

## Acceptance Criteria
- [ ] Property tests verify malformed feed payloads are rejected without script termination.
- [ ] Atomic Redis updates verified under partial failure scenarios.
- [ ] `make test-unit` and `make preflight` pass 100% green.
