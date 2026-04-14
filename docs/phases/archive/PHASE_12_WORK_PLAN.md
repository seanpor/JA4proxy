# Phase 12 Detailed Work Plan: Analytics Node Completion & Hardening

## 1. Overview
This plan outlines the final steps to transition Phase 12 from "Partial/Gap-filled" to "Enterprise-Ready". It focuses on finalizing the Python-Go integration, completing the observability stack, and applying modern TDD and security standards (Phase 18 alignment).

## 2. Phase 12a: Foundation & Packaging Hardening
**Goal:** Ensure the analytics container is lean, secure, and reliably deployable.

### 2.1. Dependency Optimization
*   **Task:** Audit `requirements-analytics.txt` to ensure minimal attack surface.
*   **Standard:** No unused heavy libraries (like `pandas` or `scipy` if `numpy` suffices).
*   **Action:** Verify `numpy` vs `scipy` usage for KS-test approximation in `../../src/analytics/distribution_analyzer.py`.

### 2.2. Health & Readiness
*   **Task:** Verify the `aiohttp` server in `../../src/analytics/main.py` correctly reflects downstream health (Redis connection, stream lag).
*   **TDD:** Add a chaos test that kills Redis and verifies `/health` returns 503 within 5 seconds.

## 3. Phase 12b: Detection Module Integration (Go-Forward)
**Goal:** Bridge the gap between Python detection results and Go Proxy enforcement.

### 3.1. Go Signal Expansion
*   **Task:** Update `internal/security/analytics_signals.go` to handle JA4 intelligence candidates if a "soft-signal" mode is desired.
*   **Action:** Implement `LocalCache` for analytics signals in Go (currently it hits Redis directly in `GetAnalyticsSignals`).
*   **TDD:** Create a Go integration test where a mocked Redis contains `analytics:campaign` and verify the Go `Pipeline` increments the score correctly.

### 3.2. Bug Fixes
*   **Task:** Fix the `get_subnet_stats` bug in `JA4FingerprintIntelligence` (referenced non-existent `self.subnet_data`).

## 4. Phase 12c: Observability & "Score Health"
**Goal:** Provide a "World-Class" view of the proxy's scoring behavior.

### 4.1. Grafana "Score Health" Dashboard
*   **Task:** Enhance `deploy/monitoring/grafana/dashboards/analytics.json`.
*   **Components:**
    *   Median Score vs 7-day Baseline (Band chart).
    *   Shadow Score (Known-good) calibration panel.
    *   Distribution Shift (KS-statistic) trend.
    *   Top Attacking Subnets (from `analytics:agg:*`).

### 4.2. Alertmanager Fine-tuning
*   **Task:** Verify `ScoreDriftDetected` and `AnalyticsStreamLagHigh` thresholds.
*   **Action:** Add an alert for `CalibrationIssue` (Shadow median > threshold).

## 5. Phase 12d: Security & Reliability Hardening
**Goal:** Apply Phase 18 standards to the Analytics Node.

### 5.1. Secure Exception Handling (Phase 18 Alignment)
*   **Task:** Audit all `except Exception` blocks in `src/analytics/*.py`.
*   **Action:** Replace with specific exceptions (e.g., `redis.exceptions.ConnectionError`, `jsonschema.ValidationError`) and implement "Pattern B" (log with context and re-raise) for internal errors.

### 5.2. Secure Logging
*   **Task:** Convert f-string logging to lazy formatting (`logger.info("msg %s", var)`) to follow project standards across all Python analytics modules.

### 5.3. Rate Limit Wiring
*   **Task:** Fully connect the `proxy_specific` rate limit configuration in `../../config/analytics.yaml` to `SecurityHardening.check_rate_limit()`.

## 6. Detailed Implementation Sequence (TDD)

### Step 1: Verification (Day 1)
1. Run `make test` for analytics: `pytest tests/unit/test_analytics_node.py tests/unit/test_detection.py`.
2. Build the Docker image: `docker build -t ja4proxy-analytics -f src/analytics/Dockerfile .`.

### Step 2: Security & Cleanup (Day 2)
1. Refactor exception handling in `../../src/analytics/aggregation.py` and `../../src/analytics/stream_consumer.py`.
2. Refactor all logging to lazy formatting in `src/analytics/`.
3. **Validation:** Ensure 100% test pass rate after refactoring.

### Step 3: Go Proxy Integration (Day 3)
1. Implement `LocalCache` for analytics signals in `internal/security/`.
2. Update Go `deriveSubnet` to match Python's implementation exactly.
3. **Validation:** `go test ./internal/security/...`

### Step 4: Observability (Day 4)
1. Update Grafana dashboard JSON.
2. Add the `CalibrationIssue` alert rule to `deploy/monitoring/prometheus/alerts.yml`.
3. **Validation:** Manual verification in a staging/POC environment.

### Step 5: Final Audit & Documentation (Day 5)
1. Sync `PHASE_12.md` sub-plans with actual implementation state.
2. Update `docs/REDIS_SCHEMA.md` if any new keys were added during hardening.
