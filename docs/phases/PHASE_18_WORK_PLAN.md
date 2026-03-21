# Phase 18 Detailed Work Plan: Security Audit Remediation

## 1. Overview
This plan implements the remediation for the findings in `PHASE_18.md` and `PHASE_17b.md`, focusing on critical security anti-patterns: broad exception handling, insecure logging, and high code complexity.

## 2. Implementation Sequence (TDD)

### Step 1: Critical Fixes - Exception Handling
**Goal:** Prevent security violations from being masked by catch-all exceptions.
*   **Target Files:** `src/security/pipeline.py`, `src/security/security_manager.py`, `src/security/blocklists.py`, `src/security/dns_enrichment.py`, `src/security/asn_classifier.py`, `src/security/rdap_enrichment.py`.
*   **Action:** Search for `except Exception:` and `except Exception as e:`.
*   **Refactor:**
    *   **External APIs/Redis:** Catch specific exceptions (`aiohttp.ClientError`, `redis.exceptions.RedisError`) and fail-open with a logged WARNING and an incremented Prometheus counter.
    *   **Internal Logic:** Catch specific errors where possible. For truly unexpected errors, use `logger.exception(...)` and `raise` (do not fail-open silently on internal state corruption).
*   **Validation:** Run `pytest tests/unit/security/` to ensure fail-open behaviors are still respected under mocked failures.

### Step 2: Secure Logging Practices
**Goal:** Prevent unnecessary string interpolation and potential data exposure.
*   **Target:** Entire Python codebase (especially `src/security/`).
*   **Action:** Use regex to find `logger.\w+\(f"` or `.format(`.
*   **Refactor:** Convert to lazy formatting: `logger.info("Message: %s", value)`.
*   **Validation:** Ensure the `pylint` score improves and `W1203` (logging-fstring-interpolation) is eliminated.

### Step 3: Architectural Complexity Reduction
**Goal:** Simplify `pipeline.py` to make security audits manageable.
*   **Target File:** `src/security/pipeline.py` (specifically `_collect_signals()`).
*   **Action:** Implement a "Signal Collector" pattern. Break `_collect_signals()` into smaller methods like `_collect_tls_signals()`, `_collect_network_signals()`, `_collect_threat_intel()`.
*   **Validation:** Run `flake8` or `mccabe` to verify cyclomatic complexity of `_collect_signals` drops below 10.

### Step 4: Final Verification
*   **Task:** Run `bandit -r src -f json`. Ensure zero High/Medium severity findings.
*   **Task:** Run the full test suite (`make test`). Ensure 100% pass rate.