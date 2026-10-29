<!--
title: Management API Contract & Schema-Driven Fuzzing
audience: developer
last_reviewed: 2026-10-29
phase: 853
-->

# Management API Contract & Schema-Driven Fuzzing

> **Size:** SMALL
> **Dependencies:** [851l]
> **Branch:** `phase-853-management-api-fuzzing`

---

## Goal

Harden the Python Management API (`management/api/`) against OpenAPI schema deviations, unhandled internal server errors (500s), malformed JSON/YAML payloads, header injection, and parameter tampering. Implement contract fuzzing using Hypothesis and schema-driven request generators executed entirely inside the containerized tools environment.

---

## Junior Dev Feasibility & Sizing

- **Verdict:** **SMALL & Straightforward**.
- **Junior Dev Friendliness:** High. Follows existing pytest patterns in `management/tests/`. Uses standard fixtures from `conftest.py` (`test_client`, `mock_redis`, `admin_token_cookies`). Runs entirely inside the pinned `ja4proxy-tools` image (`make test-unit`). Does not touch CGo, kernel drivers, or production Go proxy binaries.
- **Clear Bounds:** Targets strictly existing HTTP endpoints under `management/api/routes/` with mocked Redis backend.

---

## Scope

### In Scope
1. **Hypothesis Property-Based API Fuzzing (`management/tests/test_api_contract_fuzz.py`)**:
   - `test_fuzz_datacenter_policy_endpoint`: Fuzz `PUT /api/v1/datacenter-policy` with arbitrary UTF-8 strings, deeply nested YAML/JSON structures, and oversized policy documents to ensure clean 4xx responses without unhandled 500 exceptions.
   - `test_fuzz_config_reload_endpoint`: Fuzz `POST /api/v1/config/reload` with malformed JSON payloads and invalid query parameters.
   - `test_fuzz_bans_crud_endpoints`: Fuzz `POST /api/v1/bans/{ip}` with malformed IP path parameters, boundary TTL integers (`0`, `-1`, `2^64`), and injection-prone reason fields.
   - `test_fuzz_auth_headers_and_tokens`: Fuzz bearer token headers and session cookies with control characters, null bytes, truncated Base64, and malformed JWT structures to verify clean 401 rejections.
   - `test_fuzz_canonical_lists_crud`: Fuzz `/api/v1/allowlist` and `/api/v1/blocklist` with duplicate items, wildcard strings, and non-ASCII domain names.
2. **Contract Invariants**:
   - **No 500 Invariant**: For any arbitrary input passed to any endpoint, the API strictly returns 2xx, 4xx, or clean validation errors (`HTTP 422 Unprocessable Entity`), never an unhandled 500 Internal Server Error.
   - **JSON Response Parity**: Every non-empty error response strictly adheres to the standard error JSON schema (`{"detail": ...}`).
3. **Execution Bounds & Performance**:
   - Bounded with `@settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])` so the entire fuzz suite completes within 5–10 seconds in CI.

### Out of Scope
- Go proxy TLS/TCP network stack (already hardened in 851a-851k).
- Live distributed Redis clusters.

---

## Implementation Plan

1. **Step 1: Remote Lease & Manifest Registration**
   - Claim `phase-853-management-api-fuzzing`.
   - Update `docs/phases/manifest.yaml` marking Phase 853 `IN_PROGRESS`.
2. **Step 2: Test Implementation (`management/tests/test_api_contract_fuzz.py`)**
   - Build Hypothesis test suites leveraging FastAPI's `TestClient` and fixtures from `management/tests/conftest.py`.
   - Verify all test runs pass inside `ja4proxy-tools` with zero host dependencies.
3. **Step 3: Verification & Smoke Gate**
   - Run `docker run --rm -v "$PWD":/src -w /src ja4proxy-tools pytest management/tests/test_api_contract_fuzz.py`.
   - Run `make preflight`.
4. **Step 4: Closeout**
   - Move phase doc to `docs/phases/complete/PHASE_853.md`.
   - Update manifest (`COMPLETE`), news fragment, PR, and merge.

---

## Acceptance Criteria
- [x] Hypothesis property-based fuzz tests added for datacenter policy, config reload, bans, auth tokens, and canonical list endpoints.
- [x] Zero unhandled 500 errors across bounded generated requests.
- [x] All error responses strictly match standard JSON schema contracts (`detail` field).
- [x] `make test-unit` and `make preflight` pass 100% green in under 10 seconds (test suite executes in 1.66s).
