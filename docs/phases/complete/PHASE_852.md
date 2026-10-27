# Authlib 1.9.1 Security Upgrade & JWS Signature Bypass Regression Suite

## Goal
Verify and document the resolution of 7 Dependabot security alerts (CVE-2026-96760 [Critical], CVE-2026-114615 [High], CVE-2026-114616 [High], CVE-2026-114617 [Medium], CVE-2026-114618 [Medium], CVE-2026-114619 [Medium], CVE-2026-114620 [Medium]) by establishing regression tests and verifying automated alert closure under `authlib==1.9.1`.

## Scope
1. **Target Package:** `authlib` in `management/requirements.txt` (bumped from `1.8.0` to `1.9.1`).
2. **Regression Testing:**
   - Authlib `JsonWebSignature.deserialize_json` empty-signatures bypass (CVE-2026-96760): Ensure objects with `signatures: []` are strictly rejected with `BadSignatureError`.
   - Empty HMAC key validation (CVE-2026-114616): Ensure empty key materials are rejected (`ValueError`).
   - OIDC integration verification: Ensure all OIDC route handlers and token validation flows pass with zero regressions.

## Implementation Plan
1. **Regression Test Suite:** Add `management/tests/test_authlib_cve_regression.py` covering:
   - `test_jws_empty_signatures_rejected_cve_2026_96760`
   - `test_empty_hmac_key_rejected_cve_2026_114616`
2. **Full Test Execution:** Run the entire management test suite to verify compatibility.
3. **Roadmap & Manifest Sync:** Document Phase 852 as `COMPLETE` in `manifest.yaml` and publish changelog news fragment.

## Test Strategy
- Unit tests run inside containerized `ja4proxy-tools` with Python 3.14.
- Verify `pytest management/tests/test_authlib_cve_regression.py`.
- Full preflight gate (`make preflight`) verification.

## Acceptance Criteria
- [x] Authlib pinned to `1.9.1` in `management/requirements.txt`.
- [x] Regression tests assert rejection of empty signatures and empty keys.
- [x] All 35 OIDC tests and management tests pass.
- [x] `make lint-phases` and `make preflight` pass 100% green.
