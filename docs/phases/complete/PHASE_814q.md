# Pentest: Remediation Wave 3-4 (MEDIUM + LOW)

## Goal
Execute Phase 814q of the Phase 814 penetration testing campaign. In accordance with `PROGRAMME.md` Section 9 and `PHASE_814.md` Stage 2 ("Remediation wave 3-4 (MEDIUM + LOW)"), consolidate, audit, and finalize all 14 MEDIUM and LOW severity findings across the register and Stage 1 adversarial campaign (`814e` through `814n`), including legacy findings `JA4PROXY-2026-0074` and `JA4PROXY-2026-0089`. Verify two-state revert proofs across all remediations, confirm zero hot-path performance regressions, record canonical `closed_commit` SHAs on `main`, and ensure complete audit readiness for Stage 3 (`814r`).

## Scope
Audit and verify remediation across all 14 MEDIUM and LOW findings:

1. **JA4PROXY-2026-0074 (LOW, CVSS 2.6)**: PubSub debug log included full HMAC-signed payload.
   - *Fix commit*: `d4a224939913` (Phase 245)
   - *Regression test*: `internal/logging/redactor_test.go::TestRegression_JA4PROXY_2026_0048_redacts_opaque_fields_in_production`

2. **JA4PROXY-2026-0089 (MEDIUM, CVSS 2.2)**: Hot config reload orphaned async enrichment workers (DNS/AbuseIPDB/RDAP/feed) — enrichment silently degraded after SIGHUP.
   - *Fix commit*: `50129e13be397b064582e66fcdb372812cf65ad2` (Phase 251a)
   - *Regression test*: `internal/security/pipeline_test.go::TestPipeline_ReplaceConfig_RestartsEnrichmentWorkers`

3. **JA4PROXY-2026-0105 (LOW, CVSS 4.3)**: Missing HTTP security response headers across management API and Web UI (CSP, HSTS, X-Content-Type-Options, Frame-Ancestors).
   - *Fix commit*: `c139e964c08c77037e558fb5de8f5feaf6a09cf2` (Phase 814e)
   - *Regression test*: `tests/adversarial/mgmt/test_ui_xss_and_csp.py::test_security_response_headers_enforced`

4. **JA4PROXY-2026-0107 (LOW, CVSS 3.7)**: `pin_table_autofix.py` `ACTION_NAME_RE` regex permitted leading dashes causing potential flag injection in `git ls-remote`.
   - *Fix commit*: `52980485f56832288ce48f48c4ccc11b036f9342` (Phase 814f)
   - *Regression test*: `tests/adversarial/cicd/test_pin_table_autofix_security.py::test_parser_input_validation_regexes`

5. **JA4PROXY-2026-0109 (MEDIUM, CVSS 5.3)**: `parseSNI` and `parseALPN` permitted embedded NUL bytes and control characters causing log and event stream injection.
   - *Fix commit*: `b622b575ef8f02bd8b50033a8b2ea14e09fcd921` (Phase 814h)
   - *Regression test*: `cmd/ja4pd/pentest_sni_alpn_control_chars_test.go::TestRegression_JA4PROXY_2026_0109_SanitizesSNIAndALPNControlChars`

6. **JA4PROXY-2026-0113 (MEDIUM, CVSS 5.3)**: PROXY protocol v1 and v2 parsers accepted out-of-spec lines, tokens, and failed to discard LOCAL command headers.
   - *Fix commit*: `7c4ece9ba26bbb551ad80159cbb2b36e457efde0` (Phase 814i)
   - *Regression test*: `internal/proxy/proxy_protocol_spec_test.go::TestProxyProtocolV1_LineLengthBound`

7. **JA4PROXY-2026-0116 (MEDIUM, CVSS 5.3)**: Tarpit `copyOne` missing write deadline enabled zero-window connection and goroutine leak.
   - *Fix commit*: `37fd5b0596393c4423a62de90734164d3c1537f2` (Phase 814j)
   - *Regression test*: `cmd/ja4pd/pentest_resource_exhaustion_test.go::TestPentest_Tarpit_ZeroWindow_WriteDeadline`

8. **JA4PROXY-2026-0117 (MEDIUM, CVSS 5.3)**: Unbounded Redis structures in beaconing ZSET (missing TTL) and webhook DLQ stream (missing MaxLen).
   - *Fix commit*: `37fd5b0596393c4423a62de90734164d3c1537f2` (Phase 814j)
   - *Regression test*: `internal/security/pentest_beaconing_ttl_test.go::TestPentest_BeaconingDetector_SetsTTLOnZSET`

9. **JA4PROXY-2026-0118 (MEDIUM, CVSS 5.3)**: Management API `normalise_path` passed arbitrary path segments allowing Prometheus cardinality DoS.
   - *Fix commit*: `37fd5b0596393c4423a62de90734164d3c1537f2` (Phase 814j)
   - *Regression test*: `tests/adversarial/mgmt/test_management_metrics_cardinality.py::test_normalise_path_collapses_arbitrary_unregistered_paths`

10. **JA4PROXY-2026-0119 (MEDIUM, CVSS 5.3)**: `AdmitConn` synchronous warning log on accept overflow stalled listener loop under connection flood.
    - *Fix commit*: `37fd5b0596393c4423a62de90734164d3c1537f2` (Phase 814j)
    - *Regression test*: `cmd/ja4pd/pentest_resource_exhaustion_test.go::TestPentest_AdmitConn_LoggingThrottled`

11. **JA4PROXY-2026-0123 (MEDIUM, CVSS 5.3)**: GDPR deletion script omitted rate-limiting and offense counter namespaces.
    - *Fix commit*: `629769214f3a568cbb3402a3a3f7adab9fcb3849` (Phase 814k)
    - *Regression test*: `tests/unit/test_gdpr_delete.py::test_regression_ja4proxy_2026_0123_ratelimit_and_offense_keys_erased`

12. **JA4PROXY-2026-0126 (MEDIUM, CVSS 5.3)**: Non-atomic single-use nonce and challenge verification race condition.
    - *Fix commit*: `b7150f7451a4b356ae14fb93165368eb4fd50080` (Phase 814l)
    - *Regression test*: `management/tests/test_pentest_atomic_nonces_regression.py::test_regression_ja4proxy_2026_0126_saml_relaystate_atomic_single_use`

13. **JA4PROXY-2026-0129 (MEDIUM, CVSS 5.3)**: Read-only root filesystem and capability drop omissions in production and monitoring compose files (CIS Docker Benchmark 5.12 & 5.27).
    - *Fix commit*: `b44143895bcd69a76058b4e4047c25bfc3972a98` (Phase 814m)
    - *Regression test*: `tests/unit/test_pentest_container_read_only_rootfs_regression.py::test_regression_ja4proxy_2026_0129_prod_compose_read_only_rootfs`

14. **JA4PROXY-2026-0132 (MEDIUM, CVSS 5.4)**: Downstream telemetry injection in ServiceNow SIR incident integration.
    - *Fix commit*: `d643fed76e8cd33427b5dbeabbb6393f98517cf4` (Phase 814n)
    - *Regression test*: `tests/unit/test_pentest_servicenow_injection_regression.py::test_regression_ja4proxy_2026_0132_servicenow_sanitizes_injection_payloads`

## Remediation & Verification Strategy
1. **Metadata & Register Integrity**:
   - Ensure all 14 findings have `status: FIXED` and populate exact merge commit SHAs (`closed_commit`).
   - Validate register with `python3 scripts/findings_register.py validate`.
2. **Regression Execution**:
   - Execute all 14 regression test targets natively and inside the `ja4proxy-tools` container.
   - Run two-state revert verification (`scripts/verify_revert.sh`).
3. **Hot-Path Performance**:
   - Run microbenchmarks on TLS parsing and PROXY protocol header reassembly to confirm zero performance regression.
4. **Triad Expert Review**:
   - Security, Concurrency, and Code Quality expert subagents must all APPROVE.

## Acceptance Criteria
- All 14 findings verified with non-empty `closed_commit` entries in `docs/security/findings.yaml`.
- All 14 regression tests pass 100%.
- `make lint-phases` passes with 0 violations.
- Full CI gate (`scripts/close-phase.sh`) exits 0.
- All three expert reviews approve.
