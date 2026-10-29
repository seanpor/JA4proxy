<!--
title: Continuous Fuzzing Workflow & Corpus Synchronization
audience: developer
last_reviewed: 2026-10-29
phase: 851j
-->

# Continuous Fuzzing Workflow & Corpus Synchronization

> **Size:** SMALL
> **Dependencies:** [851i]
> **Branch:** `phase-851j-ci-fuzz-sync`

---

## Goal

Synchronize `.github/workflows/fuzzing.yml` and repository build automation with the complete inventory of 29 native Go fuzz targets authored across all packages. Refactor the CI workflow into a parallelized matrix across 8 packages, enable granular corpus caching, preserve crasher artifacts on failure, remove error masking (`continue-on-error: true`), and establish an automated drift check to prevent newly authored fuzz targets from being omitted.

---

## Scope

### In Scope
1. **Target Inventory Synchronization (All 29 Targets Across 8 Packages)**:
   - `cmd/ja4pd` (5): `FuzzClientHello`, `FuzzReadProxyProtocol`, `FuzzReadProxyProtocolV2`, `FuzzFragmentation`, `FuzzProtocolSmuggling`
   - `internal/tls` (2): `FuzzParseClientHello`, `FuzzDifferentialClientHello`
   - `internal/quic` (4): `FuzzParseClientHelloFeatures`, `FuzzReadVarint`, `FuzzParseCRYPTOFrames`, `FuzzDecodeInitialHeader`
   - `internal/webhook` (4): `FuzzComputeHMAC`, `FuzzWebhookEndpointRedaction`, `FuzzIsPrivateIP`, `FuzzWebhookEventDelivery`
   - `internal/config` (4): `FuzzLoadConfigYAML`, `FuzzLoadYAML`, `FuzzFlexInt`, `FuzzExpandEnvVars`
   - `internal/cache` (2): `FuzzLRUOperations`, `FuzzLRUKeyFormatting`
   - `internal/security` (5): `FuzzSNIAnalyzer`, `FuzzBuildRanger`, `FuzzEffectiveThresholdAndDecider`, `FuzzRiskScorer`, `FuzzPipelineBypassesAndHardBlocks`
   - `internal/redis` (3): `FuzzVerifyPubSubHMAC`, `FuzzPubSubEnvelopeRoundtrip`, `FuzzPubSubHandlerDispatch`
2. **GitHub Actions Matrix Workflow (`.github/workflows/fuzzing.yml`)**:
   - Refactored into a matrix job parameterized by package across 8 packages.
   - Removed `continue-on-error: true` so fuzz failures fail CI deterministically.
   - Granular corpus caching: `go-fuzz-${{ runner.os }}-${{ matrix.pkg }}-${{ github.run_id }}`.
   - Ephemeral crasher preservation: Uploads `**/testdata/fuzz/**` via `actions/upload-artifact` when `if: failure()`.
   - Supports `fuzztime` parameter on `workflow_dispatch` (default 30s for scheduled CI).
3. **Smoke Gate Parity & Drift Check**:
   - Synchronized `Makefile` (`test-go-fuzz-smoke`) to cover all 29 targets.
   - Implemented `tests/unit/test_fuzz_target_sync.py` asserting that every `func Fuzz*(f *testing.F)` in the repository is present in both `Makefile` and `fuzzing.yml`, and asserting that `continue-on-error: true` is not present.

### Out of Scope
- Authoring new fuzz targets (covered in 851k and 851l).
- External cloud fuzzing clusters (OSS-Fuzz / ClusterFuzz).

---

## Results & Verification
- `test-go-fuzz-smoke`: Synchronized to 29 native Go fuzz targets across 8 packages.
- `tests/unit/test_fuzz_target_sync.py`: Passed 3/3 tests (Makefile sync, fuzzing workflow sync, no continue-on-error).
- `.github/workflows/fuzzing.yml`: Syntactically validated, matrix-partitioned, and pins preserved.

---

## Acceptance Criteria
- [x] `.github/workflows/fuzzing.yml` runs all 29 native Go fuzz targets across 8 package matrix jobs.
- [x] `continue-on-error: true` is removed from the workflow; failures fail the job.
- [x] Crasher seed artifacts (`**/testdata/fuzz/**`) are preserved on failure.
- [x] Automated drift test `tests/unit/test_fuzz_target_sync.py` passes and enforces 100% parity.
- [x] `make test-go-fuzz-smoke` and `make preflight` pass 100% green.
