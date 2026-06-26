# SLSA Level 3 Release Pipeline

## Goal
Achieve SLSA Level 3 build provenance for the Go proxy binary and Docker images by integrating the `slsa-framework/slsa-github-generator` reusable workflows into the production CI.

## Background
Phase 107 (Regulatory Conformance) mapped the project to NIST SSDF and ISO standards but left SLSA L3 wiring (sub-tasks 107c.3 and 107c.4) deferred for human-led execution due to the complexity of mutating production CI workflows (`id-token: write`). This phase completes that work, providing tamper-proof build attestations.

## Scope
1.  **Go Binary Attestation**: Wire `slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml` into `.github/workflows/go-proxy-image.yml` (or a dedicated release workflow).
2.  **Docker Image Attestation**: Wire the container generator for the `ja4proxy` image.
3.  **Verifier Harness**: Implement `slsa-verify.yml` (workflow_dispatch) to dry-run the verification against a real published artifact before re-enabling `push: triggers`.
4.  **Operator Runbook**: Create `docs/for-architects/SLSA_VERIFICATION.md` with step-by-step instructions for operators to verify the binary/image they deploy.

## Implementation Plan
1.  **Step 1: Workflow Reshape**
    *   Update `.github/workflows/go-proxy-image.yml` to include `id-token: write` at the workflow level (required for OIDC keyless signing).
    *   Add the SLSA generator as a job dependency.
2.  **Step 2: Keyless Signing**
    *   Ensure the workflow uses `cosign sign` with the SLSA provenance.
    *   Update the release process to include `cosign verify-attestation`.
3.  **Step 3: Verification Script**
    *   Create `scripts/verify-slsa.sh` for local/CI verification.
4.  **Step 4: Documentation**
    *   Write the operator runbook as per Phase 107 requirements.

## Acceptance Criteria
1.  `make release` (or equivalent tag-push) produces a SLSA Level 3 attestation.
2.  `slsa-verify.yml` workflow_dispatch successfully verifies a recent artifact.
3.  `cosign verify-attestation` passes for the Go binary and Docker image.
4.  `docs/for-architects/SLSA_VERIFICATION.md` is present and accurate.

## Dependencies
*   Phase 107 (Regulatory Conformance) - **COMPLETE**
*   Phase 202 (CI Supply Chain) - **COMPLETE**
