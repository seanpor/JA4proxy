# NIST SSDF (SP 800-218) — Control Mapping

> **Status:** DRAFT — self-assessed mapping (not certification)
> **Phase:** 107b (sub-phase 107b.1 scaffolding; rows filled by 107b.2/.3)
> **Standard:** NIST SP 800-218 — Secure Software Development Framework v1.1

---

## Summary

| Total practices | Fully implemented | Partial | Not applicable |
|-----------------|-------------------|---------|----------------|
| 19              | 14                | 5       | 0              |

This mapping records JA4proxy's **alignment with** SSDF practices as a
self-assessment. It is **not** a NIST certification or attestation. Every
"implemented" claim links to a file path or workflow that exists in the
repository. "Partial" rows have a real gap noted in the Gap column.

---

## Cross-references

- See also: [`CRA_CONFORMANCE.md`](CRA_CONFORMANCE.md) — EU CRA Annex I/II
- Vulnerability handling: [`../security/CVD_POLICY.md`](../security/CVD_POLICY.md)
- Build provenance: [`../decisions/ADR-107a-slsa-level-3.md`](../decisions/ADR-107a-slsa-level-3.md)

---

## PO — Prepare the Organization

| Practice ID | Practice | Implementation | Evidence | Gap |
|-------------|----------|----------------|----------|-----|
| PO.1 | Define security requirements for software development | Security requirements documented across the threat model, comprehensive security audit, deployment checklist, and per-phase plans; the core asymmetry rule (fail-open) is recorded as an organisation-wide invariant in `CLAUDE.md`. | `docs/security/threat-model.md`, `docs/security/COMPREHENSIVE_SECURITY_AUDIT.md`, `docs/security/SECURITY_CHECKLIST.md`, `docs/runbooks/security_policy.md` | None |
| PO.2 | Implement roles and responsibilities | Security ownership, intake responsibilities, and severity-rubric-driven escalation are documented; contributor expectations and review process live in `CONTRIBUTING.md`. No formal CODEOWNERS file yet. | `docs/security/OWNERSHIP.md`, `docs/security/INTAKE_RUNBOOK.md`, `docs/security/SEVERITY_RUBRIC.md`, `CONTRIBUTING.md` | Partial — no `.github/CODEOWNERS` file enforcing per-path review assignment; routing currently relies on documented ownership only. |
| PO.3 | Implement supporting toolchains | Toolchain enforced through CI workflow `.github/workflows/ci.yml` (Go test, Python pytest, gofmt, go vet, ruff lint, Semgrep SAST, TruffleHog secrets, pip-audit, govulncheck, dependency-review) and the build/sign/SBOM pipeline `.github/workflows/go-proxy-image.yml` (Trivy, anchore SBOM, keyless cosign). All third-party `uses:` references are SHA-pinned and enforced by `tests/test_workflow_pinning.py`. | `.github/workflows/ci.yml`, `.github/workflows/go-proxy-image.yml`, `.github/workflows/release-cli.yml`, `tests/test_workflow_pinning.py`, `Makefile` | None |
| PO.4 | Define and use criteria for software security checks | Security-check criteria recorded in the deployment checklist, the comprehensive security audit, the testing strategy (per-phase completion gate including FP corpus + chaos), and the severity rubric used for triage. The closure-verification doc records the gate that every phase must pass. | `docs/security/SECURITY_CHECKLIST.md`, `docs/TESTING_STRATEGY.md`, `docs/security/CLOSURE_VERIFICATION.md`, `docs/security/SEVERITY_RUBRIC.md` | None |
| PO.5 | Implement and maintain secure environments for software development | CI runs on GitHub-hosted runners with minimum-privilege `permissions:` (`contents: read` default, elevated only per job), default-branch protection guidance lives in `scripts/branch_protection.sh`, secrets handled via GitHub Secrets and Docker secrets per the deployment runbook. Hardened production container `deploy/docker/Dockerfile.go-proxy` uses static binary build with `-trimpath` and minimal base image. | `.github/workflows/ci.yml`, `scripts/branch_protection.sh`, `deploy/docker/Dockerfile.go-proxy`, `docs/runbooks/deploy_credentials.md` | Partial — branch protection script exists but is not enforced in CI; relies on a one-time admin run. |

---

## PS — Protect the Software

| Practice ID | Practice | Implementation | Evidence | Gap |
|-------------|----------|----------------|----------|-----|
| PS.1 | Protect all forms of code from unauthorized access and tampering | Code hosted on GitHub with branch protection helper script and required PR review per `CONTRIBUTING.md`; secrets-scanning gate (`TruffleHog`) and gitleaks via `make lint-secrets` block credential leakage; `.gitignore` and the `EXCEPTIONS.md` register prevent re-introduction of historic exposures. | `scripts/branch_protection.sh`, `.github/workflows/ci.yml`, `Makefile`, `docs/security/EXCEPTIONS.md`, `.gitignore` | None |
| PS.2 | Provide a mechanism for verifying software release integrity | Container images signed keyless with cosign (Sigstore/Fulcio OIDC) and an SBOM (CycloneDX) attached to every image in `.github/workflows/go-proxy-image.yml`; CLI binary release path `.github/workflows/release-cli.yml` produces signed artefacts; the rationale and verification UX are recorded in ADR-202d and the SLSA Level 3 decision. | `.github/workflows/go-proxy-image.yml`, `.github/workflows/release-cli.yml`, `docs/decisions/ADR-202d.md`, `docs/decisions/ADR-107a-slsa-level-3.md` | Partial — currently SLSA Level 2; Level 3 provenance attestation is in flight under sub-phase 107c (ADR proposed, generator wiring not yet landed). |
| PS.3 | Archive and protect each software release | Release artefacts pushed to GHCR with immutable digests; SBOM archived alongside the image as a cosign attachment; backup operations and disaster-recovery process for operator state documented in the runbooks. | `.github/workflows/go-proxy-image.yml`, `docs/runbooks/cloud_backup_operations.md`, `docs/runbooks/disaster_recovery.md` | Partial — no separate offline archive of release artefacts beyond GHCR retention; deletion of the GHCR package would lose history. |

---

## PW — Produce Well-Secured Software

| Practice ID | Practice | Implementation | Evidence | Gap |
|-------------|----------|----------------|----------|-----|
| PW.1 | Design software to meet security requirements and mitigate security risks | Threat model and comprehensive security audit drive the design; pipeline architecture (bypass → signal collection → composite scorer → action decider with dial) and fail-open rule are recorded in `CLAUDE.md`; per-phase plan documents call out security implications. | `docs/security/threat-model.md`, `docs/security/COMPREHENSIVE_SECURITY_AUDIT.md`, `CLAUDE.md`, `docs/phases/complete/PHASE_107.md` | None |
| PW.2 | Review the software design to verify compliance with security requirements and risk information | Design decisions recorded as ADRs and indexed; per-phase plan files include a `_review.md` companion (e.g. `docs/phases/complete/PHASE_107_review.md`) with security/SRE/architecture lenses applied before implementation starts; security-review skill enforces a per-PR pass on changed code. | `docs/decisions/INDEX.md`, `docs/phases/complete/PHASE_107_review.md`, `docs/security/SECURITY_REVIEW_PHASE1.md` | None |
| PW.3 | Reuse existing, well-secured software when feasible | Direct dependencies pinned in `requirements.txt` (Python) and `go.mod` (Go), audited weekly by pip-audit and govulncheck CI jobs; container base images and third-party actions SHA-pinned; transitive CVE acceptances tracked explicitly in the CVE-exceptions register. | `requirements.txt`, `go.mod`, `.github/workflows/ci.yml`, `docs/security/CVE_EXCEPTIONS.md`, `tests/test_workflow_pinning.py` | None |
| PW.4 | Create source code by adhering to secure coding practices | Coding standards encoded in `pyproject.toml` (`[tool.ruff]` lint config) and Go build flags `-trimpath -ldflags="-s -w -extldflags '-static'"` in `deploy/docker/Dockerfile.go-proxy`; `gofmt` + `go vet` + `ruff check .` enforced by the `lint` CI job; contributor coding rules documented in `CONTRIBUTING.md` (type hints, no blocking I/O on hot path, no `time.sleep`). | `pyproject.toml`, `deploy/docker/Dockerfile.go-proxy`, `.github/workflows/ci.yml`, `CONTRIBUTING.md` | None |
| PW.5 | Configure the compilation, interpreter, and build processes to improve executable security | Go binary built with `-trimpath` (no source-path leakage) and static linking (`-extldflags '-static'`), stripped (`-s -w`); container uses a minimal hardened base; build provenance signed with cosign; `tests/test_workflow_pinning.py` enforces SHA-pinning of every CI action. | `deploy/docker/Dockerfile.go-proxy`, `.github/workflows/go-proxy-image.yml`, `tests/test_workflow_pinning.py` | Partial — currently SLSA Level 2; non-falsifiable provenance attestation (Level 3) tracked under `docs/decisions/ADR-107a-slsa-level-3.md`. |
| PW.6 | Review and/or analyze human-readable code to identify vulnerabilities and verify compliance with security requirements | Static analysis runs on every PR and on a weekly schedule via the `sast` (Semgrep with `p/ci`, `p/security-audit`, `p/secrets`), `lint`, `secrets-scan` (TruffleHog), and `dependency-review` jobs in `.github/workflows/ci.yml`; secondary linters (`bandit`, `mypy`, `hadolint`, `gitleaks`, Trivy first-party scan) wired through `make lint-static` and friends. | `.github/workflows/ci.yml`, `Makefile`, `docs/security/FINDINGS_REGISTER.md` | None |
| PW.7 | Test executable code to identify vulnerabilities and verify compliance with security requirements | Test methodology requires unit, integration, chaos/resilience, adversarial/fuzz, FP-corpus, performance, and E2E suites with a ~1.3× test-to-code ratio enforced by `make test-ratio`; CI runs the Go and Python suites on every PR; container images Trivy-scanned (`severity: CRITICAL`, `exit-code: 1`) before push in `.github/workflows/go-proxy-image.yml`. | `docs/TESTING_STRATEGY.md`, `.github/workflows/ci.yml`, `.github/workflows/go-proxy-image.yml`, `Makefile`, `tests/adversarial`, `tests/chaos` | None |
| PW.8 | Configure software to have secure settings by default | Default dial is 0 (monitor-only — proxy never blocks on first deploy); ALPN h2/h1 browser bypass is on by default; conservative thresholds documented inline in `config/proxy.yml`; security-policy bypass changes append to the policy-audit log; runbook `docs/runbooks/security_policy.md` documents the safe-default rationale. | `config/proxy.yml`, `CLAUDE.md`, `docs/runbooks/security_policy.md`, `docs/security/policies/security-policy.md` | None |

---

## RV — Respond to Vulnerabilities

| Practice ID | Practice | Implementation | Evidence | Gap |
|-------------|----------|----------------|----------|-----|
| RV.1 | Identify and confirm vulnerabilities on an ongoing basis | Continuous discovery via the weekly CVE sweep (`.github/workflows/ci.yml` schedule `0 6 * * 1`) running pip-audit + govulncheck + Semgrep + TruffleHog + dependency-review; external reports accepted via the CVD policy and routed by `INTAKE_RUNBOOK.md`; confirmed findings recorded in `findings.yaml` / `FINDINGS_REGISTER.md`. | `.github/workflows/ci.yml`, `docs/security/CVD_POLICY.md`, `SECURITY.md`, `docs/security/INTAKE_RUNBOOK.md`, `docs/security/findings.yaml`, `docs/security/FINDINGS_REGISTER.md` | Partial — CVD policy is currently in scaffold form (sub-phase 107g); SLAs and safe-harbour text land alongside this PR. |
| RV.2 | Assess, prioritize, and remediate vulnerabilities | Severity assignment per `SEVERITY_RUBRIC.md` (CVSS v3.1 per ADR-121a); fix SLAs by severity defined in the CVD policy; remediation tracked through `REMEDIATION_WAVES.md` and the per-finding entry in the findings register; accepted/transient risks recorded in `CVE_EXCEPTIONS.md`. | `docs/security/SEVERITY_RUBRIC.md`, `docs/decisions/ADR-121a-cvss-version.md`, `docs/security/CVD_POLICY.md`, `docs/security/REMEDIATION_WAVES.md`, `docs/security/CVE_EXCEPTIONS.md` | Partial — fix-SLA numbers in the CVD policy await human sign-off (107g.2 marker); operational oncall rotation not yet established. |
| RV.3 | Analyze vulnerabilities to identify their root causes | Post-incident review process documented in the security incident response runbook; recurring failure modes captured in the threat model and the comprehensive security audit; ADRs record decisions taken in response to root-cause analysis (e.g. ADR-010 fail-open, ADR-019 block-expansion ceiling). | `docs/runbooks/security_incident_response.md`, `docs/security/threat-model.md`, `docs/security/COMPREHENSIVE_SECURITY_AUDIT.md`, `docs/decisions/INDEX.md` | Partial — no formal RCA template (e.g. 5-whys, fishbone) or central RCA register; root-cause notes currently live inside ad-hoc runbook updates. |
