# Phase 134: OpenSSF Scorecard Remediation & Local Audit

> **Status:** IN_PROGRESS
> **Size:** SMALL
> **Depends on:** Phase 131
> **Owner:** Gemini CLI

## Goal

Formally document the \`scorecard-local\` testing capability and address the outstanding security findings highlighted by the OpenSSF Scorecard tool during its local run. This ensures the repository achieves the highest possible security posture score.

## Scope

### Components in Scope
- **Makefile**: Retrospective documentation of the \`scorecard-local\` target.
- **GitHub Actions**: Auditing and enforcing \`permissions: read-all\` (or stricter) across all \`.github/workflows/*.yml\` files to resolve the "Token-Permissions" finding (0/10).
- **Dependencies**: Investigating and remediating the 92 vulnerabilities flagged by the Scorecard's OSV scanner in the repository's dependency manifests (e.g., \`package-lock.json\`, \`requirements.txt\`, \`go.mod\`).

---

## Implementation Plan

### Wave 1: Token Permissions Lockdown
| ID | Task | Description | Size |
|---|---|---|---|
| **134.1** | **Audit Workflows** | Review all GitHub Actions workflows for missing or overly permissive \`permissions\` blocks. | XS |
| **134.2** | **Enforce Least Privilege** | Add \`permissions: contents: read\` or \`read-all\` as the top-level default to all workflows. | XS |

### Wave 2: Vulnerability Remediation
| ID | Task | Description | Size |
|---|---|---|---|
| **134.3** | **Identify Vulnerabilities** | Run OSV-scanner or local audits to locate the source of the 92 vulnerabilities. | S |
| **134.4** | **Patch/Remove Deps** | Update vulnerable dependencies or remove unused manifest files (e.g., legacy \`package-lock.json\`). | M |

### Wave 3: Verification
| ID | Task | Description | Size |
|---|---|---|---|
| **134.5** | **Local Scorecard Rerun** | Re-run \`make scorecard-local\` to verify the scores for Token-Permissions and Vulnerabilities have improved. | S |

---

## Acceptance Criteria

- [ ] All GitHub Actions workflows have explicit, minimal \`permissions\` defined.
- [ ] The source of the 92 vulnerabilities is identified and neutralized.
- [ ] \`make scorecard-local\` reflects a passing score for Token-Permissions and Vulnerabilities.
