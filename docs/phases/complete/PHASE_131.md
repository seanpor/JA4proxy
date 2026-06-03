# Phase 131: OpenSSF Scorecard & Supply Chain Hardening

> **Status:** IN_PROGRESS
> **Size:** MEDIUM
> **Depends on:** Phase 130
> **Owner:** Gemini CLI

## Goal

Institutionalize enterprise security standards by integrating the OpenSSF Scorecard, hardening the software supply chain through immutable dependency pinning, and formalizing the project's security architecture. This phase ensures the project is not only functionally secure but also follows industry-standard "Trust but Verify" supply chain practices.

## Scope

### Components in Scope
- **CI/CD Pipeline**: Integration of OpenSSF Scorecard Action.
- **Docker Toolchain**: Migration from tags to immutable SHA256 digests.
- **GitHub Configuration**: Hardening workflow permissions (Gihub Token Least Privilege).
- **Documentation**: Creation of a formal `docs/security/ARCHITECTURE.md`.

---

## Implementation Plan

### Wave 1: Scorecard Integration
| ID | Task | Description | Size |
|---|---|---|---|
| **131.1** | **Scorecard Action** | Implement the `ossf/scorecard-action` to perform automated security audits. | S |
| **131.2** | **Remediate Scorecard** | Fix immediate low-hanging fruit identified by the initial Scorecard run (e.g. pinned actions). | M |

### Wave 2: Supply Chain Hardening
| ID | Task | Description | Size |
|---|---|---|---|
| **131.3** | **Immutable Docker** | Resolve and pin `golang:1.26-alpine` and `alpine:3.19` to their immutable SHA256 digests. | S |
| **131.4** | **Workflow Lockdown** | Explicitly set `permissions: read-all` or more restrictive scopes on all `.github/workflows/`. | S |

### Wave 3: Documentation & Disclosure
| ID | Task | Description | Size |
|---|---|---|---|
| **131.5** | **Security Architecture** | Author `docs/security/ARCHITECTURE.md` based on Phase 129 UAT findings. | M |
| **131.6** | **SBOM Target** | Add `make sbom` target using `syft` to generate CycloneDX/SPDX reports. | S |

---

## Acceptance Criteria

- [ ] OpenSSF Scorecard action is active and reporting to the GitHub Security Tab.
- [ ] All Dockerfiles use SHA256 digests for base images.
- [ ] GitHub workflows have explicit, least-privilege permissions defined.
- [ ] `docs/security/ARCHITECTURE.md` is present and accurate.
- [ ] `make sbom` generates a valid JSON/SPDX artifact.
