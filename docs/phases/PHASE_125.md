# Phase 125: Infrastructure & Supply Chain Resilience

> **Status:** IN_PROGRESS
> **Size:** MEDIUM
> **Depends on:** Phase 123, 124 (Security Baseline)
> **Owner:** Gemini CLI (on behalf of Junior Engineer)

## Goal

Strengthen the JA4proxy's resilience against supply chain attacks, infrastructure compromise, and resource exhaustion. This phase focuses on dependency hygiene, toolchain verification, and runtime integrity monitoring to complement the code-level hardening in previous phases.

## Scope

### Components in Scope
- **Go Build Pipeline**: CI/CD toolchain and dependency pinning.
- **Runtime Integrity**: Redis state fingerprinting.
- **Observability**: Prometheus label cardinality audit.
- **External Integrations**: NetBox trust chain hardening.
- **Host Confinement**: AppArmor and Seccomp profile refinement.

### Out of Scope
- Direct remediation of Redis server vulnerabilities (managed at the infra/DBA layer).
- Management API Python code (covered by Phase 124).

---

## Implementation Plan

### Wave 1: Supply Chain & Dependency Hygiene
| ID | Task | Description | Size |
|---|---|---|---|
| **125.1** | **Logrus Upgrade** | Upgrade `github.com/sirupsen/logrus` to **v1.9.5+** to remediate CVE-2025-65637 (DoS). | XS |
| **125.2** | **Toolchain Lock** | Add a `go version` check to the CI pipeline and Docker builder to enforce Go ≥ 1.25.6. | XS |
| **125.3** | **Digest Pinning** | Pin the `golang:1.25.9-alpine` builder image to a specific SHA256 digest in the Dockerfile. | XS |

### Wave 2: Runtime Integrity & Observability
| ID | Task | Description | Size |
|---|---|---|---|
| **125.4** | **Redis Fingerprinting** | Implement a background worker to hash critical Redis state (dial, whitelist) and alert on drift. | M |
| **125.5** | **Metrics Audit** | Audit all Prometheus label values for attacker-controlled inputs (SNI, JA4) to prevent label cardinality DoS. | S |
| **125.6** | **NetBox Hardening** | Implement TLS certificate validation and change-rate alerting for the NetBox CIDR fetcher. | S |

### Wave 3: Confinement & Conformance
| ID | Task | Description | Size |
|---|---|---|---|
| **125.7** | **Seccomp Audit** | Review `config/seccomp/proxy.json` against `strace` output to remove unused syscalls. | S |
| **125.8** | **AppArmor Profile** | Create and enable a default AppArmor profile in the production `docker-compose.yml`. | S |

---

## Test Strategy

### Resilience Testing
- **DoS Simulation**: Verify that 64KB+ single-line log entries no longer crash the `logrus` writer.
- **Integrity Alerting**: Manually mutate a Redis `config:dial` key and verify the fingerprinting worker detects the drift.
- **Cardinality Check**: Flood the proxy with unique SNI values and verify Prometheus memory usage remains bounded.

### Conformance Verification
- **Build Log Review**: Verify the `go version` check passes in CI.
- **Container Inspect**: Verify `AppArmorProfile` and `SeccompProfile` are active in `docker inspect`.

---

## Acceptance Criteria

- [ ] `github.com/sirupsen/logrus` is at v1.9.5 or higher.
- [ ] Dockerfile uses a SHA256 digest for the Go builder image.
- [ ] Redis integrity worker successfully logs alerts on unauthorized state changes.
- [ ] No unbounded cardinality labels exist in the metrics package.
- [ ] NetBox integration enforces strict TLS and limits CIDR update frequency.
- [ ] AppArmor profile is active in the production environment.

---

## Reference Material

Detailed supply chain analysis and infrastructure threat models are documented in `docs/phases/archive/PHASE_125_review.md`.
