# Architectural Decision Records

> **Purpose:** Index of all architectural decisions with status and phase context

---

## Existing ADRs

| ADR | Title | Status | Phase | Last Reviewed |
|-----|-------|--------|-------|---------------|
| [ADR-001](ADR-001.md) | Go not Rust for Phase 15 proxy rewrite | Accepted | 15 | 2026-03-27 |
| [ADR-002](ADR-002.md) | Redis Streams for analytics event transport | Accepted | 12 | 2026-03-27 |
| [ADR-003](ADR-003.md) | Scoring asymmetry — whitelist TTL >> block TTL | Accepted | 1 | 2026-03-27 |
| [ADR-004](ADR-004.md) | Dial as post-scorer action modifier | Accepted | 2 | 2026-03-27 |
| [ADR-005](ADR-005.md) | RDAP block expansion off by default | Accepted | 11 | 2026-03-27 |
| [ADR-006](ADR-006.md) | Analytics node as separate container | Accepted | 12 | 2026-03-27 |
| [ADR-013](ADR-013.md) | Management UI as separate container | Accepted | 13 | 2026-03-27 |
| [ADR-015](ADR-015.md) | Go proxy rewrite — language selection rationale | Accepted | 15 | 2026-03-17 |
| [ADR-019](ADR-019.md) | Block expansion off by default with /24 ceiling | Accepted | 11 | 2026-03-27 |
| [ADR-020](ADR-020.md) | AF_PACKET vs pcap/Scapy vs PF_RING/DPDK for TAP mode capture | Accepted | 20 | 2026-03-28 |
| [ADR-021](ADR-021.md) | EDL pull vs push for external firewall integration | Accepted | 20 | 2026-03-28 |
| [ADR-022](ADR-022.md) | TAP HTTP server — standalone for Phase 20, migrates to Phase 13 | Accepted | 20 | 2026-03-28 |
| [ADR-082](ADR-082.md) | Shadow mode signal storage backend | Accepted | 82 | 2026-04-07 |
| [ADR-083a](ADR-083a.md) | Release tooling for `ja4proxy-cli` (Goreleaser + GPG + SLSA) | Accepted | 83 | 2026-04-07 |
| [ADR-083b](ADR-083b.md) | Go policy validator implementation | Accepted | 83 | 2026-04-07 |
| [ADR-121a](ADR-121a-cvss-version.md) | Stay on CVSS v3.1 for the findings register | Accepted | 121 | 2026-04-19 |
| [ADR-201a](ADR-201a.md) | Go Redis client TLS MinVersion=1.2, system CA pool only | Proposed | 201 | 2026-04-15 |
| [ADR-203a](ADR-203a.md) | Go inline proxy consumes Phase-20 TAP JA4T from Redis (does not compute it) | Proposed | 203 | 2026-04-15 |
| [ADR-093a](ADR-093a-repository-topology.md) | Terraform provider repository topology | Accepted | 93/102 | 2026-04-15 |
| [ADR-093b](ADR-093b-terraform-registry-namespace.md) | Terraform Registry namespace selection | Accepted | 93/102 | 2026-04-15 |
| [ADR-093c](ADR-093c-ttl-renewal-and-drift-detection.md) | Ban TTL renewal and drift-detection strategy | Accepted | 93/102 | 2026-04-15 |
| [ADR-105a](ADR-105a-pdf-ci-placement.md) | PDF build workflow placement (dedicated `docs-pdf.yml`, not `ci.yml`) | Accepted | 105 | 2026-04-25 |
| [ADR-105b](ADR-105b-link-checker.md) | Link-check tool selection (retain `markdown-link-check`) | Accepted | 105 | 2026-04-25 |
| [ADR-107a](ADR-107a-slsa-level-3.md) | SLSA Level 3 via `slsa-github-generator` reusable workflow | Superseded by ADR-202a | 107 | 2026-04-26 |

## Planned ADRs (To Be Written)

These decisions are implemented and well-understood but not yet formally documented. They are not blocking any current work; write them opportunistically when touching the relevant code.

| ADR | Title | Status | Phase | Notes |
|-----|-------|--------|-------|-------|
| ADR-007 | mTLS as hard bypass, not scored signal | Proposed | 5 | Rationale in CLAUDE.md Decision Log |
| ADR-008 | JA4 auto-classify produces candidate list only | Proposed | 12 | Rationale in CLAUDE.md Decision Log |
| ADR-009 | Redis Streams for cross-instance events, not Pub/Sub | Proposed | 12 | Rationale in CLAUDE.md Decision Log |
| ADR-010 | Fail-open for every external service | Proposed | 10 | Rationale in CLAUDE.md Decision Log |
| ADR-011 | In-process Trie for CIDR matching, never Redis | Proposed | 8 | Rationale in CLAUDE.md Decision Log |
| ADR-012 | Score always, even at dial=0 | Proposed | 2 | Rationale in CLAUDE.md Decision Log |
| ADR-023 | Terraform Registry namespace selection | Proposed | 83 | Required before Phase 83 implementation starts — see PHASE_83.md §3.1.1 |
| ADR-024 | Management API v2 RBAC role model | Proposed | 79 | Required before Phase 79 implementation starts |

---

## Decision Categories

### Language & Runtime
- ADR-001, ADR-015: Go vs Rust for performance-critical components
- Implicit: Python for analytics and management (scipy ecosystem, FastAPI)

### Architecture & Deployment
- ADR-006, ADR-013: Container separation for fault isolation
- ADR-009: Redis Streams vs Pub/Sub for event reliability
- ADR-011: In-process data structures vs Redis for performance

### Security & Risk
- ADR-003: Asymmetric TTLs for whitelist vs blocklist
- ADR-007, ADR-019: mTLS and block expansion security trade-offs
- ADR-010: Fail-open philosophy for external dependencies

### Scoring & Detection
- ADR-004, ADR-012: Dial semantics and always-on scoring
- ADR-008: Auto-classification safety limits

---

## How to Use This Index

1. **Before implementing a feature:** Check if an ADR exists for related decisions
2. **When making a new architectural choice:** Write an ADR before implementing
3. **When reviewing old code:** Check the "Last Reviewed" date — outdated ADRs need validation
4. **For new contributors:** Read ADRs to understand the "why" behind design choices

## ADR Process

1. **Propose:** Create ADR-NNN-title.md with Context, Options, Decision
2. **Review:** Team discussion, update based on feedback
3. **Accept:** Merge to main, update this index
4. **Maintain:** Review annually or when related code changes significantly

See [DOCUMENTATION_STANDARDS.md](../DOCUMENTATION_STANDARDS.md) §5 for full ADR format.