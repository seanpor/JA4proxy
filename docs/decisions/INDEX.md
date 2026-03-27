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
| [ADR-015](ADR-015.md) | Go not Rust for Phase 15 proxy rewrite | Accepted | 15 | 2026-03-27 |
| [ADR-019](ADR-019.md) | Block expansion off by default with /24 ceiling | Accepted | 11 | 2026-03-27 |

## Planned ADRs (To Be Written)

| ADR | Title | Status | Phase | Target Completion |
|-----|-------|--------|-------|-------------------|
| ADR-007 | mTLS as hard bypass, not scored signal | Proposed | 5 | Phase 21 |
| ADR-008 | JA4 auto-classify produces candidate list only | Proposed | 12 | Phase 21 |
| ADR-009 | Redis Streams for cross-instance events, not Pub/Sub | Proposed | 12 | Phase 21 |
| ADR-010 | Fail-open for every external service | Proposed | 10 | Phase 21 |
| ADR-011 | In-process Trie for CIDR matching, never Redis | Proposed | 8 | Phase 21 |
| ADR-012 | Score always, even at dial=0 | Proposed | 2 | Phase 21 |

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