<!--
title: Documentation_Standards
audience: Developers
last_reviewed: 2026-03-27
phase: 21
-->

# JA4proxy — Documentation Standards

> This document defines how documentation is written and kept up to date.
> The agent must follow these standards in every phase.

---

## §1. CHANGELOG Format

Every phase completion requires a CHANGELOG.md entry. Use this exact format:

```markdown
## [Phase N] — YYYY-MM-DD

### Added
- Brief description of new capability (module name in backticks)
- e.g. `src/security/sni_analyzer.py` — SNI anomaly detection (missing SNI, DGA scoring)

### Changed
- What existing behaviour changed and why
- e.g. Rate limiter upgraded from fixed-window INCR to sliding-window Sorted Set

### Redis Schema
- New keys added: `key:pattern:{var}` → type, TTL
- Keys modified: old format → new format
- Keys removed: `old:key:pattern`

### Performance
- Benchmark delta: throughput N → N conn/s, latency p99 N → Nms
- Record if no change: "No throughput impact measured"

### Breaking Changes
- Config keys renamed or removed (with migration instructions)
- Redis key schema changes that require data migration
- API changes (Phase 13+)

### Known Limitations
- Anything deferred to a later phase
- Any platform-specific behaviour
```

**Rules:**
- One entry per phase, not per commit
- Date is the date the phase completion gate passed (all tests green)
- Do not summarise what the phase file already says — focus on the delta

---

## §2. REDIS_SCHEMA.md Format

Every Redis key added by any phase must be documented here.
The file lives at `docs/REDIS_SCHEMA.md`.

```markdown
## Key: `{prefix}:{variable_part}`

**Type:** String | Hash | Sorted Set | List | Set | HyperLogLog | Bloom Filter  
**TTL:** N seconds | None (permanent) | Sliding (reset on access)  
**Written by:** proxy hot path | enrichment worker | analytics node | management UI  
**Read by:** proxy hot path | analytics node | management UI  
**Phase introduced:** Phase N  

**Value format:**
\`\`\`json
{ "field": "description of field", "other": "..." }
\`\`\`

**Notes:** any special behaviour, eviction policy, fallback if missing
```

**Rules:**
- Add the entry in the same phase that introduces the key
- When a key's format changes, update the entry and add a note with the old format
  and the phase that changed it
- Never delete entries — mark deprecated keys as `[DEPRECATED Phase N]`

---

## §3. Runbook Update Policy

The existing runbook documents (`docs/OPERATIONS.md`,
`docs/INCIDENT_RESPONSE.md`, `docs/QUICK_REFERENCE.md`) must be updated when a
phase adds a new service, new failure mode, or new operational command.

### What triggers a runbook update

| Change | Update required |
|--------|----------------|
| New Docker Compose service | Add to services table in README and SECOPS_OPERATIONS |
| New Redis key pattern | Add to REDIS_SCHEMA.md |
| New failure mode documented in code | Add to INCIDENT_RESPONSE.md |
| New management command | Add to QUICK_REFERENCE.md |
| New config section | Add to OPERATIONS.md config reference |
| New Grafana panel | Add to MONITORING_SETUP.md |
| New Prometheus alert | Add to INCIDENT_RESPONSE.md runbook section |

### INCIDENT_RESPONSE.md — Required Sections per Phase

When a new detection module is added, add a section to INCIDENT_RESPONSE.md:

```markdown
### Scenario: [Module name] causing false positives

**Symptoms:** Legitimate traffic being blocked; sudden drop in traffic; user reports

**Immediate action:**
1. Set dial to 0: `redis-cli SET config:dial 0`
2. Identify affected connections in Grafana: filter by top_signal = "[module]"
3. Check module config in config/proxy.yml

**Investigation:**
- Check Prometheus: `ja4proxy_risk_actions_total{action="block"}` spike?
- Check analytics: `analytics:report:latest` for anomalies
- Check module-specific metrics: [list metrics for this module]

**Resolution options:**
- Disable module: set `[module].enabled: false` in config, send SIGHUP
- Reduce score contribution: lower `[module].risk_score` in config
- Add to whitelist: if specific JA4/IP is being incorrectly scored

**Post-incident:**
- Document the FP trigger in CHANGELOG.md Known Limitations
- Consider adding the triggering pattern to the FP corpus test
```

---

## §4. API Documentation (Phase 13+)

The Management UI REST API must be documented with OpenAPI/Swagger.

**Implementation:** FastAPI generates OpenAPI docs automatically at `/docs` (Swagger UI)
and `/redoc`. This is enabled by default — do not disable it.

Additional requirements:

- Every endpoint must have a docstring describing: purpose, auth requirement,
  side effects (Redis writes, pub/sub messages), idempotency
- Every request/response model must use Pydantic with field descriptions
- Error responses must be documented (400, 401, 404, 409, 422)
- Rate limiting on management endpoints must be documented

**Export:** after Phase 13 is complete, export the OpenAPI spec:
```bash
python -c "from management.backend.main import app; import json; print(json.dumps(app.openapi()))" \
  > docs/api/openapi.json
```

Commit `docs/api/openapi.json` and regenerate it whenever the API changes.

---

## §5. Architecture Decision Records (ADRs)

The decision log in `CLAUDE.md` captures *what* was decided. ADRs capture *why*
in a way that helps future developers understand the reasoning without reading the
entire conversation history.

**When to write an ADR:** any decision that is not obvious and would confuse a
developer encountering it for the first time. Examples from this project:
- Why Go not Rust for Phase 15
- Why Redis Streams not Pub/Sub for analytics events
- Why the scoring asymmetry means whitelist TTL >> block TTL
- Why block expansion is off by default

**File:** `docs/decisions/ADR-NNN-short-title.md`

**Format:**
```markdown
# ADR-NNN: [Short title]

**Date:** YYYY-MM-DD  
**Status:** Accepted | Superseded by ADR-NNN | Deprecated  
**Phase:** N  

## Context
What is the problem or question this decision addresses?

## Options Considered
1. Option A — brief description
2. Option B — brief description

## Decision
We chose Option A.

## Consequences
**Positive:** what becomes easier or better
**Negative:** what becomes harder or worse; what this forecloses

## Revisit if...
Conditions under which this decision should be reconsidered.
```

**Existing decisions to write as ADRs (backlog):**

- ADR-001: Go not Rust for Phase 15 proxy rewrite
- ADR-002: Redis Streams for analytics event transport
- ADR-003: Scoring asymmetry — whitelist TTL >> block TTL
- ADR-004: Dial as post-scorer action modifier (not pre-scorer signal filter)
- ADR-005: Block expansion off by default with /24 ceiling
- ADR-006: Analytics node as separate container (not embedded in proxy)
- ADR-007: mTLS as scorer bypass not scored signal

---

## §6. README Maintenance

The README is the first thing a new developer sees. It must accurately describe the
current state of the system, not the state at project start.

**Sections that must be updated as phases complete:**

| README section | Update trigger |
|---------------|---------------|
| Security Pipeline table | Any phase that adds a new pipeline layer |
| Services table | Any phase that adds a Docker Compose service |
| Configuration section | Any phase that adds a major new config section |
| Performance table | After any load test (update with latest numbers) |
| Codebase table | After each phase (update line counts and % breakdown) |
| Documentation links | Any phase that adds a new doc file |

**Never let the README describe features that don't exist yet.** If a phase is in
progress, do not update the README until the phase completion gate has passed.

---

## §7. Per-Phase Documentation Checklist

Add this to the phase completion gate (§5 of TESTING_STRATEGY.md):

```
Documentation gate — must pass before phase is marked complete:

[ ] CHANGELOG.md entry written in standard format
[ ] docs/REDIS_SCHEMA.md updated for all new Redis keys
[ ] README.md pipeline table updated (if new pipeline layer added)
[ ] README.md services table updated (if new Docker service added)
[ ] docs/OPERATIONS.md updated (if new operational procedure)
[ ] docs/INCIDENT_RESPONSE.md updated (if new failure mode or module)
[ ] docs/QUICK_REFERENCE.md updated (if new commands)
[ ] docs/MONITORING_SETUP.md updated (if new Grafana panels or alerts)
[ ] OpenAPI spec regenerated (Phase 13+ only)
[ ] ADR written for any significant architectural decision made during phase
[ ] All new code has docstrings (spot-checked, not 100% coverage required)
[ ] All new documents have correct frontmatter (title, audience, last_reviewed, phase)
[ ] `make lint-docs` passes with zero warnings
[ ] `make link-check` passes with zero broken internal links
```
