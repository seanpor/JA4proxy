# ADR-121a: Stay on CVSS v3.1 for the Findings Register

**Status:** Accepted
**Date:** 2026-04-19
**Phase:** 121 (Pentest Remediation Consolidation & Program Discipline)

---

## Context

`docs/phases/PHASE_108.md` acceptance criterion 108n specified that findings
be scored with **CVSS v4**. Every downstream report produced since — the
2026-04-16 leader pentest campaign, the 2026-04-17 red team audit, the
2026-04-17 white-box assessment, and the fixes proposed in Phases 118, 119,
and 120 — used **CVSS v3.1** instead.

Phase 121 now stands up a canonical findings register (`findings.yaml`) that
ingests all ~50 canonical findings from those reports. The register schema
has a `cvss_v3_1` field with a `score` and `vector`; `scripts/findings_register.py validate`
enforces a `CVSS:3.1/...` vector prefix.

We must either:

1. **Stay on CVSS v3.1**, update 108n's specification to match reality, and
   proceed with ingest.
2. **Move to CVSS v4**, rescore every finding currently labelled with v3.1,
   update the register schema and tooling to accept v4 vectors (different
   structure), and delay ingest until the rescoring is complete.

## Decision

**Stay on CVSS v3.1.**

- The register schema keeps `cvss_v3_1` as the CVSS field name.
- `scripts/findings_register.py validate` continues to reject non-v3.1 vectors.
- `docs/phases/PHASE_108.md` acceptance criterion 108n is amended (separately
  under 121e) to specify **v3.1** instead of v4.
- `SEVERITY_RUBRIC.md` is explicit that CVSS is recorded for reference but
  does not determine the severity label — the project rubric does. This
  dampens the downside of whichever CVSS version we pick.

## Consequences

### Positive

- Zero rescoring work. The ~50 canonical findings ingested in 121b keep their
  existing CVSS v3.1 vectors verbatim. Ingest proceeds immediately.
- External tool compatibility: NVD, most commercial scanners (Snyk, Grype,
  Trivy at the time of writing), and most vendor advisories still emit v3.1
  as their primary vector. Operators who plug our register into third-party
  dashboards do not need to re-translate.
- The project's own **severity rubric** remains the source of truth — CVSS
  version choice is a secondary concern.

### Negative

- CVSS v4 has a more expressive threat/environmental modifier set (MAV, MAC,
  MPR, MUI, automatable, recovery, safety) that v3.1 lacks. We forgo the
  richer modelling until the register migrates (see below).
- Regulatory environments that mandate CVSS v4 (none known to apply to this
  project today — but the Cyber Resilience Act implementation guidance is
  still evolving) would require a future migration.

### Risk accepted

CVSS v4 was published by FIRST in November 2023; commercial tool support is
still catching up. If by **2026 Q4** v4 has become the default in
NVD/OSV/major scanners, we revisit this ADR and plan a migration. The
migration cost is bounded by the register size: ~50 findings × ~2 min each
to rescore ≈ 2 engineer-hours + tooling update.

## Implementation notes

1. `docs/phases/PHASE_108.md` §108n — amend "CVSS v4" → "CVSS v3.1" as part
   of Phase 121e (rescope of existing phase docs).
2. `scripts/findings_register.py` — no change (already enforces v3.1).
3. `docs/security/findings.yaml` — no change (schema already `cvss_v3_1`).
4. `docs/security/SEVERITY_RUBRIC.md` — already written assuming v3.1.
5. `docs/security/INTAKE_RUNBOOK.md` — worked example already uses v3.1.

## Revisit criteria

Re-open this ADR if **any** of the following become true:

- NVD publishes more CVSS v4 scores than v3.1 in a calendar quarter.
- A regulation this project must comply with (e.g. EU CRA secondary
  legislation) mandates CVSS v4.
- Tooling we depend on (Snyk, Trivy, Dependabot advisories) removes v3.1
  output.
- A finding cannot be adequately expressed in v3.1 without loss of fidelity
  (we have yet to encounter one in the ~50 findings currently in scope).

## Alternatives considered

- **Score in both v3.1 and v4.** Rejected: double the work, double the
  maintenance, and the rubric (not CVSS) is the thing that drives action
  anyway. Nothing is gained.
- **Drop CVSS entirely, keep only the rubric label.** Rejected: CVSS is how
  external reports arrive; discarding it would force re-translation on every
  intake.
- **Migrate now to CVSS v4 with an automated conversion tool.** Rejected:
  there is no reliable v3.1 → v4 automated conversion — FIRST's own guidance
  requires rescoring. The manual effort is the same either way, and deferring
  until tool support matures lowers the cost.
