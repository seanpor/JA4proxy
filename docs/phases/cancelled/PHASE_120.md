# Phase 120 — RETIRED (duplicate of Phase 119)

> **Status:** RETIRED — superseded by Phase 119
> **Retired under:** Phase 121e (Pentest Remediation Consolidation, 2026-04-19)
> **DUPLICATE_OF:** `docs/phases/PHASE_119.md`

---

## Why this phase was retired

Phase 120 was drafted on 2026-04-17 from the same independent red team
assessment that produced Phase 119. A 2026-04-19 review found that the 20
"novel" findings enumerated here were either:

- **Duplicates** of items already listed in Phase 119 under different local
  IDs (e.g. 120a "ALPN bypass" duplicates 119's JA4 fragmentation cluster);
  or
- **Already folded** into the canonical findings register with
  `remediation_phases` pointing at Phase 119 or its successor phases.

Keeping both PHASE_119.md and PHASE_120.md as active plans doubled the
remediation accounting and risked the "fixed once, tested once" rule the
Phase 121 program discipline is meant to enforce.

## Where to look now

- **For the canonical finding list:** `docs/security/findings.yaml`
  (human-readable view: `docs/security/FINDINGS_REGISTER.md`).
- **For the remediation plan:** `docs/phases/PHASE_119.md`.
- **For the intake / triage process that prevents this pattern recurring:**
  `docs/security/INTAKE_RUNBOOK.md`.

## Mapping from former 120a–120t to canonical IDs

The full mapping lives in the `source_refs` field of the relevant canonical
entries in `docs/security/findings.yaml`. To look up where a former 120N
item went:

```bash
python3 scripts/findings_register.py list --json \
  | jq '.[] | select(.source_refs[].id | startswith("120")) | {id, title, remediation_phases}'
```

If a 120-prefixed source ID does not appear in the register, it was folded
into a canonical entry under a different local ID from an earlier report
(most commonly `RT-NNN` or `119N`). In that case, `dedup-hint` will find it:

```bash
python3 scripts/findings_register.py dedup-hint "<short description>"
```

## Do not add new findings here

New findings from future audits go through the intake runbook, not into
this file. This stub exists only to preserve external links and git-blame
context.
