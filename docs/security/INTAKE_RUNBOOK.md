# JA4proxy Security Report Intake Runbook

> **Sub-phase:** 121i. **When a new red team report, pentest deliverable,
> vendor audit, or internal review lands, follow this runbook.** Its primary
> purpose is to prevent the "bug-hunt pile" that motivated Phase 121 — every
> new report should produce entries in the existing register, not a new phase
> document.

## Default outcome: zero new phase documents

Most reports contain findings that already map into an existing remediation
phase (109–119) or an existing canonical entry. The runbook below routes them
there. A new phase is opened only for a **net-new category** — a category
with no existing owning phase. Concrete examples that *would* have justified
a new phase at past milestones:

- *"The project has no SBOM generation pipeline"* — net-new, would have
  opened a phase.
- *"The proxy does not implement SLSA L3 provenance"* — net-new, would have
  opened a phase.
- *"Seventeen variants of PROXY protocol header spoofing"* — not net-new;
  all map to canonical PROXY-spoofing finding(s) via `source_refs`.

If in doubt: **do not open a new phase.** Open a GitHub issue, append to the
register, and revisit at the next security review.

## Step-by-step

### 1. Register the report

Drop the source document into `docs/reports/` with a date-prefixed filename:
`YYYY-MM-DD_SOURCE_NAME.md` (e.g. `2026-06-14_REDTEAM_Q2.md`). Keep the
original text unmodified — the register links to it via `source_refs.report`.

Assign the report a short stable tag (e.g. `REDTEAM_2026_Q2`). This tag
becomes the `report` value in every `source_refs` entry for findings it
contributes.

### 2. Triage each finding

For each finding in the report, run:

```bash
python3 scripts/findings_register.py dedup-hint "<finding title or keywords>"
```

Then pick one of three outcomes:

#### (a) Exact duplicate of an existing canonical entry

Append to the existing entry's `source_refs` by editing `findings.yaml`:

```yaml
source_refs:
  - report: PHASE_108
    id: L1-001
    discovered: '2026-04-09'
  - report: REDTEAM_2026_Q2          # ← NEW
    id: R-42
    discovered: '2026-06-14'
```

Do **not** change `discovered` on the parent finding (it tracks the earliest
known discovery date). Do **not** change `severity` unless the new report
contains evidence that materially shifts the rubric classification — in which
case add a `notes` entry explaining.

#### (b) Same root cause, different manifestation

Use `add` to create a new canonical ID, then set `depends_on: [<existing id>]`
or `supersedes: [<existing id>]` as appropriate. Example: PROXY protocol
**spoofing** (C-4) and PROXY protocol **smuggling** (also C-4) are sibling
findings under the same root cause but are separate entries because their
fixes live in different code paths.

#### (c) Novel finding

```bash
python3 scripts/findings_register.py add \
    --source REDTEAM_2026_Q2 \
    --source-id R-42 \
    --title "Short, searchable title" \
    --severity HIGH \
    --severity-rationale "HIGH per clause H-3 (mis-scoring at scale)" \
    --discovered 2026-06-14 \
    --lane go-proxy \
    --owner @seanpor \
    --cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" \
    --cvss-score 8.1 \
    --remediation-phases 118b
```

Severity is assigned **per `SEVERITY_RUBRIC.md`**, not copied from the
source's CVSS. Record any rubric-vs-CVSS disagreement in
`severity_rationale`.

### 3. Assign to a remediation phase

Use this decision tree:

```
Is there an existing phase whose scope covers this finding?
├── Yes: set remediation_phases: [<that phase id>].  Done.
└── No:
    └── Is the category net-new (no existing phase owns it)?
        ├── Yes: open a new phase (PHASE_XXX.md) and set remediation_phases: [<new id>].
        └── No:  file an issue explaining the mismatch; leave remediation_phases: [] and bring to security review.
```

"Scope covers" is a judgement call. Rule of thumb: if fixing this finding
would touch files that another phase's acceptance criteria already claim,
it belongs to that phase.

### 4. Produce an intake summary

Create `docs/reports/YYYY-MM-DD_INTAKE_<source>.md` containing:

- Report metadata (source, date received, triager).
- Per-finding table: source ID → canonical ID → disposition (duplicate /
  sibling / novel) → assigned remediation phase.
- List of any new phase documents opened (usually none).
- Register counts before / after intake.

Commit the intake summary, the modified `findings.yaml`, and the regenerated
`FINDINGS_REGISTER.md` (`make findings-render`) in a single atomic commit
titled `intake/<source>: <N> findings triaged`.

### 5. Validate

```bash
make verify-findings
```

Must exit 0. If it fails, fix the schema errors before the intake commit.

## Worked example: hypothetical 2026-Q2 red team report

**Report contains 17 findings.** Triage outcome:

| Source ID | Canonical | Disposition | Remediation phase |
|-----------|-----------|-------------|-------------------|
| R-01 — PROXY v2 spoofing via fragmented header | JA4PROXY-2026-0001 (existing) | Duplicate | 118a |
| R-02 — JA4 fingerprint differs across TLS records | JA4PROXY-2026-0004 (existing) | Duplicate | 118b |
| R-03 — Tarpit handler blocks on slow write | JA4PROXY-2026-0011 (existing) | Duplicate | 118f |
| R-04 — New: Redis Stream consumer lag blows memory | JA4PROXY-2026-0054 (NEW) | Novel | 113 (in-scope) |
| R-05 — New: SBOM not generated at build time | JA4PROXY-2026-0055 (NEW) | Novel | **PHASE_122** (new phase opened — net-new category) |
| R-06 … R-17 | various | mix of duplicate/sibling | various |

**Outcome:** 14 duplicates, 2 novel, 1 new phase. The 14 duplicates add one
line each to existing entries' `source_refs`. The 2 novel findings use `add`.
The one new phase is opened because "SBOM generation" has no existing owner.

## Migration trigger: >100 canonical findings

When `python3 scripts/findings_register.py list | wc -l` exceeds 100 canonical
entries, migrate from YAML to a GitHub Projects board with custom fields
matching the schema. Keep `findings.yaml` in git as a snapshot export, but
treat the Projects board as the source of truth and regenerate
`FINDINGS_REGISTER.md` from the Projects API.

Reason: beyond 100 entries, filtering / sorting / assignment workflow
benefits outweigh the YAML-in-git diff clarity. The trigger is documented
here so the migration is not forgotten when the threshold is crossed.

## Anti-patterns

- ❌ **Opening a new phase for duplicate findings.** This is the pattern that
  caused Phase 121 in the first place.
- ❌ **Copying the report's own CVSS score straight into `severity`.** Use
  the rubric.
- ❌ **Changing an existing entry's `discovered` date** to the newer date
  when a newer report surfaces the same finding.
- ❌ **Creating a canonical ID without running `dedup-hint` first.**
- ❌ **Assigning a finding to a remediation phase without checking that the
  phase's scope actually covers it.**
- ❌ **Deferring severity classification** by leaving `severity_rationale`
  empty. `make verify-findings` will fail.

## Coordinated vulnerability disclosure (CVD) intake

Reports arrive via GitHub Security Advisories (see `docs/security/CVD_POLICY.md` §2).
Triage on a best-effort basis (no SLA committed):

1. Acknowledge receipt to the reporter when first reviewed.
2. Reproduce against the most recent stable release.
3. Classify severity per `docs/security/SEVERITY_RUBRIC.md`.
4. Assign a maintainer; track in the GHSA itself (no separate ticket required).
5. On fix availability, request a CVE via GHSA, publish the advisory, credit the reporter unless they declined.

See `docs/security/CVD_POLICY.md` for the full policy including safe-harbour terms.

## Relationship to other docs

- `SEVERITY_RUBRIC.md` — how to label severity in step 2.
- `OWNERSHIP.md` — who owns the finding once triaged (sets `owner` in step 2).
- `CLOSURE_VERIFICATION.md` — what happens after the finding is picked up.
- `FINDINGS_REGISTER.md` — the generated human-readable view; update via
  `make findings-render`.
- `CVD_POLICY.md` — the public-facing coordinated vulnerability disclosure
  policy that drives the CVD intake section above.
