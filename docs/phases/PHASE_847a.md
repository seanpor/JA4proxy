<!--
title: CVE_Registry_Single_Source_Of_Truth
audience: developer
last_reviewed: 2026-10-17
phase: 847a
-->

# Phase 847a — CVE registry as single source of truth

> **Status:** PROPOSED
> **Size:** MEDIUM
> **Dependencies:** none (entry point for the 847 programme)
> **Branch:** `phase-847a-cve-registry`
> **Part of:** Phase 847 (umbrella) — see `docs/phases/PHASE_847.md`

---

## Goal

Make **one file** the only place a CVE waiver is authored, and **generate** every
derived artifact from it, so the two divergent ignore lists (7 vs 4) become
structurally impossible rather than manually kept in sync.

This phase changes **no gate behaviour**. It is a pure refactor + migration, and
must stay that way so it is trivially reviewable and safely mergeable.

---

## Scope

**In:** `security/waivers.yaml`; `scripts/render_waivers.py`; a drift test
asserting derived files match the renderer; migrating the existing **29**
third-party Trivy entries and **7** pip-audit `--ignore-vuln` flags into the
registry; wiring `Makefile` and `.github/workflows/ci.yml` to consume rendered
output.

**Out:** any change to *when* a scan fails (that is 847c); expiry re-affirmation
(847d); MEDIUM gating (847e); reachability assertions (847f); authoring any new
waiver beyond the migration.

---

## 847a.1 The registry schema

`security/waivers.yaml` — one entry per accepted finding:

```yaml
waivers:
  - id: CVE-2026-100351
    scope: third-party            # third-party | first-party
    severity: HIGH
    source: trivy                 # trivy | pip-audit
    carriers:                     # images/packages that carry it
      - grafana/grafana:13.1.6-ubuntu
    rationale: >
      kin-openapi ValidationHandler security-requirement bypass. grafana is on
      the internal monitoring network and never validates untrusted OpenAPI
      specs, so the vulnerable path is unreachable.
    reachability: internal-monitoring-only
    fix_available: false          # checked by 847d; false here (no fixed tag)
    recheck_trigger: "grafana ships kin-openapi >= 0.149.0"
    created: 2026-10-17
    expires: 2027-01-15
    owner: security-oncall
```

Field rules, enforced by the renderer:

- `id`, `scope`, `severity`, `source`, `carriers`, `rationale`, `created`,
  `expires`, `owner` are **required**.
- `fix_available` defaults to `true` and must be explicitly `false` with a
  `recheck_trigger` — forces the author to state why fixing is impossible.
- `expires` must be ≤ 90 days from `created` (matches the documented 90-day
  policy); the renderer rejects longer.

## 847a.2 The renderer

`scripts/render_waivers.py` reads the registry and writes:

| Output | Consumer |
|--------|----------|
| `.trivyignore.third-party` | `make scan-images` (already wired) |
| `.trivyignore.first-party` | first-party scan (currently empty) |
| pip-audit ignore args (a generated `.pip-audit-ignores` file) | `Makefile` **and** `ci.yml` both read it |

Each generated line keeps the human-readable justification comment **above** the
entry (matching today's file style) so `scan_images` output and the file remain
self-documenting. The renderer is deterministic (sorted by `id`) so re-running it
on an unchanged registry is a no-op — CI can assert `git diff --exit-code` on the
generated files.

`Makefile` and `ci.yml` stop listing ignores inline and instead pass
`@cat .pip-audit-ignores` args (Makefile) / `$(cat …)` (workflow). This is the
change that kills the 7-vs-4 divergence.

## 847a.3 The drift test (the guard)

A new unit test (`tests/unit/test_waivers_registry.py`) asserts, for each derived
file: **regenerating from the registry reproduces the committed file byte-for-byte.**
If someone hand-edits a derived file, the test fails with a message pointing at
`security/waivers.yaml`. This is the same discipline the repo already applies to
`TODO.md`/`PROJECT_STATUS.md` being generated (Phase 332).

## 847a.4 Migrate the existing inventory

- Import all **29** `.trivyignore.third-party` entries, preserving each existing
  justification comment as `rationale` and each `exp:` date as `expires`.
- Import the **7** `Makefile` pip-audit ignores (and reconcile against `ci.yml`'s
  **4** — the union is authoritative; where they differ, prefer the Makefile list
  and record the reconciliation in the PR).
- Regenerate; assert the regenerated files match today's committed files (modulo
  formatting/ordering), proving the migration is faithful.

---

## Test strategy

- **Round-trip fidelity:** for every migrated entry, assert the rendered output
  contains the same `id` and `exp`/`expires` as the pre-migration file.
- **Schema rejection:** unit-test that a missing `rationale`, a >90-day expiry,
  and `fix_available: false` without `recheck_trigger` each fail the renderer.
- **Determinism:** render twice, assert no diff.
- **Drift guard:** hand-edit a derived file in a scratch copy, assert the drift
  test fails.
- Run `make preflight`.

---

## Acceptance criteria

- [ ] `security/waivers.yaml` exists with the full schema; all 29 Trivy + 7
      pip-audit entries migrated.
- [ ] `scripts/render_waivers.py` generates `.trivyignore.{first,third}-party`
      and the pip-audit ignore args; deterministic.
- [ ] `Makefile` and `.github/workflows/ci.yml` read ignores from the generated
      source — **no inline `--ignore-vuln` remains in either**.
- [ ] `tests/unit/test_waivers_registry.py` fails on hand-editing a derived file.
- [ ] Regenerated files reproduce the pre-migration inventory (proven in PR).
- [ ] `make preflight` passes.

---

## Files to modify

| File | Change |
|------|--------|
| `security/waivers.yaml` | New — the registry |
| `scripts/render_waivers.py` | New — deterministic renderer |
| `tests/unit/test_waivers_registry.py` | New — drift + schema tests |
| `.trivyignore.third-party` | Regenerated (content preserved) |
| `.trivyignore.first-party` | Regenerated (still empty) |
| `.pip-audit-ignores` | New — generated ignore args |
| `Makefile` | Read ignores from `.pip-audit-ignores` |
| `.github/workflows/ci.yml` | Read ignores from `.pip-audit-ignores` |
| `docs/fragments/phase-847a-cve-registry.md` | Changelog fragment |

---

## Notes for implementer

- **Behaviour must not change.** The gate must fail on exactly the same set before
  and after. Prove it: capture `make scan-images` + pip-audit results pre- and
  post-migration and diff them in the PR description.
- Do **not** silently drop the `ci.yml`-only entries if any exist; reconcile in
  the open.
- Keep the generated `.trivyignore.*` **committed** (not gitignored): the scan
  reads them at runtime and reviewers should see waivers in the diff. The drift
  test is what stops them going stale, not gitignoring them.
