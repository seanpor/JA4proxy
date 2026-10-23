<!--
title: CVE_Registry_Single_Source_Of_Truth
audience: developer
last_reviewed: 2026-10-19
phase: 847a
-->

# Phase 847a — CVE registry as single source of truth

> **Status:** COMPLETE (2026-10-19)
> **Size:** MEDIUM
> **Dependencies:** none (entry point for the 847 programme)
> **Branch:** `phase-847a-cve-registry`
> **Part of:** Phase 847 (umbrella) — see `docs/phases/complete/PHASE_847.md`

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
(847d); MEDIUM gating (847e); reachability assertions (847f).

> **Scope deviation (recorded 2026-10-17).** The migration surfaced a live
> blocker: `CVE-2026-100351/352/353/354` (kin-openapi, in the Grafana image)
> entered the Trivy DB on 2026-10-16 and reddened `Security Scan` on `main` and
> on *every* open PR — including PR #618. No upstream tag fixes them (13.1.6 and
> 13.2.4 both ship kin-openapi v0.144.0), so a waiver is the only option. It was
> authored here rather than in a follow-up PR precisely because 847a is the
> machinery for authoring waivers, and leaving it out would leave the branch (and
> `main`) red. This is the one intended departure from "no new waivers beyond the
> migration"; gate behaviour is otherwise unchanged.
>
> **Second deviation (recorded 2026-10-19).** By the time this branch was
> scanned, the DB had moved again: `CVE-2026-100349` (kin-openapi — waived, same
> family as above) and `CVE-2026-56851` (`golang.org/x/text`) were unwaived.
> 56851 was **fixable**: bumping `prometheus v3.14.0→v3.15.0`,
> `alertmanager v0.34.0→v0.34.1` and `grafana 13.1.6-ubuntu→13.2.4-ubuntu` clears
> it, and I verified the newer tags add **no** new unwaived finding. Per the
> programme's "zero fixable-but-waived" rule and Phase 827's "upgrade the tag
> rather than renew the waiver" policy, the images were **bumped instead of
> waived**. The bump also made six existing waivers dead (their CVEs are gone from
> the new tags), and those were deleted. Net effect: fewer waivers than before.
> This is a deliberate, evidence-backed extension of 847a's scope — it is the
> honest alternative to accruing debt the programme exists to eliminate.

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
  `expires` are **required**.
- `owner` is optional and defaults to `policy.default_owner`
  (`security-oncall`).
- `fix_available` defaults to `true` and must be explicitly `false` with a
  `recheck_trigger` — forces the author to state why fixing is impossible.
- `expires` must be ≤ 90 days from `created` (matches the documented 90-day
  policy); the renderer rejects longer. `created` therefore means *the start of
  the current waiver window* (i.e. when it was last authored/renewed), which is
  what `--renew` updates.

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
- Import the pip-audit ignores: the `Makefile` had **6**, `ci.yml` had **2**
  (union **7**), and the in-flight 824c PR adds `CVE-2026-59951` (**8** total).
  The union is authoritative; both consumers now read the generated list, so the
  divergence is structural rather than reconciled by hand.
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
- **Comment preservation (regression):** assert that saving the registry keeps the
  file header and `>-` rationale style and collapses a block-form `carriers:`
  list — guarding the `yaml.safe_dump` bug found on this branch (a 1346-line
  destroy-and-reflow diff). See `tests/unit/test_waivers_registry.py`.
- **No-gap / no-dead:** `check_trivyignore_drift.py --scan-dir <reports>` reports
  zero gaps and zero dead entries against the committed ignorefile.
- Run `make preflight`.

---

## Acceptance criteria

- [x] `security/waivers.yaml` exists with the full schema; every pre-existing
      Trivy entry was migrated, and the pip-audit union (`Makefile` 6 ∪ `ci.yml`
      2 ∪ 824c's `CVE-2026-59951` = 8) is authoritative.
- [x] `scripts/render_waivers.py` generates `.trivyignore.{first,third}-party`
      and the pip-audit ignore args; deterministic (`--check` passes).
- [x] `Makefile` and `.github/workflows/ci.yml` read ignores from the generated
      source — **no inline `--ignore-vuln` remains in either**.
- [x] `tests/unit/test_waivers_registry.py` fails on hand-editing a derived file,
      and on a registry rewrite losing comments.
- [x] Regenerated files reproduce the pre-migration inventory (see the scope notes
      above for the two recorded, evidence-backed deviations).
- [x] The registry ends **smaller** than it started: six dead waivers removed,
      and `CVE-2026-56851` fixed by an image bump rather than waived.
- [x] `make scan-images` is green with **no** unwaived finding, and the drift check
      reports zero gaps / zero dead.
- [x] `make preflight` passes.

---

## Files to modify

| File | Change |
|------|--------|
| `security/waivers.yaml` | New — the registry |
| `scripts/render_waivers.py` | New — deterministic renderer (comment-preserving save) |
| `scripts/renew_trivyignore.py` | Rewritten — renews the registry, then re-renders |
| `scripts/refresh_trivyignore_justifications.py` | Rewritten — registry-aware |
| `scripts/check_upstream_image_updates.py` | Parse the multi-line carrier format |
| `tests/unit/test_waivers_registry.py` | New — drift + schema + comment-preservation tests |
| `tests/unit/test_renew_trivyignore.py` | Reworked for the registry |
| `.trivyignore.third-party` | Regenerated (content preserved) |
| `.trivyignore.first-party` | Regenerated (still empty) |
| `.pip-audit-ignores` | New — generated ignore args |
| `Makefile` | Read ignores from `.pip-audit-ignores` |
| `.github/workflows/ci.yml` | Read ignores from `.pip-audit-ignores` |
| `.github/workflows/trivyignore-renewal.yml` | Commit `security/waivers.yaml` on renewal |
| `deploy/docker/docker-compose.monitoring.yml` | Bump prometheus/alertmanager/grafana (fixes 56851) |
| `deploy/docker/docker-compose.prod.yml` | Bump prometheus/grafana |
| `docs/reference/DOCKER_IMAGES.md` | Reflect the bumped pins |
| `docs/runbooks/security_scan_exceptions.md` | Registry-based runbook |
| `docs/fragments/phase-847a-cve-registry.md` | Changelog fragment |

---

## Notes for implementer

- **Behaviour change is limited to the two recorded deviations above.** The gate
  must otherwise fail on exactly the same set before and after. Prove it: capture
  `make scan-images` + pip-audit results pre- and post-migration and diff them in
  the PR description. The image bumps (56851) and dead-waiver removals are the
  *only* intended differences, and each is backed by scan evidence.
- Do **not** silently drop the `ci.yml`-only entries if any exist; reconcile in
  the open.
- Keep the generated `.trivyignore.*` **committed** (not gitignored): the scan
  reads them at runtime and reviewers should see waivers in the diff. The drift
  test is what stops them going stale, not gitignoring them.
