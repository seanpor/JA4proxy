<!--
title: Scan_Tooling_Correctness
audience: developer
last_reviewed: 2026-10-17
phase: 847b
-->

# Phase 847b — Scan tooling correctness

> **Status:** PROPOSED
> **Size:** SMALL
> **Dependencies:** [847a]
> **Branch:** `phase-847b-scan-tooling-correctness`
> **Part of:** Phase 847 (umbrella) — see `docs/phases/PHASE_847.md`

---

## Goal

Fix three concrete correctness defects in the scan tooling that were exposed during
Phase 824c. Each is small, independent, and removes a way the tooling actively
misleads a human triaging under pressure.

---

## Defects

### 847b.1 Undercounted findings (`grep -c HIGH` on a grouped table)

`Makefile:scan-images` counts findings with:

```sh
high=$$(echo "$$result" | grep -v "Total:" | grep -c "HIGH" || true);
```

Trivy's **table** output groups by library and prints the severity **once per
group**; continuation rows for additional CVEs in the same library leave the
Severity column blank. Result: a grafana image carrying **4** kin-openapi HIGHs
was reported as `1 HIGH`. The gate still failed (`fail=1`), but the *count* a
human sees — and reasons from — is wrong, and wrong in the direction that invites
"a single CVE, easy to waive."

**Fix:** emit `--format json` (already supported), count
`.Results[].Vulnerabilities[]` programmatically, and print the per-CVE table from
the JSON. Keep the human-readable summary, but derive it from structured data.
The existing `scripts/check_trivyignore_drift.py` already reads Trivy JSON, so
reuse its parsing conventions rather than adding a third parser.

### 847b.2 Error message points at a deleted file

The failure message reads:

```
✗ HIGH/CRITICAL CVEs found — see .trivyignore for documented exceptions
```

There is **no** `.trivyignore` (split into first/third-party in Phase 822). A
person following the message's instruction finds nothing. **Fix:** name the
generated files from 847a (`.trivyignore.third-party`, and the registry
`security/waivers.yaml` as the authoring location).

### 847b.3 The two ignore lists are consumed identically

After 847a, `Makefile` and `ci.yml` both read `.pip-audit-ignores`. This phase
asserts that invariant holds: a test that both consumers resolve to the same
effective argument list, so a future edit to one cannot silently diverge. (This
is the residual guard beyond 847a's drift test, catching changes to *how* each
consumer reads the file, not just *what* it contains.)

---

## Test strategy

- **847b.1:** unit-test the JSON counter against a captured grafana scan showing
  4 kin-openapi HIGHs in one library group; assert it reports **4**, not 1. Use a
  real captured fixture (checked in under `tests/fixtures/`), not a synthetic one,
  so the grouping semantics are pinned.
- **847b.2:** assert the rendered failure message contains `.trivyignore.third-party`
  and not a bare `.trivyignore`.
- **847b.3:** assert `Makefile` and `ci.yml` both reference the generated ignore
  source and neither contains an inline `--ignore-vuln`.
- Run `make preflight`.

---

## Acceptance criteria

- [ ] Finding counts derive from Trivy **JSON**; a 4-in-one-group image reports 4.
- [ ] Failure messages name `.trivyignore.third-party` / `security/waivers.yaml`.
- [ ] `Makefile` and `ci.yml` proven to consume the same generated ignore source.
- [ ] `make preflight` passes.

---

## Files to modify

| File | Change |
|------|--------|
| `Makefile` | JSON-based counting in `scan-images` |
| `tests/fixtures/trivy-grafana-kin-openapi.json` | New — real captured scan |
| `tests/unit/test_scan_tooling.py` | New — counter + message + consumer tests |
| `docs/fragments/phase-847b-scan-tooling.md` | Changelog fragment |

---

## Notes for implementer

- Do **not** change *which* images are scanned or *which* severities gate — only
  how they are counted and reported. Any behaviour change belongs in 847c.
- The captured fixture must be the **real** grouped-table-equivalent JSON, because
  the bug is precisely about Trivy's grouping semantics; a hand-written fixture
  would not reproduce them.
