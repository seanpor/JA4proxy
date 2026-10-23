<!--
title: Scan_Tooling_Correctness
audience: developer
last_reviewed: 2026-10-19
phase: 847b
-->

# Phase 847b — Scan tooling correctness

> **Status:** COMPLETE (2026-10-19)
> **Size:** SMALL
> **Dependencies:** [847a]
> **Branch:** `phase-847b-scan-tooling-correctness`
> **Part of:** Phase 847 (umbrella) — see `docs/phases/complete/PHASE_847.md`

---

## Goal

Fix three concrete correctness defects in the scan tooling that were exposed during
Phase 824c. Each is small, independent, and removes a way the tooling actively
misleads a human triaging under pressure.

Doing the work surfaced four more of the same family (847b.4–847b.7) — found by
the honesty fix, by `make preflight`, and by reading what the tooling says about
itself. All seven are recorded below.

---

## Defects

### 847b.1 Undercounted findings (`grep -c HIGH` on a grouped table)

`Makefile:scan-images` decided pass/fail from Trivy's **human table**:

```sh
high=$$(echo "$$result" | grep -v "Total:" | grep -c "HIGH" || true);
```

and `scan-first-party` carried the identical defect:

```sh
findings=$$(echo "$$result" | grep -v "Total:" | grep -E -c "CRITICAL|HIGH" || true);
```

Trivy's table groups by library and prints the severity **once per group**;
continuation rows for the other CVEs in that group leave the Severity column
blank. **Measured on a live capture of 14 real Trivy tables, the expression
returned `1` for every one of them**, while Trivy's own line reported 4, 5 or 6.
The pinned case: an image carrying **5** kin-openapi HIGHs counts as **1** — the
direction that invites "a single CVE, easy to waive."

Two aggravating facts:

- The correct count was *right there and discarded* — `grep -v "Total:"`
  explicitly deletes the line that says `Total: 5 (HIGH: 5, CRITICAL: 0)`.
- The expression counts **lines containing a word**, not findings. Nothing ties a
  hit to a distinct CVE id, and a blank severity cell is invisible to it, so it
  does not track the true number in either direction.

**Fix:** scan with `--format json`, count `.Results[].Vulnerabilities[]` through
the parser already in `scripts/check_trivyignore_drift.py`, and print the
per-CVE table *from the JSON*. The count now has a source that cannot be affected
by how Trivy chose to render a table.

### 847b.2 Error message points at a deleted file

```
✗ HIGH/CRITICAL CVEs found — see .trivyignore for documented exceptions
```

There is **no** `.trivyignore` (split into first/third-party in Phase 822). A
person following the message finds nothing.

**Fix:** name `security/waivers.yaml` (the authoring location, from 847a) and the
generated `.trivyignore.third-party` / `.trivyignore.first-party`, plus the
runbook. Both targets now say what to do — bump the base/dep, or add a dated
entry — instead of pointing at a file that no longer exists.

The same class reached `make help`. `scan-images` advertised
`(HIGH/CRITICAL; fails on CRITICAL)` and `scan-first-party` `(CRITICAL → fail)` —
each contradicting its own recipe echo three lines below ("Fails on HIGH or
CRITICAL") and the code, which has failed on HIGH since Phase 317. An operator
reading `make help` would have concluded a HIGH-only red gate was a bug. Both
summaries now read `fails on HIGH or CRITICAL`, guarded by a test.

### 847b.3 The two ignore lists are consumed identically

After 847a, `Makefile` and `ci.yml` both read the generated `.pip-audit-ignores`.
This phase asserts that invariant holds, and adds a guard 847a did not have:
**every `--ignorefile` / `trivyignores:` consumer must name a file that exists.**
That is the test that would have caught 847b.6.

### 847b.4 *(found in implementation)* A scan that could not run passed as clean

Both targets swallowed a failed scan as a pass: `2>&1 | grep -E ... || true`
discards Trivy's `FATAL`, `grep -c` then finds no severity token, counts **0**,
and the gate reports clean. An image that was never scanned and a clean image
were indistinguishable.

This was not theoretical. Running the honest gate the first time failed loudly on
`ja4proxy-tap:1.0.0` — Trivy `FATAL: unable to find the specified image`, because
`scan-images` mounted no docker socket, so that image had been silently skipped
by that gate in **every** previous run, including CI. The old code called it
"no findings".

**Fix:** a scan that produces no readable JSON is **exit 2** and reddens the
target. The message says a scan that cannot be read is a failure, never a pass.

### 847b.5 *(found in implementation)* First/third-party classification drift

`scripts/check_image_versions.py`'s `FIRST_PARTY_IMAGES` held 6 names; the
Makefile's held 8 — missing `ja4proxy-tap` and `ja4proxy-management`. So
`--list-third-party` handed the **locally-built** `ja4proxy-tap:1.0.0` to the
third-party gate, which pulls from a registry and therefore cannot see it: an
guaranteed failure, masked as a pass by 847b.4.

**Fix:** add both names (the script now matches the Makefile) and keep coverage
where it already belonged — `scan-all` runs `scan-first-party`, which **builds**
that image and scans it with the docker socket mounted. Net coverage of
`ja4proxy-tap` is unchanged by any measure; what changed is that the attempt
scanning it now works instead of silently not happening.

### 847b.6 *(found in implementation)* A workflow still applied the pre-822 ignorefile

`.github/workflows/go-proxy-image.yml` had `trivyignores: .trivyignore` — a file
that has not existed since Phase 822. Trivy refuses to start with a missing
ignorefile (verified in this phase: `FATAL ... ignore file not found`), so this
CRITICAL gate was not applying first-party waivers as intended.

**Fix:** point it at `.trivyignore.first-party`, and keep a repo-wide test that
fails any workflow or Makefile target whose ignorefile consumer names a file that
does not exist. (The test checks *consumers* only — a `trivyignores:` field or
an `--ignorefile` argument — so prose mentioning a filename is not a false
positive.)

### 847b.7 *(found by reading the tooling's own claims)* `scan-summary` calls a HIGH "WARN"

`scripts/scan_summary.py`'s `verdict()` docstring claimed *"Defaults match the
image gate (CRITICAL fails, HIGH is advisory)"*. They never matched it, and had
not since Phase 317: `scan-images` and `scan-first-party` fail on **HIGH or
CRITICAL**, so a HIGH that just reddened the build was rendered to the operator
as a mere `WARN` — in the very report they reach for to understand a red gate.

The divergence was internal too. The misconfig and gosec rows already passed
`fail=("HIGH",)` / `fail=("CRITICAL", "HIGH")` explicitly; only the *default* the
image path relied on still encoded the pre-317 policy.

**Fix:** default to `fail=("CRITICAL", "HIGH"), warn=()` so all three consumers
agree, and reword the docstring to state what it actually does. Zero CI risk,
verified three ways: `scan-summary` is reporting-only, it is not a prerequisite
of `scan-all`, and `pipeline_summary.py` prints an unconditional verdict rather
than parsing these labels — the required check fails on `make`'s exit codes.

---

## What was built

**`scripts/trivy_image_report.py` (new)** — the single per-image gate:

| Exit | Meaning | Gate result |
|------|---------|-------------|
| 0 | no HIGH/CRITICAL findings | pass |
| 1 | HIGH/CRITICAL findings present | fail |
| 2 | scan or report could not be run/parsed | fail — never a pass |

- Per-CVE table (`PACKAGE / CVE / INSTALLED / SEVERITY`), CRITICAL first, then by
  CVE id — deterministic output for humans and diffs.
- `--json-file` reads an already-captured report (offline; how the unit tests pin
  real grouping semantics without a network).
- `--docker-socket` (opt-in) mounts the host socket, which locally-built images
  need because they exist in no registry. Third-party images deliberately get no
  socket.
- `resolve_ignorefile()` accepts exactly two spellings — the repo-relative name
  and the `/scan/…` container path it is mounted at — and **rejects anything
  else rather than re-homing it**. A plain `basename()` would turn `/etc/hosts`
  into `/scan/hosts`: a typo in a security gate quietly resolving to some other
  file. It also fails here, with a message, if the ignore file is missing,
  instead of leaving the operator to decode a Trivy FATAL.

**`scripts/check_trivyignore_drift.py`** — `VulnRow`, `load_report` and
`vuln_rows()` were promoted to module level so the gate and the drift checker use
**one** parser (847b.1's plan warned against adding a third). A test asserts the
two agree on the same report.

**`scripts/scan_summary.py` remains a report, never a gate** — it exits 0 with
findings present, and gating lives only in the new script. One correction
(847b.7): its `verdict()` default now labels HIGH `FAIL`, the way every gate and
both other report rows already did, so the report cannot understate what just
failed.

**`Makefile`** — `scan-images` and `scan-first-party` both delegate to the gate
with an explicit `--ignorefile` (`/scan/.trivyignore.third-party` and
`/scan/.trivyignore.first-party`), and both wire `|| fail=1`. No severity-counting
`grep` survives anywhere in the Makefile — a test asserts that of the whole file,
not just of these two targets.

---

## Test strategy (as executed)

`tests/unit/test_scan_tooling.py` — **24 tests** across seven groups:

1. **JSON counting** — the 5 kin-openapi CVEs count as 5 through the shared
   parser; dedup is by CVE id (one waived id must not inflate on repeated rows);
   CRITICAL wins over HIGH for the same id; the gate and the drift checker agree.
2. **The defect, pinned** — on the *real* captured table, `grep -v "Total:" |
   grep -c HIGH` yields **1** where the same file says `Total: 5`; the gate
   reports **5** and names every id individually.
3. **Failure messages** name `security/waivers.yaml` and `.trivyignore.third-party`,
   and the old `see .trivyignore …` string is gone.
4. **Consumer alignment** — Makefile and `ci.yml` both read `.pip-audit-ignores`
   and neither has an inline `--ignore-vuln`; every ignorefile *consumer* names an
   existing file; the reporter's default ignorefile exists.
5. **Classification** — the script's and the Makefile's first-party lists agree,
   and no first-party name ever appears in the third-party image list.
6. **No silent pass** — an unparseable report fails; a genuinely empty report
   passes; both targets run the gate with `|| fail=1`; no severity-`grep` counting
   survives in the Makefile.
7. **`--ignorefile` validation** — both spellings resolve identically; a path
   outside the mount is rejected rather than re-homed; a missing file fails before
   Trivy runs; the gate exits 2 rather than scanning.

Fixtures are **real captured Trivy output** (JSON + matching table), because the
bug *is* Trivy's grouping semantics — a synthetic fixture would not reproduce
them.

Beyond unit tests, the gate was validated against live images: clean image → 0;
the same image scanned with an empty ignorefile → **12 HIGH + 0 CRITICAL, exit 1**,
with real waivers → **exit 0** (so the ignorefile demonstrably changes the
outcome); a bad ignorefile path → **exit 2**; a locally-built image with
`--docker-socket` → exit 0.

- [x] Finding counts derive from Trivy **JSON**; the grouped-table case reports
      its true count (5 in the real data, not 1).
- [x] Failure messages name `.trivyignore.third-party` / `security/waivers.yaml`.
- [x] `Makefile` and `ci.yml` proven to consume the same generated ignore source,
      and no ignorefile consumer names a file that does not exist.
- [x] `make preflight` passes.

---

## Files to modify (as built)

| File | Change |
|------|--------|
| `scripts/trivy_image_report.py` | **New** — JSON gate (exit 0/1/2), per-CVE table, `resolve_ignorefile` |
| `scripts/check_trivyignore_drift.py` | Promote `VulnRow` / `load_report` / `vuln_rows` to shared parser |
| `scripts/check_image_versions.py` | `FIRST_PARTY_IMAGES` += `ja4proxy-tap`, `ja4proxy-management` |
| `Makefile` | `scan-images` + `scan-first-party` onto the gate; real failure messages; truthful `## help` |
| `.github/workflows/go-proxy-image.yml` | `trivyignores: .trivyignore` → `.trivyignore.first-party` |
| `scripts/scan_summary.py` | `verdict()` default: HIGH → `FAIL` (847b.7), docstring states what it does |
| `tests/integration/test_ci_flow.py` | Two severity tests rewritten — they *required* `grep -c "HIGH"` and the removed expression |
| `tests/unit/test_scan_summary.py` | `HIGH: 3` now expects `FAIL` |
| `tests/unit/test_scan_tooling.py` | **New** — 24 tests |
| `tests/fixtures/trivy-grafana-kin-openapi.json` | **New** — real captured Trivy JSON (5 kin-openapi HIGHs) |
| `tests/fixtures/trivy-grafana-kin-openapi.table.txt` | **New** — matching real `--format table` output |
| `docs/fragments/phase-847b-scan-tooling.md` | Changelog fragment |
| `docs/phases/manifest.yaml` | Status |
| `docs/reference/SCRIPTS.md`, `MAKEFILE_TARGETS.md` | Regenerated by `make sync` (never hand-edited) |

---

## Deviations and additions (recorded 2026-10-19)

> **5, not 4 (847b.1).** The plan says "4 kin-openapi HIGHs". Real data has **5** —
> `CVE-2026-100349` plus `-100351/-100352/-100353/-100354`. The fixtures, the
> test expectations and the gate output all use 5; the plan's number was wrong,
> and the fix (count from JSON) is unaffected either way.
>
> **Fixture size.** The captured JSON is 16 KB — the largest file in
> `tests/fixtures/`, where the others are ≤ ~4 KB (the unfiltered full report
> runs to ~1.7 MB). It is kept as real data rather than hand-synthesised, because
> the defect is Trivy's actual grouping behaviour; the risk that matters (a
> fixture that does not reproduce the bug) is eliminated by asserting the real
> table still counts 1 under the old expression.
>
> **Scope addition — 847b.4 (silent pass).** The plan's "do not change behaviour"
> and the exit-2 contract are in tension: making an unreadable scan fail *is* a
> behaviour change, and it is the whole point of 847b's "zero silent findings"
> goal. It was implemented rather than deferred because the gate cannot be
> honestly described as correct while a scanner that never ran reports clean.
>
> **Scope addition — 847b.5 (classification) touches "which images are scanned".**
> The plan says any behaviour change belongs in 847c. `ja4proxy-tap` was removed
> from the *third-party* list as a misclassification correction, not a policy
> change: it is locally built (never pullable), it is still scanned at HIGH+CRITICAL
> by `scan-first-party`, which builds it first, and the third-party attempt had
> never actually scanned it (847b.4). Severity gating and the image set are
> otherwise untouched.
>
> **Scope addition — `scan-first-party`.** The plan names `scan-images` only, but
> the sibling target had the *identical* counting expression and the *identical*
> silent-pass swallow. Fixing one and leaving the other would have left two
> counting implementations disagreeing — the divergence this programme exists to
> remove. Both now call the same gate.
>
> **`--ignorefile` spelling.** The Makefile passes `/scan/.trivyignore.*` (the
> path Trivy reads inside the mount) rather than a repo-relative name, so Phase
> 822's guard tests — which pin that path — stay green and keep guarding. The
> script accepts both spellings and validates strictly instead of silently taking
> a basename.
>
> **The plan's own tests asserted the defect (surfaced by `make preflight`).**
> `tests/integration/test_ci_flow.py` *required* `grep -c "HIGH"`,
> `grep -c "CRITICAL"` and the exact `grep -v "Total:" | grep -E -c …` in the
> recipes — pinning 847b.1's bug as a requirement — while its docstrings claimed
> HIGH was "advisory" for third-party images, which the recipe itself contradicted
> (`if high -gt 0 || crit -gt 0 → fail=1`, in force since Phase 317). The
> assertions were not deleted; they were relocated to where the policy now lives.
> `trivy_cmd()` was split out of `run_trivy()` so the tests assert the *argv*
> Trivy receives (`--severity HIGH,CRITICAL`, `--format json`, the pinned image,
> and **no** host socket for third-party images) and, behaviourally, that a HIGH
> and a CRITICAL each return exit 1. This is what the first `make preflight` run
> caught; the stale "advisory" prose went with it.
>
> **Scope addition — 847b.7 (`scan-summary` verdict).** Not in the plan, found by
> reading a docstring that claimed parity with a gate this phase had just
> re-examined. It changes no policy and no CI outcome (reporting-only, absent from
> `scan-all`, and `pipeline_summary` does not parse these labels) — it removes a
> report that understated a red gate and aligns the image rows with the
> misconfig/gosec rows that already said `FAIL` for HIGH.

---

## Notes for implementer

- Do **not** change *which severities gate* — HIGH + CRITICAL in, HIGH + CRITICAL
  out. The single deliberate exception to "do not change which images are scanned"
  is the 847b.5 classification correction, recorded above; anything further
  belongs in 847c.
- The captured fixtures must stay **real**. A hand-written fixture would not
  reproduce Trivy's library-grouped table, and that grouping *is* the bug.
- If a scan fails, it must exit 2. Adding a `|| true` anywhere on this path
  reintroduces 847b.4 — the test suite checks for it.
