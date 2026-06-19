# Phase 86h: Fixup — Correctness Bugs From Phase 86

**Status:** PROPOSED
**Depends on:** Phase 86 (86a–86g, already merged)
**Blocks:** Phase 86i (hardening)

---

## Goal

Fix three correctness bugs shipped by Phase 86 that affect production on-call quality and tool honesty. This phase is pure defect repair — no new features, no architectural change. Phase 86i will follow with the substantive hardening work.

The bugs were surfaced by a critical review comparing Phase 86 as shipped against an alternate design that had been written in parallel. Full review in `PHASE_86h_notes.md` once this phase is complete.

---

## Scope

### Bug 1 — 38 dead runbook URLs across 7 alert rule files

Two distinct flavors of dead URL:

**Flavor A — 35 `example.com` placeholders.** Every alert in the following files currently has `runbook_url: "https://docs.ja4proxy.example.com/runbooks/{{ $labels.alertname }}"`. That domain does not exist.

| File | Dead URL count |
|------|---------------:|
| `monitoring/alertmanager/rules/tap.yml` | 7 |
| `monitoring/alertmanager/rules/redis.rules.yml` | 2 |
| `monitoring/alertmanager/rules/management_ui_rules.yml` | 10 |
| `monitoring/alertmanager/rules/proxy.rules.yml` | 4 |
| `monitoring/alertmanager/rules/backup.rules.yml` | 7 |
| `monitoring/alertmanager/rules/security.rules.yml` | 5 |
| **Subtotal (Flavor A)** | **35** |

**Flavor B — 3 wrong-owner/wrong-case GitHub URLs.** `ti_feed.yml` has `runbook_url` values pointing to `https://github.com/seanoriordain/ja4proxy/blob/main/docs/runbooks/...`. Both the owner (`seanoriordain`) and the repo casing (`ja4proxy`) are wrong — the real repo is `github.com/seanpor/JA4proxy`. GitHub URL segments are case-sensitive, so these 404.

| File | Dead URL count |
|------|---------------:|
| `monitoring/alertmanager/rules/ti_feed.yml` | 3 |
| **Subtotal (Flavor B)** | **3** |

**Total:** 38 dead URLs across 7 rule files. When any of these alerts fires, the operator's Slack / PagerDuty / email notification links to a 404.

### Bug 2 — URL format inconsistency

Even after Bug 1 is fixed, the new rule files use two different `runbook_url` formats:

- `slo_alerts.yml`, `tls_alerts.yml` — relative paths: `docs/runbooks/slo_latency.md`
- `ti_feed.yml` — absolute GitHub URLs (see Bug 1 — wrong, but the *format* is the one we want)

Relative paths do not resolve in Slack, PagerDuty, email, or any other typical Alertmanager notification sink. They render as literal strings. Absolute GitHub URLs work everywhere.

### Bug 3 — Capacity calculator reports estimates as measurements

`scripts/capacity_calculator.py:38-55` hardcodes `BenchmarkConstants` (`go_full_conn_s=6200`, `go_bypass_conn_s=18400`, etc.) with a header comment claiming "sourced from docs/performance/benchmarks.md." But `docs/performance/benchmarks.md` contains only `_(measure)_` placeholders — no benchmark has been run. The calculator produces sizing recommendations from vendor-claim-grade estimates labeled as measurements. Any operator reading the output will believe they're seeing real numbers.

---

## Implementation plan

Steps are executed in order. Each step is a distinct commit.

### Step 1 — Pick the canonical URL format

Decision: **absolute GitHub URLs pointing at the real repo**. Format:
```
https://github.com/seanpor/JA4proxy/blob/main/docs/runbooks/<filename>.md
```

Note the exact casing: owner `seanpor` (not `seanoriordain`), repo `JA4proxy` (capital J, capital P — not `ja4proxy`). GitHub URL segments are case-sensitive.

Rationale: (a) works in every Alertmanager notification sink; (b) format matches `ti_feed.yml`'s intent once the owner/casing is corrected; (c) survives clone-and-browse locally via GitHub's UI.

### Step 2 — Audit every alert and map to a runbook

For each of the 38 dead URLs and the 11 relative-path URLs in `slo_alerts.yml` + `tls_alerts.yml` (49 total), identify the best existing runbook in `docs/runbooks/`. Where none fits, use a reasonable fallback (e.g., `security_incident_response.md`).

The mapping will be stored as `docs/phases/PHASE_86h_runbook_mapping.yml`:

```yaml
# PHASE_86h_runbook_mapping.yml
# Maps alert name → runbook filename (relative to docs/runbooks/).
# Used by scripts/fix_runbook_urls.py to rewrite alert rule files.
# Format: <AlertName>: <runbook_filename.md>

ProxyInstanceDown: ja4proxy_node_unhealthy.md
ProxyHighBlockRate: ja4proxy_block_rate_high.md
# ... one entry per alert across all rule files
```

If a mapping entry points to a runbook that does not exist, Step 3 creates it as a short stub ("See [related runbook] for diagnostics") — this phase does not write full runbook content, that is outside scope.

### Step 3 — Create any missing runbook stubs

For alerts whose mapped runbook does not yet exist in `docs/runbooks/`, create a one-page stub following the format in AGENTS.md (Severity, What is happening, Impact, Diagnosis, Resolution, Escalation). The stub may cross-reference existing runbooks and marks itself `**Status:** STUB — written in Phase 86h, to be expanded.` Expanding stubs is out of scope for this phase.

### Step 4 — Write `scripts/fix_runbook_urls.py`

A one-shot script that rewrites `runbook_url:` lines in all `monitoring/alertmanager/rules/*.yml` files using the mapping file. Idempotent — running it twice is a no-op.

```
Usage: python3 scripts/fix_runbook_urls.py \
  --rules-dir monitoring/alertmanager/rules/ \
  --mapping docs/phases/PHASE_86h_runbook_mapping.yml \
  --check      # dry run, exits non-zero if any URL needs fixing
```

### Step 5 — Run the fixer and commit

Run `python3 scripts/fix_runbook_urls.py`. Commit the resulting rule file changes together with the script and mapping file.

### Step 6 — Fix the capacity calculator

`scripts/capacity_calculator.py`:

- On start, read `docs/performance/benchmarks.md`. Detect `_(measure)_` placeholder markers in the "Go Proxy Benchmarks" section.
- If placeholders are present: print a loud multi-line warning to stderr before the report, then continue with the hardcoded estimates. The report output includes an **"ESTIMATED — NOT MEASURED"** banner in its header.
- Add a `--require-measured` CLI flag. If passed and placeholders are present, exit non-zero with an error message directing the operator to run `make bench` first.
- The hardcoded `BenchmarkConstants` are renamed `EstimatedConstants` and the comment rewritten to reflect that they are engineering estimates, not measurements.

Phase 86i will replace the estimates with real measurements and remove the warning path.

### Step 7 — Add guard tests (see Test strategy)

### Step 8 — Phase close-out

Update `CHANGELOG.md`, `docs/phases/manifest.yaml`, `docs/reference/REDIS_SCHEMA.md` (no new keys — confirm), run `make sync`, write `PHASE_86h_notes.md`, commit atomically.

---

## Test strategy

### Unit tests

**`tests/unit/test_phase_86h_runbook_urls.py`** — new:
- `test_no_dead_example_com_urls_in_rules`: walks all `monitoring/alertmanager/rules/*.yml`, asserts no occurrence of `docs.ja4proxy.example.com`.
- `test_no_wrong_owner_github_urls_in_rules`: asserts no occurrence of `github.com/seanoriordain` or `github.com/seanpor/ja4proxy` (lowercase) — both are dead.
- `test_all_runbook_urls_are_absolute_github`: asserts every `runbook_url:` in the rules directory starts with `https://github.com/seanpor/JA4proxy/blob/main/docs/runbooks/`.
- `test_all_runbook_urls_point_to_existing_files`: parses every `runbook_url`, converts to a local path, asserts the file exists in `docs/runbooks/`.
- `test_runbook_mapping_covers_every_alert`: loads `PHASE_86h_runbook_mapping.yml`, loads every alert name from rule files, asserts every alert has a mapping entry.
- `test_fix_runbook_urls_idempotent`: runs the fixer twice in a tmpdir, asserts second run makes no changes.
- `test_fix_runbook_urls_check_mode_exits_nonzero_when_dirty`: runs `--check` against a rule file with a dead URL, asserts exit code 1.
- `test_fix_runbook_urls_check_mode_exits_zero_when_clean`: runs `--check` against a clean rule file, asserts exit code 0.

**`tests/unit/test_phase_86h_capacity_calculator.py`** — new:
- `test_warning_printed_when_benchmarks_contain_placeholders`: runs the calculator with a placeholder benchmarks.md, captures stderr, asserts warning present.
- `test_report_contains_estimated_banner_when_placeholders_present`: captures stdout, asserts "ESTIMATED — NOT MEASURED" appears in the header.
- `test_require_measured_flag_errors_on_placeholders`: runs with `--require-measured`, asserts non-zero exit and clear error message.
- `test_require_measured_flag_succeeds_on_real_numbers`: writes a benchmarks.md with no placeholders, asserts `--require-measured` run exits 0.
- `test_calculator_still_runs_without_flag_when_placeholders_present`: regression — calculator should not be *broken* by this change, only loud.

### Integration tests

**`tests/integration/test_alertmanager_runbook_urls.py`** — new:
- `test_promtool_check_rules_all_files`: shells out to `promtool check rules monitoring/alertmanager/rules/*.yml`, asserts zero errors. Catches YAML syntax regressions from the script rewrite.
- `test_every_url_resolves_to_real_file`: redundant with unit test but runs against real on-disk files as a sanity check.

### Lint/validation

- `make lint-phases` must still exit 0 after the phase close.
- `scripts/fix_runbook_urls.py --check` added to `make lint` (or a new target `make lint-alert-urls`).

### Not testing

- Alert rule *semantics* are untouched. No tests for alert conditions, thresholds, `for` durations.
- Runbook *content* quality is not tested — stubs are explicitly allowed.

---

## Acceptance criteria

- [ ] `grep -r 'docs.ja4proxy.example.com' monitoring/alertmanager/rules/` returns zero hits.
- [ ] `grep -r 'seanoriordain\|seanpor/ja4proxy' monitoring/alertmanager/rules/` returns zero hits (wrong owner / wrong case).
- [ ] Every `runbook_url:` across all rule files uses the format `https://github.com/seanpor/JA4proxy/blob/main/docs/runbooks/<file>.md`.
- [ ] Every `runbook_url:` resolves to a file that exists in `docs/runbooks/` (verified by test).
- [ ] `docs/phases/PHASE_86h_runbook_mapping.yml` exists and covers every alert in every rule file.
- [ ] `scripts/fix_runbook_urls.py` exists, is idempotent, and has a `--check` mode that works for CI.
- [ ] Capacity calculator prints a loud `ESTIMATED — NOT MEASURED` warning + banner when benchmarks contain placeholders.
- [ ] Capacity calculator `--require-measured` flag exits non-zero when placeholders present.
- [ ] Hardcoded `BenchmarkConstants` renamed to `EstimatedConstants` with updated comment.
- [ ] All new unit tests pass.
- [ ] All new integration tests pass.
- [ ] `make test` passes with zero failures, zero warnings.
- [ ] `make lint-phases` exits 0.
- [ ] `CHANGELOG.md` has a Phase 86h entry.
- [ ] `docs/phases/manifest.yaml` updated: `86h` status `COMPLETE`.
- [ ] `PHASE_86h_notes.md` written.
- [ ] Branch pushed to `claude/phase-86h-fixup`.

---

## Out of scope

- Refactoring Datadog or Dynatrace integrations (Phase 86i).
- Running the benchmark suite or populating real numbers in `benchmarks.md` (Phase 86i).
- Grafana capacity dashboard (Phase 86i).
- Load test scenario rewrite (Phase 86i).
- Writing full content for runbook stubs created in Step 3 — they are explicitly marked STUB.
- Changes to alert conditions, thresholds, or `for` durations — only `runbook_url:` annotations are edited.
- Cleanup of any other `example.com` references outside `monitoring/alertmanager/rules/`.

---

## Risk & rollback

- **Risk:** `fix_runbook_urls.py` corrupts a YAML file. **Mitigation:** integration test runs `promtool check rules` on every file post-rewrite. Rollback is `git revert` on the single commit that ran the fixer.
- **Risk:** A mapping entry points to a runbook file that doesn't exist because Step 3 was skipped. **Mitigation:** unit test `test_all_runbook_urls_point_to_existing_files` runs before the commit that modifies rule files.
- **Risk:** `EstimatedConstants` rename breaks an import elsewhere. **Mitigation:** `grep -r 'BenchmarkConstants' .` before the rename; update all references atomically.
