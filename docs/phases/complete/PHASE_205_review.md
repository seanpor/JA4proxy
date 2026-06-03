# Phase 205 — Repository Root Cleanup & File Organisation — Critical Review

**Reviewed:** 2026-04-14 (updated; supersedes 2026-04-13 review)
**Target:** Python + Go (repo-wide, no runtime code changes)
**Phase doc:** `docs/phases/complete/PHASE_205.md`
**Branch:** `claude/phase-205-repo-root-cleanup`

---

## Step 1 — Progress Since Initial Review

Most of 205b–205e has already landed on the branch:

| Sub-phase | Status | Evidence |
|-----------|--------|----------|
| 205a — gitignore / transient file cleanup | **DONE** | `.gitignore` covers `.coverage`, `bin/`, `.venv*/`, `test_results_*.txt`, `.hypothesis/`, `node_modules/`, `.local/`, `test-results/`; transient files deleted |
| 205b — deploy dir moves | **DONE** | `docker/` → `deploy/docker/`, `monitoring/` → `deploy/monitoring/`, `ha-config/` → `deploy/haproxy/`, `integrations/` → `deploy/integrations/`, `secrets/` → `deploy/secrets/`, `ssl/` → `deploy/ssl/`, `Dockerfile-cli` → `deploy/docker/`, `Jenkinsfile.*` → `deploy/jenkins/` |
| 205c — source moves | **DONE** | `tarpit/` → `src/tarpit/`, `ebpf/` → `src/ebpf/`, `memory/` → `src/memory/` |
| 205d — test/data moves | **DONE** | `performance/` → `tests/performance/`, `test-content/` → `tests/fixtures/`, `geoip/` → `data/geoip/`, `reports/` → `docs/reports/` |
| 205e — doc/script moves | **DONE** | `ONBOARDING.md`, `QWEN.md`, `quick-start.sh` relocated |
| 205f — Python config consolidation | **PARTIAL** | `mypy.ini` + `.flake8` merged into `pyproject.toml` (commit 98020e3). `requirements*.txt` × 3 still at root — not yet migrated to `[project.optional-dependencies]` |
| 205g — terraform-provider decision | **DONE** | Moved under `deploy/` (no longer at root) |
| 205h — reference sweep + test pass | **DONE** | 2687-test suite green; compose context paths fixed; workflow pinning allowlist restored |

### Current root inventory (git ls-tree HEAD)

- **42 tracked** entries (target ≤ 20)
- **26 visible** (non-dot) — target ≤ 14
- **16 dotfiles** (hidden on GitHub, not counted against UX target)

### What remains at root

Visible offenders against the "≤14 visible" goal:

1. `security/` — contains `security/validation.py` (imported by 4 test files) and `security/policies/security-policy.md` (docs)
2. `requirements.txt`, `requirements-analytics.txt`, `requirements-test.txt` — 3 files
3. `CONTRIBUTING.md`, `SECURITY.md`, `AGENTS.md` — GitHub/Claude conventions allow these in `docs/` or `.github/`
4. `.gitlab-ci/` — audit whether still in use
5. `data/` — new top-level directory created by 205d; arguably correct, but increases count

Remaining non-movable (baseline): `README.md`, `LICENSE`, `CHANGELOG.md`, `CLAUDE.md`, `Makefile`, `go.mod`, `go.sum`, `proxy.py`, `pyproject.toml`, plus 10 source/deploy dirs (`cmd config deploy docs internal management scripts src tests` + `data`) = **19 visible at floor**.

> **The "≤14 visible" target in PHASE_205.md is unachievable without merging or deleting architectural directories.** Either revise the acceptance criterion, or drop `data/` back into `tests/fixtures/` and `src/` (for GeoIP mmap files) and remove one more top-level.

---

## Step 2 — Critical Review of Remaining Work (Six Lenses)

### 2a. Security Review

1. **HIGH — `security/validation.py` move risk.** The file exposes
   `SecurityError`, `SecurityValidator`, `ValidationError`, `MTLSManager`,
   `SecureHeadersManager`, `AuditLogger`. It is imported from
   `tests/security/test_owasp_top10.py`, `tests/compliance/gdpr_validator.py`,
   `tests/unit/test_security_validation.py`, `tests/fuzz/test_properties.py`
   as `from security.validation import …`. Moving to `src/security/validation.py`
   must update all 9 import sites atomically.
   - **No collision** confirmed: `src/security/` does not currently contain
     `validation.py`.
   - Check `pyproject.toml [tool.mypy].overrides` already lists
     `"security.validation"` — that must change to `"src.security.validation"`
     (or be removed if typing has since been fixed).

2. **LOW — `secrets/` → `deploy/secrets/` (already done).** Verify no new
   code paths hardcode `/app/secrets/` vs `/app/deploy/secrets/` inside
   container images. Current compose uses `file: ../secrets/*.txt` which
   correctly resolves to `deploy/secrets/` — OK.

3. **INFO — `requirements*.txt` migration.** Moving dependency pins into
   `pyproject.toml` changes how `pip-audit` and Dependabot discover them.
   Confirm Dependabot config (`.github/dependabot.yml`) scans pyproject.toml
   `[project.optional-dependencies]` tables.

### 2b. DevOps Review

1. **MEDIUM — `requirements-*.txt` are referenced by Dockerfiles, CI, and docs.**
   Before consolidating into `pyproject.toml`:
   - `grep -rn 'requirements[-._].*\.txt'` across `deploy/docker/`, `.github/`,
     `scripts/`, `Makefile`, `management/`.
   - Any `pip install -r requirements-test.txt` call must become
     `pip install -e '.[test]'` — and the base package must be installable
     (requires `[project]` table with `name`, `version`, `dependencies`).
   - Current `pyproject.toml` has **no `[project]` table** — only tool config.
     Adding a full `[project]` table is a non-trivial precursor and may break
     `pip install -e .` in CI if any `requires = […]` list references deps
     that have moved or been renamed.

2. **LOW — `.gitlab-ci/` still at root.** If the project uses only GitHub
   Actions now, remove it. If both CI systems are active, keep it.
   Phase 205 doc flags this as "audit first" — do the audit.

### 2c. SRE Review

1. **No observability impact.** Pure file-move phase. No new metrics, no
   failure modes, no SLI/SLO changes.

2. **LOW — Runbook references.** `docs/runbooks/` may still reference
   `docker/docker-compose.*.yml` paths. Sweep before closing:
   `grep -rn '\bdocker/docker-compose' docs/runbooks/`.

### 2d. Architecture Review

1. **MEDIUM — `data/geoip/` introduces a new top-level directory.** Phase
   205's stated goal is fewer root entries, yet 205d created `data/`. Options:
   - Keep `data/` (justifiable: MaxMind mmap files aren't source, tests, or
     deployment) — but then update PHASE_205.md acceptance criterion.
   - Move to `src/geoip_data/` or `tests/fixtures/geoip/` (test-only data).
   - The GeoIP mmap is loaded at runtime by `src/security/asn_classifier.py` —
     confirm the path it reads; update code if moved.

2. **LOW — `src/memory/` placement.** 205c moved `memory/` into `src/`. Check
   whether any content here is actually imported. If unused (historical
   artefact), delete entirely rather than hide in `src/`.

### 2e. Testing Review

1. **HIGH — Test suite must run green before marking COMPLETE.** The context
   summary claims 2687 pass — but also mentions "8 pre-existing failures in
   servicenow/splunk tests that require `deploy/__init__.py`". **Those 8
   failures were introduced by 205b** (moving `integrations/` to
   `deploy/integrations/` without an `__init__.py`). They are not
   "pre-existing" — they are regressions from this phase and must be fixed
   before close.
   - **Fix:** add `deploy/__init__.py` and `deploy/integrations/__init__.py`,
     or update test imports to use the new path, or add `deploy` to
     `sys.path` via conftest.

2. **MEDIUM — `tests/unit/test_alertmanager_runbook_urls.py` (and siblings)
   hardcode `deploy/monitoring/alertmanager/rules`.** Spot-check confirms
   this was already updated. No regression here.

3. **LOW — Parametrize coverage for moved fixtures.** Any test that does
   `Path(__file__).parent.parent.parent / "geoip"` or `/ "test-content"`
   will silently return an empty glob after the move. Run `make test` with
   `-W error::DeprecationWarning` to catch missing-file paths that currently
   just skip.

### 2f. Documentation Review

1. **HIGH — CHANGELOG entry missing.** Required by CLAUDE.md phase-close
   gate. Must describe the moves, the consolidated `pyproject.toml` tool
   config, and any revised acceptance criterion.

2. **HIGH — `docs/phases/manifest.yaml` still says `status: PROPOSED`.**
   Must become `COMPLETE` once tests + docs close out.

3. **MEDIUM — README.md navigation references.** Links to
   `./docker/...`, `./monitoring/...`, `./ONBOARDING.md` must all be
   re-checked post-move. Run:
   ```
   awk '/\]\([^)]*\)/{print FILENAME":"NR": "$0}' README.md | grep -v http
   ```
   Then verify each path exists.

4. **LOW — ADR for `data/` decision.** If `data/` stays, write a 1-page
   ADR explaining why it's a distinct top-level directory rather than under
   `src/` or `deploy/`.

---

## Step 3 — Risk Summary

| # | Finding | Severity | Lens | Recommendation |
|---|---------|----------|------|----------------|
| 1 | 8 servicenow/splunk test failures from `deploy/integrations/` missing `__init__.py` — framed as "pre-existing" but caused by 205b | **HIGH** | Testing | Add `deploy/__init__.py` + `deploy/integrations/__init__.py` OR fix test imports before marking COMPLETE |
| 2 | `pyproject.toml` has no `[project]` table — blocks `[project.optional-dependencies]` consolidation (205f remaining half) | MEDIUM | DevOps | Either defer 205f to a follow-up phase, or add a minimal `[project]` table and pin the install-from-pyproject path in CI |
| 3 | `security/validation.py` imported by 4 test files — move must update all at once | HIGH | Security | Single commit: move file + update all `from security.validation` → `from src.security.validation` + update mypy override |
| 4 | "≤14 visible on GitHub" criterion is numerically unachievable given Go/Python conventions | MEDIUM | Architecture | Revise PHASE_205.md acceptance criterion to ≤20 visible, OR delete/merge `data/`, `.gitlab-ci/` to claw back entries |
| 5 | `requirements*.txt` referenced by Dockerfiles, CI, docs | MEDIUM | DevOps | Sweep `grep -rn 'requirements.*\.txt'` before migrating; update atomically |
| 6 | `docs/runbooks/` may still contain old `docker/docker-compose.*` paths | LOW | SRE | `grep -rn '\bdocker/docker-compose' docs/runbooks/` + fix |
| 7 | Dependabot scans may miss `[project.optional-dependencies]` tables | LOW | Security | Verify `.github/dependabot.yml` after 205f |
| 8 | `data/` is a new top-level dir, undercuts the phase goal | LOW | Architecture | Write a 1-page ADR OR relocate |
| 9 | `src/memory/` content may be dead code | LOW | Architecture | `grep -rn 'from memory\|from src\.memory\|import memory'` — delete if unused |
| 10 | `.gitlab-ci/` may be abandoned | LOW | DevOps | Audit; delete or keep with a note |
| 11 | GeoIP mmap path used by `src/security/asn_classifier.py` may still point at `geoip/` | MEDIUM | Architecture | `grep -rn 'geoip/' src/ cmd/ internal/` — verify runtime paths |
| 12 | `CONTRIBUTING.md`, `SECURITY.md`, `AGENTS.md` at root — could move to `docs/` with `.github/` symlinks | LOW | Documentation | Low payoff; only do if chasing visible count |

---

## Step 4 — Junior-Engineer Sub-Task Decomposition for Remaining Work

These sub-tasks close Phase 205. All are small and independent unless noted.

### Sub-task 205-X1: Fix `deploy/integrations/` import regression
**Size:** XS (30 min)
**Depends on:** none
**Parallel with:** X2, X3, X4, X5
**Files to touch:**
- Create `deploy/__init__.py` (empty) OR delete if tests can use a different mechanism
- Create `deploy/integrations/__init__.py` (empty)
- Or alternatively, update failing test imports
**What to do:**
- Run `python3 -m pytest tests/ -x -k "servicenow or splunk" 2>&1 | head -40`
- Identify the 8 failing tests and their exact `ImportError` messages
- Add the minimum `__init__.py` files to make the import path resolve
- Re-run; confirm 0 failures
**Done when:**
- [ ] `python3 -m pytest tests/ -k "servicenow or splunk"` → 0 failures
- [ ] No other test regresses
**Watch out for:** Adding `deploy/__init__.py` can make mypy treat `deploy/` as a package — check mypy still passes.

### Sub-task 205-X2: Move `security/validation.py` → `src/security/validation.py`
**Size:** S (1 h)
**Depends on:** none
**Parallel with:** X1, X3, X4
**Files to touch:**
- `git mv security/validation.py src/security/validation.py`
- `tests/security/test_owasp_top10.py` (4 import sites)
- `tests/compliance/gdpr_validator.py` (2 import sites)
- `tests/unit/test_security_validation.py` (1 import block)
- `tests/fuzz/test_properties.py` (1 import site)
- `pyproject.toml` — update `[[tool.mypy.overrides]]` module list: `"security.validation"` → `"src.security.validation"`
**What to do:**
- Confirm no name collision: `ls src/security/validation.py` must fail before the move
- Move the file
- Bulk-update imports: `from security.validation import` → `from src.security.validation import`
- Run `make test-unit` (or the appropriate fast target)
**Done when:**
- [ ] `security/validation.py` no longer exists
- [ ] `python3 -c "from src.security.validation import SecurityValidator"` succeeds
- [ ] All 9 import sites updated
- [ ] mypy override list updated
- [ ] Unit + security test suites pass
**Watch out for:** The mypy override list also contains `"proxy"` and `"src.security.rdap_enrichment"` etc — don't accidentally edit unrelated entries.

### Sub-task 205-X3: Move `security/policies/` → `docs/security/policies/`
**Size:** XS (15 min)
**Depends on:** X2 (so `security/` can be deleted cleanly)
**Parallel with:** X1, X4, X5
**Files to touch:**
- `git mv security/policies docs/security/policies`
- `rmdir security` (should be empty after X2 + this)
- Any link references: `grep -rn 'security/policies' .` (excluding `.claude/worktrees`)
**Done when:**
- [ ] `security/` directory no longer tracked
- [ ] `docs/security/policies/security-policy.md` exists
- [ ] No dangling markdown links

### Sub-task 205-X4: Audit `.gitlab-ci/` usage
**Size:** XS (15 min)
**Depends on:** none
**Parallel with:** X1, X2, X3, X5
**Files to touch:** possibly delete `.gitlab-ci/` tree, or leave as-is
**What to do:**
- Check commit history: `git log -- .gitlab-ci/ | head`
- Ask: is there an active GitLab mirror?
- If dead: `git rm -r .gitlab-ci/`
- If live: leave + document in `docs/CI.md`
**Done when:** decision documented in `PHASE_205_notes.md`

### Sub-task 205-X5: Audit `src/memory/` for dead code
**Size:** XS (15 min)
**Depends on:** none
**Parallel with:** X1–X4
**Files to touch:** possibly delete `src/memory/`
**What to do:**
- `grep -rn 'from memory\|from src\.memory\|import memory' --include="*.py" src/ cmd/ internal/ tests/ proxy.py management/`
- If no imports: `git rm -r src/memory/`
- If imports exist: leave in place
**Done when:** decision documented; no dead directory

### Sub-task 205-X6: Revise unachievable acceptance criterion
**Size:** XS (15 min)
**Depends on:** none
**Parallel with:** all
**Files to touch:** `docs/phases/complete/PHASE_205.md`
**What to do:**
- Change "≤14 visible on GitHub" to "≤20 visible on GitHub" (realistic for Go+Python repo)
- Add a sentence explaining why `data/`, `management/`, and `proxy.py` stay visible
- Or alternatively: delete `data/` (move contents to `src/`/`tests/fixtures/`) to hit a lower number honestly
**Done when:**
- [ ] Acceptance criterion is numerically achievable
- [ ] Rationale documented inline

### Sub-task 205-X7: Sweep runbooks and README for stale paths
**Size:** S (45 min)
**Depends on:** X2, X3 complete (otherwise creates rework)
**Parallel with:** X4, X5, X6
**Files to touch:** `README.md`, `docs/runbooks/*.md`, `docs/*.md`
**What to do:**
- `grep -rn '\bdocker/docker-compose\|^\./docker/\|\bha-config/\|\bmonitoring/\b\|^\./security/\|^\./geoip/\|^\./integrations/\|^\./tarpit/\|^\./ebpf/' docs/ README.md`
- Update each match to the new path
- Verify markdown links resolve: `make lint-md` or `markdown-link-check README.md`
**Done when:**
- [ ] `grep` for old paths in docs returns zero hits
- [ ] `make lint-md` passes (if target exists)

### Sub-task 205-X8 (DROPPED from scope): Consolidate `requirements*.txt`
**Status:** rejected — cosmetic win (25 → 22 visible) did not justify atomic rewrites across Dockerfiles/CI/Makefile/Dependabot. `pip install -r requirements.txt` is idiomatic Python.
**Size:** M (2–3 h) — originally proposed as Phase 206, now dropped
**Depends on:** X1–X7 stable
**Parallel with:** none (touches many CI files)
**Files to touch:** `pyproject.toml`, all Dockerfiles in `deploy/docker/`, `.github/workflows/*.yml`, `Makefile`, `scripts/*.sh`
**What to do:**
- Add minimal `[project]` table to `pyproject.toml` with `name = "ja4proxy"`, `version = …`, `requires-python = ">=3.14"`
- Move `requirements.txt` contents → `[project.dependencies]`
- Move `requirements-test.txt` → `[project.optional-dependencies.test]`
- Move `requirements-analytics.txt` → `[project.optional-dependencies.analytics]`
- Replace `pip install -r requirements-test.txt` → `pip install -e '.[test]'` everywhere
- `git rm requirements*.txt`
- Update Dependabot config to scan pyproject.toml
**Done when:**
- [ ] `pip install -e '.[test,analytics]'` works in a fresh venv
- [ ] All Dockerfile builds pass
- [ ] All CI workflows pass
- [ ] Dependabot PRs continue to arrive for pyproject deps
**Watch out for:** N/A — dropped from scope.

### Sub-task 205-X9: Phase-close ceremony
**Size:** XS (30 min)
**Depends on:** X1–X7 (X8 optional)
**Parallel with:** none
**Files to touch:** `CHANGELOG.md`, `docs/phases/manifest.yaml`, run `make sync`
**What to do:**
- Prepend CHANGELOG entry describing the moves, consolidation, and deferred X8 if applicable
- Mark `manifest.yaml` phase 205 → `status: COMPLETE`
- `make sync` to regenerate `TODO.md` + `PROJECT_STATUS.md`
- Atomic commit of all four files
- Push branch; **do not merge to main** (orchestrator handles merge per CLAUDE.md)
**Done when:**
- [ ] `git status` clean
- [ ] `manifest.yaml` shows COMPLETE
- [ ] Branch pushed to origin

---

## Summary

- **Sub-tasks remaining:** 9 (8 required + 1 optional/deferrable)
- **Estimated effort:** ~4–5 hours for required; +3 h for optional X8
- **Critical blockers before COMPLETE:** X1 (test regression), X6 (revise criterion), X9 (close ceremony)
- **Dropped:** X8 (requirements consolidation) — cosmetic-only, not worth the blast radius

The phase is ~85% done. The remaining work is cleanup plus one genuine regression (the 8 failing integration tests). Do NOT mark the phase complete until X1 is fixed — calling it "pre-existing" is incorrect.
