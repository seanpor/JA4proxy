# Phase 205 — Repository Root Cleanup & File Organisation — Critical Review

**Reviewed:** 2026-04-13
**Target:** Python + Go (repo-wide, no runtime code changes)
**Phase doc:** `docs/phases/PHASE_205.md`

---

## Step 2 — Critical Review (Six Lenses)

### 2a. Security Review

1. **CRITICAL — `.config/` proposal will break tool auto-discovery.** The phase
   proposes moving 10 linter dotfiles into `.config/`. In practice, only 2 tools
   (golangci-lint, yamllint) already use explicit `--config` flags. The remaining 8
   tools auto-discover from CWD:
   - `.goreleaser.yml` — goreleaser expects it at root; no `--config` flag in CI
   - `.luacheckrc` — luacheck discovers from CWD only
   - `.mlc.json` — markdown-link-check has no `--config`
   - `.gitleaks.toml` — CWD auto-discovery (but `--config` works)
   - `.hadolint.yaml` — CWD auto-discovery (but `--config` works)
   - `.flake8` — CWD auto-discovery; **can merge into `pyproject.toml`** instead
   - `mypy.ini` — CWD auto-discovery; **can merge into `pyproject.toml`** instead
   - `.bandit` — this is actually a **Python script**, not a config file. It provides
     `get_skips()` — it's not a linter config at all. Moving it would be misleading.

   **Recommendation:** Drop the `.config/` directory idea entirely. Instead:
   - Merge `.flake8` and `mypy.ini` into `pyproject.toml` (removes 2 entries)
   - Leave the remaining 8 dotfiles at root (they're already hidden on GitHub)
   - Dotfiles don't count toward GitHub's visible file listing anyway

2. **LOW — `secrets/` directory contains placeholder files.** The tracked files
   (`.gitkeep`, `README.md`) are safe. The actual secret `.txt` files are untracked
   and gitignored. Moving to `deploy/secrets/` is fine. The docker-compose files
   reference `secrets/` in 82 places — all must be updated atomically.

3. **INFO — No runtime code changes.** This is a pure refactoring phase. No new
   attack surfaces, no input validation changes, no credential handling changes.

### 2b. DevOps Review

1. **HIGH — `docker/` has 868 references across the repo.** This is by far the
   highest-risk move. The references span:
   - `Makefile` (59 refs)
   - `docker/README.md` (24 self-refs)
   - Phase docs (171 refs in PHASE_89 alone)
   - Test files (`test_docker_consistency.py`, `test_dockerfile_coverage.py`)
   - CI workflows, runbooks, deployment docs
   
   Moving `docker/` → `deploy/docker/` is the single highest-risk operation. However,
   `deploy/` already exists and contains Helm, Ansible, Terraform, etc. The move is
   architecturally correct — it's just mechanically risky.

2. **MEDIUM — `monitoring/` has 279 references.** Many are in
   `docs/OBSERVABILITY_STANDARDS.md` which specifies alert rule paths like
   `monitoring/alertmanager/rules/`. Moving to `deploy/monitoring/` requires updating
   the observability standards doc, all alert rule references, and Grafana
   provisioning paths.

3. **LOW — Rollback is clean.** All changes are `git mv` + reference updates.
   `git revert` of the merge commit cleanly undoes everything. No data migration.

4. **INFO — Docker build contexts.** `.dockerignore` may reference paths that change.
   Verify Dockerfile `COPY` instructions still work after moves.

### 2c. SRE Review

1. **INFO — No observability changes.** This phase adds no metrics, alerts, or log
   changes. The only observability concern is that `monitoring/alertmanager/rules/`
   paths referenced in `OBSERVABILITY_STANDARDS.md` must be updated to
   `deploy/monitoring/alertmanager/rules/`.

2. **INFO — No failure mode changes.** Pure file reorganisation.

3. **LOW — CI pipeline may break.** GitHub Actions workflows in `.github/workflows/`
   may reference `docker/`, `monitoring/`, `ssl/` paths. These must be updated in
   the same commit as the moves.

### 2d. Architecture Review

1. **MEDIUM — `CONTRIBUTING.md` and `SECURITY.md` proposed move is partially wrong.**
   The phase doc proposes moving these to `docs/`. GitHub *does* auto-discover them
   from `docs/` — but it's a well-established convention to keep them at root. The
   cost of keeping them (2 files) is negligible versus the confusion of moving them.
   **Recommendation:** Keep `CONTRIBUTING.md` and `SECURITY.md` at root. Don't move
   `AGENTS.md` either — `CLAUDE.md` references it by relative path.

2. **MEDIUM — The `.config/` consolidation doesn't work.** As detailed in 2a.
   Dotfiles are already hidden on GitHub (the `.*` pattern). Moving them gains
   nothing visible and breaks tool discovery. The phase doc's own caveat
   ("If a tool cannot read from `.config/`, leave its dotfile at root") would
   result in most files staying put anyway.

3. **LOW — `terraform-provider/` is a Go module with its own `go.mod`.** It's
   effectively a separate project. Moving it under `deploy/` mixes concerns.
   Better to leave it at root or document it as a reference to the separate repo.

4. **INFO — `deploy/` already has 8 subdirectories.** Adding `docker/`, `monitoring/`,
   `haproxy/`, `ssl/`, `secrets/`, `integrations/`, `jenkins/` would bring it to 15.
   That's fine — it consolidates deployment concerns correctly.

### 2e. Testing Review

1. **HIGH — `tests/unit/test_docker_consistency.py` hardcodes `docker/` paths.**
   19 references. This test validates Docker Compose file consistency — it must be
   updated to use the new paths, and the test itself must pass after the move.

2. **MEDIUM — `tests/integration/test_dockerfile_coverage.py`** has 12 references
   to `docker/` paths. Same concern.

3. **INFO — No new test categories needed.** The acceptance criteria are:
   - `make test` passes (existing tests, updated paths)
   - `make lint-all` passes
   - `git ls-tree --name-only HEAD | wc -l` shows reduction
   - No dangling path references (`git grep` for old paths returns 0)

4. **INFO — `test-content/` has 0 references.** Safe to move to `tests/fixtures/`.

### 2f. Documentation Review

1. **HIGH — Massive doc update required.** The reference counts:
   - `docker/`: 868 references (many in phase docs, runbooks, deployment guides)
   - `monitoring/`: 279 references (observability standards, setup guides)
   - `ssl/`: 67 references
   - `secrets/`: 82 references
   - `performance/`: 120 references

   Phase docs are the bulk of these. Many are in historical documents (completed
   phases) where the paths will be permanently wrong unless updated. The question
   is: **do we update historical phase docs?** They describe what was true at the
   time. Recommendation: update docs that are operational references (runbooks,
   standards, READMEs), leave historical phase docs as-is but add a note at the top
   of PHASE_205 noting the path changes.

2. **MEDIUM — CHANGELOG entry needed.** Standard format.

3. **LOW — ADR recommended.** The decision to consolidate under `deploy/` and the
   decision to *not* use `.config/` should be recorded. ADR-205.

4. **INFO — No Redis schema changes.** No runbook changes (paths in runbooks do
   need updating though).

---

## Step 3 — Risk Summary

| # | Finding | Severity | Lens | Recommendation |
|---|---------|----------|------|----------------|
| 1 | `.config/` consolidation breaks 6+ tools that auto-discover from CWD | CRITICAL | Architecture | Drop `.config/` entirely; merge `.flake8` + `mypy.ini` into `pyproject.toml`; leave other dotfiles at root (they're hidden on GitHub anyway) |
| 2 | `docker/` move has 868 references — highest mechanical risk | HIGH | DevOps | Use `git mv` + automated `sed` in one atomic commit; verify CI workflows |
| 3 | `monitoring/` move requires updating `OBSERVABILITY_STANDARDS.md` paths | HIGH | Documentation | Update standards doc atomically with the move |
| 4 | `test_docker_consistency.py` hardcodes 19 `docker/` paths | HIGH | Testing | Update test file in same commit as move |
| 5 | Moving `CONTRIBUTING.md`/`SECURITY.md` to `docs/` — unnecessary churn | MEDIUM | Architecture | Keep at root — GitHub convention, negligible cost, 2 files |
| 6 | Historical phase docs contain old paths (hundreds of refs) | MEDIUM | Documentation | Update operational docs only; leave phase history as-is |
| 7 | `terraform-provider/` has own `go.mod` — doesn't belong under `deploy/` | MEDIUM | Architecture | Leave at root or remove (if separate repo is canonical) |
| 8 | `.bandit` is a Python script, not a config file — mislabelled in audit | LOW | Security | Leave at root; it's imported by Makefile lint targets |
| 9 | Docker build context (`COPY` paths in Dockerfiles) may break | LOW | DevOps | Verify all Dockerfile `COPY`/`ADD` instructions after moves |
| 10 | No untracked files found — gitignore cleanup (205a) may be a no-op | INFO | DevOps | Verify; delete any transient files if they reappear |

---

## Step 4 — Decompose into Junior-Engineer Sub-Tasks

### Phase 1: Scaffolding

#### Sub-task 1.1: Audit and confirm current root state
**Size:** XS (~30 min)
**Depends on:** none
**Parallel with:** none
**Files to touch:** none (read-only)
**What to do:**
- Run `git ls-tree --name-only HEAD | wc -l` and confirm 61 tracked entries
- Run `git ls-files --others --exclude-standard` and confirm zero untracked files
- Verify `.gitignore` already covers all cache/build artifacts
- Document any gaps found
**Done when:**
- [ ] Root entry count confirmed
- [ ] Untracked file status confirmed
- [ ] `.gitignore` gaps (if any) documented
**Watch out for:** The phase doc claims 12 untracked files but current gitignore is comprehensive — may already be clean

#### Sub-task 1.2: Merge `.flake8` and `mypy.ini` into `pyproject.toml`
**Size:** XS (~30 min)
**Depends on:** none
**Parallel with:** 1.1
**Files to touch:** `pyproject.toml`, `.flake8`, `mypy.ini`
**What to do:**
- Read `.flake8` contents: `max-line-length = 88`, `extend-ignore = E203,W503,E501,E402,F841`
- Add `[tool.flake8]` section to `pyproject.toml` with same settings
- Read `mypy.ini` contents and add `[tool.mypy]` section to `pyproject.toml`
- Delete `.flake8` and `mypy.ini`
- Verify: `make lint-static` still passes (mypy, flake8 pick up from pyproject.toml)
**Done when:**
- [ ] `.flake8` deleted, settings in `pyproject.toml`
- [ ] `mypy.ini` deleted, settings in `pyproject.toml`
- [ ] `make lint-static` passes
**Watch out for:** flake8 does NOT read from `pyproject.toml` natively — needs `flake8-pyproject` plugin or use `Flake8-pyproject`. If this is blocked, leave `.flake8` at root and only merge `mypy.ini`. Note: ruff may have replaced flake8 entirely — check if flake8 is still used.

#### Sub-task 1.3: Consolidate `requirements-*.txt` into `pyproject.toml`
**Size:** S (~1 hr)
**Depends on:** none
**Parallel with:** 1.1, 1.2
**Files to touch:** `pyproject.toml`, `requirements.txt`, `requirements-test.txt`, `requirements-analytics.txt`, `Makefile`
**What to do:**
- Read all three requirements files
- Add `[project.dependencies]` and `[project.optional-dependencies]` sections to `pyproject.toml`
- Update `Makefile` targets that reference `pip install -r requirements*.txt`
- Delete the three `.txt` files
- Verify: `pip install -e ".[test]"` works; `make test` passes
**Done when:**
- [ ] All three `requirements*.txt` files deleted
- [ ] Dependencies in `pyproject.toml` under correct groups
- [ ] `make test` passes with new install method
**Watch out for:** Some CI/CD may `pip install -r requirements.txt` directly — check `.github/workflows/` for references

### Phase 2: Core Moves — Low-Risk Directories

#### Sub-task 2.1: Move `test-content/` → `tests/fixtures/content/`
**Size:** XS (~15 min)
**Depends on:** none
**Parallel with:** 2.2, 2.3, 2.4
**Files to touch:** `test-content/`, `tests/fixtures/`
**What to do:**
- `git mv test-content/ tests/fixtures/content/` (or merge into existing `tests/fixtures/`)
- `git grep 'test-content/'` — update any references (currently 0)
**Done when:**
- [ ] `test-content/` no longer exists at root
- [ ] `make test` passes
**Watch out for:** Check if `tests/fixtures/` already exists and has content

#### Sub-task 2.2: Move `performance/` → `tests/performance/`
**Size:** XS (~30 min)
**Depends on:** none
**Parallel with:** 2.1, 2.3, 2.4
**Files to touch:** `performance/`, `tests/`, `Makefile`
**What to do:**
- `git mv performance/ tests/performance/`
- `git grep 'performance/'` — update references (120 refs, mostly in docs)
- Update Makefile targets that reference `performance/`
**Done when:**
- [ ] `performance/` no longer exists at root
- [ ] `git grep 'performance/' | grep -v tests/performance | grep -v docs/phases/PHASE_` returns 0 operational refs
- [ ] `make test` passes
**Watch out for:** Many refs are in historical phase docs — only update operational docs (Makefile, READMEs, runbooks)

#### Sub-task 2.3: Move `geoip/` → `data/geoip/`
**Size:** XS (~30 min)
**Depends on:** none
**Parallel with:** 2.1, 2.2, 2.4
**Files to touch:** `geoip/`, `config/proxy.yml`, source files that reference geoip path
**What to do:**
- Create `data/` directory
- `git mv geoip/ data/geoip/`
- `git grep 'geoip/'` — update references (17 refs)
- Check `config/proxy.yml` for geoip path settings
**Done when:**
- [ ] `geoip/` no longer exists at root
- [ ] All operational references updated
- [ ] `make test` passes
**Watch out for:** Docker volume mounts in compose files may reference `./geoip/`

#### Sub-task 2.4: Move `reports/` → `docs/reports/`
**Size:** XS (~15 min)
**Depends on:** none
**Parallel with:** 2.1, 2.2, 2.3
**Files to touch:** `reports/`
**What to do:**
- Check if `docs/reports/` already exists
- `git mv reports/ docs/reports/` (or merge)
- `git grep 'reports/'` — update references
**Done when:**
- [ ] `reports/` no longer exists at root
- [ ] `make test` passes
**Watch out for:** `docs/reports/` may already exist — check for conflicts

#### Sub-task 2.5: Move `ebpf/` → `src/ebpf/`
**Size:** XS (~15 min)
**Depends on:** none
**Parallel with:** 2.1-2.4
**Files to touch:** `ebpf/`
**What to do:**
- `git mv ebpf/ src/ebpf/`
- `git grep 'ebpf/'` — update references (10 refs)
- Check `ebpf/Makefile` for internal path references
**Done when:**
- [ ] `ebpf/` no longer exists at root
- [ ] All references updated
**Watch out for:** eBPF has its own Makefile — check internal paths

#### Sub-task 2.6: Move `tarpit/` → `src/tarpit/`
**Size:** XS (~30 min)
**Depends on:** none
**Parallel with:** 2.1-2.5
**Files to touch:** `tarpit/`, Docker Compose files
**What to do:**
- `git mv tarpit/ src/tarpit/`
- `git grep 'tarpit/'` — update references (32 refs)
- Update Docker Compose build context for tarpit service
**Done when:**
- [ ] `tarpit/` no longer exists at root
- [ ] Docker Compose tarpit service builds correctly
- [ ] All references updated
**Watch out for:** `tarpit/Dockerfile` build context path changes

#### Sub-task 2.7: Audit and handle `memory/`
**Size:** XS (~15 min)
**Depends on:** none
**Parallel with:** 2.1-2.6
**Files to touch:** `memory/`
**What to do:**
- Contents: `MEMORY.md`, `project_phase_status.md` — these are Claude agent memory files
- Check if referenced anywhere: `git grep 'memory/'` (4 refs)
- This is likely a Claude Code auto-memory directory that leaked to root
- Move to `.claude/memory/` or delete if redundant with `.claude/projects/` memory
**Done when:**
- [ ] `memory/` no longer exists at root or is documented
**Watch out for:** This may be actively used by Claude agents — check before deleting

#### Sub-task 2.8: Move doc files from root
**Size:** XS (~30 min)
**Depends on:** none
**Parallel with:** 2.1-2.7
**Files to touch:** `ONBOARDING.md`, `QWEN.md`, `quick-start.sh`
**What to do:**
- `git mv ONBOARDING.md docs/ONBOARDING.md`
- `git mv QWEN.md .qwen/QWEN.md`
- `git mv quick-start.sh scripts/quick-start.sh`
- Update references in README.md and other docs
**Done when:**
- [ ] All three files moved
- [ ] README links updated
- [ ] `make test` passes
**Watch out for:** README.md likely links to these files by relative path

### Phase 3: Core Moves — High-Risk Directories

#### Sub-task 3.1: Move `ha-config/` → `deploy/haproxy/`
**Size:** XS (~30 min)
**Depends on:** none
**Parallel with:** 3.2
**Files to touch:** `ha-config/`, `Makefile`, `scripts/`
**What to do:**
- `git mv ha-config/ deploy/haproxy/`
- `git grep 'ha-config/'` — update 6 references
- Update Makefile targets and scripts that reference ha-config
**Done when:**
- [ ] `ha-config/` no longer exists at root
- [ ] All 6 references updated
- [ ] `make test` passes
**Watch out for:** `scripts/run-benchmark.sh` and `scripts/scale-proxies.sh` reference this

#### Sub-task 3.2: Move `integrations/` → `deploy/integrations/`
**Size:** S (~1 hr)
**Depends on:** none
**Parallel with:** 3.1
**Files to touch:** `integrations/`, docs, Makefile
**What to do:**
- `git mv integrations/ deploy/integrations/`
- `git grep 'integrations/'` — update 72 references
- Focus on operational docs (runbooks, READMEs, standards)
**Done when:**
- [ ] `integrations/` no longer exists at root
- [ ] All operational references updated
- [ ] `make test` passes
**Watch out for:** Config files in `config/integrations/` are separate — don't confuse with root `integrations/`

#### Sub-task 3.3: Move `ssl/` → `deploy/ssl/`
**Size:** S (~1 hr)
**Depends on:** none
**Parallel with:** 3.1, 3.2
**Files to touch:** `ssl/`, Docker Compose files, `config/enterprise.yml`, docs
**What to do:**
- `git mv ssl/ deploy/ssl/`
- `git grep 'ssl/'` — update 67 references
- Critical: update Docker Compose volume mounts (`./ssl/certs:/etc/ssl/...`)
- Critical: update `config/enterprise.yml` (4 references)
**Done when:**
- [ ] `ssl/` no longer exists at root
- [ ] Docker Compose files updated
- [ ] All 67 operational references updated
- [ ] `make test` passes
**Watch out for:** Docker volume mount paths like `./ssl/certs:/etc/ssl/certs` must be updated to `./deploy/ssl/certs:/etc/ssl/certs`

#### Sub-task 3.4: Move `secrets/` → `deploy/secrets/`
**Size:** S (~1 hr)
**Depends on:** none
**Parallel with:** 3.1-3.3
**Files to touch:** `secrets/`, `.gitignore`, Docker Compose files, docs
**What to do:**
- `git mv secrets/ deploy/secrets/`
- Update `.gitignore` patterns from `secrets/*` to `deploy/secrets/*`
- `git grep 'secrets/'` — update 82 references
- Critical: update Docker Compose `secrets:` section volume mounts
**Done when:**
- [ ] `secrets/` no longer exists at root
- [ ] `.gitignore` updated
- [ ] Docker Compose secrets paths updated
- [ ] `make test` passes
**Watch out for:** `.gitignore` has specific `secrets/*` pattern with `!secrets/.gitkeep` exception — must update both lines

#### Sub-task 3.5: Move `monitoring/` → `deploy/monitoring/`
**Size:** S (~2 hrs)
**Depends on:** none
**Parallel with:** 3.1-3.4
**Files to touch:** `monitoring/`, `docs/OBSERVABILITY_STANDARDS.md`, Docker Compose files, Makefile
**What to do:**
- `git mv monitoring/ deploy/monitoring/`
- `git grep 'monitoring/'` — update 279 references
- **Critical:** update `docs/OBSERVABILITY_STANDARDS.md` §4 alert rule paths
- **Critical:** update `docker/docker-compose.monitoring.yml` volume mounts
- Update Makefile (15 references)
- Update `.yamllint.yaml` if it references monitoring/ paths
**Done when:**
- [ ] `monitoring/` no longer exists at root
- [ ] `OBSERVABILITY_STANDARDS.md` paths updated
- [ ] Docker Compose monitoring file updated
- [ ] All operational references updated
- [ ] `make test` passes
**Watch out for:** This has the second-highest reference count. Focus on operational docs; leave historical phase docs as-is.

#### Sub-task 3.6: Move `docker/` → `deploy/docker/`
**Size:** S (~3 hrs)
**Depends on:** 3.5 (monitoring compose references docker/)
**Parallel with:** none — do this last among the deploy/ moves
**Files to touch:** `docker/`, `Makefile`, `.github/workflows/`, Docker Compose files, docs
**What to do:**
- `git mv docker/ deploy/docker/`
- `git grep 'docker/'` — update references systematically:
  1. `Makefile` (59 refs) — most critical
  2. `.github/workflows/` — CI will break without this
  3. `docker/docker-compose.*.yml` internal references (now at `deploy/docker/`)
  4. `tests/unit/test_docker_consistency.py` (19 refs)
  5. `tests/integration/test_dockerfile_coverage.py` (12 refs)
  6. `docker/README.md` (24 self-refs)
  7. Operational docs (runbooks, deployment guides)
- Move `Dockerfile-cli` → `deploy/docker/Dockerfile.cli`
- Move `Jenkinsfile.ja4proxy-policy` → `deploy/docker/Jenkinsfile` (or `deploy/ci/`)
**Done when:**
- [ ] `docker/` no longer exists at root
- [ ] `Dockerfile-cli` no longer exists at root
- [ ] `Jenkinsfile.ja4proxy-policy` no longer exists at root
- [ ] `make test` passes
- [ ] `make lint-all` passes
- [ ] CI workflows reference correct paths
**Watch out for:** This is the riskiest single operation. The 868 total references include
many in historical phase docs — only update operational references. Test thoroughly.
Docker self-references (`docker/docker-compose.monitoring.yml` references `docker/`)
will need careful handling since they move together.

### Phase 4: Wiring & Verification

#### Sub-task 4.1: Update `.dockerignore`
**Size:** XS (~15 min)
**Depends on:** 3.1-3.6
**Parallel with:** 4.2
**Files to touch:** `.dockerignore`
**What to do:**
- Review `.dockerignore` for paths that changed
- Ensure Docker build contexts still exclude the right directories
- Test a Docker build to verify context is correct
**Done when:**
- [ ] `.dockerignore` references only current paths
- [ ] `docker build` succeeds (at least a dry run)
**Watch out for:** Build context includes everything not in `.dockerignore`

#### Sub-task 4.2: Handle `terraform-provider/`
**Size:** XS (~15 min)
**Depends on:** none
**Parallel with:** 4.1
**Files to touch:** `terraform-provider/`, potentially `deploy/README.md`
**What to do:**
- This is a separate Go module with its own `go.mod` — it's effectively a sub-project
- **Decision:** Leave at root (it has its own module path) OR move under `deploy/`
- If the separate repo `terraform-provider-ja4proxy` is canonical, remove from here
  and add a pointer in `deploy/README.md`
- Document decision in commit message
**Done when:**
- [ ] Decision documented
- [ ] Directory moved, left, or removed with pointer
**Watch out for:** Moving changes the Go module path if anyone imports it

### Phase 5: Hardening

#### Sub-task 5.1: Full reference sweep
**Size:** S (~2 hrs)
**Depends on:** 3.1-3.6, 4.1-4.2
**Parallel with:** none
**Files to touch:** any file with dangling references
**What to do:**
- For each old path, run `git grep '<old-path>'` and verify zero results in
  operational files (Makefile, scripts, CI, config, tests, active docs)
- Old paths to check: `docker/`, `ha-config/`, `monitoring/`, `ssl/`, `secrets/`,
  `integrations/`, `performance/`, `test-content/`, `geoip/`, `tarpit/`, `ebpf/`,
  `memory/`, `Dockerfile-cli`, `Jenkinsfile.ja4proxy-policy`, `ONBOARDING.md`,
  `QWEN.md`, `quick-start.sh`, `.flake8`, `mypy.ini`, `requirements-test.txt`,
  `requirements-analytics.txt`
- Fix any remaining dangling references
**Done when:**
- [ ] `git grep` for each old path returns 0 hits in operational files
- [ ] `make test` passes
- [ ] `make lint-all` passes
**Watch out for:** Historical phase docs will still reference old paths — this is acceptable

#### Sub-task 5.2: Verify root entry count
**Size:** XS (~15 min)
**Depends on:** 5.1
**Parallel with:** none
**Files to touch:** none (verification only)
**What to do:**
- `git ls-tree --name-only HEAD | wc -l` — target: ≤30
- Count GitHub-visible (non-dot) entries — target: ≤18
- Verify README.md appears early in alphabetical listing
**Done when:**
- [ ] Root tracked entries ≤ 30
- [ ] Non-dot entries ≤ 18
- [ ] README.md visible without scrolling on GitHub
**Watch out for:** Some proposed moves were dropped (see review findings) so count
won't hit the phase doc's target of 14 visible entries — this is fine

### Phase 6: Documentation

#### Sub-task 6.1: CHANGELOG entry
**Size:** XS (~15 min)
**Depends on:** 5.2
**Parallel with:** 6.2
**Files to touch:** `CHANGELOG.md`
**What to do:**
- Add entry following standard format: `## [X.Y.Z] - 2026-04-13 - Repository Root Cleanup`
- List directories moved, files consolidated, root entry count reduction
**Done when:**
- [ ] CHANGELOG entry added at top
- [ ] Format matches existing entries

#### Sub-task 6.2: Update manifest and close phase
**Size:** XS (~15 min)
**Depends on:** 5.2
**Parallel with:** 6.1
**Files to touch:** `docs/phases/manifest.yaml`
**What to do:**
- Set Phase 205 `status: COMPLETE`
- Run `make sync` to regenerate `TODO.md` and `PROJECT_STATUS.md`
**Done when:**
- [ ] Manifest updated
- [ ] `make sync` passes
- [ ] Closing commit includes manifest + generated files

---

## Step 5 — Summary

### Revised approach vs phase doc

The phase doc proposes reducing root to 14 visible entries. After review, the
realistic and safe target is **~18 visible entries** because:

1. **`.config/` consolidation is dropped** — most tools can't read from there
2. **`CONTRIBUTING.md`, `SECURITY.md`, `AGENTS.md` stay at root** — GitHub convention
3. **Dotfiles stay at root** — they're already hidden on GitHub
4. **`.flake8` and `mypy.ini` merge into `pyproject.toml`** — net -2 entries
5. **`requirements-*.txt` merge into `pyproject.toml`** — net -3 entries

### What moves (15 directories + 3 files):
- `docker/` → `deploy/docker/`
- `ha-config/` → `deploy/haproxy/`
- `monitoring/` → `deploy/monitoring/`
- `ssl/` → `deploy/ssl/`
- `secrets/` → `deploy/secrets/`
- `integrations/` → `deploy/integrations/`
- `performance/` → `tests/performance/`
- `test-content/` → `tests/fixtures/content/`
- `geoip/` → `data/geoip/`
- `tarpit/` → `src/tarpit/`
- `ebpf/` → `src/ebpf/`
- `memory/` → `.claude/memory/` or remove
- `reports/` → `docs/reports/`
- `Dockerfile-cli` → `deploy/docker/Dockerfile.cli`
- `Jenkinsfile.ja4proxy-policy` → `deploy/ci/Jenkinsfile`
- `ONBOARDING.md` → `docs/ONBOARDING.md`
- `QWEN.md` → `.qwen/QWEN.md`
- `quick-start.sh` → `scripts/quick-start.sh`

### What stays at root (unchanged from phase doc):
All 16 must-stay files + 8 linter dotfiles (10 minus flake8 and mypy) + `CONTRIBUTING.md` + `SECURITY.md` + `AGENTS.md`

### Totals
- **Sub-tasks:** 18
- **Estimated total hours:** 12-16 hours
- **Critical blockers:** None — all moves are independent and reversible
- **Highest risk:** Sub-task 3.6 (`docker/` move, 868 references)
- **Recommended execution order:** Phases 1-2 can be parallelised. Phase 3 should be
  sequential (3.1→3.5 parallel, then 3.6 last). Phases 4-6 are sequential.
