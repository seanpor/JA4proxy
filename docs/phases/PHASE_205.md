---
phase: 205
title: "Repository Root Cleanup & File Organisation"
status: PROPOSED
size: MEDIUM
created: 2026-04-13
audience: [developer, operator]
dependencies: []
---

# Phase 205 — Repository Root Cleanup & File Organisation

## Problem

The repo root has **60 tracked entries** (35 files + 25 directories). On GitHub,
users must scroll past all of this to reach the README. A well-organised repo
should have ~15–20 root entries max. The current state signals "no one owns the
layout" and makes navigation harder for new contributors.

Additionally, there are **12 untracked files** in root that should either be
gitignored or deleted, and several tracked files/directories that belong
elsewhere.

---

## Audit of Current Root (60 tracked entries)

### Files that MUST stay in root (GitHub/tooling convention)
These are expected at the root by GitHub, Go tooling, or CI. Do not move them.

| File | Reason |
|------|--------|
| `README.md` | GitHub convention |
| `LICENSE` | GitHub convention |
| `CHANGELOG.md` | GitHub convention |
| `SECURITY.md` | GitHub convention (security policy) |
| `CONTRIBUTING.md` | GitHub convention |
| `CLAUDE.md` | Claude Code convention |
| `AGENTS.md` | Claude Code convention |
| `Makefile` | Build entry point |
| `go.mod` / `go.sum` | Go module root |
| `proxy.py` | Python proxy entry point (legacy, but referenced everywhere) |
| `pyproject.toml` | Python project config (ruff, mypy, pytest) |
| `.gitignore` / `.gitattributes` | Git config |
| `.dockerignore` | Docker build context |
| `.env.example` | Environment template |

**Count: 16 files (must stay)**

### Dotfiles that MUST stay in root (tool config)
Linters and CI tools look for these in root by convention.

| File | Tool |
|------|------|
| `.bandit` | Bandit security linter config |
| `.flake8` | Flake8 config (could merge into pyproject.toml) |
| `.gitleaks.toml` | Gitleaks secrets scanning |
| `.golangci.yaml` | golangci-lint config |
| `.goreleaser.yml` | GoReleaser config |
| `.hadolint.yaml` | Dockerfile linter |
| `.luacheckrc` | Lua linter (HAProxy scripts) |
| `.mlc.json` | Markdown link checker |
| `.yamllint.yaml` | YAML linter |
| `mypy.ini` | Mypy type checker (could merge into pyproject.toml) |

**Count: 10 dotfiles (must stay, but 2 could merge into pyproject.toml)**

### Directories that are correctly placed

| Directory | Purpose |
|-----------|---------|
| `.claude/` | Claude Code config |
| `.github/` | GitHub Actions, templates |
| `.gitlab-ci/` | GitLab CI config |
| `.qwen/` | Qwen AI config |
| `cmd/` | Go entrypoints (standard Go layout) |
| `config/` | Configuration files |
| `deploy/` | Deployment (Helm, Ansible, Terraform, Docker Compose) |
| `docs/` | Documentation |
| `internal/` | Go packages (standard Go layout) |
| `management/` | Management API (FastAPI) |
| `scripts/` | Build/utility scripts |
| `src/` | Python source |
| `tests/` | Test suite |

**Count: 13 directories (correctly placed)**

### Items that should MOVE to subdirectories

| Current location | Proposed location | Rationale |
|-----------------|-------------------|-----------|
| `docker/` | `deploy/docker/` | All deployment artifacts belong under `deploy/` |
| `ha-config/` | `deploy/haproxy/` | HAProxy config is deployment infra |
| `ssl/` | `deploy/ssl/` or `tests/fixtures/ssl/` | Test certs or deployment certs |
| `geoip/` | `data/geoip/` or `deploy/geoip/` | Data files, not source code |
| `ebpf/` | `src/ebpf/` or `internal/ebpf/` | Source code, belongs with code |
| `monitoring/` | `deploy/monitoring/` | Grafana/Prometheus configs are deployment |
| `performance/` | `tests/performance/` or `benchmarks/` | Performance tests belong with tests |
| `integrations/` | `deploy/integrations/` | SIEM/SOAR integrations are deployment |
| `security/` | `docs/security/` or `src/security/` | Audit docs or security source |
| `secrets/` | `deploy/secrets/` | Secret templates are deployment |
| `tarpit/` | `src/tarpit/` or `internal/tarpit/` | Source code |
| `memory/` | `src/memory/` or remove if unused | Unclear purpose at root |
| `terraform-provider/` | `deploy/terraform-provider/` | Or keep as separate repo ref |
| `test-content/` | `tests/fixtures/` | Test data belongs with tests |
| `reports/` | `docs/reports/` | Generated reports |

**Count: 15 directories to move**

### Files that should MOVE

| Current location | Proposed location | Rationale |
|-----------------|-------------------|-----------|
| `Dockerfile-cli` | `docker/Dockerfile.cli` or `deploy/docker/Dockerfile.cli` | Dockerfiles belong with Docker config |
| `Jenkinsfile.ja4proxy-policy` | `.jenkins/Jenkinsfile` or `deploy/jenkins/` | CI config |
| `quick-start.sh` | `scripts/quick-start.sh` | Utility script |
| `ONBOARDING.md` | `docs/ONBOARDING.md` | Documentation |
| `QWEN.md` | `.qwen/QWEN.md` | Qwen AI config |
| `requirements-analytics.txt` | `management/requirements.txt` or consolidate | Per-component deps |
| `requirements-test.txt` | `tests/requirements.txt` or consolidate | Test deps |
| `requirements.txt` | Keep (pip convention) or consolidate into pyproject.toml | |

**Count: 7–8 files to move**

### Untracked files to gitignore or delete

| File | Action |
|------|--------|
| `.coverage` | Already gitignored? Verify |
| `.env` / `.env.gemini2` / `.env.Gemini2` | Add to `.gitignore` if not already |
| `ja4proxy_plan.zip` | Delete (archive artifact) |
| `package.json` / `package-lock.json` | Delete or move to `docs/` if used for markdownlint |
| `test_results_20260411_*.txt` (×5) | Delete (transient test output) |

### Directories to gitignore (build/cache artifacts)

| Directory | Action |
|-----------|--------|
| `.mypy_cache/` | Should be gitignored |
| `.pytest_cache/` | Should be gitignored |
| `.ruff_cache/` | Should be gitignored |
| `__pycache__/` | Should be gitignored |
| `.hypothesis/` | Should be gitignored |
| `node_modules/` | Should be gitignored |
| `.venv314/` / `.venv314b/` | Should be gitignored |
| `test-results/` | Should be gitignored (or move to CI artifacts) |
| `.local/` | Should be gitignored |
| `bin/` | Should be gitignored (build output) |

---

## Proposed Root After Cleanup

```
.
├── .bandit
├── .claude/
├── .dockerignore
├── .env.example
├── .flake8                    # → consider merging into pyproject.toml
├── .gitattributes
├── .github/
├── .gitignore
├── .gitleaks.toml
├── .gitlab-ci/
├── .golangci.yaml
├── .goreleaser.yml
├── .hadolint.yaml
├── .luacheckrc
├── .mlc.json
├── .qwen/
├── .yamllint.yaml
├── AGENTS.md
├── CHANGELOG.md
├── CLAUDE.md
├── CONTRIBUTING.md
├── LICENSE
├── Makefile
├── README.md                  ← visible without scrolling
├── SECURITY.md
├── cmd/
├── config/
├── data/                      # NEW — geoip, static data
├── deploy/                    # absorbs docker/, ha-config/, monitoring/, etc.
├── docs/                      # absorbs ONBOARDING.md, reports/, security/ docs
├── go.mod
├── go.sum
├── internal/
├── management/
├── mypy.ini                   # → consider merging into pyproject.toml
├── proxy.py
├── pyproject.toml
├── requirements.txt           # → consider consolidating all 3 into pyproject.toml
├── scripts/                   # absorbs quick-start.sh
├── src/                       # absorbs tarpit/, ebpf/, memory/
└── tests/                     # absorbs performance/, test-content/
```

**Result: ~26 visible entries on GitHub** (dotfiles hidden by default → ~15 visible)
vs current **~50 visible entries**. README.md visible without scrolling.

---

## Sub-phases

### 205a — Gitignore & Delete Transient Files (XS)

**Files to touch:** `.gitignore`, delete transient files
**Steps:**
1. Add missing patterns to `.gitignore`: `.coverage`, `.env`, `.env.*` (except `.env.example`), `*.zip`, `test_results_*.txt`, `node_modules/`, `.hypothesis/`, `.local/`, `bin/`, `.venv*/`
2. Delete untracked transient files: `ja4proxy_plan.zip`, `test_results_*.txt` (×5)
3. Verify `.mypy_cache/`, `.pytest_cache/`, `.ruff_cache/`, `__pycache__/`, `test-results/` are already gitignored; add if not
4. If `package.json`/`package-lock.json` are only for markdownlint, move to `docs/` or document why they're at root

**Done when:** `git ls-files --others --exclude-standard` shows no transient files in root

### 205b — Move Deployment Directories Under `deploy/` (S)

**Directories to move:**
- `docker/` → `deploy/docker/`
- `ha-config/` → `deploy/haproxy/`
- `monitoring/` → `deploy/monitoring/`
- `integrations/` → `deploy/integrations/`
- `secrets/` → `deploy/secrets/`
- `ssl/` → `deploy/ssl/` (or `tests/fixtures/ssl/` if test-only)
- `Dockerfile-cli` → `deploy/docker/Dockerfile.cli`
- `Jenkinsfile.ja4proxy-policy` → `deploy/jenkins/Jenkinsfile`

**Update all references:** Makefile, docker-compose files, CI workflows, scripts, docs.
Run `grep -r` for each moved path and update every reference.

**Done when:** All moved paths have zero dangling references; `make test` passes

### 205c — Move Source Directories Under `src/` or `internal/` (S)

**Directories to move:**
- `tarpit/` → `src/tarpit/` (Python tarpit logic)
- `ebpf/` → `src/ebpf/` (eBPF programs)
- `memory/` → audit first; move to `src/memory/` or delete if unused

**Done when:** All import paths updated; `make test` passes

### 205d — Move Test & Data Directories (S)

**Directories to move:**
- `performance/` → `tests/performance/` or `benchmarks/`
- `test-content/` → `tests/fixtures/`
- `geoip/` → `data/geoip/`
- `reports/` → `docs/reports/`

**Done when:** All references updated; `make test` passes

### 205e — Move Documentation Files (XS)

**Files to move:**
- `ONBOARDING.md` → `docs/ONBOARDING.md`
- `QWEN.md` → `.qwen/QWEN.md`
- `quick-start.sh` → `scripts/quick-start.sh`
- `security/` → audit: if docs, move to `docs/security/`; if code, leave or move to `src/security/`

**Done when:** All links in README and docs updated

### 205f — Consolidate Python Config (XS, optional)

**Merge into `pyproject.toml`:**
- `.flake8` → `[tool.flake8]` section (if still used alongside ruff)
- `mypy.ini` → `[tool.mypy]` section
- `requirements-test.txt` → `[project.optional-dependencies]` test group
- `requirements-analytics.txt` → `[project.optional-dependencies]` analytics group

**Done when:** Original files deleted; `make test` and `make lint-all` still pass

### 205g — Consolidate `terraform-provider/` (XS)

**Decision needed:** The Terraform provider has its own repo (`terraform-provider-ja4proxy`). If the in-tree copy is stale or redundant:
- Remove `terraform-provider/` from this repo
- Add a note in `deploy/` README pointing to the separate repo

If it's the active development copy:
- Move to `deploy/terraform-provider/`

**Done when:** Decision documented in ADR; directory moved or removed

### 205h — Update References & Final Verification (S)

**Steps:**
1. `grep -rn` for every old path across the entire repo
2. Update Makefile targets, docker-compose files, CI workflows, scripts, docs
3. Run full test suite: `make test`
4. Run full lint suite: `make lint-all`
5. Verify `git ls-tree --name-only HEAD` shows ≤30 root entries
6. Verify README.md is visible on GitHub without scrolling

---

## Acceptance Criteria

- [ ] Root has ≤30 tracked entries (files + directories)
- [ ] README.md visible on GitHub without scrolling past file listing
- [ ] No transient/build files in root (all gitignored)
- [ ] All deployment config consolidated under `deploy/`
- [ ] All test data consolidated under `tests/`
- [ ] No dangling path references — `make test` and `make lint-all` pass
- [ ] `.gitignore` covers all build/cache artifacts
- [ ] CHANGELOG entry added
- [ ] Manifest updated

## Non-Goals

- Not restructuring `src/` or `internal/` package layout (separate concern)
- Not renaming existing CI workflow files (too many downstream references)
- Not consolidating Go and Python into a monorepo tool like Bazel
- Not removing `proxy.py` (still used for prototyping per CLAUDE.md)

## Risks

- **High:** Moving directories will break CI, Docker builds, and scripts that
  use hardcoded paths. Sub-phase 205h (reference update) is critical and must
  be thorough. Use `git grep` not just `grep` to catch everything tracked.
- **Medium:** Other agents working in parallel may reference old paths. Coordinate
  via CLAUDE.md file ownership rules.
- **Low:** Some linter config files may not support non-root locations. Test each
  move individually before committing.
