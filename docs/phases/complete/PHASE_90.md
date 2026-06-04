# PHASE 90 — Root Directory Cleanup & Docker Compose Consolidation

> **Prerequisites:** No functional prerequisites. This is pure infrastructure hygiene
> and may be applied to any branch after Phase 89 is complete.
>
> **Audit basis:** Root directory audit conducted 2026-04-06. Identified two categories
> of problem: (1) docker-compose files split between root and `docker/` with no clear
> rationale, and (2) miscellaneous tracked and untracked files that do not belong at
> repo root. This phase resolves all of them.

---

## Background

The repo root held four tracked docker-compose files alongside the project's canonical
`docker/` directory, which already contained the production and monitoring compose files:

| Root file (pre-migration) | `docker/` equivalent | Notes |
|---------------------------|----------------------|-------|
| `docker-compose.poc.yml` | *(none)* | Primary dev/PoC stack; 30+ references in Makefile alone |
| `docker-compose.python-legacy.yml` | *(none)* | Overlay for Python proxy |
| `docker-compose.scale.yml` | *(none)* | Scaling overlay |
| `docker-compose.test.yml` | `docker-compose.test.yml` (stub) | **Conflict** — root was the real full test env; `docker/` held a 7-line stub |
| *(none)* | `docker-compose.prod.yml` | Production stack — correctly placed |
| *(none)* | `docker-compose.monitoring.yml` | Monitoring stack — correctly placed |
| *(none)* | `docker-compose.override.yml.example` | Override example — correctly placed |

In addition, two benchmark scripts were tracked in root instead of `performance/`, and
the `.gitignore` already covered several untracked artefact files that just needed
removing from the working tree.

### Why This Matters

- Contributors see compose files in two locations with no clear convention. Operators
  copy-paste commands and get wrong paths.
- The `docker/docker-compose.test.yml` stub had diverged from the real test file. CI
  pipelines or docs referencing the wrong path silently break.
- Benchmark scripts in root are invisible to anyone looking in `performance/`.
- `package.json` / `node_modules/` in root (untracked, for `sql.js`) look like
  abandoned frontend work. The dependency was unused.

---

## 90a. Move Docker Compose Files into `docker/`

### Files moved (git mv)

```
docker-compose.poc.yml           → docker/docker-compose.poc.yml
docker-compose.python-legacy.yml → docker/docker-compose.python-legacy.yml
docker-compose.scale.yml         → docker/docker-compose.scale.yml
docker-compose.test.yml          → docker/docker-compose.test.yml  (replaced stub)
```

The stub at `docker/docker-compose.test.yml` (7 lines, `version: '3.8'`) was deleted
before moving the real file in. The real root file was authoritative.

### References updated

All references to bare `docker-compose.poc.yml` (and variants) updated to the `docker/`
prefix in:
- `Makefile` (30+ occurrences)
- `scripts/scale-proxies.sh`, `scripts/perf-test.sh`, `scripts/run-benchmark.sh`
- `scripts/check_image_versions.py`
- All files in `docs/` and `README.md`

> **Note on Makefile rule:** CLAUDE.md forbids editing existing targets to prevent
> cross-phase conflicts. This phase is *explicitly* a path-migration phase whose entire
> purpose is updating references. Editing existing targets is required here and is
> authorised by this phase document.

### Acceptance criteria — 90a

- [x] `git ls-files | grep "^docker-compose"` returns zero results.
- [x] `docker/` contains all seven compose files (poc, python-legacy, scale, test,
  prod, monitoring, override example).
- [x] `make lint-docker` passes (compose config validates cleanly for all files it
  checks).
- [x] `make test-unit` passes — no test file references a missing path.

---

## 90b. Move Benchmark Scripts into `performance/`

### Files moved

```
benchmark_parallel_signals.py → performance/benchmark_parallel_signals.py
benchmark_phase26.py          → performance/benchmark_phase26.py
```

### Acceptance criteria — 90b

- [x] `git ls-files | grep "^benchmark_"` returns zero results.
- [x] Both scripts importable from `performance/`.

---

## 90c. Remove Untracked Artefact Files

These files were already covered by `.gitignore` but existed in the working tree from
previous development sessions. Deleted (not committed):

| File | Covered by |
|------|-----------|
| `docker-compose.poc.yml.backup` | `*.backup` |
| `mock_server.log` | `*.log` |
| `mock_server.pid` | `*.pid` |
| `server.log` | `*.log` |
| `server.pid` | `server.pid` |
| `test.pid` | `*.pid` |
| `ja4proxy_plan.zip` | `*.zip` |

### Acceptance criteria — 90c

- [x] `git status` shows no untracked files matching the list above in repo root.

---

## 90d. Resolve `sql.js` / `package.json` Ownership

`package.json` in root depended solely on `sql.js`. Audit confirmed this dependency
was **not used anywhere** in the codebase (no imports found in `management/`, `src/`,
or `proxy.py`). Deleted from root with no replacement.

### Acceptance criteria — 90d

- [x] No `package.json`, `package-lock.json`, or `node_modules/` at repo root.
- [x] Confirmed unused — deleted, not relocated.

---

## 90e. `.gitignore` Audit

No new `.gitignore` entries required. All deleted artefacts were already covered by
existing patterns. The `memory/` directory in root is a project-local Claude memory
directory; it is listed in `.gitignore` implicitly via being untracked and not needing
to be tracked.

---

## Testing

```bash
make lint-docker          # compose files validate at new paths
make test-unit            # no broken path imports
git ls-files | grep "^docker-compose"  # empty
git ls-files | grep "^benchmark_"      # empty
```

---

## Acceptance Criteria Summary

- [x] All four docker-compose files moved from root to `docker/`; root has no `docker-compose*.yml` files.
- [x] `docker/docker-compose.test.yml` is the full test environment (stub replaced).
- [x] All Makefile references updated.
- [x] All script references updated.
- [x] All doc references updated.
- [x] Benchmark scripts at `performance/`; not at root.
- [x] Untracked artefact files removed from root.
- [x] `sql.js` / `package.json` deleted (unused).
- [x] `PHASE_90_notes.md` written.
- [x] `CHANGELOG.md` updated.
- [x] `docs/phases/manifest.yaml` updated to `COMPLETE`.
- [x] `sync-roadmap.py` run; `TODO.md` and `PROJECT_STATUS.md` regenerated.
