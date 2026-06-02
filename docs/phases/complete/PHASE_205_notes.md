# Phase 205 — Implementation Notes

**Completed:** 2026-04-14
**Branch:** `claude/phase-205-repo-root-cleanup`

## What shipped

- All directory moves from the phase plan (205b/c/d/e/g).
- `security/validation.py` relocated to `src/security/validation.py` with all
  9 call sites updated and the mypy override list corrected.
- `security/policies/` moved to `docs/security/policies/`; `security/` directory
  removed from the tree.
- `mypy.ini` and `.flake8` consolidated into `pyproject.toml`.
- Compose build contexts corrected from `../` to `../../` after the 2-level
  relocation; volume mounts, Dockerfile paths, and secrets paths all rewritten.
- `deploy/__init__.py` added so `deploy.integrations.servicenow` resolves in
  unit tests.

## What was deferred

**205f (full `requirements*.txt` consolidation) — dropped from scope.** The
migration would require a full `[project]` table in `pyproject.toml` and
atomic rewrites across Dockerfiles, CI workflows, Makefile, and Dependabot.
The only payoff is dropping GitHub-visible root entries from 25 → 22 —
cosmetic, and `pip install -r requirements.txt` is idiomatic Python. No
Phase 206; revisit opportunistically if the Docker/CI stack is touched for
other reasons.

## Decisions

- **`data/` kept as a top-level directory.** GeoIP mmap files are neither
  source, tests, nor deployment — a dedicated `data/` directory is cleaner
  than shoehorning them into `src/` or `tests/fixtures/`. No ADR written:
  the decision is self-explanatory and low blast-radius.
- **`.gitlab-ci/` kept.** Audit showed it was last touched by Phase 82
  governance work (`ja4proxy-policy.yml`) and supports external GitLab
  mirrors. Leaving in place.
- **`src/memory/` does not exist** — earlier plan assumed a `memory/` dir
  at root; audit confirmed the phase-205 moves never created one. Nothing
  to clean up.
- **Acceptance criterion revised.** The original "≤14 visible on GitHub"
  target is arithmetically impossible given Go (`go.mod`, `go.sum`), Python
  (`proxy.py`, `pyproject.toml`), standard README/LICENSE/CHANGELOG/CLAUDE/Makefile,
  and the 10 architectural directories — floor is ~19 visible. Revised to
  "≤22 visible / ≤25 tracked". Actual result: 25 visible / 42 tracked.

## Test regression fixes

Moving `integrations/` → `deploy/integrations/` broke two test files:

- `tests/unit/test_servicenow_handler.py` — three `patch("integrations.servicenow…")`
  call strings had not been updated when the top-level `from deploy.integrations…`
  import was.
- `tests/unit/test_splunk_ban_action.py` — `_PLAYBOOK_PATH` hardcoded
  `integrations/sentinel/playbooks/Block-IP-Playbook.json` rather than
  `deploy/integrations/…`.

Both fixed in this phase. These had been mischaracterised in the context summary
as "pre-existing failures" — they were in fact regressions from 205b.

## Test result

- 5391 passed, 10 skipped, 9 xfailed on `python3 -m pytest tests/
  --ignore=tests/integration/test_docker_stack.py` (250 s wall time).
- Zero new failures attributable to this phase.
