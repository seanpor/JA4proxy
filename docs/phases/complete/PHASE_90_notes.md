# Phase 90 Notes

## Summary

Root directory audit and cleanup. All docker-compose files consolidated into `docker/`,
benchmark scripts moved to `performance/`, and untracked artefact files removed.

## Notable Decisions

### sql.js / package.json — deleted, not relocated

`package.json` at repo root depended solely on `sql.js` (browser SQLite). A full
codebase search (`grep -r "sql.js\|require.*sql\|import.*sql"`) found zero uses in
`management/`, `src/`, or `proxy.py`. Deleted outright with no replacement.

### Build contexts updated to `..`

The moved compose files used `context: .` (repo root) when running from root. After
moving to `docker/`, `context: .` would resolve to `docker/` — wrong. All build
contexts updated to `context: ..` (and `context: ../tarpit`), matching the pattern
already established in `docker/docker-compose.prod.yml`.

### docker/docker-compose.test.yml stub replaced

The `docker/docker-compose.test.yml` that existed before this phase was a 7-line stub
(`version: '3.8'` with one service). The real full test environment lived at root.
The stub was deleted and the real file moved in.

### Makefile lint-docker REDIS_PASSWORD

The `lint-docker` target's `docker compose config` validation for `docker-compose.poc.yml`
required `REDIS_PASSWORD` (the compose file uses `:?` required-variable syntax). Added
`REDIS_PASSWORD=lint-placeholder` to the two poc validation lines in `lint-docker`.

### hadolint failure is pre-existing

`make lint-docker` fails on `docker/Dockerfile` via hadolint. This is unrelated to
Phase 90 — the failure existed before this phase and the Dockerfile is unchanged.
Compose config validation (our changes) passes cleanly for all five files.

## Files Changed

- `docker/docker-compose.poc.yml` — moved from root; build contexts `context: .` → `context: ..`
- `docker/docker-compose.python-legacy.yml` — moved from root; context updated
- `docker/docker-compose.scale.yml` — moved from root (no build contexts, no changes needed)
- `docker/docker-compose.test.yml` — moved from root (replaced stub); contexts updated
- `performance/benchmark_parallel_signals.py` — moved from root
- `performance/benchmark_phase26.py` — moved from root
- `Makefile` — 30+ path references updated; REDIS_PASSWORD added to lint-docker
- `scripts/scale-proxies.sh`, `perf-test.sh`, `run-benchmark.sh` — paths updated
- `scripts/check_image_versions.py` — paths updated
- All files in `docs/` and `README.md` containing old paths — updated via bulk replace
