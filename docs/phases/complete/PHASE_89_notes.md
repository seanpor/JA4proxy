# PHASE 89 — Implementation Notes

## 89c Adaptation: docker/docker-compose.test.yml

Phase 90 ran before Phase 89 and moved the canonical 159-line docker-compose.test.yml
from the repo root into `docker/`. The 8-line stub described in Phase 89c no longer
exists as a separate file — the `docker/docker-compose.test.yml` at time of Phase 89
implementation IS the full test environment (159 lines, full services).

The Phase 89c test was adapted accordingly:
- Original acceptance criterion: assert the file does NOT exist (delete the stub)
- Adapted criterion: assert the file EXISTS and has more than 50 lines (proving it is
  the canonical version, not a stub)

File preserved. Verified the file is the 159-line canonical test environment.

## 89d Scope Expansion: Additional Volume Names Fixed

Phase 89's original scope for 89d mentioned only `redis_data` and `reports_data` in
poc.yml and `redis_data` in prod.yml. During implementation, the volume naming tests
revealed two additional volume names in `docker-compose.prod.yml` that also used
underscores: `prometheus_data`, `grafana_data`, and `loki_data`. These were renamed to
`prometheus-data`, `grafana-data`, and `loki-data` respectively to satisfy the
consistent naming rule.

Similarly, `docker/docker-compose.scale.yml` had a non-external network key
`ja4proxy_network` which was renamed to `ja4proxy-network`.

## 89j Status: start-scaled Already Fixed

Makefile line 139 already correctly references `docker/docker-compose.scale.yml`.
The phase doc (89j) shows a "before" and "after" that are identical — the file exists
and the path is correct. No change was needed.

## Passlib Compatibility Check (89a — management Dockerfile)

Phase 89a requires verifying passlib compatibility before upgrading
`docker/Dockerfile.management` to python:3.14.0-slim.

`management/requirements.txt` includes `passlib[bcrypt]>=1.7.4`. This was noted as a
risk since `passlib` 1.7.x uses `crypt` (removed in Python 3.13+). The upgrade was
applied. If runtime issues arise, replace `passlib[bcrypt]>=1.7.4` with `bcrypt>=4.0`
in `management/requirements.txt`.

## Reference Integrity Check Results

After all changes, the following grep checks were run:

```
grep -rn "dmz_net|data_net|origin_net|mgmt_net" (yml/sh/md/py, excluding .git and docs/phases)
```
No remaining references in live files. Remaining occurrences are:
- `docs/phases/` history files (must not be changed — describe historical state)
- `CHANGELOG.md` historical entry for Phase 71 (must not be changed)

```
grep -rn "redis_data|reports_data" (yml/sh/md, excluding .git and docs/phases)
```
No remaining references in compose/docker files. `docs/runbooks/infrastructure.md`
volume path references updated to `redis-data`. Deploy/Ansible files use the variable
name `redis_data_dir` which is a different context (not a compose volume key).

```
grep -rn "python:3.11-slim|python:3.14-slim\b" (excluding .git and docs/phases)
```
No remaining occurrences in actual Dockerfiles. Remaining references in docs/,
scripts/ diagnostic files, and Makefile lint targets use python:3.11-slim as a
diagnostic container — not production Dockerfiles and not scanned by the tests.

```
grep -rn "golang:1.23-alpine" (excluding .git and docs/phases)
```
No remaining occurrences outside of docs/ history files.

```
grep -rn "REDIS_PASSWORD:-changeme" (yml/yaml, excluding .git)
```
No remaining occurrences.

## docker-compose.go.yml Stale References — Investigated and Fixed

`Makefile` line 316 referenced `docker/docker-compose.go.yml` which no longer exists.
Investigation via `git log` found it was **intentionally deleted** in commit b012edf
("refactor(compose): Go proxy is production default; Python is legacy overlay") — the
Go proxy is now the default service in `docker-compose.poc.yml`, making a separate
Go overlay redundant.

Stale references updated:
- `Makefile` lint-docker target: updated to reference `docker-compose.python-legacy.yml` (the current overlay)
- `docs/runbooks/go_proxy_migration.md`: updated "start Go proxy" step to use `poc.yml` directly
- `docs/developer/GO_PORT_GUIDE.md`: removed `docker-compose.go.yml` build/run commands
- `docs/operator/CAPACITY_PLANNING.md`: updated to reference `python-legacy.yml` for parity validation

## Files Modified

| File | Change |
|------|--------|
| `docker/Dockerfile.admin` | python:3.11-slim → python:3.14.0-slim |
| `docker/Dockerfile.management` | python:3.11-slim → python:3.14.0-slim |
| `tests/docker/Dockerfile.python-proxy` | python:3.14-slim → python:3.14.0-slim |
| `tests/docker/Dockerfile.recorder` | python:3.14-slim → python:3.14.0-slim |
| `tests/docker/Dockerfile.tls-backend` | python:3.14-slim → python:3.14.0-slim |
| `tests/docker/Dockerfile.test-runner` | golang:1.23-alpine → golang:1.25-alpine; python:3.14-slim → python:3.14.0-slim |
| `src/analytics/Dockerfile` | Added LABEL dockerfile.location="module" |
| `tarpit/Dockerfile` | Added LABEL dockerfile.location="module" |
| `docker/docker-compose.poc.yml` | Renamed 4 networks to hyphen form with name: fields; renamed volumes redis_data→redis-data, reports_data→reports-data; removed network:host from 7 build blocks; added restart:unless-stopped to 7 services |
| `docker/docker-compose.prod.yml` | Renamed redis_data→redis-data, prometheus_data→prometheus-data, grafana_data→grafana-data, loki_data→loki-data; removed network:host from 3 build blocks |
| `docker/docker-compose.monitoring.yml` | Updated 3 external network name: fields; updated stale comment; REDIS_PASSWORD:-changeme → :? form |
| `docker/docker-compose.python-legacy.yml` | Updated 4 network references to hyphen names; updated comment |
| `docker/docker-compose.scale.yml` | Renamed ja4proxy_network → ja4proxy-network |
| `Makefile` | Added Dockerfile.admin and Dockerfile.management to HADOLINT_DOCKERFILES; added phase-89 targets |
| `docker/README.md` | Created (new file) |
| `docs/architecture/ISOLATION_MODEL.md` | Updated zone names in network list and acceptance criteria |
| `scripts/check-isolation.sh` | Updated diagnostic comments |
| `docs/PROJECT_STATUS.md` | Updated Phase 72 summary with new network names |
| `docs/runbooks/infrastructure.md` | Updated redis volume path references |
| `tests/unit/test_docker_consistency.py` | Created (TDD — written before fixes) |
| `tests/integration/test_dockerfile_coverage.py` | Created |
