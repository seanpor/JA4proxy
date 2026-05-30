# PHASE 89 — Dockerfile Base Image Hygiene

> **Prerequisites:** No functional prerequisites. This is infrastructure hygiene and may
> be applied to any branch after Phase 88 is complete.
>
> **Audit basis:** Docker audit conducted 2026-04-06 identified 10 issues across
> critical, high, and medium severity. This phase resolves all of them. Each sub-section
> cites the finding inline.

---

## 89a. Python Base Image Standardisation

### Finding

Two production Dockerfiles pin to `python:3.11-slim`, which reached end-of-life on
2024-10-31 and no longer receives security patches:

- `docker/Dockerfile.admin` — `FROM python:3.11-slim`
- `docker/Dockerfile.management` — `FROM python:3.11-slim`

Four test-infrastructure Dockerfiles use `python:3.14-slim` (unpinned minor tag),
meaning Docker may silently pull a different patch release on each build host:

- `tests/docker/Dockerfile.python-proxy`
- `tests/docker/Dockerfile.recorder`
- `tests/docker/Dockerfile.tls-backend`
- `tests/docker/Dockerfile.test-runner` (runtime stage)

All other Python images in the project already use `python:3.14.0-slim` correctly.

### Passlib Compatibility Check — Required Before Upgrading Management

`management/requirements.txt` includes `passlib[bcrypt]>=1.7.4`. `passlib` 1.7.x uses
Python's `crypt` module, which was deprecated in Python 3.12 and **removed in Python
3.13**. On Python 3.14, any `passlib` version below 1.8 will fail at import.

Before changing `docker/Dockerfile.management`, verify that the installed `passlib`
version supports Python 3.14. Build and test the image in isolation first:

```bash
docker build --no-cache \
  -f docker/Dockerfile.management \
  -t ja4proxy-management-test:3.14-check .

docker run --rm ja4proxy-management-test:3.14-check \
  python -c "from passlib.handlers.bcrypt import bcrypt_sha256; print('OK')"
```

If this command fails, replace `passlib[bcrypt]>=1.7.4` with `bcrypt>=4.0` in
`management/requirements.txt` and update any `passlib` call sites in the management
application code to use `bcrypt` directly. Document the change in this phase's notes.
This check is a required acceptance criterion before the phase is marked COMPLETE.

### Implementation

In `docker/Dockerfile.admin`, change:

```dockerfile
FROM python:3.11-slim
```

to:

```dockerfile
FROM python:3.14.0-slim
```

In `docker/Dockerfile.management`, change:

```dockerfile
FROM python:3.11-slim
```

to:

```dockerfile
FROM python:3.14.0-slim
```

In each of `tests/docker/Dockerfile.python-proxy`, `tests/docker/Dockerfile.recorder`,
and `tests/docker/Dockerfile.tls-backend`, change:

```dockerfile
FROM python:3.14-slim
```

to:

```dockerfile
FROM python:3.14.0-slim
```

In `tests/docker/Dockerfile.test-runner`, the runtime stage changes from
`FROM python:3.14-slim` to `FROM python:3.14.0-slim`. (The builder stage is addressed
in 89b.)

Also add `docker/Dockerfile.admin` and `docker/Dockerfile.management` to the
`HADOLINT_DOCKERFILES` list in the `Makefile`. These files are currently absent from
hadolint coverage (line 279–282):

```makefile
# Before
HADOLINT_DOCKERFILES := docker/Dockerfile docker/Dockerfile.mockbackend docker/Dockerfile.test \
    docker/Dockerfile.trafficgen docker/Dockerfile.go-proxy src/analytics/Dockerfile tarpit/Dockerfile \
    tests/docker/Dockerfile.python-proxy tests/docker/Dockerfile.recorder \
    tests/docker/Dockerfile.test-runner tests/docker/Dockerfile.tls-backend

# After
HADOLINT_DOCKERFILES := docker/Dockerfile docker/Dockerfile.admin docker/Dockerfile.management \
    docker/Dockerfile.mockbackend docker/Dockerfile.test \
    docker/Dockerfile.trafficgen docker/Dockerfile.go-proxy src/analytics/Dockerfile tarpit/Dockerfile \
    tests/docker/Dockerfile.python-proxy tests/docker/Dockerfile.recorder \
    tests/docker/Dockerfile.test-runner tests/docker/Dockerfile.tls-backend
```

After all changes, rebuild and verify:

```bash
docker compose -f docker/docker-compose.poc.yml build --no-cache admin-api management
docker compose -f docker/docker-compose.test.yml build --no-cache
```

---

## 89b. Go Toolchain Alignment

### Finding

`tests/docker/Dockerfile.test-runner` uses `golang:1.23-alpine` for its build stage.
The production file `docker/Dockerfile.go-proxy` already uses `golang:1.25-alpine`,
and `go.mod` declares `go 1.25.0`. The two-version gap means the test runner builds
a Go 1.23 binary, not the binary that ships to production, creating a silent parity gap
between what CI tests and what runs in production.

### Implementation

Align the test-runner builder stage with the production Dockerfile:

```dockerfile
# Before (tests/docker/Dockerfile.test-runner, builder stage)
FROM golang:1.23-alpine AS go-builder

# After
FROM golang:1.25-alpine AS go-builder
```

Rebuild and confirm the binary reports the correct version:

```bash
docker compose -f docker/docker-compose.test.yml build --no-cache test-runner
docker compose -f docker/docker-compose.test.yml run --rm test-runner \
  /usr/local/bin/ja4proxy --version
```

---

## 89c. Compose File Name Collision Resolution

### Finding

Two files share a near-identical name but serve completely different purposes:

| File | Lines | Content |
|------|-------|---------|
| `docker/docker-compose.test.yml` | 8 | Redis-only port stub; no networks, no services except bare `redis:` with port mappings |
| `docker/docker-compose.test.yml` (root) | 160 | Full integration test suite with TLS backend, Go proxy, Python proxy, recorder, and test-runner |

The 8-line stub has no declared network, no healthcheck, and no image pin. No Makefile
functional target references it by path; the Makefile comment at line 277 explicitly
states it cannot be validated standalone. There is no evidence this stub is used by any
current workflow. It is an abandoned stub that creates dangerous confusion with the
canonical integration test suite.

**Decision: delete `docker/docker-compose.test.yml`.**

### Implementation

Confirm no functional reference exists before deletion:

```bash
grep -rn "docker/docker-compose.test" . \
  --include="*.yml" --include="*.yaml" \
  --include="Makefile" --include="*.sh" --include="*.md"
```

The only hit should be the comment on line 277 of `Makefile`. Then:

```bash
rm docker/docker-compose.test.yml
```

Remove the now-obsolete comment from `Makefile` line 277:

```makefile
# Delete this line:
# docker/docker-compose.test.yml is an overlay stub; it cannot be validated standalone.
```

---

## 89d. Volume and Network Naming Standardisation

### Finding

`docker/docker-compose.poc.yml` uses underscore naming for all networks and two volumes:

```
Networks: dmz_net, data_net, origin_net, mgmt_net
Volumes:  redis_data, reports_data
```

`docker/docker-compose.prod.yml` and `docker/docker-compose.monitoring.yml` use hyphen
naming:

```
Networks: ja4proxy-frontend, ja4proxy-backend, ja4proxy-monitoring
Volumes:  prometheus-data, alertmanager-data, grafana-data, loki-data
```

Because `docker/docker-compose.poc.yml` has `name: ja4proxy`, Docker currently creates
networks named `ja4proxy_dmz_net`, `ja4proxy_data_net` etc. (project-name prefix + YAML
key). `docker/docker-compose.monitoring.yml` joins these as external networks using
hard-coded `name:` values matching this pattern. When both files use the same Docker
resource names, volumes and networks are shared correctly. The current inconsistency
means adding an explicit `name:` field to each POC network (to control the Docker-level
name) must be done atomically with updating the monitoring overlay's references.

Phase 72 established these four zones. The rename is cosmetic — the zone topology is
unchanged.

### ⚠ Operational Warning: Apply Atomically, Stack Must Be Down

**Bring all stacks down before applying any part of 89d.** Docker will not rename live
networks or volumes in place. If containers are running when the rename is applied and
you then run `docker compose up`, Docker creates new resources under the new names
while old containers remain attached to the old ones — connectivity is lost silently.

If you need to preserve Redis data across the rename:

```bash
# Export data before bringing the stack down
docker compose -f docker/docker-compose.poc.yml exec redis \
  redis-cli --pass "$REDIS_PASSWORD" BGSAVE
docker run --rm \
  -v ja4proxy_redis_data:/data \
  -v "$(pwd)":/backup \
  alpine tar czf /backup/redis-data-backup.tar.gz /data

# Bring all stacks down
docker compose -f docker/docker-compose.poc.yml down
docker compose -f docker/docker-compose.monitoring.yml down 2>/dev/null || true
docker compose -f docker/docker-compose.poc.yml \
               -f docker/docker-compose.python-legacy.yml down 2>/dev/null || true

# Remove old named volumes (data backed up above)
docker volume rm ja4proxy_redis_data ja4proxy_reports_data 2>/dev/null || true
```

All three files (`docker/docker-compose.poc.yml`, `docker/docker-compose.python-legacy.yml`,
`docker/docker-compose.monitoring.yml`) must be updated in a **single commit**. Running
`make lint-docker` between partial updates will fail because monitoring's external
network references will not resolve against the partially-updated base file.

### Implementation — docker/docker-compose.poc.yml: networks

Rename the four network keys and add explicit `name:` fields:

```yaml
# Before
networks:
  dmz_net:
    driver: bridge
  data_net:
    driver: bridge
    internal: true
  origin_net:
    driver: bridge
    internal: true
  mgmt_net:
    driver: bridge

# After
networks:
  ja4proxy-dmz:
    driver: bridge
    name: ja4proxy-dmz
  ja4proxy-data:
    driver: bridge
    internal: true
    name: ja4proxy-data
  ja4proxy-origin:
    driver: bridge
    internal: true
    name: ja4proxy-origin
  ja4proxy-mgmt:
    driver: bridge
    name: ja4proxy-mgmt
```

Update every service `networks:` list in `docker/docker-compose.poc.yml`:

| Service | Old network keys | New network keys |
|---------|-----------------|-----------------|
| `haproxy` | `dmz_net` | `ja4proxy-dmz` |
| `proxy` | `dmz_net, data_net, origin_net, mgmt_net` | `ja4proxy-dmz, ja4proxy-data, ja4proxy-origin, ja4proxy-mgmt` |
| `redis` | `data_net` | `ja4proxy-data` |
| `backend` | `origin_net` | `ja4proxy-origin` |
| `tarpit` | `origin_net` | `ja4proxy-origin` |
| `trafficgen` | `dmz_net` | `ja4proxy-dmz` |
| `analytics` | `mgmt_net` | `ja4proxy-mgmt` |
| `admin-api` | `mgmt_net, data_net` | `ja4proxy-mgmt, ja4proxy-data` |
| `test` | `dmz_net, data_net, origin_net` | `ja4proxy-dmz, ja4proxy-data, ja4proxy-origin` |
| `management` | `mgmt_net, data_net` | `ja4proxy-mgmt, ja4proxy-data` |

### Implementation — docker/docker-compose.poc.yml: volumes

```yaml
# Before
volumes:
  redis_data:
  redis-sock:
  reports_data:

# After
volumes:
  redis-data:
  redis-sock:
  reports-data:
```

Update the two service `volumes:` mount references:

```yaml
# redis service
- redis-data:/data        # was redis_data:/data

# test service
- reports-data:/app/reports   # was reports_data:/app/reports
```

### Implementation — docker/docker-compose.prod.yml: volume

```yaml
# volumes section (was redis_data)
volumes:
  redis-data:

# redis service mount (was redis_data:/data)
  - redis-data:/data
```

(No network changes needed in `docker/docker-compose.prod.yml` — it already uses
hyphen-named networks that are entirely independent of the POC stack.)

### Implementation — docker/docker-compose.monitoring.yml: external network names

```yaml
# Before (lines 294–302)
networks:
  ja4proxy-monitoring:
    driver: bridge
  poc_dmz_net:
    external: true
    name: ja4proxy_dmz_net
  poc_data_net:
    external: true
    name: ja4proxy_data_net
  poc_mgmt_net:
    external: true
    name: ja4proxy_mgmt_net

# After
networks:
  ja4proxy-monitoring:
    driver: bridge
  poc_dmz_net:
    external: true
    name: ja4proxy-dmz
  poc_data_net:
    external: true
    name: ja4proxy-data
  poc_mgmt_net:
    external: true
    name: ja4proxy-mgmt
```

Also update the comment near line 293 that documents how these names are derived:

```yaml
# Before
# Names match the fixed project name in docker/docker-compose.poc.yml (name: ja4proxy).

# After
# Names match the explicit name: fields on networks in docker/docker-compose.poc.yml.
# After Phase 89, poc networks have explicit name: ja4proxy-dmz / ja4proxy-data / ja4proxy-mgmt.
```

### Implementation — docker/docker-compose.python-legacy.yml: network references

```yaml
# Before (lines 33–36)
    networks:
      - dmz_net
      - data_net
      - origin_net
      - mgmt_net

# After
    networks:
      - ja4proxy-dmz
      - ja4proxy-data
      - ja4proxy-origin
      - ja4proxy-mgmt
```

Update the comment on line 44:

```yaml
# Before
# Networks are declared in docker/docker-compose.poc.yml (dmz_net, data_net, origin_net, mgmt_net).

# After
# Networks are declared in docker/docker-compose.poc.yml (ja4proxy-dmz, ja4proxy-data, ja4proxy-origin, ja4proxy-mgmt).
```

### Living Documentation Updates

Update all references to the old network key names in living documentation:

- `docs/architecture/ISOLATION_MODEL.md` — zone description table (lines 42–45) and
  acceptance criteria table (line 156)
- `scripts/check-isolation.sh` — diagnostic comments at lines 139–184 that name
  `data_net` and `origin_net`
- `docs/PROJECT_STATUS.md` — line 108 references the four-zone names

(Do **not** update `docs/phases/manifest.yaml` entries for Phases 71–75 — those entries
describe historical state and must not be retroactively edited.)

---

## 89e. Build Network Security Fix

### Finding

The `network: host` option on `build:` blocks exposes the host network interface during
image builds. `RUN` instructions can then make arbitrary outbound connections through
the host's network stack, bypassing Docker's network isolation for the build phase.

Affected build blocks:

- `docker/docker-compose.poc.yml`: proxy, backend, tarpit, trafficgen, analytics, admin-api, test (7 blocks)
- `docker/docker-compose.prod.yml`: proxy, analytics, tarpit (3 blocks)

Inspection of each Dockerfile confirms they only install packages via `pip` or `apk`
from public registries — operations that work correctly with Docker's default bridge
network. No Dockerfile documents a requirement for host networking during build.

### Implementation

Remove the `network: host` line from every `build:` block in both files:

```yaml
# Before
    build:
      context: .
      dockerfile: docker/Dockerfile.go-proxy
      network: host

# After
    build:
      context: .
      dockerfile: docker/Dockerfile.go-proxy
```

Apply to all 10 affected build blocks. Validate the compose files parse correctly and
that images build successfully:

```bash
REDIS_PASSWORD=test BACKEND_HOST=test \
  docker compose -f docker/docker-compose.poc.yml config --quiet
BACKEND_HOST=test \
  docker compose -f docker/docker-compose.prod.yml config --quiet
docker compose -f docker/docker-compose.poc.yml build --no-cache
```

### Air-gapped / Custom Build Network Environments

In environments where Docker's bridge network has no default route (air-gapped CI,
custom network policies), removing `network: host` may cause `go mod download` or
`pip install` to fail silently. If builds fail after applying this change, the
per-invocation override is:

```bash
docker build --network host -f docker/Dockerfile.go-proxy .
```

If your environment requires host networking for all builds, document this as a
site-specific override in `docs/phases/PHASE_89_notes.md` rather than restoring
`network: host` to the compose files.

If a future Dockerfile genuinely requires host network access during build (e.g., to
reach an internal registry not resolvable via bridge DNS), that requirement must be
documented with a comment above the `network: host` line explaining the specific reason.
No undocumented `network: host` build flags are permitted.

---

## 89f. REDIS_PASSWORD Consistency

### Finding

`docker/docker-compose.monitoring.yml`'s `redis-exporter` service uses:

```yaml
- REDIS_PASSWORD=${REDIS_PASSWORD:-changeme}
```

This substitutes the literal string `changeme` if the variable is unset — an operator
who forgets to set `REDIS_PASSWORD` deploys an exporter authenticating with a
known-default password. All other compose files use `${REDIS_PASSWORD:?REDIS_PASSWORD is required}`.

Note: `docker/docker-compose.python-legacy.yml` uses `${REDIS_PASSWORD:-}` (empty fallback)
but this is an overlay that is always used with `docker/docker-compose.poc.yml` as the base.
The base file enforces `:?` and fails first if the variable is unset, making the
overlay's pattern harmless in practice. The legacy overlay is **not changed** in this
phase to avoid redundant error messages.

### Implementation

In `docker/docker-compose.monitoring.yml`, change the redis-exporter environment entry:

```yaml
# Before
      - REDIS_PASSWORD=${REDIS_PASSWORD:-changeme}

# After
      - REDIS_PASSWORD=${REDIS_PASSWORD:?REDIS_PASSWORD is required}
```

Verify that starting the monitoring stack without `REDIS_PASSWORD` set produces a clear
error:

```bash
unset REDIS_PASSWORD
docker compose -f docker/docker-compose.monitoring.yml config 2>&1 \
  | grep -i "required"
# Must print: REDIS_PASSWORD is required
```

---

## 89g. Restart Policy Gaps

### Finding

In `docker/docker-compose.poc.yml`, the following permanent services have no `restart:`
policy (default is `restart: no` — they stay down after a crash until manually restarted):

| Service | Role |
|---------|------|
| `proxy` | Core traffic handler |
| `redis` | State store for bans, dial, session data |
| `backend` | Mock origin backend |
| `tarpit` | Absorbs malicious connections |
| `analytics` | Processes security signals from Redis streams |
| `admin-api` | Management API |
| `trafficgen` | Synthetic load generator (profiles-gated) |

`haproxy` (line 15) and `management` (line 380) already have `restart: unless-stopped`.

For `trafficgen`: it runs under `profiles: [traffic]` so it is not started in the
default stack. When it IS started, it should remain running until explicitly stopped —
`restart: unless-stopped` is appropriate.

### Implementation

Add `restart: unless-stopped` to each service listed above in `docker/docker-compose.poc.yml`.
Place it after the `image:` line and before the first service-specific configuration
key. Example:

```yaml
  proxy:
    build:
      context: .
      dockerfile: docker/Dockerfile.go-proxy
    image: ja4proxy:2.0.0
    restart: unless-stopped
    # ... rest of service config
```

Apply to: `proxy`, `redis`, `backend`, `tarpit`, `analytics`, `admin-api`, `trafficgen`.

---

## 89h. Compose File Index (Docker README)

### Finding

Seven Docker Compose files exist across the project with no single reference document
explaining their purpose, intended environment, or how to invoke them. Operators must
read multiple files to determine which combination to use for a given scenario.

After 89c, six files remain:

| File | Lines | Current documentation |
|------|-------|-----------------------|
| `docker/docker-compose.poc.yml` | 418 | Inline comments only |
| `docker/docker-compose.python-legacy.yml` | 46 | Header comment |
| `docker/docker-compose.scale.yml` | 92 | Header comment |
| `docker/docker-compose.test.yml` | 160 | Header comment |
| `docker/docker-compose.prod.yml` | 369 | Header comment |
| `docker/docker-compose.monitoring.yml` | 303 | No header |

### Implementation

Create `docker/README.md` with the following content:

```markdown
# Docker Infrastructure Reference

This document is the single source of truth for all Docker Compose files in JA4proxy.
Read this before running any `docker compose` command.

---

## Compose File Inventory

| File | Type | Environment | Purpose |
|------|------|-------------|---------|
| `docker/docker-compose.poc.yml` | Standalone base | Development / POC | Full stack: HAProxy + Go proxy + Redis + tarpit + analytics + admin-api + management |
| `docker/docker-compose.python-legacy.yml` | Overlay | Development only | Adds Python proxy alongside Go proxy for cross-language parity validation |
| `docker/docker-compose.scale.yml` | Overlay | Load testing | Replaces single proxy with 4 worker instances behind HAProxy |
| `docker/docker-compose.test.yml` | Standalone | CI / integration tests | Isolated test environment: Go proxy + Python proxy + TLS backend + recorder + test-runner |
| `docker/docker-compose.prod.yml` | Standalone | Production | Single-instance production stack; uses Docker secrets for credentials |
| `docker/docker-compose.monitoring.yml` | Overlay (joins POC networks) | Development / POC | Prometheus + Grafana + Loki + Alertmanager; attaches to a running POC stack |

---

## Scenarios and Commands

### Run the development stack (most common)

```bash
export REDIS_PASSWORD=$(openssl rand -base64 32)
export BACKEND_HOST=your-backend.example.com
docker compose -f docker/docker-compose.poc.yml up -d
```

### Run the development stack with monitoring

Requires the POC stack to already be running (monitoring joins its networks externally).

```bash
docker compose -f docker/docker-compose.monitoring.yml up -d
```

### Run the integration test suite (CI)

```bash
docker compose -f docker/docker-compose.test.yml up --build \
  --abort-on-container-exit --exit-code-from test-runner
```

Makefile target: `make test-go-docker`

### Add the Python proxy for parity comparison

```bash
docker compose -f docker/docker-compose.poc.yml \
               -f docker/docker-compose.python-legacy.yml \
               --env-file .env.dev up -d
```

Makefile target: `make go-start`

### Run the multi-worker scaled stack

```bash
docker compose -f docker/docker-compose.poc.yml \
               -f docker/docker-compose.scale.yml up -d
```

Makefile target: `make start-scaled`

### Deploy to production (single instance)

```bash
mkdir -p secrets
openssl rand -base64 48 > secrets/redis_password.txt
echo "your-abuseipdb-key" > secrets/abuseipdb_api_key.txt
chmod 600 secrets/*.txt
BACKEND_HOST=upstream.example.com ENVIRONMENT=production \
  docker compose -f docker/docker-compose.prod.yml up -d
```

---

## Overlay vs Standalone

**Standalone** files are complete stacks that can be brought up on their own.

**Overlay** files must be combined with a base file using multiple `-f` flags.

| File | Standalone? | Required base |
|------|-------------|---------------|
| `docker/docker-compose.poc.yml` | Yes | — |
| `docker/docker-compose.python-legacy.yml` | No | `docker/docker-compose.poc.yml` |
| `docker/docker-compose.scale.yml` | No | `docker/docker-compose.poc.yml` |
| `docker/docker-compose.test.yml` | Yes | — |
| `docker/docker-compose.prod.yml` | Yes | — |
| `docker/docker-compose.monitoring.yml` | No | Running POC stack (external network join) |

---

## Network Architecture (POC and Production Stacks)

| Network | Internal? | Connected services |
|---------|-----------|-------------------|
| `ja4proxy-dmz` | No | HAProxy, proxy, trafficgen, test |
| `ja4proxy-data` | Yes | proxy, redis, admin-api, management, test |
| `ja4proxy-origin` | Yes | proxy, backend, tarpit, test |
| `ja4proxy-mgmt` | No | proxy, analytics, admin-api, management |

`internal: true` networks have no outbound internet access. Redis and the origin backend
are isolated.

The monitoring overlay joins `ja4proxy-dmz`, `ja4proxy-data`, and `ja4proxy-mgmt` as
external networks to scrape metrics.

---

## Credentials

All compose files use `${REDIS_PASSWORD:?REDIS_PASSWORD is required}` — the stack
will refuse to start if this variable is unset or empty. There are no silent defaults
for security credentials.

The production stack (`docker/docker-compose.prod.yml`) uses Docker secrets (files in
`secrets/`) instead of environment variables.

---

## Dockerfile Location Policy

| Location | Rule |
|----------|------|
| `docker/` | All production Dockerfiles that do not own their own module directory |
| `tests/docker/` | All test-infrastructure Dockerfiles |
| `<module>/` | Dockerfiles for independently deployable modules with their own build context, labelled `dockerfile.location=module` |

Module Dockerfiles (`src/analytics/Dockerfile`, `tarpit/Dockerfile`) carry the label
`dockerfile.location=module` to distinguish them from `docker/` images in inventory
tooling. Both use the root project directory as their build context.
```

---

## 89i. Dockerfile Location Policy Metadata

### Finding

`src/analytics/Dockerfile` and `tarpit/Dockerfile` live inside their source
directories. All other production Dockerfiles live in `docker/`. Both files are
referenced via the root project context in compose files. The pattern is intentional
but undocumented, creating confusion about where to look for Dockerfiles.

Physical relocation is deferred — both files require the root context for their COPY
instructions, and the move would require path adjustments with no functional benefit at
this time. The policy established here uses LABEL metadata to make the distinction
machine-readable.

### Implementation

Add `LABEL` to `src/analytics/Dockerfile` after the `FROM` line:

```dockerfile
LABEL dockerfile.location="module" \
      dockerfile.module="src/analytics" \
      dockerfile.build-context="root"
```

Add `LABEL` to `tarpit/Dockerfile` after the `FROM` line:

```dockerfile
LABEL dockerfile.location="module" \
      dockerfile.module="tarpit" \
      dockerfile.build-context="module-local"
```

The Dockerfile Location Policy is documented in `docker/README.md` (created in 89h).

---

## 89j. Fix Broken `start-scaled` Makefile Target

### Finding

`Makefile` line 130 references `docker/docker-compose.scale.yml`:

```makefile
@docker compose -f docker/docker-compose.poc.yml -f docker/docker-compose.scale.yml up -d
```

The file `docker/docker-compose.scale.yml` does not exist. The actual file is
`docker/docker-compose.scale.yml` at the repo root. The `start-scaled` target has been broken
since it was written.

### Implementation

```makefile
# Before (Makefile line 130)
@docker compose -f docker/docker-compose.poc.yml -f docker/docker-compose.scale.yml up -d

# After
@docker compose -f docker/docker-compose.poc.yml -f docker/docker-compose.scale.yml up -d
```

---

## Testing Requirements

All tests below must be written **before** the fixes in 89a–89j are applied (TDD for
content-validation tests). Tests that verify operational behaviour (restart, healthcheck)
are marked as regression tests and should be written alongside their respective fix.

### `tests/unit/test_docker_consistency.py`

A pure-Python test module requiring only `pyyaml` (already in `requirements.txt`) and
the standard library. Runs without a Docker daemon in under two seconds.

Note on variable interpolation: Docker Compose's `${VAR:?error}` syntax is preserved
as a literal string by pyyaml (it does not expand variables). String-contains checks
work correctly on the literal text — `":?" in value` correctly identifies the required
form.

Required test cases:

**Python version pinning (89a)**

Parse every `FROM` line in every Dockerfile under `docker/`, `tests/docker/`,
`src/analytics/`, and `tarpit/`. For any line referencing a `python:` image, assert the
tag is exactly `3.14.0-slim`. Reject `3.14-slim`, `3.11-slim`, or any other form.
Assertion message must name the file and line number.

**Go version pinning (89b)**

Parse every `FROM` line referencing a `golang:` image. Assert the tag is exactly
`1.25-alpine`. Reject `1.23-alpine`, `1.24-alpine`, or any unpinned form.

**No `network: host` in build sections (89e)**

Parse every docker-compose YAML file. For each service with a `build:` block, assert
the block does not contain a `network` key. Any `network: host` in a build block must
fail and name the file and service.

**REDIS_PASSWORD uses `:?` form (89f)**

Parse every docker-compose YAML file except `docker/docker-compose.prod.yml` (which
uses Docker secrets). For every environment entry containing `REDIS_PASSWORD`, assert
the value contains `:?`. The `:-` form and `:-changeme` form must both fail.

**All volumes use hyphen naming (89d)**

Parse every docker-compose YAML file. For every key in the top-level `volumes:` block
that is not an external reference, assert the name contains no underscore characters.

**All non-external networks use hyphen naming (89d)**

Parse every docker-compose YAML file. For every key in the top-level `networks:` block
that does not have `external: true`, assert the key contains no underscore characters.

**`docker/docker-compose.test.yml` does not exist (89c)**

```python
assert not Path("docker/docker-compose.test.yml").exists(), (
    "docker/docker-compose.test.yml must be deleted (Phase 89c); "
    "it is an abandoned stub that collides with docker/docker-compose.test.yml"
)
```

**Restart policy on permanent services (89g)**

Parse `docker/docker-compose.poc.yml`. Assert that each of `proxy`, `redis`, `backend`,
`tarpit`, `analytics`, `admin-api`, `trafficgen`, `haproxy`, `management` has
`restart: unless-stopped`.

**`docker/README.md` exists and has valid content (89h)**

```python
readme = Path("docker/README.md")
assert readme.exists()
content = readme.read_text()
assert "docker/docker-compose.poc.yml" in content
assert "docker-compose.monitoring.yml" in content
# All local markdown links must reference files that exist
for link in re.findall(r'\[.*?\]\((?!http)(.*?)\)', content):
    assert (Path("docker") / link).exists() or Path(link).exists(), (
        f"docker/README.md links to non-existent file: {link}"
    )
```

**LABEL metadata present on module Dockerfiles (89i)**

```python
for path in ["src/analytics/Dockerfile", "tarpit/Dockerfile"]:
    content = Path(path).read_text()
    assert 'dockerfile.location="module"' in content, (
        f"{path} is missing LABEL dockerfile.location (Phase 89i)"
    )
```

**`start-scaled` Makefile target references correct path (89j)**

```python
makefile = Path("Makefile").read_text()
assert "docker/docker-compose.scale.yml" not in makefile, (
    "Makefile references non-existent docker/docker-compose.scale.yml (Phase 89j)"
)
```

### `tests/integration/test_dockerfile_coverage.py`

Integration-level tests that validate structural relationships. These run on the host
filesystem without a Docker daemon but do require filesystem access to the repo root.
These are regression tests — write them alongside the fixes.

**Every Dockerfile in `docker/` is referenced in at least one compose file**

Glob all files matching `docker/Dockerfile*`. For each one, search all compose YAML
files for a `build.dockerfile` value that resolves to that path. Assert at least one
match exists.

**Every Dockerfile in `tests/docker/` is referenced in at least one compose file**

Same as above for `tests/docker/Dockerfile*`. Expected referencing file:
`docker/docker-compose.test.yml`.

**Every `build.context` resolves to an existing directory**

Parse all compose YAML files. For each service with a `build:` block, resolve `context`
relative to the compose file's directory. Assert the resolved path exists.

**Every `build.dockerfile` path resolves to an existing file**

Parse all compose YAML files. For each service with a `build:` block specifying
`dockerfile:`, resolve the path relative to the build context. Assert the file exists.

**Compose files validate individually**

```python
@pytest.mark.skipif(not shutil.which("docker"), reason="Docker not installed")
def test_standalone_compose_files_validate():
    for compose_file, env in [
        ("docker/docker-compose.poc.yml", {"REDIS_PASSWORD": "test", "BACKEND_HOST": "lint"}),
        ("docker/docker-compose.test.yml", {}),
        ("docker/docker-compose.prod.yml", {"BACKEND_HOST": "lint"}),
    ]:
        result = subprocess.run(
            ["docker", "compose", "-f", compose_file, "config", "--quiet"],
            env={**os.environ, **env},
            capture_output=True,
        )
        assert result.returncode == 0, (
            f"{compose_file} failed validation:\n{result.stderr.decode()}"
        )
```

**Monitoring overlay can join renamed POC networks**

```python
@pytest.mark.skipif(not shutil.which("docker"), reason="Docker not installed")
def test_monitoring_overlay_references_valid_poc_networks():
    """External network names in monitoring must match explicit name: in poc."""
    poc = yaml.safe_load(Path("docker/docker-compose.poc.yml").read_text())
    monitoring = yaml.safe_load(
        Path("docker/docker-compose.monitoring.yml").read_text()
    )
    poc_network_names = {
        cfg.get("name", key)
        for key, cfg in poc.get("networks", {}).items()
    }
    for key, cfg in monitoring.get("networks", {}).items():
        if cfg and cfg.get("external"):
            declared_name = cfg.get("name", key)
            assert declared_name in poc_network_names, (
                f"monitoring overlay references network '{declared_name}' "
                f"which is not declared in docker/docker-compose.poc.yml"
            )
```

### Makefile Target

Add to the Makefile at the bottom (following the existing pattern for phase targets):

```makefile
## Phase 89 targets
test-phase-89:
	python -m pytest tests/unit/test_docker_consistency.py \
	                 tests/integration/test_dockerfile_coverage.py -v

test-phase-89-lint:
	REDIS_PASSWORD=lint BACKEND_HOST=lint \
	  docker compose -f docker/docker-compose.poc.yml config --quiet
	docker compose -f docker/docker-compose.test.yml config --quiet
	BACKEND_HOST=lint \
	  docker compose -f docker/docker-compose.prod.yml config --quiet
```

---

## Acceptance Criteria

- [ ] `docker/Dockerfile.admin` uses `FROM python:3.14.0-slim` (was `3.11-slim`)
- [ ] `docker/Dockerfile.management` uses `FROM python:3.14.0-slim` (was `3.11-slim`); `passlib[bcrypt]` compatibility on 3.14 verified or replaced
- [ ] All four test Dockerfiles use `FROM python:3.14.0-slim` (was `python:3.14-slim`)
- [ ] `tests/docker/Dockerfile.test-runner` builder stage uses `FROM golang:1.25-alpine` (was `golang:1.23-alpine`)
- [ ] `docker/Dockerfile.admin` and `docker/Dockerfile.management` added to `HADOLINT_DOCKERFILES` in `Makefile`
- [ ] `docker/docker-compose.test.yml` does not exist (deleted)
- [ ] Makefile line 277 comment referencing the deleted stub is removed
- [ ] All networks in `docker/docker-compose.poc.yml` use hyphen naming with explicit `name:` fields (`ja4proxy-dmz`, `ja4proxy-data`, `ja4proxy-origin`, `ja4proxy-mgmt`)
- [ ] All volumes in `docker/docker-compose.poc.yml` use hyphen naming (`redis-data`, `redis-sock`, `reports-data`)
- [ ] `docker/docker-compose.prod.yml` `redis_data` volume renamed to `redis-data`
- [ ] `docker/docker-compose.monitoring.yml` external network `name:` fields updated to `ja4proxy-dmz`, `ja4proxy-data`, `ja4proxy-mgmt`; stale comment updated
- [ ] `docker/docker-compose.python-legacy.yml` network references updated to hyphen names
- [ ] `docs/architecture/ISOLATION_MODEL.md`, `scripts/check-isolation.sh`, `docs/PROJECT_STATUS.md` updated with new network names
- [ ] Zero occurrences of `network: host` in any `build:` block across all compose files
- [ ] `docker/docker-compose.monitoring.yml` redis-exporter uses `${REDIS_PASSWORD:?REDIS_PASSWORD is required}` (was `${REDIS_PASSWORD:-changeme}`)
- [ ] `proxy`, `redis`, `backend`, `tarpit`, `analytics`, `admin-api`, `trafficgen` all have `restart: unless-stopped` in `docker/docker-compose.poc.yml`
- [ ] `docker/README.md` exists with compose file inventory, usage commands per scenario, overlay vs standalone table, network architecture table, and Dockerfile location policy
- [ ] `src/analytics/Dockerfile` carries `LABEL dockerfile.location="module"`
- [ ] `tarpit/Dockerfile` carries `LABEL dockerfile.location="module"`
- [ ] `Makefile` `start-scaled` target references `docker/docker-compose.scale.yml` (not `docker/docker-compose.scale.yml`)
- [ ] `tests/unit/test_docker_consistency.py` exists; all assertions pass against the fixed files
- [ ] `tests/integration/test_dockerfile_coverage.py` exists; all assertions pass
- [ ] `make test-phase-89` passes with zero failures
- [ ] `make lint-docker` passes with zero warnings
- [ ] `make test-phase-89-lint` passes for all standalone compose files

---

## Files to Modify

| File | Change |
|------|--------|
| `docker/Dockerfile.admin` | `FROM python:3.11-slim` → `FROM python:3.14.0-slim` |
| `docker/Dockerfile.management` | `FROM python:3.11-slim` → `FROM python:3.14.0-slim` (after passlib compat check) |
| `management/requirements.txt` | Replace `passlib[bcrypt]>=1.7.4` with `bcrypt>=4.0` if passlib fails on 3.14 |
| `tests/docker/Dockerfile.python-proxy` | `FROM python:3.14-slim` → `FROM python:3.14.0-slim` |
| `tests/docker/Dockerfile.recorder` | `FROM python:3.14-slim` → `FROM python:3.14.0-slim` |
| `tests/docker/Dockerfile.tls-backend` | `FROM python:3.14-slim` → `FROM python:3.14.0-slim` |
| `tests/docker/Dockerfile.test-runner` | Builder: `golang:1.23-alpine` → `golang:1.25-alpine`; Runtime: `python:3.14-slim` → `python:3.14.0-slim` |
| `Makefile` | Add `docker/Dockerfile.admin` and `docker/Dockerfile.management` to `HADOLINT_DOCKERFILES` (line 279); remove line 277 comment; fix line 130 `docker/docker-compose.scale.yml` → `docker/docker-compose.scale.yml` |
| `docker/docker-compose.test.yml` | Delete entirely |
| `docker/docker-compose.poc.yml` | Rename 4 networks to hyphen form with `name:` fields; rename volumes; update all service network lists; remove `network: host` from 7 build blocks; add `restart: unless-stopped` to 7 services |
| `docker/docker-compose.python-legacy.yml` | Update 4 network references to hyphen names; update comment on line 44 |
| `docker/docker-compose.prod.yml` | `redis_data` → `redis-data`; remove `network: host` from 3 build blocks |
| `docker/docker-compose.monitoring.yml` | Update 3 external network `name:` fields; update stale comment; `${REDIS_PASSWORD:-changeme}` → `${REDIS_PASSWORD:?REDIS_PASSWORD is required}` |
| `src/analytics/Dockerfile` | Add `LABEL dockerfile.location="module"` |
| `tarpit/Dockerfile` | Add `LABEL dockerfile.location="module"` |
| `docs/architecture/ISOLATION_MODEL.md` | Update old network key names in zone table and acceptance criteria table |
| `scripts/check-isolation.sh` | Update diagnostic comments referencing `data_net` and `origin_net` |
| `docs/PROJECT_STATUS.md` | Update four-zone network names at line 108 |
| `docker/README.md` | Create new file |
| `tests/unit/test_docker_consistency.py` | Create new file |
| `tests/integration/test_dockerfile_coverage.py` | Create new file |

---

## Notes for Implementer

**Implementation order.** The sub-sections can be applied in any order except: (1)
complete 89c before 89d to avoid confusing the two `test.yml` files during editing; (2)
apply all three files in 89d in a single commit — never commit poc.yml with new network
names before monitoring.yml is updated, as `make lint-docker` will fail between them.

**The 89d changes require `docker compose down` first.** See the operational warning in
§89d. Do not apply network or volume renames to a running stack.

**Rebuild with `--no-cache` after the Python base image upgrade.** Docker's layer cache
will continue serving the old `3.11-slim` base until you force a rebuild:

```bash
docker compose -f docker/docker-compose.poc.yml build --no-cache admin-api management
docker compose -f docker/docker-compose.test.yml build --no-cache
```

Verify the running image actually uses the new base after rebuilding:

```bash
docker inspect ja4proxy-admin-api:1.0.0 | python3 -c \
  "import json, sys; d = json.load(sys.stdin); \
   print([e for e in d[0]['Config']['Env'] if 'PYTHON' in e])"
```

**`docker/docker-compose.scale.yml` is not modified in this phase.** It uses its own
`ja4proxy_network` which is independent of the POC four-zone model, and it has its own
`redis-sock` volume reference. Network naming normalisation for the scale file is
deferred to a future phase.

**`docker/docker-compose.prod.yml` network definitions are unchanged.** The prod file
already uses independent hyphen-named networks (`ja4proxy-frontend`, `ja4proxy-backend`,
`ja4proxy-monitoring`) with no dependency on the POC stack's network names. The only
prod file changes in this phase are: remove `network: host` from build blocks (89e) and
rename `redis_data` → `redis-data` (89d).

**TDD order.** Write and run `tests/unit/test_docker_consistency.py` before any code
changes. All tests will fail against the current codebase. Apply fixes 89a–89j in
order. The test suite becomes the regression guard ensuring fixes are not accidentally
reverted.
