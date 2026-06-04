---
phase: 208
title: "Docker Build Dependency Caching"
status: PROPOSED
size: MEDIUM
created: 2026-05-30
audience: [developer, operator]
dependencies: []
---

# Build Dependency Caching

## Problem

Every local `make build` or `make rebuild` re-downloads the same system packages (`apt-get install`), Python dependencies (`pip install`), and (for some images) Go modules from scratch. On a typical developer machine or CI runner this adds 30–90 seconds per image per build with no benefit — the dependencies are unchanged between builds.

The user's specific complaint: **"If I do two builds in a row, it will download dependencies again."**

## Current State

### What gets downloaded on every build

| Category | Packages | Affected images |
|----------|----------|-----------------|
| `apt-get install` | `gcc`, `libpcap-dev`, `build-essential`, `curl`, `libssl-dev`, `libyaml-dev`, `wget` | 7 of 14 Dockerfiles |
| `pip install` | Full `requirements.txt` (~30 packages), `requirements-analytics.txt`, `management/requirements.txt` | 10 of 14 Dockerfiles |
| `go mod download` | 17 direct + ~30 indirect Go modules | `Dockerfile.go-proxy` (builder stage) |

### What already works

- **`Dockerfile.go-proxy`** — standard Go caching pattern: `COPY go.mod go.sum ./` then `RUN go mod download` in a separate layer. Source changes don't invalidate the module layer.
- **CI workflows** (`go-proxy-image.yml`, `release-cli.yml`) — use `docker/setup-buildx-action@v4` with `cache-from: type=gha` / `cache-to: type=gha,mode=max` (GitHub Actions cache).

### What doesn't work

- **No `DOCKER_BUILDKIT=1`** in any local build (`make build`, `make management-build`, etc.) — falls back to legacy builder.
- **No `--mount=type=cache`** for apt or pip in any Dockerfile.
- **No `docker buildx`** invocation in local builds.
- **No registry-based cache** (`type=registry`) for CI or team sharing.
- **`make rebuild`** explicitly uses `--no-cache`, which is correct for clean builds but means there is no fast incremental build path for Python images.
- **`.dockerignore`** does not exclude `tests/` from production images (noted in comment, but the overhead is small).

## Implementation Plan

### 1 — Enable Docker BuildKit by default

**Files:** `Makefile`, `deploy/docker/docker-compose.poc.yml`

Set `DOCKER_BUILDKIT=1` and `COMPOSE_DOCKER_CLI_BUILD=1` as environment variables in the Makefile's `build` target. This enables BuildKit features (including `--mount=type=cache`) for all compose-based builds.

```makefile
build:
    DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 \
    docker compose -f deploy/docker/docker-compose.poc.yml --env-file .env build
```

For standalone `docker build` targets (`management-build`, etc.), add a `BUILDKIT_PROGRESS` variable and verify BuildKit is active.

### 2 — Add apt cache mount to all 7 Dockerfiles

**Files:**
- `deploy/docker/Dockerfile` (legacy python proxy)
- `deploy/docker/Dockerfile.test`
- `deploy/docker/Dockerfile.admin`
- `deploy/docker/Dockerfile.management`
- `deploy/docker/Dockerfile.trafficgen`
- `deploy/docker/Dockerfile.mockbackend`
- `src/analytics/Dockerfile`

**Pattern:** Replace `apt-get update/install` with a BuildKit cache mount:

```dockerfile
RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
        gcc libpcap-dev build-essential curl && \
    rm -rf /var/lib/apt/lists/*
```

The `rm -f /etc/apt/apt.conf.d/docker-clean` prevents the default Docker image's APT cleanup (which deletes cached `.deb` files post-install) so BuildKit can persist them across builds.

### 3 — Add pip cache mount to all 10 Python Dockerfiles

**Files:** All Dockerfiles that run `pip install`:
- `deploy/docker/Dockerfile`
- `deploy/docker/Dockerfile.test`
- `deploy/docker/Dockerfile.admin`
- `deploy/docker/Dockerfile.management`
- `deploy/docker/Dockerfile.trafficgen`
- `deploy/docker/Dockerfile.mockbackend`
- `deploy/docker/Dockerfile.python-proxy`
- `deploy/docker/Dockerfile.tls-backend`
- `deploy/docker/Dockerfile.recorder`
- `src/analytics/Dockerfile`

**Pattern:** Wrap `pip install` with a BuildKit cache mount:

```dockerfile
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    pip install --no-cache-dir -r requirements.txt
```

Note: `--no-cache-dir` only disables pip's local wheel cache (which was redundant with BuildKit's cache mount). The `--mount=type=cache` persists downloaded wheels across builds regardless.

### 4 — Add go module cache mount to Dockerfile.go-proxy builder

**File:** `deploy/docker/Dockerfile.go-proxy`

**Pattern:**

```dockerfile
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
```

This is less impactful than the Python/apt wins (the layer-based caching already works well for Go), but it prevents the `go/pkg/mod` directory from being duplicated into the image layer.

### 5 — Add a `make build-ci` target for registry-backed cache sharing

For developers who want to share cache across machines (or CI runners), add:

```makefile
build-ci:
    docker buildx create --use --name=ja4proxy-builder --driver=docker-container
    docker buildx build \
        --cache-from=type=registry,ref=ghcr.io/seanpor/ja4proxy-buildcache \
        --cache-to=type=registry,ref=ghcr.io/seanpor/ja4proxy-buildcache,mode=max \
        -f deploy/docker/Dockerfile.go-proxy \
        -t ja4proxy-go:latest .
```

This requires an authenticated `docker login ghcr.io` but enables **cross-machine cache sharing** — CI pushes the cache, developers pull it.

### 6 — Fix `docker-compose.prod.yml` to use Go proxy Dockerfile

**File:** `deploy/docker/docker-compose.prod.yml`

Line 58 currently points to `deploy/docker/Dockerfile` (Python legacy proxy). Change to `deploy/docker/Dockerfile.go-proxy`.

This is technically a separate concern but naturally fits here since the prod.yml is part of the build definition.

### 7 — Update `.dockerignore`

Exclude `tests/` from production image builds (the comment on lines 3-5 notes this is negligible for context size, but the real cost is invalidating the Docker build cache when test files change).

## Expected Impact

| Optimization | Images affected | Time saved per build |
|-------------|-----------------|---------------------|
| apt cache mount | 7 images | 15–30s |
| pip cache mount | 10 images | 10–20s |
| go mod cache mount | 1 image | 5–10s (Go layers already cached) |
| `.dockerignore` tests/ | 8 production images | Avoids cache invalidation |
| **Total (second build)** | **All images** | **~30–60s saved** |

The first build with cache mounts will be identical in time (cache is cold). The **second sequential build** and all subsequent builds skip the download phase entirely for unchanged dependencies.

## Test Strategy

- **Build timing benchmark:** `time make build` before and after changes, run twice, compare first vs second build duration.
- **Dependency integrity:** `docker compose build` then verify the running containers have expected versions (`python --version`, `go version`, `pip list`).
- **Rebuild sanity:** `make rebuild` (with `--no-cache`) must still produce a working image.
- **CI validation:** Ensure `go-proxy-image.yml` and `release-cli.yml` continue to work (they already use BuildKit with `type=gha` cache — the changes are additive).

## Acceptance Criteria

- [ ] `make build` uses Docker BuildKit (verify with `DOCKER_BUILDKIT=1` env)
- [ ] Second sequential `make build` is visibly faster (check `docker build` output — cached layers show `CACHED`)
- [ ] `apt-get install` packages are not re-downloaded on unchanged builds (apt cache mount)
- [ ] `pip install` packages are not re-downloaded on unchanged builds (pip cache mount)
- [ ] All 14 Dockerfiles build successfully
- [ ] `docker-compose.prod.yml` references `Dockerfile.go-proxy` (not legacy Python Dockerfile)
- [ ] `make rebuild` still produces functional images (no regressions from cache mount syntax)
- [ ] No new CI failures — `go-proxy-image.yml` and `release-cli.yml` remain green
- [ ] `make lint-phases` exits 0

## Risks & Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| BuildKit cache mount syntax not supported on older Docker Engine (< 18.09) | MEDIUM | Document minimum Docker version; fall back to `DOCKER_BUILDKIT=0` env var |
| Cache mount sharing=locked causes concurrent build deadlock | LOW | Use `sharing=shared` if parallel builds are needed; document trade-off |
| apt cache grows unbounded | LOW | BuildKit auto-evicts; add `apt-get clean` as a fallback |
| `.dockerignore` `tests/` exclusion breaks `Dockerfile.test` | MEDIUM | Keep the existing exception — `Dockerfile.test` needs tests/ |
| pip cache mount conflicts with `--no-cache-dir` | LOW | Remove `--no-cache-dir` when using cache mount (redundant — BuildKit cache is the real cache) |

## Out of Scope

- Python → Go migration of any Dockerfiles
- CI pipeline restructuring (workflows already use BuildKit)
- Multi-stage build restructuring beyond cache mount additions
- Reducing base image size (that's a separate concern — distroless, Alpine variants)
- Docker layer squashing or image size optimization
- The proxy runtime errors themselves (handled in Phase 209)
