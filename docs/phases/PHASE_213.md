---
phase: 213
title: "Dependency Update Checker (`make check-updates`)"
status: COMPLETE
size: MEDIUM
created: 2026-06-01
audience: [developer]
dependencies: [212]
---

# Dependency Update Checker (`make check-updates`)

## Goal

Create a `make check-updates` target and a Python script (`scripts/check_updates.py`) that checks every lockfile-style dependency in the project for available upstream updates. The output is a single report showing what's stale across all four dependency categories, so a developer (or a junior engineer) can see at a glance what needs attention.

The target does **not** install or modify anything — it only reports. It is safe to run at any time.

## Scope

### What each check covers

| # | Category | Source of truth | Check method |
|---|----------|-----------------|--------------|
| 1 | **Docker images** | `docker-compose.*.yml` files and `Makefile:TRIVY_IMAGES` | Query Docker Hub / GCR tag API for the latest version matching the current image's version pattern |
| 2 | **Go modules** | `cmd/proxy/go.mod`, `deploy/terraform-provider/go.mod` | `go list -u -m all` — the `-u` flag tells Go to check what upgrades are available |
| 3 | **Python packages** | `requirements.txt`, `requirements-analytics.txt`, `management/requirements.txt` | `pip list --outdated --format=json` against each venv |
| 4 | **Node packages** | `package.json` / `package-lock.json` | `npm outdated --json` |

### Files to create

- `scripts/check_updates.py` — the engine: orchestrates all four checks, prints a color-coded report
- `Makefile` — add `check-updates` target (near `check-image-versions` at line 499)

### Files to check (read-only, no changes expected)

- All `docker-compose.*.yml` files under `deploy/docker/` — for Docker image version extraction
- `Makefile` — read `TRIVY_IMAGES` to know which images to check
- `cmd/proxy/go.mod` — Go dependency source
- `deploy/terraform-provider/go.mod` — Go dependency source
- `requirements.txt`, `requirements-analytics.txt`, `management/requirements.txt` — Python dependency sources
- `package.json` — Node dependency source

### Not in scope

- Actually upgrading any dependency (covered by separate phases)
- CVE scanning (that's `make scan-images` / `make scan`)
- System packages installed inside Dockerfiles via `apk add` or `apt-get install`
- Indirect / transitive dependency review
- Pinning or locking new versions of anything

## Implementation Plan

### Step 1 — Create `scripts/check_updates.py`

The script is a single Python file with a `main()` function that runs four sub-checks sequentially. Each sub-check calls an external tool or API and collects results into a list of `(name, current_version, available_version, category)` tuples. At the end it prints a unified table.

**1a — Docker image check**
For each image in `Makefile:TRIVY_IMAGES` (plus any composed images not in `TRIVY_IMAGES` like `cadvisor`, `docker-socket-proxy`, etc.), query the registry API to find the newest tag that matches the image's version family.

- **Docker Hub** (most images): `GET https://hub.docker.com/v2/repositories/{namespace}/{repo}/tags?page_size=100` — returns a JSON list of tags. Parse the response, sort by semver, find the latest.
- **GCR** (`gcr.io/cadvisor/cadvisor`): `GET https://gcr.io/v2/cadvisor/cadvisor/tags/list` — returns a JSON object with tags.
- Only report tags that are **newer** than the current tag (semver comparison).
- Skip tags that look like dev/beta/rc/nightly (optional — use a blocklist of common suffixes).

**1b — Go module check**
Run `go list -u -m all` in `cmd/proxy/` and `deploy/terraform-provider/`. The `-u` flag makes Go check upstream registries and annotate any upgradable module with `[new_version]`. The script parses lines matching the pattern `module vX.Y.Z [vA.B.C]` and reports them.

Requires `GOROOT=/snap/go/current` on this host (same as every other Go target in the Makefile).

**1c — Python package check**
Run `pip list --outdated --format=json` (or `uv pip list --outdated` if `uv` is available, since it's faster). The script finds a working Python interpreter, installs nothing, and just reads the output.

If no venv is active, the script should warn and skip (rather than checking the system Python — we don't want false positives from unrelated packages).

**1d — Node package check**
Run `npm outdated --json` in the project root. If `npm` is not installed or `package.json` has no deps, skip gracefully.

**Output format**

The script prints a single report like this:

```
=== Docker images ===
  haproxy                    2.8.5-alpine  →  2.8.12-alpine   (patch available)
  prom/prometheus            v2.48.0       →  v2.55.0         (minor available)
  grafana/grafana            10.2.2        →  11.5.0          (major available — review breaking changes)
  ...

=== Go modules (cmd/proxy) ===
  github.com/redis/go-redis/v9    v9.18.0  →  v9.20.0         (minor available)
  ...

=== Python packages (requirements.txt) ===
  aiohttp                     3.9.5        →  3.10.0          (minor available)
  ...

=== Node packages ===
  sql.js                      1.14.0       →  1.15.0          (patch available)

Summary: 12 updates available (3 major, 5 minor, 4 patch)
```

Color coding:
- Green — up to date (no output needed)
- Yellow — patch or minor available
- Red — major version available (breaking changes likely)

**Script design for a junior engineer**

- Every function has a docstring explaining what it does and why
- Constants at the top (image list, registry URLs) for easy editing
- No external Python packages beyond stdlib (uses `urllib.request` for HTTP, `subprocess` for shelling out)
- One `main()` that calls four clearly-named functions: `check_docker_images()`, `check_go_modules()`, `check_python_packages()`, `check_node_packages()`
- Graceful skips: if Docker is not running, if `go` is not found, if `npm` is not installed — print a clear warning and continue

### Step 2 — Add Makefile target

Add to `Makefile` near the existing `check-image-versions` target (around line 499):

```makefile
check-updates:  # -- Check all project dependencies for available updates
	python3 scripts/check_updates.py
```

Use `$(MAKECMDGOALS)` or just a simple comment for `--` help text. Add a one-line description in the help section (around line 96).

### Step 3 — Register in manifest, sync

Standard close-out: register Phase 213 in `manifest.yaml`, update `CHANGELOG.md`, run `sync-roadmap.py`, verify `make lint-phases`.

## Test Strategy

- Run `make check-updates` and verify the report prints all four sections (even if some sections say "none found" or "unavailable")
- Run with Docker daemon **stopped** — verify Docker section shows a clear "cannot reach Docker daemon" warning (doesn't crash)
- Run without a Go venv active — verify Go section warns and skips
- Run with `npm` not installed — verify Node section warns and skips (doesn't crash)
- Run `python3 scripts/check_updates.py --help` — verify the script has a help flag

## Acceptance Criteria

1. `make check-updates` prints a 4-section report (Docker, Go, Python, Node)
2. Every section handles its tool being missing gracefully (warning, not crash)
3. The report uses color coding (green/yellow/red) for update severity
4. A summary line at the bottom shows total available updates by type
5. No dependencies are modified by running the target
6. `make lint-phases` exits 0

## Out of scope

- Helm chart version checks (no external dependency)
- System package (`apk`/`apt`) update checking
- CVE scanning or security scoring
- Automatic PR generation for updates (Dependabot / Renovate)
- Sending reports to Slack or email
