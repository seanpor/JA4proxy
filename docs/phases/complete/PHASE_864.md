# Phase 864: Third-Party CVE Triage & HAProxy Fix-Forward Bump

## Goal
Remediate the 6 open baseline monitor issues (#700, #701, #703, #704, #705, #706) by applying the automated HAProxy 3.4.7 fix-forward bump and registering formal, machine-checked reachability waivers for upstream base-image package disclosures.

## Scope
1. **WP-864a: HAProxy Fix-Forward Bump (Resolves #703, #706)**
   - Upgrade HAProxy from `haproxy:2.8.28-alpine` to `haproxy:3.4.7-alpine` across:
     - `deploy/docker/docker-compose.poc.yml`
     - `deploy/docker/docker-compose.prod.yml`
     - `deploy/docker/docker-compose.scale.yml`
   - Validate configuration syntax:
     ```bash
     docker run --rm --add-host proxy:127.0.0.1 -v $(pwd)/config/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro haproxy:3.4.7-alpine haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg
     ```
   - Update image inventory in `docs/reference/DOCKER_IMAGES.md`.
   - Update `security/waivers.yaml`: `haproxy:3.4.7-alpine` is clean of `CVE-2026-103111` (`pcre2`), so prune `haproxy:2.8.28-alpine` from `CVE-2026-103111`'s carrier list, leaving `tecnativa/docker-socket-proxy:v0.5.0`.

2. **WP-864b: CVE-2026-85091 Waiver Registration (Resolves #704, #705)**
   - Package: `zlib` 1.3.2-r0 in Alpine base images (`tecnativa/docker-socket-proxy:v0.5.0` and `redis:7.4.11-alpine@sha256:520775a41a63e77e06c73e35d2fd9cc15921a609516818796b4ecbb813078bc7`).
   - Reachability analysis:
     - `tecnativa/docker-socket-proxy`: `reachability: local-socket-only` (no published host port, mounted to `/var/run/docker.sock`).
     - `redis`: `reachability: local-socket-only` (no published host port in deployed compose definitions `poc`, `prod`, `scale`; communicates over internal Docker networks and unix socket).
   - Register entry in `security/waivers.yaml` with 90-day expiry and recheck trigger: `"upstream alpine base image rebuilds with zlib 1.3.2-r1"`.

3. **WP-864c: CVE-2026-109518 Waiver Registration (Resolves #700, #701)**
   - Package: `apt` 2.8.3 in Ubuntu 24.04 base layers of `grafana/grafana:13.2.4-ubuntu` and `grafana/alloy:v1.21.2`.
   - Reachability analysis: `reachability: internal-monitoring-only` (monitoring containers bound to `${AGENT_BIND_IP:-127.0.0.1}`; package manager `apt` is not invoked at runtime or accessible via HTTP).
   - Register entry in `security/waivers.yaml` with 90-day expiry and recheck trigger: `"upstream ubuntu base image rebuilds with apt 2.8.4ubuntu0.1"`.

4. **WP-864d: Pipeline & Security Regression Verification**
   - Render derived ignorefiles using `docker run --rm -v "$PWD":/src -w /src ja4proxy-tools python3 scripts/render_waivers.py`.
   - Verify waiver reachability assertions using `docker run --rm -v "$PWD":/src -w /src ja4proxy-tools python3 scripts/reachability_checks.py`.
   - Run `make preflight` (`make lint`, `make scan-regression`, `make test`).
   - Verify cold-start smoke test compatibility (`scripts/start-poc.sh`).

## Out of Scope & Governance
- **No changes to `docs/security/findings.yaml`**: Upstream third-party CVE baselines are governed strictly via `security/waivers.yaml` per Phase 847a.
- No changes to Go proxy runtime code (`cmd/ja4pd`, `internal/`).

## Test Strategy
- **Configuration Parity:** `pytest tests/unit/test_docker_consistency.py` and `pytest tests/unit/test_waivers_registry.py`.
- **Waiver Schema & Reachability:** `python3 scripts/render_waivers.py --check` and `python3 scripts/reachability_checks.py`.
- **HAProxy 3.4 Runtime Syntax Check:** Verified via `haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg`.
- **Surface Regression Scan:** `make scan-regression` must pass with 0 new findings.

## Acceptance Criteria
| ID | Criterion | Verification Method |
|---|---|---|
| AC-1 | HAProxy image bumped to `3.4.7-alpine` across PoC, Prod, and Scale compose files | `git diff deploy/docker/` |
| AC-2 | `config/haproxy.cfg` syntax validation passes under `haproxy:3.4.7-alpine` | `haproxy -c` exits 0 |
| AC-3 | All 6 GitHub issues (#700, #701, #703, #704, #705, #706) resolved / linked | PR description with `Fixes #...` |
| AC-4 | `CVE-2026-85091` (`local-socket-only`) and `CVE-2026-109518` (`internal-monitoring-only`) registered with machine-checked reachability | `python3 scripts/reachability_checks.py` exits 0 |
| AC-5 | Derived ignorefiles (`.trivyignore.*`, `.pip-audit-ignores`) in sync | `python3 scripts/render_waivers.py --check` exits 0 |
| AC-6 | Full local preflight passes without error or regression | `make preflight` exits 0 |
