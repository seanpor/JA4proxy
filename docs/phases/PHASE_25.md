# Phase 25 — Docker Container Management

Status: COMPLETE

**Goal:** Close the security scanning gaps, eliminate unpinned image tags, harmonise
image versions across all compose files, and establish a sustainable image update
policy.

**Status:** OPEN

**Why now?**
A gap audit identified four concrete problems:

1. `TRIVY_IMAGES` in the Makefile is stale — wrong versions and missing images.
2. `redis/redis-stack:latest` is unpinned in `../../docker/docker-compose.prod.yml` — a security risk.
3. `../../docker/docker-compose.prod.yml` and `../../docker/docker-compose.monitoring.yml` disagree on Grafana,
   Loki, and Promtail versions — which version are we actually scanning?
4. First-party built images (`ja4proxy`, `ja4proxy-analytics`, `ja4proxy-tarpit`) are
   never scanned for OS/package CVEs.

This phase fixes all four problems and adds tooling to prevent them returning.

---

## Sub-Task 25a — Image Inventory & Version Pinning

### Deliverables

**`../DOCKER_IMAGES.md`** — canonical registry of every image used in this project.

Format:

```markdown
| Image | Pinned version | Used in | Last reviewed | Notes |
|-------|---------------|---------|---------------|-------|
| python:3.11-slim | 3.11.11-slim | docker/Dockerfile | 2026-03-24 | Base for proxy, analytics |
| redis/redis-stack | 7.4.0-v3 | docker-compose.prod.yml | 2026-03-24 | Pin digest in Phase 25c |
...
```

Covers: third-party images in all compose files, base images in all Dockerfiles.

**Version pinning rules:**

| Tag style | Acceptable? | Notes |
|-----------|-------------|-------|
| `image:latest` | **No** | Unpredictable; breaks reproducibility |
| `image:7` (major only) | **No** | Too coarse; gets silent minor upgrades |
| `image:7.4` (major.minor) | Acceptable for low-risk monitoring images | Still gets patch upgrades |
| `image:7.4.0` (major.minor.patch) | **Preferred** | Fully deterministic |
| `image:7.4.0@sha256:abc` (digest-pinned) | Best | Phase 25d optional stretch goal |

**Immediate pins required:**

| Image | Current | Fix to |
|-------|---------|--------|
| `redis/redis-stack` | `latest` | `7.4.0-v3` (or current stable at time of implementation) |

**Version harmonisation — prod vs monitoring compose files:**

`../../docker/docker-compose.prod.yml` and `../../docker/docker-compose.monitoring.yml` must use the same
version for shared images. Divergence detected:

| Image | prod version | monitoring version | Resolution |
|-------|-------------|-------------------|------------|
| `grafana/grafana` | 10.2.0 | 10.2.2 | Align to 10.2.2 (monitoring is newer) |
| `grafana/loki` | 2.9.0 | 3.3.2 | **Major version jump** — test config compatibility first; see §25a Notes |
| `grafana/promtail` | 2.9.0 | 3.3.2 | **Major version jump** — same as Loki |

**§25a Notes — Loki/Promtail v2→v3 migration:**

Loki 3.x changed the config schema. Before updating prod compose:

1. Spin up monitoring stack (`docker compose -f docker/docker-compose.monitoring.yml up`).
2. Verify `../../monitoring/loki/loki-config.yml` and `../../monitoring/loki/promtail-config.yml` work with 3.3.x.
3. If config is incompatible, update the YAML configs first.
4. Update prod compose only after monitoring stack validates clean.

Do **not** skip validation — a broken Loki in prod means no log ingestion.

### Acceptance Criteria

- [ ] `../DOCKER_IMAGES.md` exists and lists every image from all compose files and Dockerfiles.
- [ ] No `:latest` tags in any compose file (`grep -r ':latest' docker/ | grep image:` returns empty).
- [ ] `../../docker/docker-compose.prod.yml` and `../../docker/docker-compose.monitoring.yml` agree on version for every shared image.
- [ ] All version changes validated against compose `config` command (no parse errors).

---

## Sub-Task 25b — Extended CVE Scan Coverage

### Current gaps

`make scan-images` covers only 8 images from a hardcoded list in the Makefile.
Problems:

- `prom/node-exporter:v1.7.0` (in monitoring compose) not in scan list.
- First-party images (`ja4proxy:latest`, `ja4proxy-analytics:latest`,
  `ja4proxy-tarpit:latest`) never scanned.
- Dockerfiles never checked for config misconfigurations (USER root, no
  HEALTHCHECK, ADD with URL, etc.).
- Both `../../docker/docker-compose.prod.yml` and `../../docker/docker-compose.monitoring.yml` deploy images
  but only prod images are scanned.

### Deliverables

**Fix `TRIVY_IMAGES` in Makefile:**

Update the hardcoded list to match the current prod + monitoring compose versions.
Add `prom/node-exporter:v1.7.0`. Remove duplication from the Makefile; derive from
`../DOCKER_IMAGES.md` where possible.

**`make scan-dockerfiles` target:**

```makefile
scan-dockerfiles:
    @echo "=== Trivy: Dockerfile/compose misconfiguration scan ==="
    @docker run --rm -v $(PWD):/scan aquasec/trivy:latest config \
        --severity HIGH,CRITICAL --exit-code 1 \
        /scan/docker /scan/src/analytics
    @echo "✓ Dockerfile scan passed"
```

Catches: running as root, missing HEALTHCHECK, `ADD` with URL, exposed secrets,
missing `no-new-privileges`, etc. Does not require building images.

**`make scan-first-party` target:**

```makefile
scan-first-party:
    @echo "=== Trivy: first-party image CVE scan ==="
    @echo "    Run 'make build' first to ensure images are current."
    @fail=0; \
    for img in ja4proxy:latest ja4proxy-analytics:latest ja4proxy-tarpit:latest; do \
        echo "  Scanning $$img ..."; \
        result=$$(docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
            aquasec/trivy:latest image --severity HIGH,CRITICAL --exit-code 0 \
            --no-progress --scanners vuln --format table "$$img" 2>&1 \
            | grep -E "CRITICAL|HIGH|Total:" || true); \
        critical=$$(echo "$$result" | grep -c "CRITICAL" || true); \
        echo "    $$result"; \
        [ "$$critical" -eq 0 ] || { echo "    ^^^ CRITICAL in $$img — update base image"; fail=1; }; \
        echo ""; \
    done; \
    [ $$fail -eq 0 ] || exit 1
    @echo "✓ First-party image scan complete"
```

**Update scan policy:**

- `make scan-images` (third-party) — CRITICAL → fail, HIGH → warn (existing policy, keep).
- `make scan-first-party` — CRITICAL → fail; HIGH → warn (same policy).
- `make scan-dockerfiles` — CRITICAL + HIGH → fail (we own these files, zero tolerance).

**Update Makefile help and CI section:**

Add `scan-first-party` and `scan-dockerfiles` to the help block and to any CI
instructions in `CONTRIBUTING.md`.

### Acceptance Criteria

- [ ] `TRIVY_IMAGES` in Makefile matches actual deployed versions (no stale versions).
- [ ] `prom/node-exporter:v1.7.0` included in `TRIVY_IMAGES`.
- [ ] `make scan-dockerfiles` runs without Docker build and reports Dockerfile misconfigs.
- [ ] `make scan-first-party` scans all three first-party images after `make build`.
- [ ] All three scan targets appear in `make help` output.

---

## Sub-Task 25c — Image Update Policy

### The Problem

Without a documented policy, images drift in two failure modes:

- **Too conservative** — images run for years, accumulate CVEs, security team flags
  them in audit.
- **Too aggressive** — images are updated ad hoc, untested minor-version changes
  break configs silently.

### Version Update Policy

**Principle:** Follow releases, do not lead them. Update within a predictable window.

| CVE severity | Action | Timeline |
|-------------|--------|----------|
| CRITICAL | Immediate — file an issue, schedule update within 48h of confirmed fix released | 48h after fix available |
| HIGH | Scheduled — update in next maintenance window | Within 2 weeks |
| MEDIUM/LOW | Deferred — include in quarterly review | Quarterly |
| No CVE | Quarterly review — update if N+1 minor available and stable | Quarterly |

**Stability window:** Do not run an image version released less than 7 days ago unless
it fixes a CRITICAL CVE. Reason: early releases occasionally have regressions; waiting
7 days lets the community surface them.

**Maximum age:** No image should run a version more than 2 minor releases behind
the current stable. Example: if grafana is at 11.2.x, we should be on ≥11.0.x.

**Never use `:latest`** — in production compose files. Use a specific version tag.

**Digest pinning (optional stretch goal):** Pin images to their SHA256 digest in
`../../docker/docker-compose.prod.yml`. This is the gold standard but requires a process to
update digests. Implement only if the team adopts a CI pipeline that automates it.

### `../../scripts/check_image_versions.py`

A lightweight script that:

1. Reads all image tags from `../../docker/docker-compose.prod.yml` and `../../docker/docker-compose.monitoring.yml`.
2. Checks for `image:latest` tags (error).
3. Reports when the same image appears with different versions in different files (warning).
4. Outputs a summary report.

Does **not** call Docker Hub or any external API — just analyses the compose files.
Add `make check-image-versions` target.

```python
#!/usr/bin/env python3
"""
check_image_versions.py — detect :latest tags and version drift between compose files.

Does NOT call external APIs. Reads compose files and reports:
  - Any :latest tag (error)
  - Any image that appears with different versions in different files (warning)

Exit 0 = no problems.
Exit 1 = :latest tags found or version drift detected.
"""
```

### `../runbooks/docker_image_updates.md`

A runbook covering:

1. Triggering a scan: `make scan-images && make scan-first-party && make scan-dockerfiles`.
2. Interpreting Trivy output.
3. How to research a CVE — NVD link, check if a fixed version is available, check
   if the finding is a false positive (library embedded but not reachable).
4. Update procedure: edit compose file, edit DOCKER_IMAGES.md, run scan, validate
   compose config, test with `make test`, open PR with scan output attached.
5. Who approves: any contributor (for MEDIUM/LOW), lead required for CRITICAL updates.

### Acceptance Criteria

- [ ] Image update policy documented in `../runbooks/docker_image_updates.md`.
- [ ] `../../scripts/check_image_versions.py` exists, detects `:latest` and version drift, exits 1 on findings.
- [ ] `make check-image-versions` target added to Makefile.
- [ ] `make check-image-versions` runs in < 5 seconds (no external calls).
- [ ] Script included in `make check-manifest` or called from a new `make check-all` target.

---

## Sub-Task 25d — Dockerfile Base Image Hardening

### Current state

```dockerfile
FROM python:3.11-slim   # No patch version — gets silent Python micro-releases
```

Issues:
- Unpinned patch version: `python:3.11-slim` moves to the latest 3.11.x without notice.
- `apt-get install gcc libpcap-dev curl` — curl is only needed for the HEALTHCHECK;
  a lighter alternative is `wget` (already used in other health checks).
- No `.dockerignore` check — build context may include test files, secrets dir, etc.

### Deliverables

**Pin Python base image to patch version:**

```dockerfile
FROM python:3.11.11-slim
```

Check the current patch version at time of implementation and use that.

**Remove `curl` from production Dockerfile:**

Replace `curl` with `wget` in the HEALTHCHECK (consistent with monitoring images):

```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD wget --spider -q http://localhost:9090/metrics || exit 1
```

This eliminates one package from the attack surface. If `curl` is needed for
testing, add it only to `Dockerfile.test`.

**`.dockerignore` audit:**

Verify `.dockerignore` exists and excludes:

```
.git/
secrets/
tests/
*.md
.coverage*
.local/
__pycache__/
*.pyc
.env
```

**`make scan-dockerfiles` catches remaining issues** (see §25b).

### Acceptance Criteria

- [ ] All first-party Dockerfiles use pinned patch versions for base images (`FROM x:a.b.c-variant`).
- [ ] `curl` removed from `docker/Dockerfile` production image; HEALTHCHECK uses `wget`.
- [ ] `.dockerignore` excludes secrets dir, test files, coverage artifacts.
- [ ] `make scan-dockerfiles` passes (zero HIGH/CRITICAL misconfig findings) after changes.
- [ ] `make scan-first-party` passes (zero CRITICAL CVE findings) after base image update.

---

## Testing Requirements

This phase has no Python logic changes — all deliverables are Makefile targets,
shell scripts, compose files, and documentation. Testing is:

- `make scan-images` — must pass after version updates.
- `make scan-dockerfiles` — must pass after Dockerfile changes.
- `make scan-first-party` — must pass after base image pin.
- `make check-image-versions` — must exit 0 after harmonisation.
- `make check-manifest` — must pass after this phase is complete.

Add a test in `../../tests/unit/test_check_image_versions.py` for the Python script:

```python
# tests/unit/test_check_image_versions.py
# Tests: latest-tag detection, version-drift detection, clean-compose baseline.
```

---

## Documentation Gate

Before marking Phase 25 COMPLETE:

- [ ] `../DOCKER_IMAGES.md` written and complete.
- [ ] `../runbooks/docker_image_updates.md` written.
- [ ] CHANGELOG.md updated with a Phase 25 entry.
- [ ] `manifest.yaml` status set to COMPLETE.
- [ ] `../../scripts/sync-roadmap.py` re-run.
- [ ] `make check-manifest` passes.

---

## Completion Checklist

```
[ ] 25a: docs/DOCKER_IMAGES.md created
[ ] 25a: redis/redis-stack:latest pinned to specific version
[ ] 25a: prod/monitoring compose files harmonised (same version for shared images)
[ ] 25a: Loki/Promtail v3 config validated before prod compose updated
[ ] 25b: TRIVY_IMAGES list corrected (stale versions fixed, node-exporter added)
[ ] 25b: make scan-dockerfiles target added
[ ] 25b: make scan-first-party target added
[ ] 25b: All three scan targets in make help
[ ] 25c: docs/runbooks/docker_image_updates.md written
[ ] 25c: scripts/check_image_versions.py written and tested
[ ] 25c: make check-image-versions target added
[ ] 25d: docker/Dockerfile base image pinned to patch version
[ ] 25d: curl removed, HEALTHCHECK uses wget
[ ] 25d: .dockerignore audited/created
[ ] All scan targets pass
[ ] CHANGELOG.md updated
[ ] manifest.yaml set to COMPLETE + sync-roadmap.py run
[ ] make check-manifest passes
```
