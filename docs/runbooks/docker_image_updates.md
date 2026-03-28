---
title: Docker Image Update Runbook
audience: operator
last_reviewed: 2026-03-28
---

# Docker Image Update Runbook

This runbook covers how to scan images for CVEs, interpret results, and safely update image versions.

---

## 1. Triggering a Scan

Run all three scan targets together for a full picture:

```bash
make check-image-versions   # detect :latest tags and version drift (fast, no Docker)
make scan-images            # CVE scan of third-party images
make scan-first-party       # CVE scan of images we build (run 'make build' first)
make scan-dockerfiles       # misconfiguration scan of Dockerfiles (no build needed)
```

`make check-image-versions` completes in under 5 seconds and requires no Docker daemon. Run it before every PR that touches compose files.

---

## 2. Interpreting Trivy Output

Trivy reports findings in a table. The columns that matter:

| Column | Meaning |
|--------|---------|
| `VULNERABILITY ID` | CVE identifier — look it up at https://nvd.nist.gov/vuln/search |
| `SEVERITY` | CRITICAL / HIGH / MEDIUM / LOW |
| `INSTALLED VERSION` | What's currently in the image |
| `FIXED VERSION` | The version that patches the CVE (blank = no fix yet) |
| `STATUS` | `fixed` means a patched version exists; `affected` means no fix yet |

**CRITICAL with a fixed version** — action required. Follow §4 below.

**HIGH with a fixed version** — schedule for next maintenance window.

**CRITICAL/HIGH with no fixed version** — investigate whether the vulnerable code path is reachable in our deployment. Document the decision in this file under §6.

**MEDIUM / LOW** — defer to quarterly review.

---

## 3. Researching a CVE

1. Search the CVE at [NVD](https://nvd.nist.gov/vuln/search) to read the full description.
2. Check the upstream release notes for the affected image to confirm a fix is available.
3. Determine if the vulnerable library is *reachable* in our deployment. For example, a CVE in `curl` inside a Redis image is low risk if we never exec into Redis containers. Document your reasoning.
4. Check whether the finding is a false positive — Trivy sometimes flags statically linked libraries that aren't present at runtime. Use `trivy image --format json` and inspect the `Layer` field to confirm.

---

## 4. Update Procedure

### Updating a third-party image

1. Edit the image version in the relevant compose file(s):
   - `docker/docker-compose.prod.yml`
   - `docker/docker-compose.monitoring.yml`
2. Update `docs/DOCKER_IMAGES.md` — change the `Pinned version` and `Last reviewed` columns.
3. Update `TRIVY_IMAGES` in `Makefile` to match the new version.
4. Validate the compose files parse correctly:
   ```bash
   docker compose -f docker/docker-compose.prod.yml config > /dev/null
   docker compose -f docker/docker-compose.monitoring.yml config > /dev/null
   ```
5. Run the full scan to confirm the CVE is resolved:
   ```bash
   make check-image-versions && make scan-images
   ```
6. Run the test suite:
   ```bash
   make test
   ```
7. Open a PR with the scan output attached as a comment.

### Updating a first-party base image

First-party images (`ja4proxy`, `ja4proxy-analytics`, `ja4proxy-tarpit`) inherit their CVE surface from the Python base image. To update:

1. Check [hub.docker.com/\_/python](https://hub.docker.com/_/python/tags?name=3.11) for the current `3.11.x-slim` patch version.
2. Update `FROM python:3.11.X-slim` in:
   - `docker/Dockerfile`
   - `src/analytics/Dockerfile`
   - `docker/Dockerfile.test`
3. Update `docs/DOCKER_IMAGES.md` — `Pinned version` and `Last reviewed`.
4. Rebuild and scan:
   ```bash
   make build && make scan-first-party && make scan-dockerfiles
   ```
5. Run the test suite:
   ```bash
   make test
   ```

---

## 5. Version Update Policy

| CVE severity | Action | Timeline |
|-------------|--------|----------|
| CRITICAL | File an issue; update within 48h of confirmed fix | 48h after fix available |
| HIGH | Schedule for next maintenance window | Within 2 weeks |
| MEDIUM / LOW | Defer to quarterly review | Quarterly |
| No CVE | Quarterly review — update if N+1 minor is stable (≥7 days old) | Quarterly |

**Stability window:** Do not run an image version released less than 7 days ago unless it fixes a CRITICAL CVE.

**Maximum age:** No image should run a version more than 2 minor releases behind current stable.

**Never use `:latest`** in production compose files.

---

## 6. Known False Positives / Accepted Risks

Document decisions to accept a finding here. Include CVE ID, affected image, rationale, and review date.

| CVE | Image | Rationale | Accepted by | Review date |
|-----|-------|-----------|-------------|-------------|
| — | — | No accepted risks at this time | — | — |

---

## 7. Approval

- **MEDIUM / LOW**: any contributor may update and merge.
- **HIGH**: lead review required before merge.
- **CRITICAL**: immediate fix; page the on-call lead if outside business hours.
