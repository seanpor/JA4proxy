# Security Remediation — CI Supply Chain + Default Credential Removal

> **Status:** PROPOSED
> **Parent Size:** LARGE — split into 5 SMALL sub-phases below.
> **Last revised:** 2026-04-11 (sub-phase breakdown for junior engineer handoff).

## Goal

Eliminate six infrastructure-level critical findings: (1) GitHub Actions workflow
uses unpinned `@v4`/`@v5` action tags instead of SHA-pinned references, creating
a supply chain attack vector; (2–4) default credentials in Grafana (`admin`),
Management API (`admin/admin`), and HAProxy stats (`admin/admin123`) exposed via
compose file fallback values; (5) no SBOM generation or image signing for the main
Go proxy image; (6) no CI workflow for the Go proxy image build/sign/push.

---

## Sub-phase index

| ID | Sub-phase | Repo area | Size | Depends on |
|---|---|---|---|---|
| **202a** | SHA-pin GitHub Actions (policy workflow) | `.github/workflows/` | XS | none |
| **202b** | Remove default credential fallbacks | `docker/*.yml` | XS | none |
| **202c** | Harden Dockerfile.go-proxy | `docker/Dockerfile.go-proxy` | XS | none |
| **202d** | Go proxy image CI workflow | `.github/workflows/go-proxy-image.yml` | S | 202c |
| **202e** | Test Redis hardening | `docker/docker-compose.test.yml` | XS | none |

All sub-phases are **SMALL** or **XS**. 202a, 202b, 202c, and 202e are fully
independent and can be worked in parallel. 202d depends on 202c (Dockerfile must be
hardened before CI builds from it).

---

## Sub-phase 202a — SHA-pin GitHub Actions (XS)

**Goal:** Replace all `@v4`/`@v5` action references with SHA-pinned commits in the
policy workflow.

**Why this matters:** Unpinned action tags are a supply chain attack vector. If an
action's repository is compromised, every CI run that references it pulls malicious
code.

**Files to modify:**
- `.github/workflows/ja4proxy-policy.yml` — SHA-pin all actions

**Steps:**
1. Read `.github/workflows/ja4proxy-policy.yml` and identify all unpinned actions.
2. Replace each with its SHA-pinned equivalent. Follow the existing pattern in
   `.github/workflows/release-cli.yml` which already uses SHA-pinned actions:
   - `actions/checkout@v4` → `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683` (v4.1.1)
   - `actions/setup-python@v5` → `actions/setup-python@65d7f2d534ac1bc67fcd62888c5f4f3d2cb2b236` (v5.0.0)
3. Run `yamllint .github/workflows/ja4proxy-policy.yml` — must pass.
4. Verify no `@v` references remain: `grep -n '@v[0-9]' .github/workflows/ja4proxy-policy.yml`

**Acceptance criteria:**
- [ ] All GitHub Actions in ja4proxy-policy.yml are SHA-pinned (no `@v4`, `@v5`, etc. remain)
- [ ] `yamllint` passes on the workflow file
- [ ] `grep -rn '@v[0-9]' .github/workflows/ja4proxy-policy.yml` returns no matches
- [ ] CHANGELOG.md entry written
- [ ] PHASE_202a_notes.md written

**Out of scope:** Other workflow files (only ja4proxy-policy.yml), action SHA update automation.

---

## Sub-phase 202b — Remove default credential fallbacks (XS)

**Goal:** Replace `:-default` fallbacks with `:?required` syntax so containers refuse
to start without explicit credentials.

**Why this matters:** Default passwords like `admin/admin` and `admin/admin123` are
shipped in compose files and are trivially discoverable by anyone reading the repo.
An operator who deploys without setting env vars gets production credentials that
are publicly known.

**Files to modify:**
- `docker/docker-compose.monitoring.yml` — Grafana + HAProxy stats credentials
- `docker/docker-compose.poc.yml` — Management API credentials

**Steps:**
1. `docker/docker-compose.monitoring.yml`:
   - Change `GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD:-admin}` to
     `${GRAFANA_PASSWORD:?GRAFANA_PASSWORD is required}`
   - Change `--haproxy.scrape-uri=http://${HAPROXY_STATS_USER:-admin}:${HAPROXY_STATS_PASSWORD:-admin123}@...`
     to use `:?` required syntax for both user and password.
2. `docker/docker-compose.poc.yml`:
   - Change `MANAGEMENT_JWT_SECRET=${MANAGEMENT_JWT_SECRET:-change-me-in-production}` to
     `${MANAGEMENT_JWT_SECRET:?MANAGEMENT_JWT_SECRET is required}`
   - Change `MANAGEMENT_ADMIN_USER=${MANAGEMENT_ADMIN_USER:-admin}` to `:?` required
   - Change `MANAGEMENT_ADMIN_PASSWORD=${MANAGEMENT_ADMIN_PASSWORD:-admin}` to `:?` required
3. Verify: `grep -r ':-admin' docker/` and `grep -r ':-change-me' docker/` return no matches.
4. Run `make lint-yaml` — compose files must validate.

**Acceptance criteria:**
- [ ] `grep -r ':-admin' docker/` returns no matches
- [ ] `grep -r ':-change-me' docker/` returns no matches
- [ ] Grafana refuses to start without `GRAFANA_PASSWORD` env var
- [ ] Management API refuses to start without `MANAGEMENT_JWT_SECRET`
- [ ] `make lint-yaml` passes
- [ ] CHANGELOG.md entry written
- [ ] PHASE_202b_notes.md written

**Out of scope:** Helm chart secrets, Docker secrets migration, test compose files.

---

## Sub-phase 202c — Harden Dockerfile.go-proxy (XS)

**Goal:** Ensure the Go proxy Dockerfile runs as non-root and uses a pinned base image.

**Why this matters:** Running containers as root is a privilege escalation risk if
the container is breached. Unpinned base images (`:latest`) introduce supply chain
risk and non-reproducible builds.

**Files to modify:**
- `docker/Dockerfile.go-proxy` — add non-root USER directive, verify base image pinning

**Steps:**
1. Read `docker/Dockerfile.go-proxy` and check:
   - Is the builder base image pinned to a specific version (not `:latest`)?
   - Is the runtime base image pinned?
   - Does a `USER` directive exist (non-root)?
2. If base images are unpinned, pin them to specific versions (e.g., `golang:1.25.0-alpine`, `alpine:3.21`).
3. If no `USER` directive exists, add:
   ```dockerfile
   RUN addgroup -g 1000 -S ja4proxy && adduser -u 1000 -S ja4proxy -G ja4proxy
   USER 1000:1000
   ```
4. Add `LABEL org.opencontainers.image.source=https://github.com/anomalyco/JA4proxy` if missing.
5. Run `hadolint docker/Dockerfile.go-proxy` — must pass.
6. Build the image: `docker build -f docker/Dockerfile.go-proxy -t ja4proxy-go:test .`

**Acceptance criteria:**
- [ ] `Dockerfile.go-proxy` has `USER` directive (non-root, UID 1000)
- [ ] All base images are pinned to specific versions (no `:latest`)
- [ ] `hadolint` passes with zero warnings
- [ ] Image builds successfully
- [ ] PHASE_202c_notes.md written

**Out of scope:** Multi-arch builds, image scanning (that's 202d), runtime security profiles.

---

## Sub-phase 202d — Go proxy image CI workflow (S)

**Goal:** Create a CI workflow that builds, tests, SBOM-generates, signs, and pushes
the Go proxy image.

**Why this matters:** Without CI for the Go proxy image, there's no automated
verification that the image is built correctly, no artifact provenance, and no
signature verification for supply chain integrity.

**Files to create:**
- `.github/workflows/go-proxy-image.yml` — new CI workflow

**Steps:**
1. Create `.github/workflows/go-proxy-image.yml`. **Use `.github/workflows/release-cli.yml` as a template** — copy its job structure, SHA-pinned actions, and cosign signing pattern. Key diffs:
   - Trigger: `push.paths: ['docker/Dockerfile.go-proxy']` + tags `v*-go-proxy`
   - Jobs: `test` → `build` → `scan` → `sbom` → `sign` → `push`
   - The `sign` job follows the same cosign pattern as `release-cli.yml`
2. All actions in this workflow must be SHA-pinned (follow 202a pattern). Key actions to pin:
   - `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683` (v4.1.1)
   - `actions/setup-go@cdcb36043654635271a94b9a6d13e80b8cf34bfd` (v5.0.0)
   - `docker/login-action@74a5d14239724027a4387673988a71e09627b3f3` (v3.3.0)
   - `docker/build-push-action@5cd11c5a643b59765d86a1acd1e33b5e0547387c` (v6.7.0)
   - `sigstore/cosign-installer@59acb6260d9c0ba8f4a2f9d9b48431a222b68e20` (v3.5.0)
   - `anchore/sbom-action@546297c6bacc20a46774b77881726467e1564b8d` (v0.16.3)
3. Add required secrets documentation to `docs/enterprise/`:
   - `COSIGN_PRIVATE_KEY`, `COSIGN_PASSWORD` for image signing
   - `GHCR_TOKEN` for GHCR push (use `${{ secrets.GITHUB_TOKEN }}` — no extra secret needed)
4. Test the workflow by pushing to a feature branch and observing the GitHub Actions run.

**Acceptance criteria:**
- [ ] `.github/workflows/go-proxy-image.yml` builds, tests, SBOM-generates, signs, and pushes
- [ ] All actions in the workflow are SHA-pinned
- [ ] Trivy scan passes (no CRITICAL in our code; OS-level CRITICALs ignored
      via `--ignore-unfixed` + `.trivyignore`, with each ignored CVE documented
      in the workflow file)
- [ ] SBOM generated in CycloneDX JSON format
- [ ] Image signed with cosign
- [ ] `yamllint` passes on the workflow file
- [ ] CHANGELOG.md entry written
- [ ] PHASE_202d_notes.md written

**Out of scope:** Image verification policies in Kubernetes, admission webhook, Helm chart integration.

---

## Sub-phase 202e — Test Redis hardening (XS)

**Goal:** Bind test Redis to localhost and set a test password.

**Why this matters:** Test Redis is currently exposed on all interfaces (`6380:6379`)
with no password, creating an attack surface on developer machines and CI runners.

**Files to modify:**
- `docker/docker-compose.test.yml` — bind Redis to 127.0.0.1, add test password

**Steps:**
1. Set `REDIS_PASSWORD` to a test password: `${REDIS_PASSWORD:-test-fixtures-pw}`
2. Change Redis port binding from `6380:6379` to `127.0.0.1:6380:6379`
3. Verify any test code that connects to Redis uses the password. The URL format with password is:
   `redis://:test-fixtures-pw@127.0.0.1:6380/0` (note the colon before the password — this is the Redis ACL password syntax).
   Search for `redis://localhost:6380` or `redis://127.0.0.1:6380` in test files and update.
   **Important:** Tests using `fakeredis` do NOT need the password — fakeredis ignores auth. Only update tests that connect to a real Redis instance via docker-compose.
4. Run `make test` — all tests must still pass with the password.
5. Run `docker compose -f docker/docker-compose.test.yml config` — must validate.

**Acceptance criteria:**
- [ ] Test Redis port bound to `127.0.0.1:6380:6379`
- [ ] Test Redis password set via env var with fallback
- [ ] `make test` passes (all tests connect with password)
- [ ] `docker compose config` validates
- [ ] PHASE_202e_notes.md written

**Out of scope:** Test Redis TLS, production Redis changes.

---

## Full Phase Acceptance Criteria (all sub-phases)

- [ ] All 5 sub-phases complete (see individual acceptance criteria above)
- [ ] `grep -r ':-admin' docker/` returns no matches
- [ ] `grep -r ':-change-me' docker/` returns no matches
- [ ] All GitHub Actions are SHA-pinned across all workflow files
- [ ] `Dockerfile.go-proxy` has `USER` directive (non-root)
- [ ] Go proxy image CI workflow builds, signs, and pushes successfully
- [ ] `make lint-yaml` passes (compose files valid)
- [ ] CHANGELOG.md entry written

## Out of Scope

- Changing Helm chart secrets management (that's a Kubernetes-specific concern).
- Implementing image verification policies in Kubernetes (admission webhook).
- Adding Redis TLS configuration to management API or analytics services.
- Migrating POC compose to Docker secrets (documented, accepted risk for dev).
