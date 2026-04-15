# Security Remediation — CI Supply Chain + Default Credential Removal

> **Status:** PROPOSED
> **Parent Size:** LARGE — split into 5 SMALL sub-phases below.
> **Last revised:** 2026-04-15 (refreshed against current repo state: paths moved to
> `deploy/docker/` in phase 205; 202a & 202c already partially done; canonical
> action SHAs now come from existing `.github/workflows/ci.yml`).

## Goal

Close six infrastructure-level gaps identified at the 2026-04-11 audit. Some have
since been partially remediated (see **Current state** column). What remains:

| Gap | Sub-phase | Current state (2026-04-15) |
|-----|-----------|----------------------------|
| GitHub Actions unpinned | 202a | `ja4proxy-policy.yml` & `ci.yml` fully SHA-pinned. `release-cli.yml` all regular actions SHA-pinned; one reusable workflow still tag-pinned. |
| Grafana default `admin` | 202b | Confirmed: `GRAFANA_PASSWORD:-admin` |
| Management API default `admin/admin` | 202b | Confirmed in `deploy/docker/docker-compose.poc.yml` |
| HAProxy stats default `admin/admin123` | 202b | Confirmed in `deploy/docker/docker-compose.monitoring.yml` |
| `Dockerfile.go-proxy` hardening | 202c | Already has `USER ja4proxy` and pinned base images. Gaps: no explicit UID 1000, no OCI labels. |
| No Go-proxy image CI workflow | 202d | Confirmed missing. |
| Test Redis exposed on all interfaces w/ no password | 202e | Confirmed: `6380:6379`, `REDIS_PASSWORD: ""` |

---

## Canonical action SHAs (source of truth: `.github/workflows/ci.yml` as of 2026-04-15)

Any new workflow file MUST reuse these exact SHAs. Do NOT pull SHAs from older
documentation.

```
actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd         # v6.0.2
actions/setup-go@4a3601121dd01d1626a1e23e37211e3254c1c06c         # v6.4.0
actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405     # v6.2.0
docker/login-action@4907a6ddec9925e35a0a9e82d7399ccc52663121      # v4.1.0
docker/build-push-action@bcafcacb16a39f128d818304e6c9c0c18556b85f # v7.1.0
```

Actions newly introduced by 202d (recorded at implementation time, 2026-04-15):

```
docker/setup-buildx-action@4d04d5d9486b7bd6fa91e7baf45bbb4f8b9deedd  # v4.0.0
docker/metadata-action@030e881283bb7a6894de51c315a6bfe6a94e05cf      # v6.0.0
sigstore/cosign-installer@dc72c7d5c4d10cd6bcb8cf6e3fd625a9e5e537da   # v3.7.0
anchore/sbom-action@55dc4ee22412511ee8c3142cbea40418e6cec693         # v0.17.8
aquasecurity/trivy-action@18f2510ee396bbf400402947b394f2dd8c87dbb0   # v0.29.0
```

SLSA reusable workflow SHA resolved in 202a:
```
slsa-framework/slsa-github-generator/...@f7dd8c54c2067bafc12ca7a55595d5ee9b75204a  # v2.1.0
```

---

## Sub-phase index

| ID | Sub-phase | Repo area | Size | Depends on |
|---|---|---|---|---|
| **202a** | Final workflow-pinning audit (+ optional SLSA reusable) | `.github/workflows/` | XS | none |
| **202b** | Remove default credential fallbacks | `deploy/docker/*.yml` | XS | none |
| **202c** | Explicit UID + OCI labels in `Dockerfile.go-proxy` | `deploy/docker/Dockerfile.go-proxy` | XS | none |
| **202d** | Go proxy image CI workflow (build/scan/SBOM/sign/push) | `.github/workflows/go-proxy-image.yml` | S | 202c |
| **202e** | Test Redis hardening (loopback + password) | `deploy/docker/docker-compose.test.yml` | XS | none |

202a, 202b, 202c, and 202e are fully independent and parallel-safe. 202d depends
on 202c so that the image built by CI is already hardened.

---

## Sub-phase 202a — Final workflow-pinning audit (XS)

**Why this matters:** Unpinned action tags are a supply chain attack vector.
Previous phases have pinned the bulk of the actions; this sub-phase closes the
residual gap so the repo-wide invariant holds.

**Files to audit/modify:**
- `.github/workflows/ja4proxy-policy.yml`
- `.github/workflows/ci.yml`
- `.github/workflows/release-cli.yml`
- `docs/decisions/ADR-202a.md` *(new — if SLSA exception accepted)*

**Steps:**
1. Run `grep -nE "uses: [^@]+@(v[0-9]|main|master)" .github/workflows/*.yml`.
   Expected output at time of writing: one match in `release-cli.yml:57` —
   `slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0`.
2. Decision gate — choose one:
   - **(a)** SHA-pin the SLSA reusable workflow to v2.1.0's commit SHA (look up
     `slsa-framework/slsa-github-generator` release tag `v2.1.0` → commit).
   - **(b)** Document in `docs/decisions/ADR-202a.md` that reusable workflows
     from the `slsa-framework` org are allowlisted by tag because GitHub's
     supply-chain docs explicitly permit tag-pinning trusted reusables.
3. Confirm `grep -rnE "uses: [^@]+@v[0-9]" .github/workflows/*.yml` shows no
   ordinary-action matches (reusable workflow OK if route (b) taken).
4. `yamllint .github/workflows/` — must pass.

**Acceptance criteria:**
- [x] No ordinary GitHub Action uses `@v*` or `@main`/`@master` anywhere.
- [x] SLSA reusable is SHA-pinned (Path A, ADR-202a Accepted).
- [x] `yamllint` passes on all workflow files.
- [x] CHANGELOG entry written.
- [x] `docs/phases/PHASE_202_notes.md` written (consolidated per repo convention).

**Out of scope:** changes to existing pinned SHAs (those are current).

---

## Sub-phase 202b — Remove default credential fallbacks (XS)

**Why this matters:** Default passwords like `admin/admin` and `admin/admin123`
are trivially discoverable from the repo. `:?required` syntax forces operators
to set real secrets before `docker compose up` succeeds.

**Files to modify:**
- `deploy/docker/docker-compose.monitoring.yml`
- `deploy/docker/docker-compose.poc.yml`
- `Makefile`, `scripts/`, `.github/workflows/` — any invocation touching the
  above compose files that currently relies on the defaults

**Findings (confirmed 2026-04-15):**
- `deploy/docker/docker-compose.monitoring.yml:82` — `GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD:-admin}`
- `deploy/docker/docker-compose.monitoring.yml:255` — `http://${HAPROXY_STATS_USER:-admin}:${HAPROXY_STATS_PASSWORD:-admin123}@haproxy:8404/stats;csv`
- `deploy/docker/docker-compose.poc.yml:376` — `MANAGEMENT_JWT_SECRET=${MANAGEMENT_JWT_SECRET:-change-me-in-production}`
- `deploy/docker/docker-compose.poc.yml:377` — `MANAGEMENT_ADMIN_USER=${MANAGEMENT_ADMIN_USER:-admin}`
- `deploy/docker/docker-compose.poc.yml:378` — `MANAGEMENT_ADMIN_PASSWORD=${MANAGEMENT_ADMIN_PASSWORD:-admin}`

**Steps:**
1. Replace each `${VAR:-default}` with `${VAR:?VAR is required}` (5 changes).
2. Grep every shell/CI path that currently invokes `docker compose` on these
   files:
   `grep -rE "docker compose.*compose\.(monitoring|poc)" Makefile scripts/ .github/`
   For each invocation:
   - If the CI job is expected to run this compose, export the env vars at
     the top of the job (or skip the job if secrets are absent in PR builds).
   - If a dev-only `make` target requires creds, document the required vars
     in `make help` output and/or `docs/runbooks/deploy_credentials.md`.
3. Add `docs/runbooks/deploy_credentials.md` listing all 6 required env vars
   with: purpose, who sets it, failure mode if missing, rotation guidance.
4. `docker compose -f deploy/docker/docker-compose.poc.yml config` — must fail
   clearly when `MANAGEMENT_JWT_SECRET` is unset.

**Acceptance criteria:**
- [x] `grep -r ":-admin\|:-change-me\|:-admin123" deploy/docker/` returns no matches.
- [x] `docker compose -f deploy/docker/docker-compose.poc.yml config` fails clearly without `MANAGEMENT_JWT_SECRET`.
- [x] `docker compose -f deploy/docker/docker-compose.monitoring.yml config` fails clearly without `GRAFANA_PASSWORD`.
- [x] `docs/runbooks/deploy_credentials.md` exists, references all 6 env vars.
- [x] Makefile lint/test targets updated with placeholder injection to keep static validation runnable on a fresh checkout.
- [x] CHANGELOG entry written.
- [x] `docs/phases/PHASE_202_notes.md` written (consolidated).

**Out of scope:** Helm chart secrets (Kubernetes-native concern), Docker secrets
migration, test compose file (separately 202e).

---

## Sub-phase 202c — Explicit UID + OCI labels in Dockerfile.go-proxy (XS)

**Why this matters:** The Dockerfile already runs as non-root, but the system
user created by `adduser -S` receives a **random low UID (<1000)** assigned by
busybox. Kubernetes workloads with `securityContext.runAsNonRoot: true` **and**
`runAsUser: 1000` (the industry-standard numeric check) fail to start against
such images. Using an explicit `-u 1000` fixes this and makes the image safe
for Pod Security Admission `restricted` profiles.

OCI labels make the image discoverable and traceable from a registry.

**File to modify:**
- `deploy/docker/Dockerfile.go-proxy`

**Current state (already done — do NOT redo):**
- `USER ja4proxy` directive exists (line 51).
- Builder pinned to `golang:1.25-alpine` (line 17).
- Runtime pinned to `alpine:3.19` (line 36).

**Steps:**
1. Change (line 39):
   ```dockerfile
   RUN addgroup -S ja4proxy && adduser -S -G ja4proxy ja4proxy
   ```
   to:
   ```dockerfile
   RUN addgroup -g 1000 -S ja4proxy && adduser -u 1000 -S -G ja4proxy ja4proxy
   ```
2. Change (line 51):
   ```dockerfile
   USER ja4proxy
   ```
   to:
   ```dockerfile
   USER 1000:1000
   ```
3. Add OCI labels after the `FROM alpine:3.19` line (before the `RUN`):
   ```dockerfile
   LABEL org.opencontainers.image.source="https://github.com/anomalyco/JA4proxy" \
         org.opencontainers.image.title="ja4proxy" \
         org.opencontainers.image.description="TLS-aware passthrough security proxy" \
         org.opencontainers.image.licenses="Apache-2.0"
   ```
4. *(Optional — do only if adopted elsewhere)* Digest-pin base images:
   `golang:1.25-alpine@sha256:…` and `alpine:3.19@sha256:…`. Get digests via
   `docker pull <image> && docker inspect --format='{{index .RepoDigests 0}}' <image>`.
   If you digest-pin, document the policy (how to update) in ADR-202c.
5. Build & verify:
   ```
   docker build -f deploy/docker/Dockerfile.go-proxy -t ja4proxy-go:test .
   docker run --rm --entrypoint /bin/sh ja4proxy-go:test -c 'id -u && id -g'
   # expect: 1000 / 1000
   hadolint deploy/docker/Dockerfile.go-proxy
   ```

**Acceptance criteria:**
- [x] `docker run --rm --entrypoint /bin/sh ja4proxy-go:test -c 'id -u'` prints `1000` (verified locally; CI verification deferred to first green `go-proxy-image.yml` run).
- [x] `docker inspect ja4proxy-go:test --format='{{ .Config.User }}'` equals `1000:1000`.
- [x] `docker inspect ja4proxy-go:test --format='{{index .Config.Labels "org.opencontainers.image.source"}}'` is non-empty.
- [x] `hadolint deploy/docker/Dockerfile.go-proxy` passes with zero errors.
- [x] Image still builds and the proxy binary still runs.
- [x] CHANGELOG entry written.
- [x] `docs/phases/PHASE_202_notes.md` written (consolidated).

**Out of scope:** multi-arch builds, Trivy scanning (→ 202d), runtime seccomp
profiles, Pod Security Admission configuration.

---

## Sub-phase 202d — Go proxy image CI workflow (S)

**Why this matters:** No CI currently builds, scans, SBOMs, signs, or pushes
the Go proxy image. Without this, there is no automated verification, no
provenance, no signature, and operators have to build images locally from an
unverified source tree.

**File to create:**
- `.github/workflows/go-proxy-image.yml`

**Supporting files:**
- `scripts/verify-image-signature.sh` — end-user verification helper
- `docs/decisions/ADR-202d.md` — chosen signing backend (keyless vs key-based)
- `.trivyignore` — empty-but-commented file for triaged CVEs

**Steps:**
1. Scaffold `.github/workflows/go-proxy-image.yml` using
   `.github/workflows/release-cli.yml` as the structural template. Reuse every
   canonical SHA from the table at the top of this document — do NOT pull SHAs
   from old documentation.
2. Triggers:
   ```yaml
   on:
     push:
       paths:
         - 'deploy/docker/Dockerfile.go-proxy'
         - 'cmd/proxy/**'
         - 'internal/**'
         - 'go.mod'
         - 'go.sum'
       tags: ['v*-go-proxy']
     workflow_dispatch:
   ```
3. Jobs (sequential): `test` → `build` → `scan` → `sbom` → `sign` → `push`.
   - `test`: `go test -race ./...` (reuses existing `ci.yml` Go setup).
   - `build`: `docker/build-push-action`, outputs local image.
   - `scan`: `aquasecurity/trivy-action`, `--severity CRITICAL`, honour `.trivyignore`.
   - `sbom`: `anchore/sbom-action`, CycloneDX JSON, attach as OCI artifact.
   - `sign`: `sigstore/cosign-installer` + `cosign sign --yes` (keyless OIDC
     preferred — see ADR-202d).
   - `push`: tag and push to `ghcr.io/<owner>/ja4proxy-go:${{ github.sha }}`
     and `:${{ github.ref_name }}` for tags. Uses `${{ secrets.GITHUB_TOKEN }}`.
4. Add `scripts/verify-image-signature.sh`:
   ```bash
   #!/usr/bin/env bash
   # Usage: scripts/verify-image-signature.sh <image-ref>
   set -euo pipefail
   image="${1:?image-ref required}"
   cosign verify "$image" \
     --certificate-identity-regexp "^https://github.com/anomalyco/JA4proxy/" \
     --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
   ```
5. Write `docs/decisions/ADR-202d.md` covering:
   - Decision: keyless cosign (Fulcio OIDC) — no secrets to rotate.
   - Where SBOMs live: attached to image via `cosign attach sbom` and OCI referrers API.
   - Who verifies: users via `verify-image-signature.sh`; ADR notes future work for
     admission-controller verification.
6. `.trivyignore`: create file with a comment header documenting the triage format:
   `<CVE-ID> # reason: …; expires: YYYY-MM-DD; owner: <name>`.
7. Push branch, observe workflow run, fix any red, verify signed image
   retrievable and verifiable.

**Acceptance criteria:**
- [ ] `.github/workflows/go-proxy-image.yml` runs green end-to-end on a push to its trigger paths. *(Deferred: workflow has not yet run on `main`; verified only on branch push. First green run happens after merge.)*
- [x] All `uses:` entries are SHA-pinned with `# version` comments matching the canonical SHA table above (plus the newly added ones, recorded back into this doc).
- [x] Trivy job configured to fail on CRITICAL vulnerabilities outside `.trivyignore` (live signal deferred to post-merge CI run).
- [x] SBOM produced in CycloneDX JSON format and attached as OCI artifact via `cosign attach sbom --type cyclonedx` (also uploaded as workflow artifact).
- [ ] Image signed via keyless cosign and retrievable from GHCR. *(Deferred to post-merge; local branch cannot push to GHCR.)*
- [x] `scripts/verify-image-signature.sh` present (mode 755) with correct identity-regexp and OIDC-issuer; live success deferred to post-merge signed image.
- [x] `yamllint .github/workflows/go-proxy-image.yml` passes.
- [x] ADR-202d is Accepted.
- [x] CHANGELOG entry written.
- [x] `docs/phases/PHASE_202_notes.md` written (consolidated).

**Out of scope:** Kubernetes admission webhook, Helm chart image pinning,
multi-arch manifest lists.

---

## Sub-phase 202e — Test Redis hardening (XS)

**Why this matters:** Test Redis is currently exposed on all interfaces
(`6380:6379`) with no password. On a developer laptop or CI runner on an
untrusted network, this is an unauthenticated open Redis.

**File to modify:**
- `deploy/docker/docker-compose.test.yml`
- `tests/conftest.py` / any integration fixture that builds a real-Redis URL
  against port 6380

**Current state (confirmed 2026-04-15):**
- `deploy/docker/docker-compose.test.yml:25` — `"6380:6379"`
- `deploy/docker/docker-compose.test.yml:68` & `:98` — `REDIS_PASSWORD: ""`

**Steps:**
1. Change port mapping to loopback: `"127.0.0.1:6380:6379"`.
2. Set a test password via env var with a safe fallback:
   ```yaml
   environment:
     REDIS_PASSWORD: "${REDIS_TEST_PASSWORD:-test-fixtures-pw}"
   command: ["redis-server", "--requirepass", "${REDIS_TEST_PASSWORD:-test-fixtures-pw}"]
   ```
3. Update any real-Redis test fixture to use the authenticated URL:
   `redis://:test-fixtures-pw@127.0.0.1:6380/0` (note the **empty username**
   before the colon — `redis://password@host` would treat `password` as the
   username).
4. `fakeredis` tests need no change (fakeredis ignores auth).
5. Verify:
   ```
   docker compose -f deploy/docker/docker-compose.test.yml config
   docker compose -f deploy/docker/docker-compose.test.yml up -d redis-test
   ss -tlnp | grep :6380   # must show 127.0.0.1, not 0.0.0.0 or *
   make test
   ```

**Acceptance criteria:**
- [x] `deploy/docker/docker-compose.test.yml` binds Redis port to `127.0.0.1` only.
- [x] Test Redis password is set and honoured (`redis-cli -a <pw> PING` works, no-auth fails).
- [x] All integration tests that touch real Redis authenticate with the password.
- [x] `make test` passes.
- [x] `docker compose config` validates.
- [x] `docs/phases/PHASE_202_notes.md` written (consolidated).

**Out of scope:** TLS on test Redis (separate phase), production Redis
(already hardened in phase 201).

---

## Full Phase Acceptance Criteria (all sub-phases)

- [x] All 5 sub-phases complete (see individual acceptance criteria above).
- [x] `grep -r ":-admin\|:-change-me\|:-admin123" deploy/docker/` returns no matches.
- [x] No ordinary GitHub Action uses `@v*`, `@main`, or `@master` in any workflow.
- [x] `deploy/docker/Dockerfile.go-proxy` has explicit UID 1000 and OCI labels.
- [x] `.github/workflows/go-proxy-image.yml` exists.
- [ ] `.github/workflows/go-proxy-image.yml` runs green end-to-end. *(Deferred: post-merge first CI run.)*
- [x] Test Redis binds loopback and requires a password.
- [x] `make lint-yaml` and `yamllint .github/workflows/` both pass.
- [x] CHANGELOG entry written.
- [x] `docs/runbooks/deploy_credentials.md` exists.
- [x] ADR-202d is Accepted; ADR-202a is Accepted (Path A); ADR-202c is Accepted.

## Out of Scope

- Helm chart secrets management (Kubernetes-specific concern).
- Kubernetes admission webhook for image signature verification.
- Redis TLS for management API or analytics services.
- Migrating POC compose to Docker secrets (documented, accepted risk for dev).
- Rotating cosign keys (if key-based is chosen over keyless — ADR-202d covers policy).
- Changing any already-pinned action SHAs (current set is valid).
