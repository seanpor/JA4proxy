# Phase 202 — Implementation Notes

**Branch:** `claude/phase-202-ci-supply-chain`
**Status:** COMPLETE (202a–202e merged on branch; close-out pending)
**Date:** 2026-04-15

Consolidated notes across all five sub-phases. See `PHASE_202.md` for the spec
and `PHASE_202_review.md` for the original review. Following the repo
convention (see `PHASE_201_notes.md`), this file replaces the per-sub-phase
`PHASE_202{a,b,c,d,e}_notes.md` that were planned in the phase spec.

---

## 202a — Final workflow-pinning audit + SLSA SHA-pin

**Files:** `.github/workflows/release-cli.yml` (line 57),
`docs/decisions/ADR-202a.md`, `tests/test_workflow_pinning.py` (allowlist).

Decision: **Path A — SHA-pin the SLSA reusable workflow** (ADR-202a Accepted).

- SHA resolved via
  `curl -s https://api.github.com/repos/slsa-framework/slsa-github-generator/git/refs/tags/v2.1.0`:
  lightweight tag; `object.sha` is the commit directly, no annotated-tag
  dereference needed.
- Applied SHA: `f7dd8c54c2067bafc12ca7a55595d5ee9b75204a`.
- `release-cli.yml:57` now reads:
  ```yaml
  uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@f7dd8c54c2067bafc12ca7a55595d5ee9b75204a  # v2.1.0
  ```
- `tests/test_workflow_pinning.py` permits reusable workflows via
  `REUSABLE_WORKFLOW_RE`; the SHA-pin form for the same reusable also
  passes since it matches `SHA_PIN_RE`. No allowlist change was needed
  *for* the SLSA reusable (the allowlist extension in 202d below covers
  five newly introduced ordinary actions).

Rationale (see ADR-202a): one invariant across the whole repo is easier to
audit and maintain than a trusted-org allowlist. Future SLSA version bumps
follow the SHA lookup + potential annotated-tag dereference procedure
documented in the ADR.

---

## 202b — Remove default credential fallbacks

**Files:** `deploy/docker/docker-compose.monitoring.yml`,
`deploy/docker/docker-compose.poc.yml`, `Makefile`,
`docs/runbooks/deploy_credentials.md`.

Replaced five `${VAR:-default}` fallbacks with `${VAR:?VAR is required}`:

| Variable | File |
|---|---|
| `GRAFANA_PASSWORD` | `docker-compose.monitoring.yml` |
| `HAPROXY_STATS_USER` | `docker-compose.monitoring.yml` |
| `HAPROXY_STATS_PASSWORD` | `docker-compose.monitoring.yml` |
| `MANAGEMENT_JWT_SECRET` | `docker-compose.poc.yml` |
| `MANAGEMENT_ADMIN_USER` | `docker-compose.poc.yml` |
| `MANAGEMENT_ADMIN_PASSWORD` | `docker-compose.poc.yml` |

Because `docker compose config --quiet` is used as a structural-lint step in
several Makefile targets that never actually start services, the Coder
wired **placeholder injection** into those targets so a fresh checkout still
lints cleanly without secrets:

- `lint-docker` (Makefile lines ~303–333): exports
  `BACKEND_HOST=lint-placeholder`, `REDIS_PASSWORD=lint-placeholder`,
  `MANAGEMENT_JWT_SECRET=lint-placeholder`,
  `MANAGEMENT_ADMIN_USER=lint-placeholder`,
  `MANAGEMENT_ADMIN_PASSWORD=lint-placeholder`,
  `GRAFANA_PASSWORD=lint-placeholder`,
  `HAPROXY_STATS_USER=lint-placeholder`,
  `HAPROXY_STATS_PASSWORD=lint-placeholder`
  before each `docker compose config --quiet` invocation.
- `test-phase-89-lint` (Makefile lines 1091–1096): same pattern with the
  shorter literal `lint`.

These placeholders are not secrets and never reach a running container.
Documented in `docs/runbooks/deploy_credentials.md` "What the Makefile does
for lint/test targets" so operators don't confuse them with real creds.

Runbook additions:
- Six required env vars enumerated with purpose, who-sets-it, failure-mode,
  strength guidance, rotation pointer.
- Dev `.env` template, CI job examples, PR-from-fork ephemeral-secret
  pattern.
- Cross-links to `credential_rotation.md` and `security_incident_response.md`.

---

## 202c — Explicit UID 1000 + OCI labels

**File:** `deploy/docker/Dockerfile.go-proxy`.

ADR-202c is now Accepted. Changes:

- Line 39: `LABEL` block with
  `org.opencontainers.image.source`, `.title`, `.description`, `.licenses`,
  placed immediately after `FROM alpine:3.19` (line 36).
- Line 47:
  `RUN addgroup -g 1000 -S ja4proxy && adduser -u 1000 -S -G ja4proxy ja4proxy`
  (was unpinned busybox `-S` allocation).
- Line 59: `USER 1000:1000` (numeric form — kubelet's `runAsNonRoot`
  validator accepts it without `/etc/passwd` lookup).

Chosen UID 1000 over distroless's 65532: our base is alpine, and 1000 is the
de-facto industry standard for the first non-privileged service user on
alpine-based images (`nginx`, `postgres`, Bitnami). Rationale fully
documented in ADR-202c; the ADR also records the host-UID-collision
tradeoff for bind-mount scenarios.

Verified locally: `docker inspect --format='{{ .Config.User }}' ja4proxy-go:test`
returns `1000:1000`; `hadolint` clean; image builds.

---

## 202d — Go proxy image CI workflow

**Files:** `.github/workflows/go-proxy-image.yml` (new),
`scripts/verify-image-signature.sh` (new, mode 755),
`docs/decisions/ADR-202d.md` (Accepted), `.trivyignore` (new, header only).

**Signing decision:** keyless cosign (Fulcio OIDC). ADR-202d details the
tradeoff analysis vs key-based signing.

Workflow structure:

- Two jobs: `test` (Go unit tests) → `build-scan-sign-push`.
- Top-level `permissions: contents: read, packages: write, id-token: write`.
- Triggers: path-based push on Go source / Dockerfile / `go.{mod,sum}`,
  git tags matching `v*-go-proxy`, and `workflow_dispatch`.
- `sign` step: `cosign sign --yes "${tag}@${DIGEST}"` (line 134). No
  `--key`; keyless via Fulcio.
- `sbom` step: `anchore/sbom-action` writes CycloneDX JSON (line 99).
  Attached **twice**:
  1. Workflow artifact (CI-retention convenience).
  2. OCI artifact via
     `cosign attach sbom --sbom sbom.cdx.json --type cyclonedx "${tag}@${DIGEST}"`
     (line 146) — discoverable with `cosign download sbom`.

**Action SHAs introduced (all SHA-pinned with `# version` comments):**

| Action | SHA | Version |
|---|---|---|
| `docker/setup-buildx-action` | `4d04d5d9486b7bd6fa91e7baf45bbb4f8b9deedd` | v4.0.0 |
| `docker/metadata-action` | `030e881283bb7a6894de51c315a6bfe6a94e05cf` | v6.0.0 |
| `sigstore/cosign-installer` | `dc72c7d5c4d10cd6bcb8cf6e3fd625a9e5e537da` | v3.7.0 |
| `anchore/sbom-action` | `55dc4ee22412511ee8c3142cbea40418e6cec693` | v0.17.8 |
| `aquasecurity/trivy-action` | `18f2510ee396bbf400402947b394f2dd8c87dbb0` | v0.29.0 |

All five are allowlisted in `tests/test_workflow_pinning.py`'s
`KNOWN_ACTION_SHAS` dict — the Coder extended this at 202d close. That
allowlist is the verification surface for the pin-and-tag-comment pairing
(see the header comment in `test_workflow_pinning.py` for the contract).

`scripts/verify-image-signature.sh`:
```bash
cosign verify "$image" \
  --certificate-identity-regexp "^https://github.com/anomalyco/JA4proxy/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

`.trivyignore`: header-only file with triage format documented
(`CVE-YYYY-NNNNN # reason: …; expires: YYYY-MM-DD; owner: …`). No CVEs
triaged in this phase; the scan job fails closed on any CRITICAL.

**Deferred to post-merge:** the first live end-to-end workflow run, first
signed image in GHCR, live sample output of
`scripts/verify-image-signature.sh`. The branch cannot push to GHCR from a
fork-like context; first green run happens after `main` merge. ADR-202d
also records the deferred future work for a Kubernetes admission
controller (Kyverno / Sigstore Policy Controller) verifying signatures at
deploy time — out of scope for this phase.

---

## 202e — Test Redis hardening

**Files:** `deploy/docker/docker-compose.test.yml`,
integration fixtures under `tests/` that build a real-Redis URL.

- Port mapping: `"127.0.0.1:6380:6379"` (loopback only).
- Password: `REDIS_PASSWORD: "${REDIS_TEST_PASSWORD:-test-fixtures-pw}"` and
  `command: ["redis-server", "--requirepass", "${REDIS_TEST_PASSWORD:-test-fixtures-pw}"]`.
- Integration fixtures updated to authenticate via
  `redis://:test-fixtures-pw@127.0.0.1:6380/0` (empty-username form —
  `redis://password@host` would treat `password` as username).
- `fakeredis`-backed unit tests unchanged (fakeredis ignores auth).

---

## What was NOT done (by design)

- **Live CI run on `main` post-merge.** The workflow exists and is
  structurally correct; proving green is a post-merge activity by
  orchestrator/close-out, not the implementing agents.
- **Admission-controller image-signature policy.** Future work per
  ADR-202d.
- **Offline/air-gapped verification story.** The cosign v2 attached-bundle
  mode is the default path; a fully air-gapped operator runbook is future
  work if/when a real air-gapped consumer appears.
- **`cosign attest` with in-toto predicates** in addition to
  `cosign sign`. Not needed for `cosign download sbom`; reserved for the
  day attestation-based admission policy is required.
- **Emergency unsigned-push override.** Explicitly rejected in ADR-202d to
  keep the "every GHCR image is signed" invariant free of exceptions.
- **New Prometheus metrics, log lines, Redis keys, or config keys.** This
  phase is pure infra; the only application-visible change is that
  `docker compose up` now fails fast on missing env vars (no new runtime
  signals).

---

## Test surface at close

- `python3 -m pytest tests/test_workflow_pinning.py` — green (allowlist
  includes the five new SHAs added in 202d).
- `python3 -m pytest tests/integration/test_container_config.py
  tests/integration/test_go_proxy_image.py` — TDD tests from Wave 1a,
  green after Wave 2.
- `yamllint .github/workflows/` — clean.
- `hadolint deploy/docker/Dockerfile.go-proxy` — clean.
- `grep -rE "uses: [^@]+@(v[0-9]|main|master)" .github/workflows/*.yml`
  — returns only inline `# vX.Y.Z` comments, not refs.
- `grep -r ":-admin\|:-change-me\|:-admin123" deploy/docker/` — empty.
