# Phase 202 — Critical Review

> **Target:** `docs/phases/PHASE_202.md` — "CI Supply Chain + Default Credential Removal"
> **Scope:** infrastructure (CI/CD, compose, Dockerfile, test Redis) — no runtime Go/Python code.
> **Dependencies:** none (manifest confirms). No phase blockers.
> **Reviewer:** cybersecurity/DevOps/SRE lens, 2026-04-15.

---

## TL;DR

The phase goal is right — six real infra gaps — but the phase doc has **drifted from reality** on two sub-phases (202a and 202c are already partially/fully done) and uses the **wrong directory prefix throughout** (`docker/` vs actual `deploy/docker/`, moved by phase 205). The remaining work (202b, 202d, 202e) is clean, small, and parallel-safe. Before any implementation begins, the phase doc must be refreshed against current repo state.

No CRITICAL findings. Two HIGH (stale phase doc, wrong paths) that block clean handoff. Everything else is plan-quality nits.

---

## Verified state vs phase doc claims

| Sub-phase | Phase doc says | Actual state (2026-04-15) | Action |
|---|---|---|---|
| 202a SHA-pin `ja4proxy-policy.yml` | Not pinned, needs work | **Already fully SHA-pinned** (4 uses, all 40-char SHAs with version comments). `ci.yml` also fully pinned (18/18). `release-cli.yml` 10/10 on `uses:` actions, but line 57 references SLSA reusable workflow at `@v2.1.0` (tag, not SHA) | Rescope 202a: audit ALL workflows, only action is the SLSA reusable workflow (trusted org — often accepted tag-pinned) |
| 202b default creds | `docker/*.yml` | Paths are `deploy/docker/*.yml`; 5 real findings confirmed: `GRAFANA_PASSWORD:-admin`, `HAPROXY_STATS_USER:-admin`, `HAPROXY_STATS_PASSWORD:-admin123`, `MANAGEMENT_JWT_SECRET:-change-me-in-production`, `MANAGEMENT_ADMIN_USER:-admin`, `MANAGEMENT_ADMIN_PASSWORD:-admin` | Valid, proceed with path correction |
| 202c `Dockerfile.go-proxy` | Needs USER + pinned base | **Already has non-root USER** (line 51, `USER ja4proxy`), **base images pinned to `golang:1.25-alpine` and `alpine:3.19`** (not `:latest`). Gaps: no UID explicitly set (alpine `adduser -S` assigns a random low UID — breaks k8s `runAsNonRoot` numeric check); no OCI `LABEL`; base images tag-pinned not digest-pinned | Rescope 202c: explicit UID, OCI labels, digest-pin bases |
| 202d Go image CI | No workflow | Confirmed missing | Valid, proceed |
| 202e test Redis | Exposed `6380:6379`, no password | Confirmed: `"6380:6379"` on all interfaces, `REDIS_PASSWORD: ""` | Valid, proceed |

---

## 2a. Security Review

- **Threat model:** six pre-existing gaps; no new attack surface introduced. Core asymmetry (FP cost > FN cost) unaffected — all changes are infra-only, no runtime decision paths.
- **Supply chain:** the phase doc's suggested action SHAs (`11bd71…` for `actions/checkout`) are **older than what the repo already uses** (`de0fac2e…` which is checkout v6.0.2). Using the doc's SHAs would be a regression. The phase doc pre-dates phase 201's SHA-pinning work.
- **Secrets handling:** `:?required` syntax is the right mechanism — containers refuse to start instead of silently accepting defaults. Beware: `docker compose config` fails early if env vars unset, which may break CI smoke tests that don't currently export these — needs checked in 202b.
- **Hardcoded secrets:** no new ones introduced. 202e adds `test-fixtures-pw` which is intentional test-only and gitignored-free (never rotated).
- **Privilege (202c):** current `USER ja4proxy` uses alpine's `-S` system user which gets a random UID < 1000 (typically 100-ish). Kubernetes `securityContext.runAsNonRoot: true` **with `runAsUser: 1000` check will fail**. Explicit `-u 1000` recommended (aligns with phase doc step 3).
- **OWASP:** N/A (no web-facing code changes).

## 2b. DevOps Review

- **Build/deploy:** 202d introduces a new CI workflow building/signing/pushing to GHCR. `release-cli.yml` is a solid template. Trigger on `docker/Dockerfile.go-proxy` **path is wrong** (`deploy/docker/Dockerfile.go-proxy`). Needs correction.
- **Feature flags / rollback:** all changes are config-only on the infra layer; revertible by `git revert`. No data migration.
- **Resource:** nil.
- **SBOM/cosign (202d):** the repo already has cosign signing patterns in `release-cli.yml` — use that for the Go image too. `COSIGN_PRIVATE_KEY`/`COSIGN_PASSWORD` secrets likely already configured at org level; verify before requesting user action.

## 2c. SRE Review

- **Observability:** no new metrics/logs/alerts needed (pure infra).
- **Failure modes:** 202b `:?required` — if ops forgets to set `GRAFANA_PASSWORD`, Grafana will refuse to start. Document in a release note or runbook so upgrade surprises are softened.
- **Runbook:** recommend a small entry in `docs/runbooks/` (`deploy_credentials.md` or similar) listing the required env vars now that defaults are gone.
- **Capacity:** nil.
- **Graceful degradation:** N/A (infra).

## 2d. Architecture Review

- **Fit:** outside the proxy pipeline entirely. No interface boundary implications.
- **Concurrency:** N/A.
- **IPv6 (202e):** `127.0.0.1:6380:6379` is IPv4-only. On dual-stack hosts where tests prefer `::1`, this could break. Safer form: `"127.0.0.1:6380:6379"` is fine for test because tests already explicitly use `127.0.0.1` — but call it out. Alternatively bind to `::1` as well via two port mappings.
- **Redis schema:** no new keys.

## 2e. Testing Review

- **202b:** add test that `docker compose -f deploy/docker/docker-compose.poc.yml config` **fails** when `MANAGEMENT_JWT_SECRET` is unset, **passes** when set. Pattern: `test_container_config.py` per CLAUDE.md web-phase rule.
- **202c:** test that built image's running UID is 1000, not 0 or random-low (`docker run --rm ja4proxy-go:test id -u`).
- **202d:** the CI workflow IS the test — first run-through is the acceptance test. Add a `scripts/verify-image-signature.sh` using `cosign verify` so the verification procedure is versioned.
- **202e:** update any test code that builds a Redis URL for `6380` to include the password. Check `tests/conftest.py` and `tests/integration/` before changing the default, not after.
- **Test-to-code ratio:** this phase is infra-only; the ratio doesn't apply in the usual way. The test burden is smoke/config-validation, not unit tests.

## 2f. Documentation Review

- **CHANGELOG:** one entry per sub-phase per existing pattern.
- **Redis schema:** no changes.
- **Runbook:** new file `docs/runbooks/deploy_credentials.md` recommended.
- **ADR:** 202d (image signing & SBOM strategy) deserves ADR-202d — pull vs push verification, what's trusted, key rotation policy.
- **Phase doc SMART-ness:** mostly good. Needs refresh for: (a) directory path `docker/` → `deploy/docker/` everywhere, (b) 202a scope narrowing (already done, only SLSA left), (c) 202c scope narrowing (USER exists, pin digests + explicit UID only).

---

## Step 3 — Risk Summary

| # | Finding | Severity | Lens | Recommendation |
|---|---|---|---|---|
| 1 | Phase doc paths use `docker/` but actual repo layout is `deploy/docker/` (moved in phase 205) | HIGH | 2b / 2f | Refresh all file paths in `PHASE_202.md` before handoff |
| 2 | 202a scope is largely stale — `ja4proxy-policy.yml` & `ci.yml` already fully SHA-pinned; only `release-cli.yml` line 57 SLSA reusable workflow remains | HIGH | 2a / 2f | Rescope 202a to "audit all workflows, pin SLSA reusable workflow if policy requires SHA for reusables" — could become WONTFIX if tag-pinning a trusted reusable is acceptable policy |
| 3 | 202c: `Dockerfile.go-proxy` already has `USER` + pinned base images (`golang:1.25-alpine`, `alpine:3.19`). Remaining gaps: no explicit UID (breaks k8s `runAsUser: 1000`), no OCI `image.source` label, bases pinned to tag not digest | MEDIUM | 2a / 2f | Rescope 202c to UID + OCI labels + optional digest-pin; drop USER-add step (done) |
| 4 | Phase doc step 2 suggests SHA `11bd71…` for `actions/checkout@v4.1.1` — older than what's in-tree (`de0fac2…` v6.0.2) | MEDIUM | 2a | Any new workflow (202d) MUST match SHAs already used elsewhere — grep existing workflows for the canonical SHA and reuse |
| 5 | 202b `:?required` syntax will break `docker compose config` / `docker compose up` when env vars unset — could silently break any CI/dev smoke path that doesn't export them | MEDIUM | 2b / 2e | Before pushing 202b, `grep -r "docker compose" .github/ scripts/ Makefile` and confirm all invocations either export creds or use `--env-file` |
| 6 | 202c running UID — alpine `adduser -S` assigns random system-uid < 1000; fails `runAsNonRoot` numeric policies in k8s | MEDIUM | 2a | Use `-u 1000` in phase-2c change; document in the Dockerfile |
| 7 | 202d Dockerfile-path filter trigger — phase doc says `push.paths: ['docker/Dockerfile.go-proxy']` which won't match the real path | MEDIUM | 2b | Use `deploy/docker/Dockerfile.go-proxy` and `internal/**`, `cmd/proxy/**`, `go.mod`, `go.sum` as triggers (image changes when Go code changes too) |
| 8 | 202e `"6380:6379"` → `"127.0.0.1:6380:6379"` on dual-stack hosts where tests prefer `::1` may break; check `tests/conftest.py` Redis URL | LOW | 2c | Grep tests for `6380` / `127.0.0.1` / `::1` before changing binding |
| 9 | No runbook entry planned for new required env vars — ops upgrade surprise | LOW | 2c / 2f | Add `docs/runbooks/deploy_credentials.md` listing env vars and what fails without each |
| 10 | No ADR planned for image signing / SBOM / verification policy | LOW | 2f | Add ADR-202d (one page): chosen signing backend (keyless vs key-based), where SBOMs live, who verifies |
| 11 | 202d acceptance criterion "Trivy scan passes (no CRITICAL vulnerabilities)" gives Trivy veto over merges — legitimate but needs an allow-list for triaged CVEs | LOW | 2b | Add `.trivyignore` with comment-per-entry pattern; set `exit-code: 1` only for `--severity CRITICAL` |
| 12 | Phase doc lists 5 sub-phases but manifest dependencies-list is empty — fine, but sub_phase dependency (202d→202c) should be annotated in the manifest `sub_phases` tree | INFO | 2f | Add `depends_on: [202c]` under 202d in manifest for tooling clarity |

---

## Step 4 — Junior-Engineer Sub-Tasks

All sub-tasks are SAFE: no production runtime touched. Worst-case failure is a CI red or a container that refuses to start locally. Default dial invariant preserved (we touch no scoring code).

### Pre-flight — PM must do before spawning agents

### Sub-task 0.1: Refresh PHASE_202.md against current repo state
**Size:** S (1 h)
**Depends on:** none
**Parallel with:** none (gates everything else)
**Files to touch:** `docs/phases/PHASE_202.md`
**What to do:**
- Replace every `docker/` with `deploy/docker/` (also `monitoring/`, `config/` paths).
- Rescope 202a to just "audit ALL workflows, pin SLSA reusable workflow OR document policy decision" and remove the stale `@v4→SHA` examples; provide the real canonical SHAs from `.github/workflows/ci.yml` instead.
- Rescope 202c to "add explicit UID 1000 + OCI labels + (optional) digest-pin bases"; remove the "add USER directive" step because it's already there.
- Correct the 202d trigger path filter.
**Done when:**
- [ ] `grep -n "docker/" docs/phases/PHASE_202.md | grep -v "deploy/docker"` returns nothing
- [ ] 202a and 202c scopes reflect 2026-04-15 state, not 2026-04-11 state
**Watch out for:** don't rewrite the phase doc in place without committing — the refresh itself is a traceable artefact.

### Scaffolding

### Sub-task 1.1: Add deploy-credentials runbook stub
**Size:** XS (20 min)
**Depends on:** 0.1
**Parallel with:** 1.2, 1.3
**Files to touch:** `docs/runbooks/deploy_credentials.md` (new)
**What to do:** list every env var made mandatory (`GRAFANA_PASSWORD`, `HAPROXY_STATS_USER`, `HAPROXY_STATS_PASSWORD`, `MANAGEMENT_JWT_SECRET`, `MANAGEMENT_ADMIN_USER`, `MANAGEMENT_ADMIN_PASSWORD`) with: what fails without it, who needs to set it, rotation guidance.
**Done when:**
- [ ] File exists with all 6 env vars documented
- [ ] Referenced from `docs/runbooks/README.md` index

### Sub-task 1.2: Add ADR-202d stub for image signing & SBOM
**Size:** XS (30 min)
**Depends on:** 0.1
**Parallel with:** 1.1, 1.3
**Files to touch:** `docs/decisions/ADR-202d.md` (new)
**What to do:** decision (keyless OIDC vs key-based cosign), where SBOMs live (GHCR attached artifact vs release asset), who verifies (users vs admission controller).
**Done when:**
- [ ] Status: Proposed, resolves before 202d merge

### Sub-task 1.3: Add .trivyignore with triage pattern
**Size:** XS (15 min)
**Depends on:** 0.1
**Parallel with:** 1.1, 1.2
**Files to touch:** `.trivyignore` (new or extend)
**What to do:** empty-but-commented file documenting the entry format (`CVE-YYYY-NNNNN # reason + expiry-date`). No actual CVEs to suppress until 202d runs.

### Core logic — all parallel

### Sub-task 2.1: 202a — audit all workflows, pin what's left
**Size:** XS (30 min)
**Depends on:** 0.1
**Parallel with:** 2.2, 2.3, 2.5
**Files to touch:** `.github/workflows/release-cli.yml`
**What to do:**
- Run `grep -nE "uses: [^@]+@(v[0-9]|main|master)" .github/workflows/*.yml` — expect only the SLSA reusable at `release-cli.yml:57`.
- Either pin to SHA (check GitHub's docs for SLSA v2.1.0 commit) OR document in `docs/decisions/ADR-202a.md` that the SLSA reusable is allowlisted by tag because it's a trusted org reusable workflow (GitHub policy permits this).
**Done when:**
- [ ] No unpinned action references remain OR ADR documents the exception
- [ ] `grep -nE "uses: [^@]+@v[0-9]" .github/workflows/*.yml` empty (for ordinary actions)
**Watch out for:** reusable workflows (`workflow_call`) are NOT the same as actions — GitHub does allow tag-pinning these from trusted orgs per their own docs.

### Sub-task 2.2: 202b — swap defaults to `:?required` in compose files
**Size:** XS (30 min)
**Depends on:** 0.1
**Parallel with:** 2.1, 2.3, 2.5
**Files to touch:** `deploy/docker/docker-compose.monitoring.yml`, `deploy/docker/docker-compose.poc.yml`
**What to do:**
- Replace the 5 confirmed findings with `${VAR:?VAR is required}` syntax.
- Grep `Makefile`, `.github/workflows/`, `scripts/` for any `docker compose` invocation touching these files — if any invocation relies on the defaults, update it to export env vars or skip gracefully.
**Done when:**
- [ ] `grep -r ":-admin\|:-change-me\|:-admin123" deploy/docker/` empty
- [ ] `docker compose -f deploy/docker/docker-compose.poc.yml config` fails with clear error when `MANAGEMENT_JWT_SECRET` unset, passes when set
**Watch out for:** breaking local `make smoke` / CI smoke — check before pushing.

### Sub-task 2.3: 202c — explicit UID + OCI labels in Dockerfile.go-proxy
**Size:** XS (30 min)
**Depends on:** 0.1
**Parallel with:** 2.1, 2.2, 2.5
**Files to touch:** `deploy/docker/Dockerfile.go-proxy`
**What to do:**
- Change `addgroup -S ja4proxy && adduser -S -G ja4proxy ja4proxy` to `addgroup -g 1000 -S ja4proxy && adduser -u 1000 -S -G ja4proxy ja4proxy`.
- Change `USER ja4proxy` to `USER 1000:1000` (numeric for k8s `runAsNonRoot`).
- Add `LABEL org.opencontainers.image.source="https://github.com/anomalyco/JA4proxy"`, `…image.title`, `…image.licenses`.
- Optional: digest-pin `golang:1.25-alpine@sha256:…` and `alpine:3.19@sha256:…` — look up via `docker pull` + `docker inspect --format='{{index .RepoDigests 0}}'`.
**Done when:**
- [ ] `docker build -f deploy/docker/Dockerfile.go-proxy -t ja4proxy-go:test .` succeeds
- [ ] `docker run --rm --entrypoint /bin/sh ja4proxy-go:test -c 'id -u'` prints `1000`
- [ ] `hadolint deploy/docker/Dockerfile.go-proxy` returns zero warnings
**Watch out for:** UID 1000 may collide with existing user inside some base images — alpine doesn't have one at 1000 by default, so safe here.

### Sub-task 2.5: 202e — bind test Redis to loopback + set password
**Size:** XS (30 min)
**Depends on:** 0.1
**Parallel with:** 2.1, 2.2, 2.3
**Files to touch:** `deploy/docker/docker-compose.test.yml`, test helpers that build Redis URLs
**What to do:**
- Change `"6380:6379"` → `"127.0.0.1:6380:6379"`.
- Change `REDIS_PASSWORD: ""` → `REDIS_PASSWORD: "${REDIS_TEST_PASSWORD:-test-fixtures-pw}"`.
- Add `command: ["redis-server", "--requirepass", "${REDIS_TEST_PASSWORD:-test-fixtures-pw}"]`.
- Grep `tests/conftest.py`, `tests/integration/`, `Makefile` for `6380` and update any real-Redis URL to `redis://:test-fixtures-pw@127.0.0.1:6380/0`.
**Done when:**
- [ ] Test compose config validates
- [ ] `make test` passes (fakeredis unaffected; real-Redis integration tests use password)
- [ ] `ss -tlnp | grep :6380` after `docker compose up` shows bind on 127.0.0.1, not 0.0.0.0
**Watch out for:** the Redis URL colon syntax — `redis://:password@host/db` has an **empty username** before the colon. A URL like `redis://password@host/db` silently interprets `password` as the username.

### Sub-task 2.4: 202d — Go proxy image CI workflow (depends on 2.3)

### Sub-task 2.4a: 202d workflow scaffold
**Size:** S (2 h)
**Depends on:** 2.3
**Parallel with:** nothing in Wave 2
**Files to touch:** `.github/workflows/go-proxy-image.yml` (new)
**What to do:**
- Copy `.github/workflows/release-cli.yml` job skeleton: `test` → `build` → `scan` → `sbom` → `sign` → `push`.
- Triggers: `push.paths: ['deploy/docker/Dockerfile.go-proxy', 'cmd/proxy/**', 'internal/**', 'go.mod', 'go.sum']`; `tags: ['v*-go-proxy']`; `workflow_dispatch`.
- Every `uses:` must be SHA-pinned — copy SHAs from `ci.yml` / `ja4proxy-policy.yml` for consistency (do NOT use phase-doc-suggested SHAs).
- Build with `docker/build-push-action`, scan with `aquasecurity/trivy-action`, SBOM with `anchore/sbom-action` (CycloneDX JSON), sign with `sigstore/cosign-installer` + `cosign sign`.
**Done when:**
- [ ] `yamllint .github/workflows/go-proxy-image.yml` passes
- [ ] `grep -E "uses: [^@]+@v[0-9]" .github/workflows/go-proxy-image.yml` empty
- [ ] Workflow parses in GitHub Actions UI (`gh workflow view go-proxy-image.yml`)

### Sub-task 2.4b: 202d cosign + secrets wiring
**Size:** S (1 h)
**Depends on:** 2.4a
**Parallel with:** none
**Files to touch:** `.github/workflows/go-proxy-image.yml`, `docs/decisions/ADR-202d.md`, optionally `docs/enterprise/` secrets docs
**What to do:**
- Decide keyless (Fulcio OIDC) vs key-based (`COSIGN_PRIVATE_KEY` + `COSIGN_PASSWORD`). Default to keyless — simpler, no secret rotation.
- If keyless: no secrets to add. If key-based: document the secret names + rotation cadence in ADR-202d.
- `scripts/verify-image-signature.sh` (new) with `cosign verify --certificate-identity-regexp …` for users to check signatures.
**Done when:**
- [ ] ADR-202d is Accepted, not Proposed
- [ ] Verification script succeeds against a signed image from the CI run

### Sub-task 2.4c: 202d end-to-end smoke
**Size:** S (1 h)
**Depends on:** 2.4b
**Files to touch:** none (operational)
**What to do:** push branch, observe CI, fix any red, verify signed image in GHCR, verify `cosign verify` works, verify SBOM attached as OCI artifact.
**Done when:**
- [ ] Workflow runs green end-to-end on the branch
- [ ] `cosign verify ghcr.io/anomalyco/ja4proxy-go:<sha>` succeeds
- [ ] SBOM artifact retrievable (`cosign download sbom …`)

### Testing

### Sub-task 3.1: container-config test for required secrets
**Size:** XS (30 min)
**Depends on:** 2.2
**Files to touch:** `tests/integration/test_container_config.py` (extend)
**What to do:** parameterised test that unsets each of the 6 env vars in turn and asserts `docker compose config` fails with a clear error mentioning the variable name.

### Sub-task 3.2: Dockerfile UID test
**Size:** XS (20 min)
**Depends on:** 2.3
**Files to touch:** `tests/integration/test_go_proxy_image.py` (new or extend)
**What to do:** build image, `docker run --rm --entrypoint id <image>` → assert uid=1000, gid=1000.

### Sub-task 3.3: Redis loopback-bind test
**Size:** XS (20 min)
**Depends on:** 2.5
**Files to touch:** `tests/integration/test_container_config.py`
**What to do:** parse `deploy/docker/docker-compose.test.yml`, assert `ports[*]` for `redis-test` service starts with `127.0.0.1:`.

### Hardening

### Sub-task 4.1: `make smoke` / CI invocation audit
**Size:** XS (30 min)
**Depends on:** 2.2
**Files to touch:** `Makefile`, `scripts/smoke.sh`, `.github/workflows/*.yml`
**What to do:** every `docker compose` invocation that touches monitoring/poc files must export the required env vars first OR guard with `if [[ -z "$GRAFANA_PASSWORD" ]]; then skip; fi`.

### Documentation

### Sub-task 5.1: CHANGELOG + manifest + phase-notes
**Size:** XS (30 min)
**Depends on:** all 2.x
**Files to touch:** `CHANGELOG.md`, `docs/phases/manifest.yaml`, `docs/phases/PHASE_202_notes.md`
**What to do:** one CHANGELOG block per sub-phase; manifest status flipped to COMPLETE; notes file summarising what changed vs the original phase doc (specifically: 202a already done, 202c rescope).

---

## Step 5 — Summary

- **Total sub-tasks:** 14 (1 pre-flight, 3 scaffolding, 6 core, 3 testing, 1 hardening, 1 docs) across 5 groups.
- **Estimated total hours:** ~8 h of engineering, plus one CI run-through (~15 min wall clock).
- **Parallelism:** after pre-flight 0.1, sub-tasks 1.1/1.2/1.3 run in parallel; then 2.1/2.2/2.3/2.5 run in parallel; 2.4a→b→c is serial; 3.x parallel after their 2.x prereq.
- **Critical blockers before implementation:**
  1. **0.1 MUST complete first** — the phase doc is stale. Without a refresh, agents will modify non-existent paths and suggest SHAs older than what's already in-tree.
- **No CRITICAL security findings** in the proposal itself. The six gaps it closes are real, the approach is sound, the residual risk after this phase is low.

**Recommendation:** proceed with `/run-phase 202` ONLY after pre-flight 0.1 is complete and committed.
