# Pentest: Supply Chain and CI/CD (Fork-Based, De-Escalation Ladder)

## Goal

Execute a comprehensive adversarial penetration test of JA4proxy's complete software supply chain, build pipeline, and GitHub Actions CI/CD automation. Evaluate the security boundaries of workflows (specifically `pull_request_target` triggers with elevated write tokens), `${{ }}` expression injection into execution blocks, action pinning integrity, artifact tampering detection (SLSA provenance verification failure paths), container image signing, dependency confusion risks, and multi-agent CI automation. Strictly adhere to the canonical five-level de-escalation ladder (L0 static review to L4 push probe per `RULES_OF_ENGAGEMENT.md` §4) with owner checkpoints and stop-at-lowest-level discipline. Every discovered finding must adhere to the 12-section fix-specification standard (`PROGRAMME.md` §9) and include a verified two-state regression proof (`scripts/verify_revert.sh`).

## Scope

### In Scope

1. **Canonical De-Escalation Ladder Protocol (`RULES_OF_ENGAGEMENT.md` §4):**
   - **L0 (Static Review):** Read, parse, and reason statically about all 16 workflow files (`.github/workflows/*.yml`), composite actions, and CI helper scripts without triggering any runs. No execution anywhere.
   - **L1 (Inert Fork Inventory):** Private isolated fork created, **Actions disabled**, secrets scrubbed. Inventory what *would* run and confirm the fork is completely inert.
   - **L2 (Fork Simulation with Dummy Secrets):** Actions enabled in the fork, **dummy secrets only** (synthetic/canary values, never real secrets). Benign PR from a fork-internal branch. Notify owner after L1.
   - **L3 (Fork Adversarial Content):** Adversarial *content* in a fork-internal PR (crafted branch name, workflow payload, commit message). **Mandatory owner checkpoint before entry.**
   - **L4 (Push / Permission Probe):** Push/permission probe only if L3 demonstrates a plausible unconfirmed execution path. Requires owner go-ahead per instance.
   - **Governing Rule:** Stop at the lowest level that answers the question. Upstream testing is **strictly PROHIBITED (RED)**. Immediate abort if any upstream event or unintended effect is observed.

2. **Elevated Privilege Workflows (`pull_request_target`):**
   - **Tier 1 Target — `maintainer-automerge.yml` (Phase 838):**
     - Runs on `pull_request_target` with elevated write tokens (`contents: write`, `pull-requests: write`).
     - Condition audit: `if: (github.actor == 'seanpor' || startsWith(github.head_ref, 'phase-')) && !github.event.pull_request.draft`.
     - Attack vector: Verify if an external attacker can submit a PR from a fork branch named `phase-exploit` to satisfy `startsWith(github.head_ref, 'phase-')`, triggering automated squash-merging of untrusted code into `main` or abusing write permissions.
     - Verification: Prove whether `github.head_ref` refers to the fork branch name and whether fork repository qualification (`github.event.pull_request.head.repo.full_name == github.repository`) is strictly required.
   - **Tier 1 Target — `pin-table-autofix.yml` (Phase 812-C):**
     - Runs on `pull_request_target` with `contents: write`.
     - Condition audit: `if: github.event.pull_request.user.login == 'dependabot[bot]'`. Can actor validation be spoofed via user rename, commit authorship, or crafted webhook payloads?
     - Git worktree hygiene: Evaluate `git fetch origin "$HEAD_REF"` and `git worktree add /tmp/pr-branch "origin/$HEAD_REF"`.
     - Refspec injection: Test if `$HEAD_REF` containing path traversal (`../../main`), ref flags (`--upload-pack`), or malicious refspecs can manipulate upstream git state.
     - Git execution risks during worktree checkout: Determine whether `git worktree add` invokes `.git/hooks`, malicious filter drivers defined in untrusted `.gitattributes`, or recursive `.gitmodules`.
     - Push target confinement: Assert `git push origin "HEAD:refs/heads/${HEAD_REF}"` cannot overwrite protected branches (`main`, release tags).
     - Parser attack surface: Audit `scripts/pin_table_autofix.py` against ReDoS, AST manipulation, and unexpected triple injection.

3. **Expression Injection & Untrusted Contexts Audit (All 16 Workflows):**
   - Perform static AST analysis of all 16 workflows:
     - `.github/workflows/ci.yml`
     - `.github/workflows/dependabot-automerge.yml`
     - `.github/workflows/dependabot-pr-refresh.yml`
     - `.github/workflows/docs-link-check.yml`
     - `.github/workflows/docs-pdf.yml`
     - `.github/workflows/go-proxy-image.yml`
     - `.github/workflows/ja4proxy-policy.yml`
     - `.github/workflows/maintainer-automerge.yml`
     - `.github/workflows/management-image.yml`
     - `.github/workflows/nightly-benchmark.yml`
     - `.github/workflows/pin-table-autofix.yml`
     - `.github/workflows/process-metrics.yml`
     - `.github/workflows/release-cli.yml`
     - `.github/workflows/scorecard.yml`
     - `.github/workflows/slsa-verify.yml`
     - `.github/workflows/trivyignore-renewal.yml`
   - Detect inline expansion of `${{ ... }}` in `run:` blocks containing untrusted contexts (`github.head_ref`, `github.event.pull_request.title`, `github.event.issue.body`, `github.event.comment.body`, git commit messages, workflow inputs).
   - Verify that all untrusted expressions are passed strictly via intermediate environment variables (`env:`).

4. **Token Permissions & Least Privilege:**
   - Audit job-level and top-level `permissions:` blocks across all 16 workflows.
   - Verify default `permissions: read-all` or explicit minimal declarations (`contents: read`).
   - Audit secret isolation: confirm no repository secrets (`CR_PAT`, `DOCKERHUB_TOKEN`, `SLACK_WEBHOOK`, etc.) are exposed or leakage-prone in fork PR contexts.

5. **Action Pinning & Supply Chain Integrity:**
   - Verify SHA-256 commit hash pinning across all third-party GitHub Actions (`actions/checkout`, `docker/build-push-action`, `setup-python`, etc.).
   - Test enforcement of `tests/test_workflow_pinning.py` against unpinned actions or mutable tag references.
   - Evaluate cache poisoning risks in `actions/cache` across workflow branches.

6. **Artifact Integrity & SLSA Provenance Verification:**
   - Adversarial verification of `slsa-verify.yml`:
     - Test failure closed on tampered container image digest.
     - Test failure closed on mismatched source URI (fork provenance presented to upstream base).
     - Test failure closed on tampered in-toto predicate or subject digest.
     - Test Cosign / Sigstore OIDC SAN identity boundary enforcement.
   - Audit SBOM completeness (Syft / CycloneDX) against container image layers.

7. **Dependency Confusion & Namespace Protection:**
   - Audit Python dependencies (`requirements.txt`, `pyproject.toml`, `setup.cfg`) and Go modules (`go.mod`, `go.sum`).
   - Confirm internal package names and build tooling do not collide with public PyPI or Go proxy namespaces.

### Out of Scope
- Denial of service attacks against GitHub infrastructure or runners.
- Social engineering or credential attacks on maintainers.
- Any live execution or testing against the upstream `seanpor/JA4proxy` repository.

---

## Implementation Plan

### Step 1: L0 Static AST & Expression Injection Scanner
1. Author `tests/adversarial/cicd/test_workflow_expression_injection.py`:
   - Parse all 16 workflow YAML files into an Abstract Syntax Tree.
   - Search every `run:` shell step for inline `${{ ... }}` syntax referencing untrusted contexts.
   - Assert zero occurrences of untrusted contexts directly embedded in shell strings.

### Step 2: L0/L1 `pull_request_target` Security & Worktree Isolation Test Suite
1. Author `tests/adversarial/cicd/test_maintainer_automerge_security.py`:
   - Test event condition evaluation against simulated PR payloads:
     - External fork PR with branch named `phase-attack`.
     - External fork PR with maintainer username spoofing.
     - Non-draft vs draft status handling.
   - Assert that `maintainer-automerge.yml` rejects any PR where `head.repo.full_name != github.repository`.
2. Author `tests/adversarial/cicd/test_pin_table_autofix_security.py`:
   - Test actor validation against spoofed events (`dependabot[bot]` login check).
   - Test refspec injection: evaluate branch names containing path traversals (`../../main`), shell escapes, and flags.
   - Test git worktree checkout safety:
     - Assert `-c core.hooksPath=/dev/null` is set or verified.
     - Assert untrusted `.gitattributes` filter drivers (`smudge`, `clean`) cannot execute arbitrary code during checkout.
     - Assert submodule recursion is disabled.
   - Test push constraint: assert push refspec is strictly bounded and cannot target protected branches.
   - Test `scripts/pin_table_autofix.py` parser robustness against ReDoS and corrupted workflow entries.

### Step 3: L0 Workflow Permissions & Secrets Audit
1. Author `tests/adversarial/cicd/test_workflow_permissions.py`:
   - Inspect all 16 workflows for top-level and job-level `permissions:`.
   - Assert no job has unconstrained `write-all` permissions.
   - Verify that write tokens (`contents: write`, `pull-requests: write`, `id-token: write`) are strictly restricted to jobs that require them and gated with repository qualification.

### Step 4: L1 SLSA Provenance & Tamper-Detection Negative Tests
1. Author `tests/adversarial/cicd/test_slsa_tamper_detection.py`:
   - Test `slsa-verifier` negative control modes:
     - Altered image digest (tampered binary).
     - Altered source URI (e.g. `github.com/attacker/ja4proxy`).
     - Corrupted or forged in-toto statement predicate.
   - Assert all failure modes exit non-zero and fail closed.

### Step 5: L0 Dependency Confusion & Namespace Protection Audit
1. Author `tests/adversarial/cicd/test_dependency_confusion.py`:
   - Inspect all dependencies in `requirements.txt`, `pyproject.toml`, and `go.mod`.
   - Verify no private unreserved package names exist that can be claimed on public package indexes.

### Step 6: Remediation, Two-State Regression Verification & Phase Close-Out
1. Register any identified vulnerabilities in `docs/security/findings.yaml` with allocated `JA4PROXY-2026-NNNN` IDs and open linked GitHub issues.
2. Implement remediation patches (e.g., securing `maintainer-automerge.yml` and `pin-table-autofix.yml`).
3. Verify two-state proofs (`scripts/verify_revert.sh`) for all findings.
4. Run `make preflight` and prepare phase closeout via `scripts/close-phase.sh`.

---

## Test Strategy

- **L0 Static AST Verification:** Inspect all 16 GitHub Actions workflow files for syntax, permissions, and expression injection without triggering runner execution.
- **L1 Synthetic Simulation:** Mock GitHub runner environments, event payloads, and git execution contexts to verify validation logic offline.
- **L2 Fork Testing (If Needed):** Isolated private fork with dummy secrets and inert workflows.
- **L3 Adversarial Fork Testing (Owner Checkpoint Mandatory):** Only if static analysis requires validation of complex runner behaviour.
- **Regression Invariants:** Validate that CI gates fail when unpinned actions, expression injections, unauthorized PR branches, or tampered artifacts are introduced.

---

## Acceptance Criteria

- [x] Comprehensive test suite covering all 16 workflow files in `tests/adversarial/cicd/` passing 100%.
- [x] Detailed adversarial audit of `maintainer-automerge.yml` proving safe gate condition (fork PRs cannot trigger auto-merge).
- [x] Detailed audit of `pin-table-autofix.yml` proving safety against refspec injection, worktree filter exploitation, and unauthorized push targets.
- [x] SLSA provenance failure demonstrated closed against deliberately tampered artifacts and mismatched source URIs.
- [x] Zero unescaped expression injections `${{ ... }}` in `run:` shell steps across all 16 workflows.
- [x] All findings registered in `docs/security/findings.yaml` with verified two-state proofs.
- [x] `make preflight` and `bash scripts/close-phase.sh` exit 0.
