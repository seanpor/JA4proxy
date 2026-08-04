#!/usr/bin/env bash
# scripts/branch_protection.sh — bootstrap GitHub branch protection for main.
#
# Phase 61 (created) · Phase "protect-correctness" (rewritten). Run this once
# when the repo is configured, and again whenever the set of required status
# checks in .github/workflows/ci.yml changes. The contexts below MUST equal the
# `name:` of every non-continue-on-error job in ci.yml (excluding the PR-only
# dependency-review job) — enforced by tests/test_workflow_pinning.py.
#
# Usage:
#     bash scripts/branch_protection.sh <owner>/<repo>
#
# Requires: gh CLI authenticated as a user with admin on the repo.
#
# Rationale for each setting:
#   required_status_checks.strict = true
#       PRs must be up-to-date with main before merging (no merge skew).
#   required_pull_request_reviews.required_approving_review_count = 0
#       Require a PR (this is what actually blocks direct pushes — a required
#       status check alone does NOT), but 0 human approvals: this is an
#       AI-agent project where the gate is CI, not human review.
#   enforce_admins = true
#       The rule binds everyone, admins included — otherwise actors pushing
#       with the admin token bypass it entirely (which is how broken commits
#       had been reaching main). Emergency hotfix: temporarily disable with
#       `gh api -X DELETE repos/<repo>/branches/main/protection/enforce_admins`,
#       land the fix, then re-enable with `-X POST` on the same path.
#   restrictions = null
#       Anyone with write can open a PR; the CI checks are the real gate.
set -euo pipefail

REPO="${1:?Usage: branch_protection.sh <owner>/<repo>}"

gh api "repos/${REPO}/branches/main/protection" \
  --method PUT \
  --header "Accept: application/vnd.github+json" \
  --field "required_status_checks[strict]=true" \
  --field "required_status_checks[contexts][]=Meta-Validation (Doctor + Meta-Lint)" \
  --field "required_status_checks[contexts][]=Full Lint (make lint)" \
  --field "required_status_checks[contexts][]=Full Test Suite (make test)" \
  --field "required_status_checks[contexts][]=Go Build + Compose Validate" \
  --field "required_status_checks[contexts][]=Go race tests (make test-race)" \
  --field "required_status_checks[contexts][]=Security Scan (make scan)" \
  --field "required_status_checks[contexts][]=Secrets scan (TruffleHog)" \
  --field "required_status_checks[contexts][]=SAST (Semgrep)" \
  --field "required_status_checks[contexts][]=Python dependency audit (pip-audit)" \
  --field "required_status_checks[contexts][]=Go dependency audit (govulncheck)" \
  --field "required_status_checks[contexts][]=Traceability matrix check" \
  --field "required_status_checks[contexts][]=lychee on conformance + audience-scoped docs" \
  --field "required_status_checks[contexts][]=Cold-start smoke test (start-poc.sh)" \
  --field "enforce_admins=true" \
  --field "required_pull_request_reviews[required_approving_review_count]=0" \
  --field "restrictions=null"

echo "Branch protection applied to ${REPO}:main"
