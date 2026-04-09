#!/usr/bin/env bash
# scripts/branch_protection.sh — bootstrap GitHub branch protection for main.
#
# Phase 61. Run this ONCE when the repo is first configured, and again whenever
# the set of required status checks in .github/workflows/ci.yml changes.
#
# Usage:
#     bash scripts/branch_protection.sh <owner>/<repo>
#
# Requires: gh CLI authenticated as a user with admin on the repo.
#
# Rationale for each setting:
#   required_status_checks.strict = true
#       PRs must be up-to-date with main before merging. Prevents "merge
#       skew" where two green PRs interact badly after merge.
#   required_pull_request_reviews = null
#       This is an AI-agent project — the gate is CI, not human review.
#   enforce_admins = false
#       Allows emergency hotfix via admin override, which is still logged in
#       the audit trail for review.
#   restrictions = null
#       Anyone with write can open a PR; the CI check is the real gate.
#
# Direct pushes to main remain blocked by the required_status_checks rule.
set -euo pipefail

REPO="${1:?Usage: branch_protection.sh <owner>/<repo>}"

gh api "repos/${REPO}/branches/main/protection" \
  --method PUT \
  --header "Accept: application/vnd.github+json" \
  --field "required_status_checks[strict]=true" \
  --field "required_status_checks[contexts][]=Go tests" \
  --field "required_status_checks[contexts][]=Python tests" \
  --field "required_status_checks[contexts][]=Lint (go vet + gofmt + ruff)" \
  --field "required_status_checks[contexts][]=Secrets scan (TruffleHog)" \
  --field "required_status_checks[contexts][]=SAST (Semgrep)" \
  --field "required_status_checks[contexts][]=Python dependency audit (pip-audit)" \
  --field "required_status_checks[contexts][]=Go dependency audit (govulncheck)" \
  --field "enforce_admins=false" \
  --field "required_pull_request_reviews=" \
  --field "restrictions="

echo "Branch protection applied to ${REPO}:main"
