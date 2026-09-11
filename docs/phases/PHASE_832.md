# Dependabot Grouping & PR Backlog Reduction

## Goal
Radically reduce PR noise, merge churn, and CI queue congestion by configuring Dependabot grouped version updates, scheduled rebase sweeps, and automated conflict recovery.

## Background & Problem Analysis
Currently, 15 pull requests remain open. When dependencies update on their monthly cycle, Dependabot generates 15 to 20 individual, fine-grained pull requests simultaneously across pip, gomod, docker, and github-actions:
1. **The Rebase Treadmill**: Under `require_status_checks.strict: true`, landing each individual PR causes all remaining open PRs to become `BEHIND`. Merging 15 single PRs requires 15 consecutive CI cycles (~20 minutes each = ~5 hours of serialized CI time).
2. **Lockfile Collisions (`DIRTY`)**: Multiple PRs edit identical files (`go.mod`/`go.sum` or `requirements.txt`). As soon as one lands, the others hit merge conflicts and stall until re-created or rebased.
3. **Missing Grouping**: Dependabot currently has a `groups:` block configured only for `github-actions`. All `pip`, `gomod`, and `docker` updates are opened as un-grouped, 1-package-per-PR pull requests.

## Scope
1. **Dependabot Grouped Updates (`.github/dependabot.yml`)**:
   - Introduce logical `groups:` for:
     - `gomod`: group minor/patch dependencies together (`patterns: ["*"]`).
     - `pip`: group non-breaking application dependencies together (`patterns: ["*"]`, excluding major pins).
     - `docker`: group Dockerfile base image bumps.
   - Result: Instead of 15–20 individual PRs per cycle, Dependabot opens **3 to 4 consolidated PRs** (e.g., "build(deps): bump gomod dependencies", "build(deps): bump pip dependencies").
2. **Active Conflict Resolution in Cascading Rebase (`.github/workflows/dependabot-pr-refresh.yml`)**:
   - When a PR enters `mergeable_state == "dirty"`, trigger `@dependabot rebase` or close-and-reopen to force Dependabot to resolve lockfile drift.
3. **Scheduled Off-Peak Sweeps**:
   - Add a scheduled cron trigger (`schedule: - cron: '0 2 * * *'`) to `dependabot-pr-refresh.yml` so any PRs that became `BEHIND` overnight automatically rebase before the working day.

## Implementation Plan

### Step 1: Group Dependabot Ecosystems
Update `.github/dependabot.yml`:
```yaml
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "monthly"
    groups:
      python-dependencies:
        patterns:
          - "*"
        exclude-patterns:
          - "pip-audit"

  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "monthly"
    groups:
      go-dependencies:
        patterns:
          - "*"
```

### Step 2: Add Scheduled Run to `dependabot-pr-refresh.yml`
Ensure `dependabot-pr-refresh.yml` runs both on `push: branches: [main]` and on a daily schedule (`cron: '0 3 * * *'`), keeping the queue steadily draining.

### Step 3: Test & Validation
- Validate `.github/dependabot.yml` syntax.
- Verify `make lint-phases`.
- Measure queue reduction from grouped updates.

## Acceptance Criteria
1. `.github/dependabot.yml` defines groups for `pip`, `gomod`, and `docker`.
2. New dependency update cycles produce grouped PRs instead of dozens of micro-PRs.
3. CI and merge queue times decrease by over 70% per update cycle.
