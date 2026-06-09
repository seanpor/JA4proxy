---
phase: 302
title: Repository Security Settings & Dependabot Automation
status: COMPLETE
size: SMALL
created: 2026-06-09
completed: 2026-06-09
audience: [operator, security, developer]
---

# Repository Security Settings & Dependabot Automation

## Goal

Turn on GitHub's free security aids for a **non-profit, zero-user, low-time**
project — maximising coverage while keeping ongoing effort near zero. The key
constraint: `main` is branch-protected (10 required checks + `enforce_admins` +
require-PR), so anything that opens PRs (Dependabot) must **auto-merge on green**
or it becomes a manual treadmill.

## What was enabled (via `gh api` — repo settings, not committable)

| Setting | State | Why |
|---|---|---|
| Dependabot **alerts** | ✅ enabled | Free, alerts-not-PRs → zero noise; flags vulnerable deps. |
| Dependabot **security updates** | ✅ enabled | Auto-PRs that *fix* vulnerable deps; auto-merge handles them (below). |
| **Private vulnerability reporting** | ✅ enabled | Free, zero-noise CVD intake for a security project. |
| Secret scanning + **push protection** | ✅ already on | Kept. |
| Secret scanning **validity checks** | ⚠️ operator UI toggle | Could **not** be set via API (no-op). Enable in Settings → Code security → Secret scanning. |
| Secret scanning **non-provider patterns** | ❌ left off | Higher false-positive rate; not worth the noise here. |

Commands used (for reproducibility):
```bash
gh api -X PUT repos/<owner>/<repo>/vulnerability-alerts
gh api -X PUT repos/<owner>/<repo>/automated-security-fixes
gh api -X PUT repos/<owner>/<repo>/private-vulnerability-reporting
```

## What was added (this PR — committable)

1. **`.github/workflows/dependabot-automerge.yml`** — enables GitHub auto-merge on
   Dependabot **patch/minor** PRs (they merge themselves once the 10 required
   checks pass). **Major** updates are left for manual review. Uses
   `dependabot/fetch-metadata` (SHA-pinned + added to the `KNOWN_ACTION_SHAS`
   allowlist in `tests/test_workflow_pinning.py`).
2. **`.github/dependabot.yml` → `monthly`** (was weekly) for all three ecosystems
   (github-actions, pip, gomod) — already grouped + capped at 5 open PRs; monthly
   halves the cadence so version-update PRs stay low-volume.

## Operator action still required (UI-only — cannot be scripted)

- [ ] **CodeQL** — Settings → Code security → Code scanning → **Set up → Default**.
      Adds deep Go+Python SAST. Leave it **informational** (do *not* add it to the
      required-status-checks set) so it never blocks merges.
- [ ] **Secret-scanning validity checks** — Settings → Code security → toggle on
      (API was a no-op).

## Deliberate non-goals
- Auto-merging **major** version bumps (can break APIs → manual review).
- Making CodeQL a *required* check (would need a branch_protection.sh + test
  update and risks the path-filter footgun; informational is enough here).
- Non-provider secret patterns (noise).

## Acceptance Criteria
1. Dependabot alerts, security updates, and private vulnerability reporting are
   enabled (verified via `gh api`).
2. A Dependabot patch/minor PR auto-merges once its required checks pass.
3. `dependabot.yml` is monthly; the auto-merge workflow is SHA-pinned and passes
   `tests/test_workflow_pinning.py`.
4. The two UI-only toggles are documented for the operator.
