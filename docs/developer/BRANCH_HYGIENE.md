# Git Branch Lifecycle and Hygiene Guide

This document defines the branch lifecycle, classification rules, and cleanup methodology for the JA4proxy repository. It outlines how to identify and purge stale remote and local branches to maintain a clean git workspace.

---

## 1. The Squash-Merge "Unmerged" Side-Effect

JA4proxy uses a **Squash-and-Merge** workflow for all pull requests landing on the `main` branch. 
When a pull request is merged:
1. All commits on the feature branch are combined (squashed) into a single new commit on `main`.
2. This new commit has a different hash (SHA) than the commits on the feature branch.

Because the original commit hashes from the feature branch never appear in `main`'s history, standard git commands like `git branch -r --no-merged origin/main` will continue to report the remote feature branch as **unmerged**, even though its code changes have fully landed on `main`. 

Over time, this creates a large build-up of stale remote branches.

---

## 2. Analysis & Classification Methodology

To solve the squash-merge problem without risk of deleting unmerged work, we use a combined **Git Diff & GitHub API** check to classify branches.

### Branch Classification Logic
For each unmerged branch returned by `git branch -r --no-merged origin/main`:

1.  **Dependabot Filter:**
    - If the branch name starts with `dependabot/`, it is grouped as a `Dependabot` branch. These are handled separately since they are automatically managed by Dependabot.
2.  **GitHub PR State Query:**
    - Query the GitHub CLI (`gh pr list --head <branch_name> --state all`).
    - If an associated PR exists and is `MERGED` or `CLOSED`, the branch is classified as **Stale** (safe to delete).
3.  **Code Difference Check:**
    - If there is no PR, or if the PR check is inconclusive, we run `git diff origin/main...<branch_name> --stat`.
    - If the diff output is empty, it means the code changes on this branch are already 100% present on `main` (either squash-merged or manually aligned). The branch is classified as **Stale** (safe to delete).
4.  **Commit Age Check:**
    - Query the timestamp of the latest commit on the branch (`git log -1 --format=%ct`).
    - If there is no associated PR and the branch contains code diffs:
      - If the last commit is **older than 30 days**, it is classified as **Stale/Abandoned** (safe to delete).
      - If the last commit is **newer than 30 days**, it is classified as **Active** (preserve).
5.  **Active Safeguard:**
    - If there is an open PR associated with the branch, it is classified as **Active** (preserve).

---

## 3. Automated Cleanup Tool

A Python script is provided at `scripts/branch_hygiene.py` to automate this analysis and cleanup.

### Running a Dry-Run Audit (Default)
By default, the script runs in **dry-run** mode, listing the status of all branches without modifying anything:
```bash
python3 scripts/branch_hygiene.py
```

### Performing Deletions
To purge all branches classified as **Stale**, run the script with the `--delete` and `--no-dry-run` flags:
```bash
python3 scripts/branch_hygiene.py --delete --no-dry-run
```
This will:
1. Prune stale remote branches: `git push origin --delete <branch>`
2. Delete corresponding local tracking branches: `git branch -D <branch>`

*Note: The script will never delete branches classified as Active.*

---

## 4. Manual Verification & Rescue Procedure

If a branch is classified as Stale but you believe it contains work that was not merged:
1.  **Inspect the Diff:** Run `git diff origin/main...origin/<branch>` to see the exact changes.
2.  **Check commits:** Run `git log origin/main..origin/<branch>` to view the branch history.
3.  **Restore:** If you need to rescue a branch, checkout a new local branch from it:
    ```bash
    git checkout -b rescue-<branch> origin/<branch>
    ```

---

## 5. Routine Maintenance Proposal (For Junior Engineers)

To keep the repository clean and avoid remote clutter, the following routine should be executed by a junior engineer at a future stage:

### Schedule & Frequency
- **Frequency:** Once at the beginning of each development cycle (or monthly).
- **Time Required:** ~10 minutes.

### Step-by-Step Procedure
1.  **Sync Local Repository:**
    ```bash
    git checkout main
    git pull origin main
    git fetch --prune
    ```
2.  **Run the Audit:**
    ```bash
    python3 scripts/branch_hygiene.py
    ```
3.  **Review the Report:**
    - Examine the **ACTIVE** list. Ensure no ongoing feature branches are misclassified.
    - Examine the **STALE** list. Verify that the listed branches correspond to completed/closed phases (e.g. `phase-118*`, `phase-220*`).
4.  **Execute the Cleanup:**
    ```bash
    python3 scripts/branch_hygiene.py --delete --no-dry-run
    ```
5.  **Verify Remote Cleanup:**
    - Check the branch list on GitHub to ensure the stale branches have disappeared.
