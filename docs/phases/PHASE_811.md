---
phase: 811
title: Git history rewrite — purge the 25 MB ja4-tap binary and coverage.txt revisions
status: PROPOSED
created: 2026-07-30
audience: [developer, operations]
---

# Git History Rewrite — Purge `ja4-tap` and `coverage.txt` from All History

> **STATUS: PROPOSED — plan for review. No destructive action until approved.**
> Closes GitHub issue [#292](https://github.com/seanpor/JA4proxy/issues/292).
> PR #291 (landed in Phase 810) untracked the committed `ja4-tap` binary and
> `coverage.txt` from the current tree via `git rm --cached`. That stops
> future growth but does nothing about blobs already baked into history —
> `.git` is still carrying them. This phase removes them from history itself.

## Goal (plain language)

Shrink the repository's `.git` by rewriting history to strip out the
`ja4-tap` binary and all historical `coverage.txt` revisions, then safely
land the rewritten history on `main` with minimum disruption to
collaborators and in-flight work.

## Current state (measured, not assumed)

```
$ git count-objects -vH
count: 5947
size: 79.26 MiB
in-pack: 19291
packs: 26
size-pack: 41.97 MiB
prune-packable: 175
garbage: 0 bytes
```

Blobs confirmed via `git rev-list --objects --all | git cat-file --batch-check`:

| Path | Revisions | Size each | Notes |
|---|---|---|---|
| `ja4-tap` (repo root) | 1 | 25,253,584 bytes (~24.1 MiB) | Added in #279, untracked by PR #291. Distinct from `cmd/ja4-tap/main.go`, which is source and stays. |
| `coverage.txt` | 8 | ~220–293 KB each (~1.9 MiB total) | Repeated commits of a generated coverage report; untracked by PR #291. |

Rewriting history to drop these two paths should shrink the pack by
roughly 26 MiB (~33% of current `size-pack`).

**Currently no open PRs** (`gh pr list --state open` — empty) and **108**
stale remote `phase-*`/misc branches exist on `origin` (from parallel-agent
work; corrected after independent review — an earlier draft undercounted
this at ~20). These matter because **any branch based on pre-rewrite
history becomes incompatible with rewritten `main`** — its common ancestor
disappears, so a later PR from it would try to re-introduce the old blobs.
See Step 1 below.

## Implementation plan

### Step 0 — Pre-flight inventory (safe, read-only)

1. `git ls-remote --heads origin` — enumerate every remote branch (108 as of
   this writing).
2. **Do not use `git log origin/main..origin/<branch>` as the merged/dead
   test** — this repo squash-merges every PR (per `AGENTS.md`), so a
   squash-merged branch's original commits never collapse into `main`'s
   ancestry and this check reports nonzero "unique commits" for
   essentially every branch, merged or not (confirmed during review: 108/108
   branches showed false-positive unique commits, including branches merged
   weeks ago via already-closed PRs). Instead, classify each branch via
   `gh pr list --state merged --search "head:<branch>"` — if a merged PR
   exists for that head, the branch is dead and safe to delete outright
   regardless of what raw commit-range diff shows.
3. Branches with no matching merged PR and no open PR get flagged for the
   user: either land them first (normal PR, before the rewrite) or accept
   they'll need to be recreated from the new history afterward.
4. Confirm again immediately before the destructive step that no new PRs
   opened since planning (`gh pr list --state open`).

### Step 1 — Backup

`git clone --mirror` the current `origin` to a local path outside the
working tree (e.g. `/tmp/.../JA4proxy-premirror-backup.git`) before any
rewrite. This is the rollback point — if anything goes wrong, push it back
to `origin` to restore the pre-rewrite state.

**Rollback caveat (added after independent review):** pushing the mirror
back only restores `origin` itself. Anyone who fetched the rewritten
history in the gap between the force-push and the rollback still has it
locally, and a second reset creates a third, mixed history state for them.
If rollback is ever needed, Step 5.2's collaborator notification must
include a distinct rollback message (not just the forward "history was
rewritten, re-clone" message) telling anyone who already fetched to
re-clone *again* from the restored `origin`.

### Step 2 — Rewrite history

`git-filter-repo` is not installed anywhere in this repo's tooling today
(confirmed: not on host, not in `Dockerfile.tools`). Per `AGENTS.md`
Container-Strict rules, it must run inside a container, not via host `pip`.

**Correction from independent review:** a bare `python:3.14-slim` image has
no `git` binary, and `git-filter-repo` shells out to `git` at runtime — the
originally planned `docker run --rm -v <mirror>:/repo -w /repo
python:3.14-slim …` invocation would fail immediately. Use an image with
`git` already present, e.g.:

```bash
docker run --rm -v <mirror>:/repo -w /repo python:3.14-slim \
  bash -c "apt-get update -qq && apt-get install -y -qq git && \
           pip install --quiet git-filter-repo && \
           git filter-repo --invert-paths --path ja4-tap --path coverage.txt --force"
```

This is a throwaway container invocation, not a `Dockerfile.tools` change —
`git-filter-repo` is not added as a permanent tool-image dependency.

On the **mirror clone** (never the working tree):

```bash
git filter-repo --invert-paths \
  --path ja4-tap \
  --path coverage.txt \
  --force
```

- `--path ja4-tap` matches only the exact root-level path — verified above
  that `cmd/ja4-tap/main.go` is a different path and is untouched.
- `--path coverage.txt` strips every historical revision, not just current.
- `filter-repo` rewrites every commit after the earliest touched commit, so
  **all commit hashes on `main` change** from that point forward.

### Step 3 — Verify before pushing anywhere

1. `git count-objects -vH` on the rewritten mirror — expect `size-pack` down
   ~26 MiB from the 41.97 MiB baseline.
2. `git log --all -- ja4-tap` — expect empty.
3. `git log --all -- coverage.txt` — expect empty.
4. **Tree equivalence check** — the current `HEAD` tree must be byte-identical
   before and after (PR #291 already untracked both paths, so removing their
   history should not change what's checked out today):
   `git diff <old-main-HEAD> <new-main-HEAD> --stat` restricted to the actual
   tree contents (comparing tree hashes of the tip commit, not full history)
   must show zero differences.
5. Re-clone the rewritten mirror into a scratch directory and run
   `make preflight` (lint + scan + test) against it — must pass exactly as
   it does on current `main`, proving the rewrite didn't corrupt anything
   CI depends on.
6. **Tag/release check (added after independent review):** `git tag -l` and
   `gh release list` — confirm the `v2.0.0` tag/release's commit hash is
   unaffected (it predates the commit that introduced `ja4-tap`, so it's
   expected to be untouched, but this must be confirmed against the
   rewritten mirror, not assumed). If `filter-repo` did renumber it, decide
   deliberately whether to re-tag/re-point the release rather than leaving
   it dangling.

### Step 4 — Land it

This is fundamentally incompatible with the normal PR flow (Phase 332):
`filter-repo` changes commit hashes, so there is no diff to review or merge
— it *is* a new `main`. Per the `AGENTS.md` branch-protection emergency
procedure:

```bash
gh api -X DELETE repos/seanpor/JA4proxy/branches/main/protection/enforce_admins
git push --force origin <rewritten-main>:main
gh api -X PATCH  repos/seanpor/JA4proxy/branches/main/protection/enforce_admins
```

Re-enable enforcement **immediately** in the same sitting — never leave it
disabled. This step requires the user's live go-ahead at execution time
(distinct from approving this plan), since it invalidates every existing
clone; see Coordination below.

**Honesty note (added after independent review):** `AGENTS.md` scopes this
override to "`main` is broken and a fix cannot wait for normal CI" — an
outage response. This rewrite is planned maintenance, not an outage; it's
using the same mechanism for a different, but equally legitimate, purpose.
Flagging the mismatch explicitly rather than silently stretching the
outage-only wording. Worth a small follow-up to broaden `AGENTS.md`'s
override language to name planned history rewrites as a second sanctioned
use case, so the next person doesn't have to make the same judgment call.

### Step 5 — Post-rewrite cleanup

1. **Expectation-setting (added after independent review):** a force-push
   does not immediately reclaim space on GitHub's servers — old objects can
   remain reachable/clonable via GitHub's internal retention until GC runs,
   especially if any fork or PR ref still points at them. Local
   `git count-objects -vH` on the rewritten mirror will show the shrinkage
   immediately; GitHub's reported repo size may lag. This is not a blocking
   acceptance gate.
2. Delete/recreate the stale remote branches identified in Step 0 that would
   otherwise dangle against a nonexistent ancestor.
3. Post a comment on issue #292 and notify collaborators (per its own
   acceptance criteria) that `main` was rewritten on `<date>` and everyone
   must re-clone or `git fetch origin && git reset --hard origin/main`
   (with an explicit warning this discards local branches based on old
   history).
3. Close issue #292 referencing this phase.

## Coordination requirements (from issue #292, carried forward)

- Confirmed **no open PRs** at plan time — re-check immediately before Step 4.
- Schedule the force-push for a moment with no other phase branches
  mid-flight, or accept that those branches will need to be rebuilt from
  the new history.
- Announce before (this phase doc / issue comment) and after (Step 5.2).
- The actual force-push (Step 4) is a live, human-supervised action — this
  phase doc's approval authorizes the plan, not a blank check to force-push
  autonomously. Confirm again at that exact moment.

## Test / verification strategy

There's no application code changing, so "tests" here means the
verification battery in Step 3, plus:

- `make preflight` clean on a scratch re-clone of the rewritten history.
- A guardrail regression check: confirm `.gitignore` (updated in PR #291)
  still excludes `ja4-tap` and `coverage.txt` so they can't be re-added by
  accident — no code change expected, just confirming it survived the
  rewrite untouched.

## Acceptance criteria

- [ ] `git count-objects -vH` on `origin/main` shows `.git` shrunk by
      roughly the ~26 MiB removed (ja4-tap + all coverage.txt revisions)
- [ ] `git log --all -- ja4-tap` on the rewritten `origin/main` is empty
- [ ] `git log --all -- coverage.txt` on the rewritten `origin/main` is empty
- [ ] Tip-commit tree of rewritten `main` is identical to pre-rewrite `main`
      (no unintended content change)
- [ ] `make preflight` passes on a fresh clone of rewritten `main`
- [ ] Branch protection (`enforce_admins`) re-enabled immediately after push
- [ ] Stale remote branches reconciled (deleted or flagged for recreation)
- [ ] Collaborators notified (issue #292 comment); issue #292 closed
- [ ] Full mirror backup retained until the rewrite is confirmed stable
      (not deleted as part of this phase — kept as a manual rollback point)

## Out of scope

- Git LFS migration for any future large binaries — a process fix, not part
  of this cleanup.
- General repo hygiene beyond the two paths named in #292.
- Rewriting history on branches other than `main` (dead branches get
  deleted, not rewritten; live branches get rebuilt from new `main` by
  whoever owns them).
- Adding `git-filter-repo` as a permanent tool-image dependency — this is a
  one-off, run via a throwaway container invocation.
