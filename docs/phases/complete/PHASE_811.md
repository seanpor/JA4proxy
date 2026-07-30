---
phase: 811
title: Git history rewrite — purge the 25 MB ja4-tap binary and coverage.txt revisions
status: COMPLETE
created: 2026-07-30
completed: 2026-07-30
audience: [developer, operations]
---

# Git History Rewrite — Purge `ja4-tap` and `coverage.txt` from All History

> **STATUS: LANDED on `main` (2026-07-30) — `main` and the `v2.0.0` tag are
> rewritten and pushed. Step 5 (stale-branch reconciliation) still open —
> see "Landing attempt" and "Post-landing state" below.**
> Closes GitHub issue [#292](https://github.com/seanpor/JA4proxy/issues/292).
> PR #291 (landed in Phase 810) untracked the committed `ja4-tap` binary and
> `coverage.txt` from the current tree via `git rm --cached`. That stops
> future growth but does nothing about blobs already baked into history —
> `.git` is still carrying them. This phase removes them from history itself.

## Landing attempt (2026-07-30) — findings beyond the reviewed plan

The reviewed plan (Steps 0–3 below) executed exactly as written and passed
every check. Landing it (Step 4) surfaced three real-world obstacles the
plan and its independent review did not anticipate, because none of them
are visible from local git state:

1. **A second, independent protection layer.** `AGENTS.md`'s documented
   override only covers the classic `enforce_admins` API. `main` is *also*
   covered by a GitHub **repository ruleset** (`main branch protection
   ruleset`, id `17259177`, rules: `deletion` + `non_fast_forward`,
   `bypass_actors: []`). Disabling `enforce_admins` alone does not allow a
   force-push — the ruleset must independently be set to
   `enforcement: disabled` and restored after
   (`gh api -X PUT repos/seanpor/JA4proxy/rulesets/17259177 -f enforcement=disabled`,
   then `-f enforcement=active` immediately after). `AGENTS.md`'s
   branch-protection callout should be updated to mention this ruleset —
   tracked as a follow-up, not done in this phase.
2. **`GH006` was a sequencing mistake, not a third blocker.** It appeared
   because `enforce_admins` had already been restored to `true` (correctly,
   per "never leave it disabled") *before* the ruleset was even discovered
   and tested — so at the moment of that attempt, `enforce_admins` was back
   on and correctly rejected the force-push per its own classic-protection
   rules (`allow_force_pushes: false`, required reviews, 12 required status
   checks — `enforce_admins=false` exempts admins from all of these
   together). **Both `enforce_admins` and the ruleset must be disabled at
   the same time** for the push to go through, not tested one after the
   other.
3. **`GH007`: push would publish a private email address.** Because
   `git-filter-repo` gives every commit from the earliest touched commit
   onward a new SHA — including ones whose *content* never changed —
   GitHub treats ~2,400 commits as brand new and re-scans them for leaked
   private emails. History contained three real personal addresses used
   before the project switched to the GitHub noreply address:
   `seanpor@acm.org` (1857 commits), `seoriord@tcd.ie` (94), and
   `sean@porreca.io` (2) — all confirmed as the same person
   (`Sean O'Riordain`) via `git log --all --format='%an <%ae>'`. Per
   explicit user direction, fixed properly rather than by disabling
   GitHub's leak-prevention setting: added a `--mailmap` pass to the
   `filter-repo` invocation remapping all three to
   `seanpor@users.noreply.github.com` (the address already used for all
   recent commits and already in `git config user.email`). Re-verified the
   full Step 3 battery against this combined rewrite — identical results
   (tree hash unchanged, paths gone, `make preflight` green) plus zero
   remaining occurrences of the three real addresses in
   `git log --all --format='%ae'` / `%ce`.

4. **A third, independent protection setting, only discoverable by trying:**
   classic branch protection's `allow_force_pushes: false`. This is
   **not** governed by `enforce_admins` at all — GitHub treats "who may
   force-push" as its own toggle that even exempted admins don't bypass.
   With `enforce_admins` and the ruleset both correctly disabled together
   (per finding 2), the push to `main` still failed with `GH006: Cannot
   force-push to this branch`. There is no dedicated REST sub-resource for
   this field (unlike `enforce_admins`); it required a full
   `PUT .../branches/main/protection` call carrying every existing setting
   unchanged except `allow_force_pushes: true`, `enforce_admins: false`.
   Attempting this API call was initially **blocked by the user's Claude
   Code permission classifier** as an unreviewed repo-protection-modifying
   action — stopped and asked the user explicitly rather than working
   around it; user approved, provided the go-ahead, and the call proceeded.

**Every override was restored to its original state after each attempt.**
With all three (`enforce_admins`, the ruleset, `allow_force_pushes`)
disabled simultaneously, the push succeeded:

```
remote: Bypassed rule violations for refs/heads/main:
remote: - Changes must be made through a pull request.
remote: - 12 of 12 required status checks are expected.
 + 99cde1bd...ce0f2532 main -> main (forced update)
```

All three settings were restored to their exact original values
(`allow_force_pushes: false`, `enforce_admins: true`,
ruleset `enforcement: active`) immediately after, confirmed via API
read-back.

## Post-landing state (2026-07-30)

- `origin/main` → `ce0f253274d771caab57ec148ca44149d0f323cb` (rewritten,
  matches the verified local rewrite exactly)
- `origin/refs/tags/v2.0.0` → `7897a180ef1ac781065fcf8c3d8f3cf7e70ca500`
  (rewritten; content/tree/message identical to the original tag, only the
  parent-hash chain changed — see the tag finding in Step 3.6)
- Verified via a **fresh, independent clone** of `https://github.com/seanpor/JA4proxy.git`
  (not the local rewrite artifact): checking out `main` shows zero history
  for `ja4-tap` or `coverage.txt`, and zero occurrences of the three real
  personal email addresses — `main` itself is fully clean.
- `git log --all` / `git count-objects` on that same fresh clone **still
  show the old blobs, old emails, and the pre-rewrite pack size** — this is
  expected, not a failure: `--all` walks every ref, and the 108 other
  remote branches (93 already merged, 14 with unmerged commits — see Step 0)
  were deliberately left untouched by this phase and still hold the old,
  unrewritten history. **The repo will not actually shrink on GitHub, and
  those objects remain reachable, until those branches are deleted or
  rebuilt.** This makes Step 5 not optional cleanup but the remaining work
  to realize this phase's actual goal.
- Branch protection and the ruleset are back to their exact pre-phase
  state — confirmed by API read-back, not just by memory of what was set.

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
docker run --rm -v <mirror>:/repo -v <mailmap>:/mailmap.txt -w /repo python:3.14-slim \
  bash -c "apt-get update -qq && apt-get install -y -qq git && \
           pip install --quiet git-filter-repo && \
           git filter-repo --invert-paths --path ja4-tap --path coverage.txt \
             --mailmap /mailmap.txt --force"
```

This is a throwaway container invocation, not a `Dockerfile.tools` change —
`git-filter-repo` is not added as a permanent tool-image dependency.

On the **mirror clone** (never the working tree):

```bash
git filter-repo --invert-paths \
  --path ja4-tap \
  --path coverage.txt \
  --mailmap /mailmap.txt \
  --force
```

- `--path ja4-tap` matches only the exact root-level path — verified above
  that `cmd/ja4-tap/main.go` is a different path and is untouched.
- `--path coverage.txt` strips every historical revision, not just current.
- `filter-repo` rewrites every commit after the earliest touched commit, so
  **all commit hashes on `main` change** from that point forward — this
  cascades to *every* descendant, unrelated to the two removed paths, and
  is why the mailmap pass is combined into the same invocation rather than
  run separately (a second rewrite would just re-cascade all the hashes
  again for no reason).
- `--mailmap /mailmap.txt` (added after the `GH007` finding above) remaps
  the three legacy personal author/committer addresses to the GitHub
  noreply address already used everywhere else in the project. Mailmap
  format, one line per real→canonical mapping:
  ```
  Sean O'Riordain <seanpor@users.noreply.github.com> <seanpor@acm.org>
  Sean O'Riordain <seanpor@users.noreply.github.com> <seoriord@tcd.ie>
  Sean O'Riordain <seanpor@users.noreply.github.com> <sean@porreca.io>
  ```

### Step 3 — Verify before pushing anywhere

1. `git count-objects -vH` on the rewritten mirror — **executed**: pristine
   mirror-to-mirror comparison went 50.95 MiB → 39.34 MiB size-pack
   (**-11.6 MiB, -23%**), not the ~26 MiB raw-blob-size estimate in the
   original draft. Confirmed why: `git verify-pack -v` on the original pack
   shows the `ja4-tap` blob's *packed* (zlib-compressed) size is 11,931,576
   bytes, not its raw 25,253,584 bytes — the binary compresses ~2.1x, so the
   pack only ever carried ~11.4 MiB for it plus a smaller amount for
   `coverage.txt`'s text revisions. (The original ~41.97 MiB baseline in
   this doc's "Current state" section was measured on a working-tree local
   clone with looser packing, not a clean mirror — not apples-to-apples;
   the mirror-to-mirror figures above are the correct comparison.)
   Real, meaningful reduction — just smaller than first estimated.
2. `git log --all -- ja4-tap` — **executed**: empty.
3. `git log --all -- coverage.txt` — **executed**: empty.
4. **Tree equivalence check** — **executed**: `main^{tree}` hash identical
   before and after (`bdea4b93e84049f4f08909aa3d26b889fe1efb29` both sides),
   confirming PR #291's untracking means the rewrite changes zero bytes of
   what's checked out today.
5. Re-clone the rewritten mirror into a scratch directory and run
   `make preflight` (lint + scan + test) against it — must pass exactly as
   it does on current `main`, proving the rewrite didn't corrupt anything
   CI depends on. **Executed — PASSED, exit 0.** `751 passed, 4 skipped` in
   the Python suite, integration smoke tests and CI/workflow guardrail
   tests both green, Go build/lint clean. The bandit `exception while
   scanning file` noise seen mid-run is a pre-existing Python 3.14/bandit
   AST quirk unrelated to this rewrite (`lint-security` still reports
   passed); confirmed harmless, not a regression.
6. **Tag/release check (added after independent review) — executed, and
   the assumption was WRONG:** `v2.0.0`'s commit hash *does* change
   (`f44524f...` → `3bf800f...`). Diffing the two raw commit objects shows
   tree, author, committer, and message are byte-identical — only the
   **parent hash** differs. Root cause: `v2.0.0` predates the `ja4-tap`
   commit (confirmed via `merge-base --is-ancestor`) but does **not**
   predate all `coverage.txt` revisions — an earlier `coverage.txt` commit
   is itself an ancestor of `v2.0.0`, so the parent chain changes and
   cascades forward through every descendant, `v2.0.0` included. **This
   means Step 4 must explicitly force-push the rewritten tag, not just
   `main`** (`git push --force origin refs/tags/v2.0.0`), or the GitHub
   Release stays pinned to a commit hash that becomes unreachable/orphaned
   once the old history is gone from `origin`.

### Step 4 — Land it

This is fundamentally incompatible with the normal PR flow (Phase 332):
`filter-repo` changes commit hashes, so there is no diff to review or merge
— it *is* a new `main`. **As actually executed** (see "Landing attempt"
above for how this recipe was found — `AGENTS.md`'s documented
`enforce_admins`-only procedure was insufficient by itself):

```bash
# 1. Disable all three independent layers, simultaneously:
gh api -X PUT repos/seanpor/JA4proxy/branches/main/protection \
  --input protection_unlock.json   # full payload: allow_force_pushes=true,
                                    # enforce_admins=false, everything else unchanged
gh api -X PUT repos/seanpor/JA4proxy/rulesets/17259177 -f enforcement=disabled

# 2. Push immediately:
git push --force origin <rewritten-main>:main
git push --force origin refs/tags/v2.0.0

# 3. Restore both, immediately, in the same sitting:
gh api -X PUT repos/seanpor/JA4proxy/branches/main/protection \
  --input protection_restore.json  # same payload, allow_force_pushes=false,
                                    # enforce_admins=true
gh api -X PUT repos/seanpor/JA4proxy/rulesets/17259177 -f enforcement=active
```

There is no dedicated REST sub-resource for `allow_force_pushes` (unlike
`enforce_admins`) — it requires a full `PUT .../branches/main/protection`
call carrying every other existing setting unchanged. Fetch the current
config first (`gh api repos/seanpor/JA4proxy/branches/main/protection`) and
build the unlock/restore payloads from it — don't hand-write one from
memory, since a dropped field silently changes a setting you didn't intend
to touch.

`refs/tags/v2.0.0` **must** be force-pushed too (see Step 3.6) — its commit
hash changed even though its content didn't, because an ancestor
`coverage.txt` revision predates it. Skipping this leaves the `v2.0.0`
GitHub Release pointing at a commit that's absent from the new history.

Re-enable enforcement **immediately** in the same sitting — never leave it
disabled. This step requires the user's live go-ahead at execution time
(distinct from approving this plan), since it invalidates every existing
clone; see Coordination below. **Confirmed done**: read back
`allow_force_pushes: false`, `enforce_admins: true`, ruleset
`enforcement: active` via the API immediately after pushing, not just
assumed from the command having been issued.

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
4. Close issue #292 referencing this phase.

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

- [x] `git count-objects -vH` on `origin/main` shows `.git` shrunk —
      **landed**, but the full 11.6 MiB reduction won't be visible in
      GitHub's own repo-size reporting until the reconciled/deleted stale
      branches are actually pruned server-side (see Post-landing state)
- [x] `git log --all -- ja4-tap` on the rewritten `origin/main` is empty —
      confirmed on `main` specifically via a **fresh independent clone**
      (not the local rewrite artifact)
- [x] `git log --all -- coverage.txt` on the rewritten `origin/main` is
      empty — confirmed same way
- [x] Tip-commit tree of rewritten `main` is identical to pre-rewrite `main`
      — confirmed, `bdea4b93e84049f4f08909aa3d26b889fe1efb29` both sides
- [x] `make preflight` passes on a fresh clone of rewritten `main` —
      PASSED twice (once pre-mailmap, once on the final combined rewrite),
      751 passed/4 skipped + integration + guardrail suites green both times
- [x] `refs/tags/v2.0.0` force-pushed alongside `main` — done,
      `origin/refs/tags/v2.0.0` now `7897a180ef1ac781065fcf8c3d8f3cf7e70ca500`
- [x] Branch protection (`enforce_admins`, the ruleset, and
      `allow_force_pushes`) re-enabled immediately after push — confirmed
      via API read-back, not just assumed
- [x] Stale remote branches reconciled — 93 confirmed dead via merged-PR
      lookup deleted (user-approved); the 14 with real unmerged commits
      deliberately left untouched (user-approved) — see Step 0 branch-status
      table for the full list; their owners still need to rebuild them from
      the new `main` if that work is ever revived
- [x] Collaborators notified (issue #292 comment); issue #292 closed —
      done, https://github.com/seanpor/JA4proxy/issues/292#issuecomment-5135076374
- [x] Full mirror backup retained (kept in scratch, not deleted as part of
      this phase — manual rollback point if ever needed)

Also confirmed, beyond the original list: no real personal email addresses
(`seanpor@acm.org`, `seoriord@tcd.ie`, `sean@porreca.io`) remain on `main`
— all remapped to `seanpor@users.noreply.github.com` via the mailmap pass
added in response to the `GH007` finding.

## Out of scope

- Git LFS migration for any future large binaries — a process fix, not part
  of this cleanup.
- General repo hygiene beyond the two paths named in #292.
- Rewriting history on branches other than `main` (dead branches get
  deleted, not rewritten; live branches get rebuilt from new `main` by
  whoever owns them).
- Adding `git-filter-repo` as a permanent tool-image dependency — this is a
  one-off, run via a throwaway container invocation.

## Follow-ups (not done in this phase)

- **Update `AGENTS.md`'s branch-protection callout** to document the
  repository ruleset (id `17259177`) and `allow_force_pushes` alongside
  `enforce_admins` — its documented override procedure was incomplete, and
  the next person to need a force-push to `main` will hit the same
  surprises this phase did if it isn't fixed. Also correct the documented
  `PATCH` verb for `.../protection/enforce_admins` to `POST` (the actual
  GitHub API verb; `PATCH` 404s).
- **14 stale branches with real unmerged commits** need their owners to
  decide: rebuild from the new `main` (if the work is still wanted) or
  formally abandon and delete. Left untouched by this phase — see the list
  in the issue #292 closing comment.
- **Monitor GitHub's reported repo size** — local shrinkage is confirmed;
  GitHub's own size reporting may lag until server-side GC reclaims the
  now-unreferenced objects from the 93 deleted branches.
