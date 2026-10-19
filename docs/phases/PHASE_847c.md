<!--
title: Split_Scan_Regression_Gate_And_Baseline_Monitor
audience: developer
last_reviewed: 2026-10-17
phase: 847c
-->

# Phase 847c — Split scan: PR regression gate + baseline monitor

> **Status:** PROPOSED
> **Size:** LARGE
> **Dependencies:** [847a, 847b]
> **Branch:** `phase-847c-scan-split`
> **Part of:** Phase 847 (umbrella) — see `docs/phases/PHASE_847.md`

---

## Goal

Stop a **new upstream CVE from reddening unrelated PRs**, without weakening the
guarantee that matters: *a PR must not introduce a new unwaived finding.*

This is the structural core of the 847 programme — the change that converts CVE
handling from reactive to controlled.

---

## The split

| | PR regression gate (required) | Baseline monitor (scheduled) |
|---|---|---|
| **Trigger** | every PR | cron (daily/weekly) |
| **Compares** | the PR's images/deps vs the **baseline recorded on `main`** | the full deployed set vs `security/waivers.yaml` |
| **Fails on** | only findings the **PR introduces** | never blocks a PR; files/updates an issue |
| **Purpose** | block regressions | surface drift, feed 847d |

The insight that makes this safe rather than lax: **the diff is computed on the
same surfaces.** If a PR bumps an image, adds a dep, or changes a base tag, the
scan of *that surface* changes, and any new unwaived finding on it is a diff and
fails. Only findings that already exist on `main`'s baseline — and are therefore
already triaged (waived or accepted) — are non-blocking. Upstream DB churn moves
the *baseline*, which the monitor handles asynchronously; it cannot redden a PR
that didn't touch the affected surface.

---

## 847c.1 Baseline recording

Record, per image/dep, the set of High/Critical CVE IDs, keyed by the immutable
image digest (`image@sha256:…`) — **not** the tag, because two tags can share a
digest and a digest is what actually got scanned.

- Store as a committed artifact (e.g. `security/baseline.json`), refreshed by a
  controlled job that runs on `main` after merge.
- The PR gate reads the baseline for the **merge-base** of the PR, so it judges
  the PR against what `main` currently is, not what it was last week.

## 847c.2 The PR regression gate

New required check `scan-regression`:

1. Determine the images/deps the PR touches (diff-aware: compose files,
   `requirements*.txt`, Dockerfiles). If it touches none, the gate is a no-op
   pass — this alone removes most of today's friction.
2. Scan the touched surfaces; diff findings vs the recorded baseline.
3. **Fail iff** a finding is present that is (a) not in the baseline and (b) not
   an approved waiver in `security/waivers.yaml`.

The existing `scan-images` full-scan target is **retained but de-required** for
PRs — it becomes the baseline monitor's input. Nothing is deleted; only its
trigger changes.

## 847c.3 The baseline monitor (scheduled)

New workflow, cron-triggered:

1. Full scan of every deployed image/dep.
2. Diff the full result against `security/waivers.yaml`.
3. **New unwaived finding** → open (or update) a GitHub issue with the full
   evidence: CVE, severity, carrier, fixed-version, reachability context. One
   issue per finding, deduplicated by ID — not one per scan run, so it cannot
   flood.
4. Hand the finding to **847d** (fix-forward bot) when that phase lands; until
   then, the issue is the deliverable.
5. Report the **fixable-queue** count (findings whose `fix_available: true`) —
   this metric must trend to ~0 and is the programme's health signal.

This closes the hole the repo already documented once (2026-08-19, the incident
that produced `check_trivyignore_drift.py`): a CVE that appeared in the DB with
no one watching. The drift checker detects it; the monitor *surfaces and tracks*
it.

---

## Test strategy

- **Prove the split works (the headline test).** Simulate: (a) a PR that touches
  nothing security-relevant → gate passes even with new upstream CVEs present;
  (b) a PR that bumps a compose image to one carrying a new unwaived HIGH → gate
  **fails**. Record both in the PR description.
- **Baseline correctness:** assert the gate uses the merge-base baseline, and
  that a finding already on `main` does not fail a PR that merely rebases.
- **Monitor dedup:** run the monitor twice against the same drift; assert it does
  not create a second issue.
- **No-vacuous-pass:** assert the gate fails if the baseline file is missing or
  unparseable (fail-safe, not fail-open).
- Run `make preflight`.

---

## Acceptance criteria

- [ ] Baseline is recorded per digest and refreshed on `main` post-merge.
- [ ] `scan-regression` is a required check; fails **only** on findings the PR
      introduces on surfaces it touches.
- [ ] A PR touching no security-relevant surface passes regardless of upstream
      DB state (demonstrated).
- [ ] A PR bumping to a vulnerable image fails (demonstrated).
- [ ] Scheduled monitor opens/updates deduplicated issues on drift and reports the
      fixable-queue count.
- [ ] Full `scan-images` retained (de-required), feeding the monitor.
- [ ] `make preflight` passes.

---

## Files to modify

| File | Change |
|------|--------|
| `security/baseline.json` | New — recorded findings per digest |
| `scripts/scan_regression.py` | New — diff-aware PR gate |
| `scripts/scan_baseline_monitor.py` | New — scheduled drift surfacer |
| `.github/workflows/ci.yml` | Add `scan-regression` required check |
| `.github/workflows/scan-baseline-monitor.yml` | New — cron monitor |
| `Makefile` | De-require full `scan-images` for PRs; keep it callable |
| `tests/unit/test_scan_regression.py` | New |
| `tests/unit/test_scan_baseline_monitor.py` | New |
| `docs/fragments/phase-847c-scan-split.md` | Changelog fragment |

---

## Notes for implementer

- **Fail-safe, never fail-open.** If the baseline is missing, unparseable, or the
  scan errors, the gate must **fail**. A gate that silently passes on error is
  worse than today's always-red gate, because it is trusted.
- **Digest-keying is not optional.** Tag-keying would let a retagged-but-identical
  image look like a change, and a mutated tag look like no change. Digests are
  the only stable identity.
- Keep the monitor's issue volume bounded: one issue per finding ID, updated in
  place. Alert fatigue is the main adoption risk for this phase.
- This phase is the largest in the programme; land it behind its own review and
  do not bundle 847d with it.
