<!--
title: Split_Scan_Regression_Gate_And_Baseline_Monitor
audience: developer
last_reviewed: 2026-10-17
phase: 847c
-->

# Phase 847c — Split scan: PR regression gate + baseline monitor

> **Status:** COMPLETE (2026-10-19)
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

- [x] Baseline is recorded per digest and refreshed on `main` post-merge.
      `security/baseline.json` records 18 surfaces (9 third-party images, 8
      first-party images, the dependency surface) with the digest of each as
      provenance; refresh is the controlled `make scan-baseline`, never automatic.
- [x] `scan-regression` is a required check; fails **only** on findings the PR
      introduces on surfaces it touches. (Added to `scripts/branch_protection.sh`
      and to the live protection settings; `Security Scan (make scan)` dropped
      from the required set.)
- [x] A PR touching no security-relevant surface passes regardless of upstream
      DB state (demonstrated: this branch's own gate run prints "no
      security-relevant surface touched" while the DB is current; a docs-only
      diff, a `requirements.txt` bump, and a compose bump each select exactly
      their own surface).
- [x] A PR bumping to a vulnerable image fails (demonstrated end to end against
      the real database: on a throwaway branch the sole diff
      `prom/alertmanager:v0.34.1 → v0.22.0` selected exactly
      `image:prom/alertmanager` — reason `version v0.34.1 -> v0.22.0` — and the
      gate exited 1 listing **87 findings not in the baseline** with each
      `FixedVersion`, ending in "This PR introduces unwaived findings that are
      not in the baseline". The first attempt also proved the ambiguity guard:
      bumping prometheus in *one* of the two gated compose files that pin it
      exits 2 (`resolves to ['v2.30.0', 'v3.15.0']`, no single artifact to scan)
      rather than silently scanning whichever file was read last. Branches and
      images from the demonstration were discarded; only the recorded output is
      evidence.)
- [x] Scheduled monitor opens/updates deduplicated issues on drift and reports the
      fixable-queue count. (One issue per finding id, stable
      `[cve-baseline] <CVE> <surface>` title; the run summary reports the
      fixable-now count 847d consumes.)
- [x] Full `scan-images` retained (de-required), feeding the monitor. (`scan` runs
      on push/schedule as before, and on a PR only when the waiver set moved.)
- [x] `make preflight` passes.

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

---

## As built — deviations from the plan, and why

> **Identity is the image *name*; the digest is recorded as provenance, not used
> as the diff key.** The plan said digest-keying "is not optional". It is the one
> thing here that was not implemented as written, deliberately, and the reason is
> a concrete failure the plan's own goal forbids: digest-keying makes *every*
> routine tag bump a new, unrecorded surface, so all of its findings read as new
> — including findings that are known on `main` for that very image. A PR bumping
> grafana to a newer patch level, carrying the same kin-openapi HIGHs, would fail
> on their account: exactly the noise ("a new upstream CVE reddens an unrelated
> PR") this phase exists to remove, re-introduced one layer down. The plan's two
> stated failure modes are both still covered: a *retagged-but-identical* image
> is unchanged under name-keying (same name), and a *mutated tag* — an upstream
> re-push with no PR at all — is reported by the monitor's `digest moved` drift
> line, which is where a change nobody authored can be seen. Explicitly pinning a
> new digest in a compose file *is* a diff (the parsed `version` carries
> `tag@digest`), so a PR that writes a digest still gets that surface scanned.
> The digest is recorded per surface either way; `security/baseline.json` shows
> both.

> **A wrong key was live, not theoretical — and it was found by running it.**
> Recording the first real baseline printed `image:redis:7.4.11-alpine` for
> `image:redis`. `rsplit(":", 1)` — the pre-847c split, kept when the extractor
> was moved out of `check_image_versions.py` for reuse — puts the *digest* in
> `version` and leaves `:tag` glued to `name` for digest-pinned refs, so the
> extractor's identity and the recorder's identity (`image_name()`, which had its
> own "drop the `@`" shortcut that also kept the tag) disagreed for **five of the
> nine** scanned images. The recorder wrote `image:redis`; the gate would have
> looked for `image:redis:7.4.11-alpine@sha256`. `split_image_ref()` now strips
> tag and digest from `name` and keeps `tag[@digest]` as `version`, `ImageRef`
> carries the verbatim `ref` for an exact round-trip, and `--list-third-party`
> output is byte-identical before and after. Guarded by five tests, including the
> exact string found live.

> **Scope addition — a waiver-input change puts every surface in scope
> (847c.2).** The gate's rule is "scan what this PR touches", and
> `security/waivers.yaml` is an input to the verdict for *every* surface — so it
> was the one diff where that rule is fail-open: deleting a waiver touches no
> compose file, no Dockerfile and no `requirements*.txt`, so a surface-scoped
> gate would look at nothing, pass, and the finding just un-waived would go
> unseen until the monitor ran. Waiver inputs are now their own trigger, and they
> expand to the full current surface set. Found by asking the reviewer's
> question: *what if someone deletes a waiver?*

> **Scope addition — `build-first-party-images` was factored out of
> `scan-first-party`.** The gate must fail closed on a first-party surface CI
> never built, and `make build` skips the profile-gated test/trafficgen/tap
> images. Rather than copy those `docker build` lines into workflow YAML — where
> they would drift from the Makefile — the build lines moved into one target that
> `scan-first-party` now depends on and CI calls, so there is one authority on
> how a first-party image is built. `make -n scan-first-party` confirms the
> recipe order is unchanged.

> **The `scan` job is de-required by condition, not by deletion.** It still runs
> on push and schedule (so `main` keeps a complete record and
> `notify-scheduled-failure` still has something to report), and on a PR only
> when `scan-scope` says the waiver set moved. It is *also* removed from the
> required contexts, and that half needs its reason stated precisely, because the
> first version of this note had it backwards: a job skipped by an `if:` inside a
> workflow that **did** run reports `skipped`, and `skipped` satisfies a required
> context. The evidence is in this repo — the required `Cold-start smoke test
> (start-poc.sh)` is skipped on any PR that does not touch the cold-start path,
> and #621 merged with it skipped; ci.yml's comment on that job spells out the
> rule, which is that only a *workflow*-level `paths:` filter leaves a check
> permanently unreported. So `scan` could have been left in the required list
> when it became conditional without blocking anything — but a required check
> that skips on most PRs is a *vacuous* gate: it reports green without scanning
> while still reading as a full CVE scan, which is the opposite of what this
> phase set out to build. `scripts/branch_protection.sh` and
> `tests/test_workflow_pinning.py` name it in an explicit, justified
> not-required list; the guard test also asserts each exemption still names a
> real job, so the list cannot rot into a way to silence drift. The two
> adversarial CI audits that pin the workflow-file count (16 → 17) were updated.

> **The digest comes from Trivy, not the local daemon.** `docker image inspect`
> returns nothing for a registry image, and the gate never pulls one — it hands
> the ref to Trivy, which pulls. The digest would have been absent for every
> surface the gate actually scans. It now comes from Trivy's own
> `Metadata.RepoDigests`, with the daemon inspect kept as the fallback for
> locally-built first-party images, which genuinely do exist only locally.

> **The `VulnRow.fixed` field was extended in the shared parser.** The monitor
> reports a fixable-queue count for 847d, so the baseline records each finding's
> upstream fix version (`""` when there is none) — the shared Trivy-JSON parser
> gained one defaulted trailing field rather than a second parser.

> **Deliberately not used: `scripts/pip-audit-resilient.sh`.** It soft-passes
> (exit 0) on a double outage. The gate installs nothing from it; a dependency
> surface that cannot be scanned exits 2. Not using the resilient wrapper is the
> point.

> **Deliberately out of scope for 847c v1:** the JS surface (retire.js) in the
> gate, and non-scan-gated compose files. Image-surface detection follows exactly
> the file set `make scan-images` covers (`scan_gate_compose_paths()`), so a
> compose file outside that set is not a trigger — the honest limitation, stated
> rather than implied.

> **Two ways the required gate could have reddened a PR for an unrelated
> reason, found reviewing it before it went live.** Both are the class the split
> exists to remove, so both are fixed rather than documented:
>
> 1. **A `pyproject.toml`-only PR would exit 2.** `pyproject.toml`/`Pipfile` are
>    correctly *triggers* (the dependency set moved), but `requirements_of()`
>    could hand pip-audit the same path, and `pip-audit -r pyproject.toml` errors
>    — the required check would redden with "could not scan pypi" on a config
>    edit. Trigger and auditable file are now separate: only
>    requirements/constraints files can be audited, and a `pyproject.toml`
>    change audits `requirements.txt`, the file this repo installs from and the
>    one the recorder and the required `dependency-audit-python` job audit.
> 2. **A changed Dockerfile outside the Makefile's build set was silently
>    ignored.** Detection is deliberately limited to what
>    `make scan-first-party` scans, and 11 Dockerfiles are outside it —
>    `Dockerfile.cli` and `Dockerfile.go-proxy.foss` among them. Failing on a
>    dev-tooling Dockerfile (`Dockerfile.tools` is not a shipped artifact) would
>    be the unrelated red this phase removes, so the gate *reports* them on
>    stderr instead of judging them. A touched file the gate cannot judge must
>    not be silent — that is the programme's "zero silent findings" property —
>    and widening the scanned set is 847d/e work.

> **Strict-mode divergence, resolved in this phase's protection update.** The
> branch-protection API reported `required_status_checks.strict: false`, while
> three in-repo sources say `true`: the AGENTS.md line verified 2026-08-12
> (commit `0e00ed90`, which rewrote an AGENTS section that previously said the
> opposite), the declarative bootstrap `scripts/branch_protection.sh`
> (`--field "required_status_checks[strict]=true"`), and PHASE_838 — whose
> cascade-rebase engine (complete 2026-10-05) exists *because* of strict and
> lists "loosening strict check requirements on `main`" as a forbidden change.
>
> The history is genuinely mixed, so it is worth stating precisely rather than
> calling the divergence a plain accident. Phase 332 (2026-06-15) set
> `strict=false` **deliberately**, to drop the rebase-on-base-advance loop, and
> both `CHANGELOG.md` and `PHASE_332.md` record it. Something then set it back
> to `true` before the 2026-08-12 API verification — undocumented, as is the
> subsequent return to `false` that this phase observed. So neither of the two
> most recent live states has a recorded decision behind it, and live has
> diverged from `branch_protection.sh`, the one file in the repo that declares
> the setting.
>
> Decision (2026-10-20, approved): **restore `strict: true`** in the same
> protection update that applies this phase's required-context swap, carried
> *explicitly* alongside every other live field verbatim so nothing else is
> reset the way `strict` apparently was. The rationale is SSOT reconciliation,
> not history-guessing: live must match the declared policy, and if the June
> Phase-332 preference for `false` is still wanted, that is a deliberate,
> reviewable change — edit `[strict]` in `scripts/branch_protection.sh`, flip
> the line in AGENTS.md, and update this file and PHASE_838's constraint in the
> same commit — never an unrecorded API state.
