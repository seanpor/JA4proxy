<!--
title: Zero_Unwaived_CVEs_Program
audience: developer
last_reviewed: 2026-10-17
phase: 847
-->

# Phase 847 — Zero Unwaived CVEs (programme umbrella)

> **Status:** COMPLETE (2026-10-23)
> **Size:** LARGE
> **Dependencies:** none (847a is the entry point; the rest chain from it)
> **Branch:** `phase-847-cve-zero-path`
> **Splits into:** 847a–847g (see roadmap below)

---

## Goal

Replace today's **reactive, debt-accumulating** CVE handling with a **controlled,
repeatable, evidence-bound** process whose steady-state is *zero unwaived
Medium/High/Critical findings* — and make the **fix path cheaper than the waiver
path**, so the process reduces risk over time instead of accreting it.

This is a **process** phase, not a remediation phase. It does not itself fix CVEs;
it builds the machinery that fixes them continuously and refuses to let them hide.

---

## Why (the diagnosis)

Two incidents during Phase 824c (2026-10-16) exposed the structural problem:

1. A new HIGH (`mcp` CVE-2026-59951) landed in the advisory DB and reddened
   **every** PR, including unrelated ones. The fix had to be hand-applied in
   **two** places (`Makefile` and `.github/workflows/ci.yml`), which had already
   drifted to **7** vs **4** `--ignore-vuln` flags.
2. A new HIGH family (kin-openapi `CVE-2026-100351/352/353/354`) appeared in the
   Trivy DB for the pinned `grafana/grafana` image and again reddened every PR.
   Triage happened under time pressure; a "bump the image" theory was pursued and
   **proved wrong** (grafana 13.2.4 still bundles kin-openapi `v0.144.0`), because
   the authoritative check (a full JSON scan) was expensive enough that a
   truncated `tail -40` was used as a proxy and gave a false answer.

Root cause, in one line: **the gate conflates "this PR regressed security" with
"the upstream DB changed."** Those are different events needing different
responses. Conflating them is what forces people to waive under pressure — and
waiving under pressure is how hacky, untracked decisions get made.

Four compounding defects:

| # | Defect | Evidence |
|---|--------|----------|
| 1 | **No diff/baseline gating** — a required `Security Scan` fails on upstream DB churn, so unrelated CVEs block unrelated work. Zero safety: the CVE exists whether or not the PR merges. | No baseline/diff code anywhere in `scripts/` or `.github/workflows/`. |
| 2 | **Expiry is theatre** — `renew_trivyignore.py` auto-bumps `exp:` to `today+7` when within 5 days; its own docstring admits it never checks whether a fix shipped. "90-day expiry" means "renewed forever, silently." | `scripts/renew_trivyignore.py` docstring. |
| 3 | **Two sources of truth** for waivers, already diverged. | 7 ignores in `Makefile`, 4 in `ci.yml`. |
| 4 | **Fix path costs more than waive path** — waiving is a 1-line edit; fixing is a PR + image validation + smoke test. Under pressure everyone waives, and nothing tells you when a fix *does* ship. | — |

Current inventory (2026-10-17): **29** entries in `.trivyignore.third-party`
(0 first-party), **6/2** diverging pip-audit ignores (Makefile vs `ci.yml`; union
7), gate scans `HIGH,CRITICAL`
only (MEDIUM not gated), and the only scheduled security jobs are
`trivyignore-renewal`, `dependabot-automerge`, `dependabot-pr-refresh` — there is
**no scheduled scan**, which is exactly why new-DB-CVEs are discovered by accident
on someone else's PR.

After 847a the ignorefile holds **28** entries: the kin-openapi waivers were added
and six entries that the monitoring-image bump rendered dead were removed (see
`PHASE_847a.md`).

---

## Definition of done — what "zero" honestly means

Literal zero findings in pinned third-party images is **not achievable** — we do
not control upstream release cadence (grafana has not shipped a kin-openapi fix
in any tag). Promising literal zero would be a lie that fails on day one.

"Zero" is therefore defined as five properties that **are** achievable and that
together make a hanging CVE impossible:

1. **Zero untriaged findings.** Every new Medium/High/Critical finding is
   triaged within an SLA (target: 5 working days) by the baseline monitor — not
   discovered by accident on an unrelated PR.
2. **Zero waived findings with a fix available.** The "fixable queue" is always
   empty: if an upstream fix exists, the bot opens the fix PR and the waiver is
   removed. A waiver may only exist when **no fix exists**.
3. **Zero auto-renewed expiries.** Every waiver is re-affirmed on its *premise*
   (fix shipped? carrier still carries it? reachability claim still true?), never
   blind re-dated. An expiring waiver with an available fix escalates.
4. **Zero silent findings.** Baseline drift (DB added findings to a pinned image)
   is always surfaced by the scheduled monitor, so nothing accumulates unseen.
5. **Zero divergent waiver lists.** One registry renders every derived artifact;
   hand-editing a derived file fails CI.

A waiver, in this programme, is **not a hack**. It is a first-class, evidenced,
owner-assigned, premise-bound record. The hack was never "waiving" — it was
waiving as an anonymous one-line comment in a Makefile with no evidence and no
re-check trigger.

---

## Target architecture

```
                       security/waivers.yaml            <- ONE source of truth
                       (id, severity, carriers, rationale,
                        reachability evidence, fix-status,
                        owner, created, expires, premise)
                                 |
                       scripts/render_waivers.py        <- renderer (847a)
                                 |
        +------------------------+------------------------+
        |                        |                        |
  .trivyignore.first-     .trivyignore.third-      pip-audit ignore args
  party (generated)       party (generated)        (generated; consumed by
                                                    Makefile + ci.yml alike)
                                 |
              +------------------+-------------------+
              |                                      |
   PR REGRESSION GATE (required)          BASELINE MONITOR (scheduled)
   scan PR images/deps, diff vs           full scan, diff vs registry,
   baseline recorded on main,             new unwaived -> issue + fix PR,
   FAIL only if PR INTRODUCES a           does NOT block unrelated PRs
   new unwaived finding.                  (847c)
   Upstream churn cannot redden it.              |
                                                 v
                                        FIX-FORWARD BOT (847d)
                                        checks fix availability, opens
                                        image-bump PR with before/after
                                        CVE table + smoke test; replaces
                                        auto-renewal with re-affirmation.
```

**The key inversion:** CI gates on the *diff* (what this PR changes); a scheduled
job monitors the *baseline* (what the world changed). That single split is what
stops "a new upstream CVE reddens every PR" — the symptom that drove both 824c
blockers.

---

## Roadmap

| Sub-phase | Title | Size | Depends on | Delivers |
|-----------|-------|------|-----------|----------|
| **847a** | CVE registry as single source of truth | MEDIUM | — | `security/waivers.yaml` + renderer + drift test; migrates 29 Trivy + 8 pip-audit entries. No gate change. Kills divergence. |
| **847b** | Scan tooling correctness | SMALL | 847a | Count CVEs from Trivy **JSON** (not `grep -c HIGH` on grouped tables); fix the "see `.trivyignore`" message; both ignore lists driven from the registry. |
| **847c** | Split scan: regression gate + baseline monitor | LARGE | 847a, 847b | Required PR gate diffs vs a recorded baseline; scheduled monitor files issues on drift. Ends "new CVE reddens every PR." |
| **847d** | Fix-forward bot + expiry re-affirmation | MEDIUM | 847c | Scheduled job checks fix availability, opens bump PRs with scan diffs; expiry re-affirmation replaces blind re-dating. |
| **847e** | MEDIUM-CVE gating (measure, then extend) | MEDIUM | 847c | Inventory the MEDIUM surface, then extend the same registry + diff machinery to MEDIUM. Decision gated on the inventory. |
| **847f** | Reachability evidence binding | MEDIUM | 847a | Turn waiver justifications into automated assertions (e.g. "grafana is internal-only" → compose-network check); a broken premise invalidates the waiver. |
| **847g** | Go 1.27.3 bump + CVE-2026-111943 triage | SMALL | 847a, 847c | Clear the Go stdlib CVE from every surface we build (base-image bump) and decide per third-party surface: bump where a fixed tag exists, else a dated waiver. Split out mid-programme when the CVE landed. |

Sequencing rationale: **847a first** (mechanical, unblocks everything, zero risk);
**847c is the structural win** (highest value, needs a/b in place); **847e waits
for 847c** because extending the gate to MEDIUM is only affordable once
diff-based gating stops MEDIUM churn from reddening every PR; **847f is
independent polish** that can land any time after the registry exists.

Each sub-phase is independently shippable and reviewable, and sized so a single
engineer can own one end to end.

---

## Risks and mitigations

| Risk | Mitigation |
|------|-----------|
| Diff-gating lets a PR merge that adds a vulnerable dep. | The PR gate compares the PR's images/deps against the baseline **on the same surfaces** — a new dep/image with new findings is a diff and fails. Only pre-existing, already-triaged findings are non-blocking. |
| Baseline monitor's issues get ignored (alert fatigue). | Bounded: it only opens/updates **one** issue per new finding, and 847d turns most into auto-fix PRs. A weekly digest reports the fixable-queue count, which must stay ~0. |
| Registry renders wrong → gate silently passes on nothing. | 847a's drift test asserts rendered files == source; 847b keeps the existing "guard the guard" style minimums. Rendering is deterministic and unit-tested. |
| MEDIUM escalation (847e) explodes the waiver count. | Inventory-first: measure the MEDIUM surface before committing. If it is large, gate MEDIUM on **new** findings only (diff), never the full baseline, and ratchet down. |
| A person re-adds `--ignore-vuln` by hand to unblock. | 847a makes the derived files the only accepted source; a hand-edit fails the drift test with a message pointing at the registry. |

---

## Out of scope (explicitly)

- **Patching third-party gobinaries at build time.** Untracked divergence from
  upstream — strictly worse than an evidenced waiver. Rejected deliberately.
- **Making baseline drift a required check again.** That is defect #1; 847c
  exists to undo it.
- **Continuing blind `exp:` re-dating.** Replaced by 847d's re-affirmation.
- **Actually remediating specific CVEs.** This programme builds the machine; the
  machine (847d) opens the remediation PRs. A one-off remediation may ride along
  in any sub-phase but is not its deliverable.
- **First-party CVE policy beyond what the registry models.** `.trivyignore.first-party`
  is currently empty; 847a gives it the same machinery for free but does not
  author first-party waivers.

---

## Immediate unblock note (not part of this programme)

At the time of writing, PR #618 (Phase 824c) is blocked by the four kin-openapi
CVEs. **No grafana tag fixes them** (verified: 13.1.6 and 13.2.4 both ship
kin-openapi `v0.144.0`), so an evidenced waiver is the correct answer today. That
waiver should be landed as a **small, correctly-evidenced** change (rationale +
reachability argument + re-check trigger: *re-evaluate when grafana ships
kin-openapi ≥ 0.149.0*), ideally by first landing 847a so it is entered in the
registry rather than as an anonymous Makefile comment. Landing it through the new
machinery is the controlled version of exactly the thing this programme builds.

---

## Test strategy (programme-level)

Every sub-phase must, in addition to its own tests:

- **Prove it can fail.** Temporarily introduce a synthetic unwaived finding and
  confirm the relevant gate/monitor catches it; revert. Record in the PR.
- **Prove no silent pass.** Assert minimum-count guards so a broken extractor or
  empty scan cannot pass vacuously (existing repo convention).
- Run `make preflight` (lint + scan + test) before opening any PR.

## Outcome (2026-10-23)

All seven sub-phases are complete and merged (847a #620, 847b #621, 847c #623,
847d #635, 847e #636, 847f/847g/824c #640). The machinery is running; this
section records the state it produced, measured rather than asserted.

**The five properties, and what enforces each:**

| Property | Mechanism | State on 2026-10-23 |
|---|---|---|
| Zero untriaged | Nightly `scan-baseline-monitor.yml`: full scan of every surface + the Python dependency set, one deduplicated issue per *unwaived* finding | 18 surfaces, **0 unwaived HIGH/CRITICAL** (`security/baseline.json`) |
| Zero fixable-but-waived | `fix-forward.yml` + 847d's `fix_available` records and re-check triggers | fixable queue **0**; every remaining waiver is `fix_available: false` at a specific measured version |
| Zero auto-renewed expiries | `renew_trivyignore.py` re-affirms the *premise* (carrier still carries it? fix shipped? reachability still true?) and escalates instead of re-dating | 21 waivers, all dated, latest expiry 2027-01-21; 17 were **deleted outright** when their fix shipped (ten image waivers in 847g, seven pip waivers at close-out) rather than left for an expiry to notice |
| Zero silent findings | Required `Scan Regression (surfaces touched)` diffs every touched surface against the recorded baseline; monitor covers the untouched ones | required gate is `scan-regression`; the full `make scan` is de-required on PRs (it only measures upstream churn) |
| Zero divergent lists | `security/waivers.yaml` renders `.trivyignore.third-party`, `.trivyignore.first-party` and `.pip-audit-ignores`; a drift test fails CI on a hand edit | `render_waivers.py --check` green; both scan paths in the Makefile read the same rendered files |

**The MEDIUM band, measured before it was gated** (847e, re-measured in 847g):
79 unwaived findings across 18 surfaces, down from 152; diff-only gate at the
same baseline rule as HIGH; ratchet ceiling 79 in `tests/unit/test_medium_ratchet.py`
so accretion must be a reviewed edit.

**Waivers are evidence, not prose.** Every one of the 21 names a registered
reachability check that CI executes (`reachability_checks.py`: 20 machine-checked,
1 attested, 0 broken). The programme found and fixed three false premises that
predated it — a port-parsing bug in the exposure classifier, an "internal-only"
claim on a service that publishes 443/80, and a `not-imported` check that passed
vacuously for namespace distributions — which is the strongest argument that the
binding was worth doing: the *justifications* were the unreliable part, not the
gate.

**Honest limits, recorded so they are not mistaken for done:**

- One reachability value (`input-path-unreachable`, haproxy) is **attested**, not
  machine-checked. The check verifies the evidence exists; it cannot verify the
  evidence is right.
- **"Fixable queue 0" means "no *adoptable* clearing".** Two of the 21 waivers
  (`CVE-2026-59951`, `CVE-2026-114603`) name a published fix version that cannot
  be taken, because `semgrep` hard-pins the vulnerable one; 847d records that as
  `blocked` → `fix_available: false` plus a `recheck_trigger`, not as "no fix
  exists". The distinction is the whole point of `recheck_trigger`: when semgrep
  relaxes its pin, the premise changes and the waiver must go.
- `pip-audit` carries no severity, so every pip finding is gated as HIGH
  regardless of its advisory CVSS. The registry records the advisory severity;
  the gate stays conservative. This is why `CVE-2026-114603` is a MEDIUM waiver
  that the monitor files as HIGH.
- **Dead pip waivers are not detected automatically** (issue #642). The Trivy
  side has `check_trivyignore_drift --fail-on-dead`; the pip side has nothing,
  because the monitor's baseline diff only looks at *unwaived* findings. This
  was not cosmetic: a re-audit without ignores showed `.pip-audit-ignores` held
  **seven** ids for findings that no longer exist (four urllib3, pygments,
  protobuf, PYSEC-2026-2132). A dead ignore keeps `--ignore-vuln` alive, so a
  regression back into the vulnerable range would be suppressed silently — the
  exact failure this programme exists to prevent. They were removed at close-out
  (registry 28 → 21); **Phase 848 landed the detector** — the monitor now audits
  without the ignore flags, splits waived/unwaived/dead in process, and files one
  auto-closing `[cve-waiver]` issue per dead id.
- `main` is still not verified after an auto-merged PR run by
  `app/github-actions` (issue #622). That is a CI-plumbing gap, not a CVE
  process gap, and it is tracked separately.

---

## Acceptance criteria (programme-level)

- [x] All sub-phases exist as manifest entries with correct deps — **seven**, not
      six: 847g was split out on 2026-10-21 when CVE-2026-111943 landed mid-programme.
- [x] Each sub-phase meets its own acceptance criteria and the three programme
      tests above. Every one recorded a demonstration that it can fail: 824c's
      forward check was proven vacuous by a route rename, 847c's gate by a
      synthetic finding, 847f's checks by breaking a premise, 847g's pin test by
      reverting the pin.
- [x] A single registry is the only place a waiver is authored; every derived
      artifact is generated and drift-checked (`render_waivers.py --check` in `make lint`).
- [x] A new upstream CVE no longer reddens unrelated PRs (demonstrated in 847c):
      `Scan Regression (surfaces touched)` is the required gate and it compares
      against the recorded baseline, per surface.
- [x] The fixable-queue is reported and ~0 (demonstrated in 847d); it is **0**
      today, and 847g removed ten waivers whose fix had actually shipped rather
      than waiting for an expiry to notice.
