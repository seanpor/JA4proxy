<!--
title: "Engineering Method — Case Studies"
audience: architects, contributors
last_reviewed: 2026-04-25
phase: 106g
-->

# Engineering Method — Case Studies

This document is a companion to [`METHOD.md`](METHOD.md) and
[`PHASE_ANATOMY.md`](PHASE_ANATOMY.md). It walks through three real phases of
JA4proxy's history — each one taught us something the method documents could
not have taught us in the abstract. The point is not to celebrate the phases.
The point is to record what was planned, what actually shipped, and what we
revised mid-flight or after the fact. Read these alongside the formal method
to see where the rules came from.

Each case study answers six questions: goal, outcome, plan vs. delivery,
what went wrong, what we would do differently, take-away. The "what went
wrong" sections are deliberate. A method document with no scars is a
marketing document.

---

### Phase 15 — Go Rewrite of Proxy Core

**Goal:** rewrite `proxy.py` and `src/security/` in Go to remove the
Python-GIL throughput ceiling and ship a single production runtime.

**Outcome:** `cmd/proxy/` plus `internal/{tls,security,redis,cache,config}/`
shipped as the production proxy. Python implementation kept on the bench as
the prototype-of-record. 75+ Go unit tests pass; JA4 byte-for-byte parity
with the Python reference for every fixture in `tests/fixtures/clienthello/`.

**Plan vs. delivery.** The plan in `docs/phases/complete/PHASE_15.md` and
`docs/decisions/ADR-015.md` was deliberately late in the roadmap. We made the
non-obvious choice to keep Phase 15 last instead of starting the rewrite at
Phase 1. The rationale, captured in ADR-015 and the phase preamble, was that
the Python prototype defined correctness — its test suite was the
specification — and rewriting before the design stabilised would have meant
porting bugs and re-porting them every time a signal module changed. We held
the line on this even when throughput numbers from the Python proxy looked
embarrassing (~350 conn/s with a real Redis). What shipped matched the plan
in shape: same `config/proxy.yml` schema, same Redis key layout, all signal
modules wired through `buildPipelineConfig()`, drop-in HAProxy upstream
swap. What did not match the plan was the cost of the porting itself.

**What went wrong.** Three things, all of them invisible until the rewrite
started.

First, the Python prototype carried implicit invariants that lived only in
the code, not the tests. The clearest example was the dial formula. The
risk-scorer uses banker's rounding (`round(101 - (dial/100) * (101 -
configured))`), and Python's `round()` is banker's rounding by default —
nobody had ever written a test that asserted "this score, at this dial, must
round this exact way." The Go rewrite naturally used Go's default rounding
(half-away-from-zero) and produced different actions at boundary scores. We
caught it during cross-language parity testing, not before, and the fix
required a small banker's-rounding helper plus a parity test that ran the
same vectors through both implementations. The lesson was uncomfortable:
the Python tests had been passing for fifteen phases without ever pinning
this behaviour explicitly.

Second, the subplan went stale during the rewrite. `PHASE_15_subplan.md`
was written early, with module-level granularity ("port the SNI analyser,
port the TCP analyser"), and by the time the second module was being
written it no longer matched the file layout we had settled on. We had to
stop and rewrite it mid-phase to file-level detail — exact function
signatures, exact signal names and scores, exact test names — so a less
capable agent or a returning human could pick it up without reverse-
engineering the diff. The pattern shows up in the project memory still:
"PHASE_15_subplan.md is now fully detailed."

Third, a tooling quirk burned an afternoon. Snap-installed Go on the
development host sets `GOROOT=/usr/share/go`, which is not where snap
actually puts the toolchain. `go build` and `go test` work but tools that
read GOROOT directly (linters, some IDEs) fail in confusing ways. The fix
was a one-line `~/.bashrc` export and a note in the project memory, but it
is the kind of friction that compounds across multiple agent sessions.

**What we would do differently.** Capture invariants in tests, not just in
code. The banker's-rounding case is the canonical example — any time the
prototype relies on a language default, write a test that asserts the
default. Run cross-language parity tests from day one of the rewrite, not
as a closing gate. Treat subplans as living documents the way the phase
docs are treated, with the same pre-implementation review.

**Take-away.** Rewriting a stable design is mostly mechanical. The
non-mechanical part is discovering what the prototype quietly assumed.
Tests are the contract; if the contract is not in the tests, the rewrite
will find it the hard way.

---

### Phase 82 — Policy-as-Code, Shadow Mode & Governance

**Goal:** express all mutable JA4proxy rules as YAML in version control,
applied via the Management API in CI/CD; ship shadow-mode simulation so a
CISO can see "what would dial=80 have blocked last week" before raising the
dial.

**Outcome:** `docs/phases/complete/PHASE_82.md` is fully retro-tagged with 19
REQ-IDs. `docs/policy/schema.md` documents the YAML schema.
`docs/decisions/ADR-082.md` records the shadow-mode storage decision
(Redis with LZ4 compression for ≤ 50M connections/month; ClickHouse above
that). The offline validator and apply script are the deliverable that
landed in the phase; the platform-dependent pieces (live API, four-eyes UI,
ServiceNow integration, simulation runner) are deferred to Phase 100.

**Plan vs. delivery.** The plan deliberately split acceptance criteria into
"offline-testable" (§10.1, REQ-082-01 through REQ-082-09) and
"platform-dependent" (§10.2, REQ-082-10 through REQ-082-19) before any code
was written. The split was not retrospective. The phase explicitly chose
schema-validated YAML over a custom DSL because Pydantic-v2 could enforce
every constraint we cared about (TTL expiry, JA4 format, CIDR shape, dial
bounds, shadow-mode-approved gating on dial increases > 20 points) without
inventing new syntax. We also chose a stopgap pattern — Phase 82 ships a
Python script `scripts/ja4proxy-policy.py` with the same CLI surface that
the Phase 83 Go binary will replace. CI templates only need one word
changed at the cutover.

**What went wrong.** Of 19 REQ-IDs, 13 ended up tagged `[MANUAL-REVIEW]`
and only 6 had concrete automated test references. That ratio looks
reasonable on paper — the platform-dependent items genuinely need a live
Phase 79 API and a running analytics node — but the experience of writing
the phase taught us a process lesson the manifest does not capture.

When we wrote acceptance criteria like "policy apply is idempotent across
all resource types against a live Phase 79 API" (REQ-082-10), we treated
"verified by `[MANUAL-REVIEW]`" as a way of saying "this can't be
automated yet, defer it." That is true, but it also disguised criteria
that *could* have been driven toward a testable shape with more thought.
"Idempotent across all resource types" is testable today against the mock
API that already exists in `tests/integration/test_policy_apply.py` —
REQ-082-08 already covers eight idempotency tests against that mock. The
right move was to fold REQ-082-10 into REQ-082-08 with the addition that
the same test must run against the live API in Phase 100. Instead, we left
it as a separate manual item, which makes the deferred set look larger
than it really is.

The other process scar: shadow mode required an architectural decision
(Redis vs. ClickHouse) that we initially planned to make during
implementation. The phase doc §3.3.1 is explicit that no shadow-mode code
is written until ADR-082 is committed. That gate held — the ADR landed
before any code — but only because someone reading the plan flagged it.
The first draft did not have a hard gate; it had a "decision to be made"
note that could easily have slipped to the bottom of the to-do list.

**What we would do differently.** Drive criteria toward testable shape
during `/review-phase`, not after. When a REQ-ID reaches for
`[MANUAL-REVIEW]`, ask twice: is the live thing genuinely required, or is
a fake good enough for the automated half? If a fake covers most of the
behaviour, write that test now and add a manual addendum for the live
case. Do not let `[MANUAL-REVIEW]` become a parking lot.

Treat architectural decisions as hard gates with their own ADR slot in the
phase doc, not as inline notes. The pattern in §3.3.1 ("No shadow mode
code starts until the ADR is committed") is now a template we apply to
any phase that needs a decision before code.

**Take-away.** Acceptance criteria are not just documentation — they are
the shape of the work. A criterion that defers to manual review by
default rewards laziness in test design. Force the testable form first;
let the manual form be a conscious choice with a reason next to it.

---

### Phase 200-series — Security Remediation Wave

**Goal:** package the response to the 2026-04-11 strategic security
architecture review and the subsequent pentest campaign as discrete
numbered phases, so each finding has explicit acceptance criteria and a
traceable fix.

**Outcome:** Phase 200 (PROXY-protocol trust check + v2 parser, 11 REQ-IDs);
Phase 201 (Go Redis TLS + silent-failure hardening, sub-phases 201a–201e);
Phase 202 (CI supply-chain pinning + default credential removal,
sub-phases 202a–202e); Phase 203 (Go missing signals — TAP-derived JA4T,
ja4_tls_mismatch, weak ciphers, DGA, deep health). Each phase shipped
with REQ-IDs traceable to a finding ID in
`docs/security/FINDINGS_REGISTER.md`.

**Plan vs. delivery.** The decision to package the audit response as a
sequence of small numbered phases — rather than one giant "security
fixes" branch — was deliberate. It came from the experience of earlier
ad-hoc fixes (see CLAUDE.md "Security Fixes Applied" memory entries) where
the fix landed but the regression test did not, or the fix landed for one
signal module but not the sibling that had the same bug. The 200-series
forced one finding → one phase → one acceptance-criteria block →
one regression test, and the audit register tracked closure by finding ID,
not by commit SHA.

What shipped matched that intent. Phase 200, REQ-200-08 is named
`pentest_proxy_parser_regression_test.go::TestRegression_JA4PROXY_2026_0001_StripsUntrustedHeader`
— the finding ID is in the test name. Phase 201 carved its sub-phases
along strict scope lines (TLS, error logging, health check, input
validation, close-out) so a reviewer could verify each in isolation.

**What went wrong.** Two scars worth recording.

The first showed up in `PHASE_201_review.md` and was severe enough that
the entire phase had to be rewritten before any code was committed. The
original Phase 201 had a sub-phase 201a claiming four Go signal scores
had drifted from `config/signal_scores.yml` and listing the corrections.
The reviewer ran `make check-scores` and it exited 0 — there was no
drift. The phase had been written against a stale branch or the numbers
had been transcribed backwards, and applying the original 201a would
have *introduced* the drift it claimed to fix. The catch was clean (the
reviewer noticed before any work started) but the lesson stuck: phase
docs that cite specific numeric values must be verified against `make`
targets at the moment the doc is written, not days later.

The second scar is broader and runs through the whole 200-series. Some
phases re-discovered the same root cause in a different module. Phase
200 was the PROXY-protocol trust gap — the Go proxy trusted PROXY
headers from any source. That fix is one regex of a finding. Reviewing
the related code afterwards, sibling input paths in other parts of the
Go proxy needed the same trust-boundary check. We caught them in later
phases instead of as part of 200. Each catch produced a new phase,
which is traceable, but the better outcome would have been "Phase 200
sweeps the whole codebase for the same input-validation pattern in one
pass." The findings register has the trail; what it shows is several
phases that should arguably have been one.

**What we would do differently.** When a security finding identifies a
category — "we trust input X without validating its source" — sweep the
codebase for siblings in the same phase. The fix for one is rarely
isolated. We have since added a security-sweep checklist item to
`/review-phase` for any phase tagged `security_remediation`: before
closure, grep for the same antipattern across the whole repo and either
absorb the siblings into the current phase or open follow-up phases
explicitly with cross-references. The check is cheap; missing it is
not.

We have also tightened the convention that phase docs which cite
specific values (signal scores, config keys, test names) must be
verified against the live repo at the moment the phase doc is reviewed.
The Phase 201 false-premise rewrite is the cautionary tale we point at
when an agent asks why the `/review-phase` skill verifies citations.

**Take-away.** Numbered phases as the unit of security remediation are
worth the overhead — they make closure auditable and traceability
mechanical. The two failure modes are stale citations in the plan and
narrow scoping that misses sibling instances of the same bug. Both are
process problems with process fixes: verify citations during review,
sweep for siblings before close.

---

## Where to read more

- [`METHOD.md`](METHOD.md) — the formal statement of the phase-based method
  these case studies are an instance of.
- [`PHASE_ANATOMY.md`](PHASE_ANATOMY.md) — annotated walk-through of one
  representative phase from plan through close.
- [`docs/phases/complete/PHASE_15.md`](../phases/complete/PHASE_15.md),
  [`docs/phases/complete/PHASE_82.md`](../phases/complete/PHASE_82.md),
  [`docs/phases/complete/PHASE_200.md`](../phases/complete/PHASE_200.md) — the source phase
  documents for each case study.
- [`docs/decisions/ADR-015.md`](../decisions/ADR-015.md),
  [`docs/decisions/ADR-082.md`](../decisions/ADR-082.md) — the
  architectural-decision records cited above.
- [`docs/phases/complete/PHASE_201_review.md`](../phases/complete/PHASE_201_review.md) —
  the critical review that caught the false-premise sub-phase.
