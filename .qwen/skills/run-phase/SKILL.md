---
name: run-phase
description: Expert project manager orchestrating the complete implementation of a numbered phase using a parallel multi-agent team, followed by an independent critical review.
---

# Run Phase

Expert project manager orchestrating the complete implementation of a numbered phase
using a parallel multi-agent team, followed by an independent critical review.

**Invocation:** `/run-phase <phase-number>` (e.g., `/run-phase 201`)

**Pre-condition:** The target phase doc at `docs/phases/PHASE_XX.md` exists and
has been reviewed (ideally via `/review-phase`). The working tree is clean.

---

## Architecture: Wave-Based Parallel Execution

You are the **Project Manager (PM)**. You orchestrate four specialist agents who
run in parallel where dependencies allow. Communication flows through you — when
one agent produces output another needs, you relay the relevant context.

```
                        ┌─────────┐
                        │   PM    │  ← You (orchestrator)
                        └────┬────┘
                             │
         ┌───────────────────┼───────────────────┐
         │      Wave 1       │      Wave 2       │      Wave 3
         │   (parallel)      │   (parallel)      │   (sequential)
    ┌────┴────┐  ┌───┴───┐  │  ┌───┴───┐        │
    │   TDD   │  │  Doc  │  │  │ Coder │        │
    │  Writer │  │ Eng   │  │  │       │        │
    │         │  │(early)│  │  │       │        │
    └─────────┘  └───────┘  │  └───┬───┘        │
                             │      │             │
                             │  ┌───┴───┐        │
                             │  │  Doc  │        │
                             │  │ Eng   │        │
                             │  │(late) │        │
                             │  └───────┘        │
                             │                    │
                             │  ┌─────────────────┼─────────────┐
                             │  │  Wave 3 (seq)   │             │
                             │  │                 │             │
                             │  │   QA Engineer   │  Cyber      │
                             │  │                 │  Architect   │
                             │  │                 │             │
                             │  └─────────────────┴─────────────┘
```

**Wave 1 — parallel, no dependencies:**
- TDD Test Writer: writes failing tests that define the contract
- Doc Engineer (early): scaffolds config docs, Redis schema, ADR stubs, CHANGELOG draft

**Wave 2 — after TDD tests exist:**
- Coder: makes the tests green (PM relays test file paths and contract summary)
- Doc Engineer (late): finalizes docs using actual implementation details

**Wave 3 — sequential:**
- QA Engineer: adversarial testing, coverage audit, acceptance walkthrough
- Cyber Architect: independent review of all completed work

---

## Step 0 — PM: Load Context & Plan

You (the PM) do this step yourself. Do not delegate it.

1. Read `CLAUDE.md` in full (project rules, core asymmetry, cross-cutting requirements).
2. Read the target phase document (`docs/phases/PHASE_XX.md`).
3. Read `docs/phases/manifest.yaml` for status and dependencies.
4. Read `config/proxy.yml` for current config surface.
5. Read `docs/REDIS_SCHEMA.md` if the phase touches Redis.
6. Read `docs/STYLE_GUIDE.md` and `docs/TEST_ORGANIZATION.md`.
7. Read `docs/OBSERVABILITY_STANDARDS.md` if the phase adds metrics/alerts.
8. Skim existing source files that the phase will modify or extend.
9. If a `/review-phase` output exists at `docs/phases/PHASE_XX_review.md`, read it
   and use its sub-task decomposition as the starting work breakdown.

**Create a branch:** `git checkout -b phase-XX-description` from latest `main`.

**Produce a work plan** with:
- File ownership map: which files each agent will touch (no overlaps within a wave)
- Wave schedule: what runs in parallel, what blocks on what
- Risk flags: anything that needs user input before agents start

**Present the plan to the user and wait for approval before proceeding.**

---

## Step 1 — Wave 1: TDD Test Writer + Doc Engineer (Early)

Launch these two agents **in parallel** using the Agent tool with `subagent_type: "general-purpose"`.

### Agent 1a: TDD Test Writer

**Their instructions:**

> You are a TDD Test Engineer. You write tests BEFORE implementation exists.
> Tests define the contract — code that doesn't satisfy your tests is wrong.
>
> **Write tests for phase XX based on these acceptance criteria:** [paste them]
>
> **Rules:**
> - Every acceptance criterion gets at least one test.
> - Include negative tests: invalid input, missing config, Redis down, timeout.
> - Include boundary tests: empty strings, zero values, max values, IPv6.
> - For external services, create/extend mocks in `tests/mocks/`.
> - For web phases, create `test_pages.py` and `test_container_config.py`.
> - Tests must FAIL (no implementation yet). Verify they fail for the RIGHT
>   reason — import errors or syntax errors mean YOU made a mistake.
> - No `assert True`. No `assert result is not None` without checking the value.
> - Every assertion tests a specific, meaningful property.
> - Parametrize where there are 3+ similar cases.
> - Mock at the boundary, not deep inside — test real logic, mock I/O.
> - Chaos tests: one per documented failure mode.
> - If the phase adds a signal: FP corpus test against Tranco top 10k pattern.
>
> **Follow the patterns in these existing files:** [list paths]
> **Write to these files:** [list paths from ownership map]
>
> Run the tests and report which ones fail and WHY they fail.

### Agent 1b: Doc Engineer (Early)

**Their instructions:**

> You are a Documentation Engineer doing early-phase scaffolding. The
> implementation doesn't exist yet — you are working from the phase spec.
>
> **For phase XX, do the following:**
>
> 1. **Config scaffolding:** Add new config keys to `config/proxy.yml` with
>    inline comments (purpose, valid values, default, hot-reload status).
>    Use safe/conservative defaults.
> 2. **Redis schema:** Add new key patterns to `docs/REDIS_SCHEMA.md`
>    (pattern, type, TTL, purpose, phase number).
> 3. **ADR stub:** If the phase makes non-obvious architectural decisions,
>    create `docs/decisions/ADR-NNN.md` with the decision and rationale.
> 4. **CHANGELOG draft:** Prepend a draft entry to `CHANGELOG.md`.
> 5. **Runbook stub:** If new failure modes exist, add stub entries to the
>    relevant runbook.
>
> Mark anything you're uncertain about with `<!-- TODO: verify after impl -->`.

### PM: After Wave 1 completes

1. **Collect outputs.** Read the test files and doc scaffolding they created.
2. **Check for conflicts.** If both touched the same file, merge manually.
3. **Prepare the Coder brief.** Summarize:
   - Which test files exist and what contracts they define
   - What config keys were scaffolded and their defaults
   - What Redis keys were documented
4. **Prepare the Doc Engineer (late) brief.** Note what was left as TODO.

---

## Step 2 — Wave 2: Coder + Doc Engineer (Late)

Launch these two agents **in parallel**.

### Agent 2a: Coder (Implementation Engineer)

**Their instructions:**

> You are an Implementation Engineer. Your job is to write the minimum correct
> code to make the failing tests green. You don't gold-plate.
>
> **Phase XX tests are in:** [list test file paths]
> **Config keys already scaffolded in:** `config/proxy.yml`
> **Redis keys documented in:** `docs/REDIS_SCHEMA.md`
>
> **Rules:**
> - Read the failing tests first — they ARE the spec.
> - Follow existing patterns in `proxy.py`, `src/security/`, `internal/`.
> - Python: type hints on all public functions, docstrings on public classes.
> - Go: godoc on exports, errors returned not panicked, context propagation.
> - No blocking I/O on the hot path. Ever.
> - External calls: fire-and-forget (`asyncio.create_task()` / goroutines).
> - Every external call: failure handler → log + counter + neutral return.
> - Prometheus metrics: `ja4proxy_{subsystem}_{name}_{unit}`.
> - IPv6 handled everywhere an IP is touched.
>
> **After implementation:**
> - Run all tests. Fix until green.
> - Run `ruff check .` / `gofmt -l . && go vet ./...`. Fix all issues.

### Agent 2b: Doc Engineer (Late)

**Their instructions:**

> You are a Documentation Engineer doing the late-phase pass. The early
> scaffolding is already in place. Your job is to finalize everything that
> depends on implementation details.
>
> **Do the following:**
> - Review and finalize the CHANGELOG draft — make it accurate.
> - Check that all `<!-- TODO: verify after impl -->` markers are resolved.
>   Read the actual implementation to verify.
> - Document new Prometheus metrics: name, type, labels, what it measures.
> - Document new log lines: level, message pattern, when emitted.
> - Document new alerts if applicable.
> - Verify all public interfaces have appropriate docstrings/godoc.
> - Check that non-obvious implementation choices have brief WHY comments.
> - Update phase doc: check off completed acceptance criteria.

### PM: After Wave 2 completes

1. **Read the Coder's report.** Note any design decisions or new interfaces.
2. **Verify tests pass:** run `make test-unit` yourself.
3. **Prepare the QA brief.** Summarize what was implemented and any tricky decisions.

---

## Step 3 — Wave 3: QA Engineer

### Agent 3: QA Engineer

**Their instructions:**

> You are a QA Engineer. You break things. You find gaps between what was
> intended, what was built, and what was tested.
>
> **Phase XX acceptance criteria:** [paste them]
> **Implementation files:** [list paths]
> **Test files:** [list paths]
>
> **Your audit:**
>
> 1. **Test coverage:** Run tests with coverage. Identify untested paths.
>    Check test-to-code ratio (target ~1.3x).
> 2. **Test strength:** For each test, ask: "would this fail if the
>    implementation were wrong?" If not, strengthen or rewrite it.
> 3. **Integration:** Run `make test-unit` — all existing tests must still pass.
> 4. **Config abuse:** Set each new config key to invalid values — verify
>    graceful handling. Remove keys — verify defaults apply.
> 5. **Edge cases:** IPv6 everywhere, empty/null/missing values, concurrent
>    access, Redis unavailable during each new operation.
> 6. **Acceptance walkthrough:** Go through every criterion line by line.
> 7. **Chaos/resilience:** Verify chaos tests exist for every failure mode.
>
> **Fix everything you find.** Write additional tests for gaps.

### PM: After QA completes

1. **Review QA findings.** If there are blockers, fix them or re-spawn agents.
2. **Run `make test-unit`** to verify everything still passes.
3. **Proceed to the independent review.**

---

## Step 4 — Independent Critical Review (Cyber Architect)

This is a **separate, independent agent** that has NOT seen any of the work above.
It reviews from scratch. Do NOT paste the other agents' reports into its prompt.

### Agent 4: Expert Cyber Architect

**Their instructions:**

> You are an independent Expert Cyber Architect reviewing phase XX of JA4proxy.
> You have NOT been involved in the implementation. You assume nothing works
> until you verify it yourself.
>
> **Context:** Read `CLAUDE.md` for project rules. Read `docs/phases/PHASE_XX.md`
> for what this phase should deliver.
>
> **Then examine the actual implementation.** Use `git diff main...HEAD` to see
> every change. Read every modified file in full.
>
> **Perform these audits:**
>
> ### A. Security Audit
> - Threat model: what new attack surfaces? Are they mitigated?
> - Input validation: every external input validated?
> - Secrets: no credentials in logs, config, errors, or Redis?
> - Privilege: no unnecessary capabilities?
> - Supply chain: new deps pinned? CVEs checked?
> - Core asymmetry: FP still costs more than FN in all new paths?
> - Injection: no command injection, SSTI, SSRF, unsafe deserialization?
> - OWASP top 10 for web-facing surfaces.
>
> ### B. Gap Analysis
> - Cross-reference EVERY acceptance criterion against implementation — PASS/FAIL.
> - Cross-reference against `CLAUDE.md` cross-cutting requirements.
> - Check no existing functionality broken or weakened.
> - Check no existing tests deleted, weakened, or assertions relaxed.
>
> ### C. Test Strength Audit
> - For each test: would it FAIL if the implementation were wrong?
> - Check for tautological tests that pass regardless.
> - Check mock fidelity — do mocks include error paths?
>
> ### D. Observability Audit
> - Every new code path emits a metric or structured log.
> - Error paths increment counters (not just log).
> - Log levels correct: ERROR=action needed, WARN=degraded, INFO=state change.
>
> ### E. Documentation Audit
> - CHANGELOG accurate? Redis schema complete? Config keys documented?
> - Runbook updated? ADR exists for non-obvious decisions?
>
> ### F. Regression & Rollback
> - Run `make test-unit`. All pass?
> - No shared files edited outside ownership rules?
> - Rollback-safe: reverting leaves system functional?
>
> ### G. Performance & Resources
> - No blocking I/O on hot path.
> - No unbounded growth (Redis keys, caches, logs).
> - No N+1 Redis patterns. Bounded hot-path allocation.
>
> ### H. IPv6 Parity
> - Every IP code path handles v4 and v6.
>
> **Your verdict — one of:**
>
> **PASS** — all checks satisfied, no blocking issues.
> **PASS WITH NOTES** — minor issues, not blocking. List them.
> **FAIL** — blocking issues. For each: severity, what's wrong, specific fix.

### PM: After Architect Review

**If PASS or PASS WITH NOTES:**
- Apply any noted minor fixes yourself.
- Proceed to Step 5 (Phase Close).

**If FAIL:**
- Triage each finding by which role should fix it.
- Re-spawn the relevant agent(s) with specific fix instructions.
- After fixes, re-spawn the Architect for a re-review.
- If the same finding fails twice: escalate to the user.

---

## Step 5 — Phase Close

Once the independent review passes:

1. Run `make test` — all tests must pass with zero warnings.
2. Run `ruff check .` and `gofmt -l .` — zero lint issues.
3. Update `docs/phases/manifest.yaml`: set `status: COMPLETE`.
4. Run `make sync` to regenerate `TODO.md` and `PROJECT_STATUS.md`.
5. Stage all changes and create a final atomic commit.
6. Run `git diff main...HEAD --stat` and present the summary to the user.
7. Ask the user if they want to push and create a PR.

---

## Orchestration Rules

### File Ownership (Enforced Per Wave)
- **TDD Writer owns:** `tests/` files for this phase, `tests/mocks/` additions
- **Doc Engineer owns:** `docs/`, `CHANGELOG.md`, config file comments
- **Coder owns:** `src/`, `internal/`, `cmd/` implementation files
- **QA owns:** can modify any file, but commits separately tagged `QA fixes`
- **No two parallel agents touch the same file in the same wave.**

### Failure Handling
- **If an agent gets stuck:** collect what they produced and fix it yourself
  or re-brief a new agent with more specific instructions.
- **If tests won't go green:** check if the test contract is wrong (TDD Writer
  mistake) or the implementation is wrong (Coder mistake).
- **If the Architect fails the same thing twice:** escalate to the user.
- **Never skip a step.** If a step produces no work, explicitly state
  "Wave N, Agent X: nothing to do" and move on.
