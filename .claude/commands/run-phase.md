# Run Phase

Expert project manager orchestrating the complete implementation of a numbered phase
using a parallel multi-agent team, followed by an independent critical review.

**Input:** The user provides a phase number (e.g., `93`) or path to a phase document.

**See also:** Run `/review-phase XX` first to get a critical review and sub-task
decomposition. This skill automatically picks up that output if it exists.

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
    Wave 1 (parallel)     Wave 2      Wave 3      Wave 4      Wave 5
    ┌─────────┐          ┌────────┐  ┌────────┐  ┌────────┐  ┌──────────┐
    │   TDD   │          │ Coder  │  │  Doc   │  │   QA   │  │  Cyber   │
    │  Writer │          │        │  │  Eng   │  │        │  │ Architect│
    │         │          │        │  │ (late) │  │        │  │(independ)│
    └─────────┘          └────────┘  └────────┘  └────────┘  └──────────┘
    ┌─────────┐               │           │           │            │
    │  Doc    │               │           │           │            │
    │  Eng    │          depends on  depends on  depends on   depends on
    │ (early) │          Wave 1      Wave 2      Wave 3       Wave 4
    └─────────┘
```

**Wave 1 — parallel, no dependencies:**
- TDD Test Writer: writes failing tests that define the contract
- Doc Engineer (early): scaffolds config docs, Redis schema, ADR stubs, CHANGELOG draft

**Wave 2 — after TDD tests exist:**
- Coder: makes the tests green (PM relays test file paths and contract summary)

**Wave 3 — after Coder completes:**
- Doc Engineer (late): finalizes docs using actual implementation details
  (PM relays new function signatures, metric names, config keys from Coder output)

**Wave 4 — after code + docs complete:**
- QA: adversarial testing, coverage audit, acceptance walkthrough
- Then: Independent Cyber Architect review (must be after QA fixes are applied)

---

## Step 0 — PM: Load Context & Plan

You (the PM) do this step yourself. Do not delegate it.

1. Read `CLAUDE.md` in full (project rules, core asymmetry, cross-cutting requirements).
2. Read the target phase document (`docs/phases/PHASE_XX.md`).
   - **If the phase doc does not exist, STOP.** Per the Mandatory Planning Protocol
     in `AGENTS.md`, the phase doc must be created and reviewed by the user before
     any work begins. Tell the user and abort.
3. Read `docs/phases/manifest.yaml` for status and dependencies.
   - **Check that all prerequisite phases (dependencies) have `status: COMPLETE`.**
     If not, abort and list which prerequisites are incomplete.
4. Read `config/proxy.yml` for current config surface.
5. Read `docs/REDIS_SCHEMA.md` if the phase touches Redis.
6. Read `docs/STYLE_GUIDE.md` and `docs/TESTING_STRATEGY.md`.
7. Read `docs/OBSERVABILITY_STANDARDS.md` if the phase adds metrics/alerts.
8. Skim existing source files that the phase will modify or extend.
9. If a `/review-phase` output exists at `docs/phases/PHASE_XX_review.md`, read it
   and use its sub-task decomposition as the starting work breakdown.
10. **Determine Go vs Python.** Per CLAUDE.md: "Default to the Go side. Touch the
    Python side only when the task explicitly involves prototyping." Brief all agents
    with which language this phase targets.

**Create a branch:** `git checkout -b phase-XX-description` from latest `main`.
If the branch already exists, check it out. If it has diverged from main, rebase first.

**Produce a work plan** with:
- File ownership map: which files each agent will touch (no overlaps within a wave)
- Wave schedule: what runs in parallel, what blocks on what
- Risk flags: anything that needs user input before agents start

**Present the plan to the user and wait for approval before proceeding.**

---

## Step 1 — Wave 1: TDD Test Writer + Doc Engineer (Early)

Launch these two agents **in parallel** using the Agent tool. Each gets its own
brief with full context — they cannot see each other's work.

### Agent 1a: TDD Test Writer

Spawn with `subagent_type: "general-purpose"`. Include in the prompt:

- The full phase document content (copy it into the prompt)
- The list of acceptance criteria
- Paths to existing test files and mocks they should follow as patterns
- The test file paths they should create (from your file ownership map)

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
> - For phases that extend existing modules, some tests may pass against current
>   code — that's fine. The key tests (new functionality) must fail.
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
> Commit with message: `phase-XX: TDD tests (red)`
> Run the tests and report which ones fail and WHY they fail.

### Agent 1b: Doc Engineer (Early)

Spawn with `subagent_type: "general-purpose"`. Include in the prompt:

- The full phase document content
- Current state of `config/proxy.yml`, `docs/REDIS_SCHEMA.md`, `CHANGELOG.md`
- The doc file paths they should create/update (from your file ownership map)

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
>
> Commit with message: `phase-XX: doc scaffolding (early)`
> Report what you created and what needs to be finalized after implementation.

### PM: After Wave 1 completes

When both agents return:

1. **Collect outputs.** Read the test files and doc scaffolding they created.
2. **Check for conflicts.** If both touched the same file (shouldn't happen with
   good ownership mapping), merge manually preserving all content.
3. **Prepare the Coder brief.** Summarize:
   - Which test files exist and what contracts they define
   - What config keys were scaffolded and their defaults
   - What Redis keys were documented
4. **Prepare the Doc Engineer (late) brief.** Note what was left as TODO.
5. **Commit any merge fixes.**

---

## Step 2 — Wave 2: Coder

The Coder runs alone — Doc Engineer (late) waits for the Coder's output.

### Agent 2a: Coder (Implementation Engineer)

Spawn with `subagent_type: "general-purpose"`. Include in the prompt:

- The full phase document content
- The test file contents (paste them or list paths — the agent can read them)
- The config keys that were scaffolded
- The source file paths they should create/modify (from ownership map)

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
> - Never hardcode secrets. Use environment variables per CLAUDE.md conventions.
>
> **After implementation:**
> - Run all tests. Fix until green.
> - Run `ruff check .` / `gofmt -l . && go vet ./...`. Fix all issues.
> - Commit per logical component: `phase-XX: implement <component>`
>
> Report: which tests now pass, any design decisions you made, any new
> function signatures / metric names / config keys the Doc Engineer needs.

### PM: After Wave 2 completes

1. **Read the Coder's report.** Note any design decisions or new interfaces.
2. **Verify tests pass:** run `make test-unit` yourself.
3. **Prepare the Doc Engineer (late) brief** with the Coder's actual output:
   function signatures, metric names, config keys, design decisions.

---

## Step 3 — Wave 3: Doc Engineer (Late)

The Doc Engineer (late) runs after the Coder so it can verify against real
implementation, not guesses.

### Agent 3: Doc Engineer (Late)

Spawn with `subagent_type: "general-purpose"`. Include in the prompt:

- What was created in the early pass and what was left as TODO
- The Coder's report: new function signatures, metric names, config keys, design decisions
- The phase document for reference
- Observability standards from `docs/OBSERVABILITY_STANDARDS.md`

**Their instructions:**

> You are a Documentation Engineer doing the late-phase pass. The early
> scaffolding is already in place. The implementation is now complete.
> Your job is to finalize everything using actual implementation details.
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
>
> Commit with message: `phase-XX: documentation (final)`
> Report what was finalized and any concerns about implementation accuracy.

### PM: After Wave 3 completes

1. **Verify docs are consistent with implementation.**
2. **Prepare the QA brief.** Summarize:
   - What was implemented and where
   - What design decisions were made
   - What the Coder flagged as tricky or uncertain
   - Full list of acceptance criteria for walkthrough

---

## Step 4 — Wave 4: QA Engineer

This runs **sequentially** — QA needs the complete codebase with docs.

### Agent 4: QA Engineer

Spawn with `subagent_type: "general-purpose"`.

**Their instructions:**

> You are a QA Engineer. You break things. You find gaps between what was
> intended, what was built, and what was tested. You are adversarial but
> constructive.
>
> **Phase XX acceptance criteria:** [paste them]
> **Implementation files:** [list paths]
> **Test files:** [list paths]
> **Design decisions made by the Coder:** [paste summary]
>
> **Your audit:**
>
> 1. **Test coverage:** Run tests with coverage. Identify untested paths.
>    Check test-to-code ratio (target ~1.3x). Verify no test is trivially
>    passing (mocks returning exactly what's asserted).
> 2. **Test strength:** For each test, ask: "would this fail if the
>    implementation were wrong?" If not, strengthen or rewrite it.
> 3. **Integration:** Run `make test` (full gate, not just unit) — all existing tests must still pass.
>    Check that bypasses, scoring, and action logic are unaffected.
> 4. **Config abuse:** Set each new config key to invalid values — verify
>    graceful handling. Remove keys — verify defaults apply.
> 5. **Edge cases:** IPv6 everywhere, empty/null/missing values, concurrent
>    access to shared state, Redis unavailable during each new operation.
> 6. **Acceptance walkthrough:** Go through every criterion line by line.
>    For each: verify it's met and a test proves it. Flag any ambiguous ones.
> 7. **Chaos/resilience:** Verify chaos tests exist for every failure mode
>    and actually simulate realistic failure (not just `raise Exception`).
> 8. **Test ordering:** Run `pytest --randomly-seed=12345` to verify no hidden
>    state dependencies between tests.
>
> **Fix everything you find.** Write additional tests for gaps. Strengthen
> weak assertions. Add missing edge cases.
>
> Commit: `phase-XX: QA fixes`
>
> Report: what you found, what you fixed, what you couldn't fix (blockers),
> and your confidence level (HIGH / MEDIUM / LOW) for each acceptance criterion.

### PM: After Wave 4 completes

1. **Review QA findings.** If there are blockers, decide whether to:
   - Fix them yourself
   - Re-spawn the Coder or TDD Writer to address specific issues
   - Escalate to the user
2. **Run `make test`** to verify the full gate still passes.
3. **Proceed to the independent review.**

---

## Step 5 — Independent Critical Review (Cyber Architect)

This is a **separate, independent agent** that has NOT seen any of the work above.
It reviews from scratch. Spawn it with a clean brief — do NOT paste the other
agents' reports. Let it form its own conclusions.

### Agent 5: Expert Cyber Architect

Spawn with `subagent_type: "general-purpose"`.

**Their instructions:**

> You are an independent Expert Cyber Architect reviewing phase XX of JA4proxy.
> You have NOT been involved in the implementation. You assume nothing works
> until you verify it yourself. You are looking for what everyone else missed.
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
> - Secrets: no credentials in logs, config, errors, or Redis? Grep for hardcoded API keys, passwords, tokens.
> - Privilege: no unnecessary capabilities?
> - Supply chain: new deps pinned? CVEs checked?
> - Core asymmetry: FP still costs more than FN in all new paths?
> - Injection: no command injection, SSTI, SSRF, unsafe deserialization?
> - OWASP top 10 for web-facing surfaces.
> - Crypto: no custom crypto, proper TLS, no downgrade paths?
>
> ### B. Gap Analysis
> - Cross-reference EVERY acceptance criterion against implementation — list each
>   one with PASS/FAIL.
> - Cross-reference against `CLAUDE.md` cross-cutting requirements.
> - Check no existing functionality broken or weakened.
> - Check no existing tests deleted, weakened, or assertions relaxed.
> - Check for TODO/FIXME/HACK without tracking.
>
> ### C. Test Strength Audit
> - For each test: would it FAIL if the implementation were wrong? Prove it by
>   identifying the specific assertion that would catch a broken implementation.
> - Check for tautological tests that pass regardless.
> - Check mock fidelity — do mocks include error paths?
> - Check parametrize coverage — are edge cases present?
> - No `time.sleep()` in tests.
> - Chaos tests simulate realistic failure, not just `raise Exception`.
>
> ### D. Observability Audit
> - Every new code path emits a metric or structured log.
> - Error paths increment counters (not just log).
> - Latency paths have histograms.
> - Log levels correct: ERROR=action needed, WARN=degraded, INFO=state change.
>
> ### E. Documentation Audit
> - CHANGELOG accurate? Redis schema complete? Config keys documented?
> - Runbook updated? ADR exists for non-obvious decisions?
> - Phase doc criteria all checked off?
>
> ### F. Regression & Rollback
> - Run `make test-unit`. All pass?
> - No existing Makefile targets modified?
> - No shared files edited outside ownership rules?
> - Rollback-safe: reverting leaves system functional?
>
> ### G. Performance & Resources
> - No blocking I/O on hot path.
> - No unbounded growth (Redis keys, caches, logs).
> - Goroutines/tasks have lifecycle management.
> - No N+1 Redis patterns. Bounded hot-path allocation.
>
> ### H. IPv6 Parity
> - Every IP code path handles v4 and v6.
> - Tests include IPv6 cases.
> - Redis IP keys use canonical form.
> - CIDR: v4 /24, v6 /48.
>
> **Your verdict — one of:**
>
> **PASS** — all checks satisfied, no blocking issues.
> **PASS WITH NOTES** — minor issues, not blocking. List them.
> **FAIL** — blocking issues. For each: severity, what's wrong, specific fix.
>
> Produce a structured report with a findings table:
> | # | Finding | Severity | Audit | Status | Fix |
> |---|---------|----------|-------|--------|-----|

### PM: After Architect Review

**If PASS or PASS WITH NOTES:**
- Apply any noted minor fixes yourself.
- Proceed to Step 6 (Phase Close).

**If FAIL:**
- Triage each finding by which role should fix it.
- Re-spawn the relevant agent(s) with specific fix instructions and the
  Architect's findings. Include the exact finding text.
- After fixes, re-spawn the Architect for a **re-review** of only the failed
  items plus a regression check on the fixes.
- If the same finding fails twice: escalate to the user.

---

## Step 6 — Phase Close

Once the independent review passes:

1. Run `bash scripts/close-phase.sh` — this is the mechanical gate (ruff, gofmt,
   go vet, go test, make test, sync-roadmap). **Do not proceed until it exits 0.**
2. If `close-phase.sh` is not available, run manually:
   `make test && ruff check . && gofmt -l .` — zero failures, zero lint issues.
3. Update `docs/phases/manifest.yaml`: set `status: COMPLETE`.
4. Run `make sync` to regenerate `TODO.md` and `PROJECT_STATUS.md`.
5. Stage all changes and create a final atomic commit:
   `phase-XX: complete — <one-line summary>`
6. Run `git diff main...HEAD --stat` and present the summary to the user.
7. Ask the user if they want to push and create a PR.

---

## Orchestration Rules

### Communication Protocol
- **Agents cannot see each other.** You are the switchboard. When Agent A
  produces output that Agent B needs, you extract the relevant parts and
  include them in Agent B's prompt or send via SendMessage.
- **Keep relayed context focused.** Don't dump Agent A's entire output into
  Agent B's prompt. Extract: file paths created, interface signatures,
  design decisions, and open questions.
- **Conflict resolution:** If two parallel agents made incompatible choices
  (shouldn't happen with good file ownership), you resolve it. Prefer the
  choice that's more conservative / fail-open.

### File Ownership (Enforced Per Wave)
Before each wave, explicitly assign file ownership:
- **TDD Writer owns:** `tests/` files for this phase, `tests/mocks/` additions
- **Doc Engineer owns:** `docs/`, `CHANGELOG.md`, config file comments
- **Coder owns:** `src/`, `internal/`, `cmd/` implementation files
- **QA runs solo (Wave 4):** no ownership conflict — may modify any file, commits tagged `QA fixes`
- **No two parallel agents touch the same file in the same wave.**

### Progress Reporting
After each wave, report to the user:
- What was completed
- Any issues or decisions made
- What's next
Keep it to 3-5 lines. The user can ask for details.

### Failure Handling
- **If an agent gets stuck:** don't wait forever. If no progress after a
  reasonable effort, collect what they produced and either fix it yourself
  or re-brief a new agent with more specific instructions.
- **If tests won't go green:** check if the test contract is wrong (TDD Writer
  mistake) or the implementation is wrong (Coder mistake). Fix the right one.
- **If the Architect fails the same thing twice:** stop. Describe the problem
  to the user — it likely needs a design change, not just an implementation fix.
- **Never skip a step.** If a step produces no work (e.g., no Redis keys),
  explicitly state "Wave N, Agent X: nothing to do" and move on.
- **Time budget:** if the phase has >20 sub-tasks, suggest splitting before starting.
