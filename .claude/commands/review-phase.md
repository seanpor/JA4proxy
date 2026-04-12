# Review Phase

Perform a comprehensive cybersecurity / DevOps / SRE / architect critical review of a
phase document, then decompose it into small, junior-engineer-ready sub-tasks.

**Input:** The user provides a phase number or path to a phase document.

**See also:** After this review, use `/run-phase XX` to execute the implementation
with a parallel agent team.

## Step 1 — Load Context

1. Read `CLAUDE.md` (project rules, core asymmetry, cross-cutting requirements).
2. Read the target phase document (`docs/phases/PHASE_XX.md`).
   - If the phase doc does not exist, **stop**. Per the Mandatory Planning Protocol
     in `AGENTS.md`, the phase doc must be created and reviewed by the user before
     any work begins. Tell the user and abort.
3. Read `docs/phases/manifest.yaml` to understand phase status and dependencies.
   - Check that all prerequisite phases (dependencies) have `status: COMPLETE`.
     If not, warn the user and list which prerequisites are incomplete.
4. Read `config/proxy.yml` to understand current config surface.
5. Read `docs/OBSERVABILITY_STANDARDS.md` for metric/log/alert conventions.
6. Skim related source files referenced in the phase doc.
7. Determine whether this phase targets **Go (production)** or **Python (prototype)**
   per CLAUDE.md: "Default to the Go side. Touch the Python side only when the task
   explicitly involves prototyping." This determination governs all review lenses.

## Step 2 — Critical Review (Six Lenses)

Produce a structured review covering each lens. For each, list specific findings
(not generic advice). Reference file paths and line numbers where relevant.

### 2a. Security Review
- Threat model: what attack surfaces does this phase introduce or modify?
- Input validation: are all external inputs (network, config, API) validated?
- Secrets handling: any risk of credential leakage in logs, config, or Redis?
- Hardcoded secrets: grep for API keys, passwords, tokens, connection strings in code.
- Privilege: does any component run with more privilege than needed?
- Supply chain: any new dependencies? Are they pinned and audited?
- Does the phase respect the core asymmetry (false positives cost more than false negatives)?
- OWASP top 10 applicability for any web-facing components.

### 2b. DevOps Review
- Build & deploy: any changes to Docker, Compose, Helm, CI/CD pipelines?
- Configuration: are new config keys documented, hot-reloadable, with safe defaults?
- Rollback: can this change be rolled back without data loss?
- Feature flags: should this be behind a toggle for gradual rollout?
- Resource requirements: CPU, memory, disk, network implications?

### 2c. SRE Review
- Observability: are new Prometheus metrics, log lines, and alerts defined?
- Failure modes: what breaks if Redis is down? If an external API times out?
- SLI/SLO impact: does this affect latency, error rate, or availability?
- Capacity: any new Redis keys, streams, or storage that could grow unbounded?
- Graceful degradation: does the fail-open principle hold for all new paths?
- Runbook: does the operations team need new procedures? Check `docs/runbooks/`.

### 2d. Architecture Review
- Does this fit the existing pipeline (TCP accept → bypass → signals → scorer → action)?
- Interface boundaries: are new modules cleanly separated?
- Data flow: any new coupling between components?
- Concurrency: any shared state, race conditions, or hot-path blocking?
- IPv6: does every IP-touching path handle both v4 and v6?
- Redis schema: are new keys documented in `docs/REDIS_SCHEMA.md`?

### 2e. Testing Review
- Are all acceptance criteria testable and unambiguous?
- Which test categories are needed (unit, integration, chaos, adversarial, FP corpus, perf, E2E)?
- Are external services properly mocked?
- For web phases: are `test_pages.py` and `test_container_config.py` needed?
- Is the ~1.3x test-to-code ratio achievable? (Check current: `make test-ratio`)

### 2f. Documentation Review
- CHANGELOG entry format correct?
- Redis schema updates needed?
- Runbook updates needed?
- ADR needed for any non-obvious decisions?
- Phase doc itself: are acceptance criteria SMART (Specific, Measurable, Achievable, Relevant, Time-bound)?

## Step 3 — Risk Summary

Produce a table:

| # | Finding | Severity | Lens | Recommendation |
|---|---------|----------|------|----------------|

Severity: CRITICAL / HIGH / MEDIUM / LOW / INFO

## Step 4 — Decompose into Junior-Engineer Sub-Tasks

Break the phase into sub-tasks that meet ALL of these criteria:

- **Small:** 1-4 hours of work each, max. A junior engineer should be able to
  complete one in a single focused session.
- **Self-contained:** each sub-task has a clear input, output, and done condition.
  No ambiguity about what "done" looks like.
- **Ordered:** number them in dependency order. Mark which can run in parallel.
- **Safe:** a junior engineer cannot accidentally break production by completing
  any single sub-task, even incorrectly.
- **Testable:** each sub-task includes its own test criteria.

For each sub-task, produce:

```
### Sub-task N.M: <title>
**Size:** XS / S (hours estimate)
**Depends on:** N.K (or "none")
**Parallel with:** N.J, N.L (or "none")
**Files to touch:** list of specific files
**What to do:** 2-5 bullet points, specific enough that someone unfamiliar with
the codebase can follow them after reading the referenced files.
**Done when:**
- [ ] specific, checkable acceptance criterion
- [ ] specific test that must pass
**Watch out for:** 1-2 gotchas from the critical review above
```

Group sub-tasks into phases:
1. **Scaffolding** — config keys, types, interfaces, empty test files
2. **Core logic** — the actual implementation, one concern per sub-task
3. **Testing** — unit tests, integration tests, chaos tests
4. **Wiring** — connecting to the pipeline, Docker/Compose, Makefile targets
5. **Hardening** — edge cases from the security/SRE review
6. **Documentation** — CHANGELOG, Redis schema, runbook, ADR

## Step 5 — Output Format

Present the full review as a single document with clear markdown headers.
End with a summary: total sub-task count, estimated total hours, critical
blockers that must be resolved before any implementation begins.

Always write the review to `docs/phases/PHASE_XX_review.md` so that `/run-phase`
can pick it up automatically. Also print a summary in the conversation.
