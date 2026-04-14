# Phase Document Style Guide

This guide defines the format and conventions for all files in `docs/phases/`.
Read this before creating or editing a phase document.

---

## Naming

Files are named `PHASE_NN.md` where `NN` is zero-padded to two digits:
`PHASE_00.md`, `PHASE_01.md`, ..., `PHASE_16.md`, `PHASE_17.md`.

Sub-documents for large phases that were split mid-implementation use a suffix:
`PHASE_04A.md`, `PHASE_05A.md`. Prefer keeping a phase in one file; only split
when an in-progress phase grows beyond ~500 lines of substantive content.

---

## Title Line

```markdown
# PHASE NN — Short Descriptive Title
```

Use an em-dash (`—`) with a space on each side. Use title case. Keep it to one
line. Do not include a version number or date. Do not use emoji in the title.

**Feature phases** (adding new capability):

```markdown
# PHASE 09 — Beaconing Detection
# PHASE 10 — AbuseIPDB Integration
# PHASE 16 — Test Suite Hardening, Extended Fingerprinting & Operational Excellence
```

**Bug-fix / infrastructure phases** (no new features):

```markdown
# PHASE 17 — Fix Docker Test Container Hang
# PHASE 18 — Security Audit & Code Quality Remediation
```

---

## Status Line

The second element is always a status line:

```markdown
## Status: OPEN
```

Valid statuses:

| Status | Meaning |
|--------|---------|
| `OPEN` | Not started or in progress |
| `COMPLETE` | All acceptance criteria checked off |
| `BLOCKED` | Cannot proceed until a dependency is resolved |

Follow the status line with `---`.

Feature phases written before implementation begins may omit the status line
(the older phases 0–16 predate this convention). New phases from 17 onwards
include it.

---

## Top-Level Structure

The overall shape of a phase document:

```markdown
# PHASE NN — Title

## Status: OPEN

---

## Goal              ← one paragraph, why this phase exists

---

## NNa. First Section
## NNb. Second Section
## NNc. Third Section

---

## Acceptance Criteria   ← always present, always last substantive section

---

## Files to Modify       ← table of file → change

---

## Notes for Implementer ← optional, for caveats and gotchas
```

---

## The Goal Section

One to four sentences. Explain **why** this phase exists, not what it does.
Answer: what problem does it solve? What is the system state before and after?

```markdown
## Goal

Detect Command-and-Control beacon patterns by analysing the timing of connections
from the same IP+JA4 fingerprint pair. Malware beacons home at regular intervals
with remarkably consistent timing. Human browsing is irregular. This distinction
is measurable purely from connection timestamps — no content inspection required.
```

For bug-fix phases, the goal states the symptom and the target outcome:

```markdown
## Goal

`make test` shows all 1174 tests passing but the Docker container hangs for ~265s
until `timeout 300` kills it, reporting `Passed: 0`. This phase fixes the hang
and ensures the exit code and reported counts are accurate.
```

Do not put implementation details in the Goal. Those go in the numbered sections.

---

## Numbered Sections

Major work items are numbered using the phase prefix:

```
## 9a. Module: `src/security/beaconing_detector.py`
## 9b. Redis Schema
## 9c. Pipeline Integration
## 9d. Tests
```

Use lower-case letters (`a`, `b`, `c`, ...). The phase number and letter together
form a unique cross-reference (e.g. "see 9b" from another doc is unambiguous).

Each section has:
- A **problem statement** (what is wrong or missing, or what capability is needed)
- An **implementation description** (how to build it)
- Code examples where the exact shape of the implementation matters

For bug-fix phases, sections can be labelled by fix number:

```
## 1. Add PYTHONUNBUFFERED
## 2. Patch `_tor_refresh_loop`
## 3. Change hook to `tryfirst=True`
```

For audit/quality phases, sections can be labelled by finding:

```
## 18a. Exception Handling
## 18b. Logging Format
## 18c. Function Complexity
```

Each finding section should have a **Finding** subsection (what the problem is,
with evidence) and a **Fix** subsection (what to change, with before/after code):

```markdown
## 18b. Logging Format

### Finding

Several logging calls use f-string formatting...

### Fix

Replace all f-string logging calls with lazy formatting...
```

---

## Code Blocks

Use fenced code blocks with a language hint:

````markdown
```python
def coefficient_of_variation(values: list[float]) -> float:
    ...
```

```yaml
environment:
  - PYTHONUNBUFFERED=1
```

```
redis key: beacon:{ip}:{ja4}
```
````

Use plain (no language) fenced blocks for file trees, command output, and Redis
key schemas. Use `python`, `yaml`, `dockerfile`, `makefile`, `go`, `bash` as
appropriate.

Before/after comparisons use two consecutive code blocks with a comment label:

```python
# Before
@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus): ...

# After
@pytest.hookimpl(tryfirst=True)
def pytest_sessionfinish(session, exitstatus): ...
```

Or a comment inside the block:

```python
with patch(
    "src.security.asn_classifier.ASNClassifier._refresh_tor_list",
    new=_noop,
), patch(
    # NEW: also patch the background loop so no tasks are orphaned
    "src.security.asn_classifier.ASNClassifier._tor_refresh_loop",
    new=_noop,
):
    yield
```

---

## Tables

Use tables for:
- Files to modify
- Redis key schemas
- Acceptance criteria that benefit from a structured view
- Configuration keys with descriptions

```markdown
| File | Change |
|------|--------|
| `deploy/docker/Dockerfile.test` | Add `ENV PYTHONUNBUFFERED=1` |
| `tests/conftest.py` | Patch `_tor_refresh_loop` → `_noop` |
```

Keep table cells short. If a cell needs more than one sentence, pull the detail
into the surrounding prose or a sub-section.

---

## Acceptance Criteria

Every phase document must have an `## Acceptance Criteria` section with
checkbox-style items. Items must be specific and testable — not aspirational:

```markdown
## Acceptance Criteria

- [ ] `time make test` completes in ≤ 60s
- [ ] Results file contains "1174 passed" summary line
- [ ] Exit code from `make test` is 0
- [ ] No tests change from PASSED to FAILED
```

Bad (too vague):

```markdown
- [ ] Performance is improved
- [ ] Code is cleaner
- [ ] Security is better
```

When a criterion involves a specific command, include the command:

```markdown
- [ ] `bandit -r src -ll` reports zero high/medium findings
- [ ] `pylint src --fail-under=8.0` passes
```

When a criterion involves a metric or threshold, state the number:

```markdown
- [ ] FP rate on Tranco top-10k domains is ≤ 1%
- [ ] Beacon detection latency adds ≤ 5ms to the hot path (p99)
```

Check off items by replacing `- [ ]` with `- [x]` as they are completed. When
all items are checked, update the Status line to `COMPLETE`.

---

## Files to Modify

After Acceptance Criteria, include a two-column table of every file that the
phase touches:

```markdown
## Files to Modify

| File | Change |
|------|--------|
| `src/security/beaconing_detector.py` | New file — BeaconingDetector class |
| `src/security/pipeline.py` | Wire BeaconingDetector into `_collect_signals()` |
| `config/proxy.yml` | Add `beaconing:` config section |
| `tests/unit/security/test_beaconing_detector.py` | New file — unit tests |
| `tests/chaos/test_beaconing_chaos.py` | New file — resilience tests |
| `docs/REDIS_SCHEMA.md` | Document `beacon:{ip}:{ja4}` key |
| `CHANGELOG.md` | Add Phase 9 entry |
```

List test files. List documentation files. If a file is new, say "New file —".
If an existing file is modified, describe the modification concisely.

---

## "What Was Already Tried" Section

For bug-fix phases where earlier attempts failed, include a table of failed
approaches before the fix details. This prevents re-attempting the same dead ends:

```markdown
## What Was Already Tried (and why it did not work)

| Attempt | Why it failed |
|---------|---------------|
| `pytest_sessionfinish(trylast=True)` + `os._exit()` | Hook never reached — hang occurs before session-finish hooks fire |
```

---

## Notes for Implementer

Optional last section. Use for caveats that don't fit elsewhere:
- Interactions with other phases or components
- Things that must NOT be done (and why)
- Tests that are intentionally unaffected by a change
- Future extension points

```markdown
## Notes for Implementer

- Chaos tests that specifically test `_tor_refresh_loop` behaviour patch the method
  themselves via `patch.object(instance, ...)` — they are unaffected by the
  session-level patch.
- Do **not** add `pyproject.toml` to the Docker image. It would change asyncio_mode
  from STRICT to AUTO and could mask test failures.
```

Use `**bold**` sparingly — only for genuine warnings ("do NOT", "never").

---

## Prose Style

**Direct and developer-facing.** Write for the implementer who will read this doc
once and then go write code. Not for a manager, not for a committee review.

- Use active voice. "Add X to Y" not "X should be added to Y".
- State facts. "The hook never fires" not "The hook may not fire in some cases".
- One idea per paragraph.
- Short paragraphs. Three to five sentences is usually enough.
- No filler. Skip "In order to", "It is important to note that", "As mentioned above".

**Avoid:**
- Emoji anywhere in the document
- Corporate/PM language: "Owner", "Effort estimate", "Resources Required",
  "Executive Summary", "Stakeholders"
- Risk matrices, CVSS scores, likelihood × impact tables — these belong in a
  separate security audit document, not a phase doc
- Numbered "Tasks" with sub-bullets — use sections instead
- "Phase 1, Phase 2, Phase 3" for internal sub-phases — use the `NNa`, `NNb`
  pattern to avoid confusion with the project phase numbering

**Tense:**
- Problem descriptions: present tense ("The hook never fires")
- Fix descriptions: imperative ("Change `trylast=True` to `tryfirst=True`")
- Acceptance criteria: imperative or declarative ("completes in ≤ 60s",
  "`bandit` reports zero findings")

---

## Cross-References

Reference other phase docs by filename:

```markdown
See PHASE_17.md Notes for Implementer.
This builds on the Redis schema established in PHASE_00.md.
```

Reference sections within a phase doc using their number:

```markdown
Do 16a–16e first — they unblock accurate coverage measurement for 16f–16k.
```

Reference project-wide docs by path:

```markdown
Read `docs/TEST_ORGANIZATION.md §10` before starting.
See `docs/OBSERVABILITY_STANDARDS.md` for the full metric naming spec.
```

---

## What Does Not Belong in a Phase Document

| Content | Where it belongs |
|---------|-----------------|
| API reference docs | `docs/` or inline docstrings |
| Redis key schema | `docs/REDIS_SCHEMA.md` |
| Prometheus metric registry | `docs/OBSERVABILITY_STANDARDS.md` |
| Runbook instructions | `docs/runbooks/` |
| Architecture decision rationale | `docs/decisions/ADR-NNN.md` |
| CHANGELOG entry | `CHANGELOG.md` |
| Ongoing monitoring notes | `docs/OBSERVABILITY_STANDARDS.md` |
| Security policy | `docs/security/` |

Phase docs describe **what to build and how to verify it**. Everything else lives
in the appropriate supporting document.
