# JA4proxy Agent Protocol

This document defines the mandatory operational standards for AI agents working on the JA4proxy project. Adherence to these rules ensures architectural consistency, security, and a high-quality handoff for human developers.

---

## 📋 Mandatory Planning Protocol — Read Before Doing Anything

**When asked to perform any work — new feature, bug fix, refactor, or investigation — the agent MUST follow this sequence. No exceptions.**

### Step 1 — Write the plan first

Before writing a single line of code or running any mutating command:

1. Determine the correct phase number (check `docs/phases/manifest.yaml` for the next available number).
2. Create the phase document at `docs/phases/PHASE_XX.md` using the standard template:
   - **Goal** — one-paragraph summary of what is being built and why.
   - **Scope** — exact list of files to be created or modified.
   - **Implementation plan** — numbered steps in the order they will be executed.
   - **Test strategy** — which test categories are needed and what they verify.
   - **Acceptance criteria** — explicit, checkable conditions that define "done".
   - **Out of scope** — explicit list of things this phase will NOT touch.
3. Present the plan to the user with a brief summary: *"Here is the plan — please review before I begin."*

### Step 2 — Wait for explicit approval

Do **not** proceed until the user gives a clear go-ahead (e.g., "looks good", "proceed", "yes").

If the user requests changes to the plan, update `PHASE_XX.md` and re-present it. Repeat until approved.

### Step 3 — Implement

Only after written approval: create the branch, write code, write tests, and follow the Phase Close-Out Checklist.

### Why this matters

Code written before a plan is reviewed tends to drift from intent, require rewrites, and accumulate technical debt. The plan document is the contract between the agent and the user. Starting with code instead of a plan is the single most common source of rework on this project.

> **Exception:** If the user explicitly says "just do it, no plan needed" or "skip the plan", proceed directly to implementation. Record this waiver in the phase notes.

---

## 🛠️ Tool Usage & Communication

- **Bash Tool:** Use only the `command` field — do not include `description`. This triggers validation errors in opencode (another agent that works on this repo).
- **High-Signal Output:** Adopt a Senior Engineer persona. Be concise, direct, and technical. Avoid conversational filler, apologies, or "I will now..." preambles.
- **Explain Before Acting:** Briefly explain the intent and potential impact of any command that modifies the filesystem or system state.
- **Efficiency:** Parallelize independent searches (`Grep`, `Glob`) and file reads to minimize turn overhead.

---

## Roadmap & Task Management

The project uses a **Manifest-Driven Roadmap** to prevent documentation drift.

- **Single source of truth for phase status:** `docs/phases/manifest.yaml` — nowhere else.
- **Synchronization:** Run `python3 scripts/sync-roadmap.py` after any change to the manifest. This regenerates `docs/phases/TODO.md` and `docs/PROJECT_STATUS.md`.
- **Validation:** Run `python3 scripts/lint-phases.py` (or `make lint-phases`) to catch broken action_plan paths, stale phase numbers in headings, and invalid status values. Must exit 0 before any phase-closeout commit.

> **Note:** The Phase Index table in `CLAUDE.md` is a static reference summary and is **not actively maintained**. For current phase status always read `docs/phases/manifest.yaml` or `docs/phases/TODO.md`.

### Phase Documentation Rules (read before creating or renaming phase docs)

These rules exist so that renaming a phase never requires editing file content — only the filename and the manifest entry.

**Rule 1 — Phase number lives in the FILENAME only.**
H1 headings must contain the phase title, NOT the phase number:
```markdown
# Backup System Enhancements - Phase 1: Core Features    ✓  (title only)
# Phase 22: Backup System Enhancements - Phase 1...      ✗  (number in heading = will go stale)
```

**Rule 2 — Status lives in `docs/phases/manifest.yaml` only.**
Do NOT include a `Status:` line in phase doc files. If an existing doc has one, ignore it — trust the manifest.

**Rule 3 — Sub-task labels use letters, not `NNa`/`NNb`.**
```markdown
### A — List Management UI     ✓
### 52a — List Management UI   ✗  (stale when renumbered)
```

**Rule 4 — To rename/renumber a phase:**
1. Rename the file (e.g. `PHASE_45.md` → `PHASE_52.md`)
2. Update `action_plan:` in `docs/phases/manifest.yaml`
3. Run `make lint-phases` — must exit 0
4. No content edits needed (because the number isn't in the content)

### Phase Close-Out Checklist (mandatory — run in order, do not skip steps)

Every phase must be closed by completing **all** of the following before the next phase begins:

1. **Tests pass:** `make test` — zero failures, zero warnings.
2. **Go tests pass:** `make go-test` — zero failures. Required for any phase that touches Go source.
3. **CHANGELOG.md:** Add a standard entry for the phase (see `docs/DOCUMENTATION_STANDARDS.md`).
4. **REDIS_SCHEMA.md:** Document every new Redis key introduced.
5. **Signal scores:** If the phase adds or changes any signal score value, run `make check-scores` — must exit 0. This verifies both Python and Go implementations match `config/signal_scores.yml`.
6. **Parity check:** If the phase affects connection scoring or pipeline decisions, run `make parity-check` (requires both proxies running). Must exit 0. See *Go/Python Proxy Parity* section below.
7. **docs/phases/manifest.yaml:** Set `status: COMPLETE`, add `completed: YYYY-MM-DD`. Remove resolved gaps. Add new gaps to appropriate future phases.
8. **Phase doc hygiene:** If the phase doc (`docs/phases/PHASE_XX.md`) contains a `## Status:` line, **remove it** — status belongs only in the manifest (Rule 2). This line going stale is a common source of confusion between agents.
9. **Sync:** Run `python3 scripts/sync-roadmap.py` to regenerate `docs/phases/TODO.md` and `docs/PROJECT_STATUS.md`.
10. **Lint:** Run `make lint-phases` — must exit 0. Fix any violations before continuing.
11. **Atomic commit:** Commit code, `CHANGELOG.md`, `docs/phases/manifest.yaml`, `docs/phases/TODO.md`, `docs/PROJECT_STATUS.md`, and the phase doc together in a single commit.

> **Why this matters:** `docs/phases/manifest.yaml` is the only document downstream tooling reads. If it is not updated at phase-close, `docs/phases/TODO.md` and `docs/PROJECT_STATUS.md` will show stale state, and future sessions will have incorrect context about what work remains.

---

## Git & Version Control

- **Atomic Commits:** One commit per phase or logical sub-task. Do not bundle unrelated refactors with feature work.
- **Commit Preparation:** Always run `git status && git diff HEAD` to review changes before committing.
- **Commit Messages:**
  - Propose a draft message before executing the commit.
  - Follow the format: `type(scope): brief description` (e.g., `feat(security): add JA4X fingerprinting`).
  - Focus on **why** a change was made, not just **what** changed.
- **Pushing:** Push only when a phase is fully complete and all close-out checklist items pass (`git push origin claude/phase-XX-description`). Do not push mid-phase or for speculative work. The orchestrator handles merging to `main` — never push directly there.

---

## Testing, Linting & Validation (TDD)

- **Test-First:** Always search for existing tests before modifying code. If a bug is reported, reproduce it with a new test case first.
- **Zero-Tolerance Policy:**
  - **No Skips:** No tests may be skipped (`@pytest.mark.skip`) without explicit, manual approval.
  - **No Warnings:** All tests and builds must pass with **zero warnings, zero errors, and zero failures**.
  - **Linting as Testing:** All linting must pass with zero warnings.
- **Approved Exception Workflow:**
  1. **Identify:** Present a technical justification for any unavoidable skip or warning.
  2. **Approve:** Obtain explicit user approval in the session history.
  3. **Log:** Record the exception in `docs/security/EXCEPTIONS.md` with a unique ID (e.g., `#001`).
  4. **Annotate:** Code-level suppressions MUST include a comment referencing the ID:
     - Python: `# Approved Exception #001: see docs/security/EXCEPTIONS.md`
     - Go: `// Approved Exception #001: see docs/security/EXCEPTIONS.md`
- **Mandatory Coverage:** A change is incomplete without corresponding tests (Unit, Integration, and Chaos).
- **Finality:** A task is only "Done" when the relevant test suite and linters pass 100% using the project `Makefile`.

### Web service TDD — two mandatory test categories

Both failures below reached production because they were absent from the initial test suite. Every web service agent must include them.

#### 1. HTML page rendering tests (catches framework API mismatches)

Every route that returns HTML **must** have a test that:
- GETs the route with a valid auth token and asserts `status_code == 200`
- Asserts `"text/html"` in `Content-Type`
- Asserts at least one landmark string is in `response.text`
- GETs the route *without* a token and asserts `status_code < 500`

**Why:** The Starlette `TemplateResponse` API changed between versions (`TemplateResponse(name, context)` → `TemplateResponse(request, name, context)`). A test that only checked redirect behavior (401) on page routes never executed the template rendering path. The mismatch was invisible until the container ran against a real Starlette version.

Pattern (copy into every `test_pages.py`):
```python
async def test_login_page_renders(test_client):
    r = await test_client.get("/login")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "JA4" in r.text  # landmark string

async def test_dashboard_renders(authenticated_client):
    r = await authenticated_client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]

async def test_unauthenticated_never_500(test_client):
    r = await test_client.get("/")
    assert r.status_code < 500  # 401 ok, 500 = crash before auth ran
```

#### 2. Container configuration parity tests (catches env var mismatches)

Every service that connects to an external dependency (Redis, DB, etc.) **must** have a test that:
- Reads `docker-compose.poc.yml` (or the relevant compose file) and verifies that the compose env section passes the correct connection string format
- Verifies that when a password env var is set, the built connection URL actually contains it

**Why:** fakeredis requires no password, so unit tests passed 67/67 while the real container connected to password-protected Redis with a bare `redis://redis:6379/0` URL and got `AuthenticationError` at runtime.

Pattern (copy into every `test_container_config.py`):
```python
def test_docker_compose_redis_url_includes_password():
    with open("docker-compose.poc.yml") as f:
        content = f.read()
    service_section = content[content.find("  myservice:"):][:1500]
    url_match = re.search(r"REDIS_URL=([^\n]+)", service_section)
    assert url_match, "REDIS_URL not found in service definition"
    assert "REDIS_PASSWORD" in url_match.group(1), (
        "REDIS_URL must include ${REDIS_PASSWORD}. "
        "fakeredis doesn't need auth — real Redis does."
    )
```

### What `make test` actually checks — read ALL of it

`make test` runs four static-analysis tools **before** pytest. A task is not done until
every section shows a green tick:

```
✓ mypy: OK
✓ bandit: OK
✓ ruff: OK
✓ pip-audit: OK
... 2700+ passed, N skipped (all approved), 0 failed
```

Any `✗` or `[!]` is a blocking failure. Do not declare a phase complete, and do not
commit, until all four tools and pytest are clean.

### ProxyServer test-stub maintenance

`ProxyServer` stubs bypass `__init__` via `object.__new__`. Whenever any code adds a
new instance attribute used in `start()`, `handle_connection()`, or `create()`, **all
four stubs must be updated in the same commit**:

| File | Helper |
|------|--------|
| `tests/unit/test_graceful_shutdown.py` | `_make_server_stub()` |
| `tests/unit/test_proxy_remaining.py` | `_make_server_stub()` (top-level) |
| `tests/unit/test_proxy_remaining.py` | `TestProxyServerShutdownCoverageGaps._make_server_stub()` |
| `tests/unit/test_proxy_server.py` | `_make_server()` |
| `tests/integration/test_pipeline.py` | `_make_shutdown_server_stub()` |

**Before referencing `self._foo` in new proxy.py code**, grep to confirm the attribute
exists in `__init__`:

```bash
grep -n "self\._foo" proxy.py
```

Never invent attribute names (e.g. `self._session`) that differ from what `__init__`
actually sets (e.g. `self._aiohttp_session`).

### New source files — import hygiene

Every new `.py` file must pass ruff immediately. After creating a file run:

```bash
python3 -m ruff check --select I001 --fix <file>
python3 -m mypy <file>
```

Every new `.go` file must pass vet immediately. After creating a file run:

```bash
GOROOT=/snap/go/current go vet ./...
```

Fix all issues before committing.

---

## Go/Python Proxy Parity

The project maintains two complete proxy implementations that must produce identical
decisions for identical inputs. Three permanent tools enforce this:

### Signal score registry (`config/signal_scores.yml`)

This file is the **single authoritative source** for every signal score value used by
either proxy. When adding or changing a signal:

1. Update `config/signal_scores.yml` first — this is the spec.
2. Implement in Python (`src/security/`) matching the registry value exactly.
3. Implement in Go (`internal/security/`) matching the registry value exactly.
4. Run `make check-scores` — must exit 0 before committing.

Never hardcode a score in either proxy without a corresponding entry in the registry.
If `make check-scores` reports drift, fix the code — do not adjust the registry to
match wrong code.

### Binary ClientHello fixtures (`tests/fixtures/clienthello/`)

These `.bin` files are the ground truth for JA4 fingerprint computation. The expected
fingerprint for each file is in `tests/fixtures/clienthello/README.md`.

- Both Python and Go test suites assert `parse(fixture) == expected_ja4`.
- If you change JA4 computation in either proxy, update README.md with the new
  expected values and confirm both suites pass.
- To capture new fixtures: `python3 scripts/capture_clienthello.py`

### Live parity harness (`make parity-check`)

Sends synthetic traffic through both proxies and compares `(action, score)` pairs.
Required in the close-out checklist for any phase that touches scoring or pipeline
logic. Both proxies must be running (`make go-start` + `make start`).

### When adding a new signal module

A new signal in one proxy requires a corresponding implementation in the other before
the phase can be marked COMPLETE. If there is a genuine reason to skip the Go port
(e.g., the signal is Python-only analytics), create an explicit gap in the manifest:

```yaml
gaps:
  - "Go: <signal_name> not yet ported (see Phase NNN)"
```

A phase with an unresolved Go parity gap may not be marked COMPLETE.

### GOROOT environment note

The snap Go installation sets `GOROOT=/usr/share/go` which does not exist on this host.
All `go` commands require:

```bash
GOROOT=/snap/go/current go build ./...
GOROOT=/snap/go/current go test ./...
```

Or add `export GOROOT=/snap/go/current` to `~/.bashrc` to set it permanently.

---

## Build & Compilation

- **Strict Compilation:** All compiled code (Go, etc.) must compile with the equivalent of `-Wall` (all warnings enabled).
- **Zero-Warning Build:** The build process must produce **zero warnings**. Any compiler warning is a blocking failure that must be resolved before the code is considered valid.

---

## Security & Coding Standards (Phase 18 Alignment)

- **Logging:** **Never use f-strings or `.format()` in logging calls.** Use lazy formatting to prevent overhead and accidental data exposure.
  - `logger.info("Connection from %s", ip)`  (correct)
  - `logger.info(f"Connection from {ip}")`   (wrong)
- **Exception Handling:** **Never use broad `except Exception:` blocks.**
  - Catch specific exceptions (e.g., `redis.ConnectionError`, `aiohttp.ClientError`).
  - Implement "Fail-Open" for enrichment: if an external API/Redis fails, log a WARNING, increment a counter, and allow the connection without that specific signal.
- **Secrets:** Never log, print, or commit API keys, Redis passwords, or TLS private keys. Check `.env.example` for required variables.
- **Naming:** Follow `docs/STYLE_GUIDE.md` strictly (e.g., `PascalCase` for classes, `snake_case` for metrics with `ja4proxy_` prefix).

---

## Documentation Maintenance

Every phase completion requires updating the following (per `docs/DOCUMENTATION_STANDARDS.md`):

1.  **CHANGELOG.md:** Standard entry under the correct version/phase.
2.  **docs/REDIS_SCHEMA.md:** Document every new key, its type, TTL, and owner.
3.  **README.md:** Update the "Security Pipeline" or "Services" tables if architecture changed.
4.  **ADRs:** Create a new Architectural Decision Record in `docs/decisions/` for any non-obvious design choices (e.g., choosing a specific library or algorithm).

---

## Strategic Review Protocol

To prevent technical myopia and ensure enterprise-readiness, the project maintains a **Multi-Role Critique** log.

- **Source of Truth:** `docs/GEMINI_CRITIQUE.md`
- **Execution:** At the end of every major **Epic** or **Phase**, the agent must perform a holistic review from these specific perspectives:
  - **CEO:** Market fit, time-to-value, and strategic roadblocks.
  - **CTO:** Scalability, tech debt, and long-term architecture (e.g., K8s operators).
  - **QA:** Environmental stability, deterministic testing, and stateful regression.
  - **Pentester:** Attack surface, bypass risks (e.g., Proxy-protocol spoofing), and forgery resilience.
  - **Compliance:** Privacy by design (GDPR), DSAR capabilities, and audit integrity.
- **Triage:** Actionable findings from the critique MUST be triaged into `docs/phases/manifest.yaml` as new **Gaps** or **Tasks** before the phase is considered complete.

---

## Project Context Hierarchy


If instructions conflict, use this priority:
1.  **User Hints** (Directives in the current session)
2.  **docs/phases/PHASE_XX.md** (Current phase mandate)
3.  **AGENTS.md** (This document)
4.  **CLAUDE.md** (Project-wide architecture and cross-cutting rules)
5.  **docs/STYLE_GUIDE.md** / **docs/DOCUMENTATION_STANDARDS.md**
6.  **General System Prompt**
