# JA4proxy Agent Protocol

This document defines the mandatory operational standards for AI agents working on the JA4proxy project. Adherence to these rules ensures architectural consistency, security, and a high-quality handoff for human developers.

---

## 📋 Mandatory Planning & Concurrency Protocol — Read First

**When asked to perform any work, the agent MUST follow this sequence to prevent overlapping work with other parallel agents.**

### Step 1 — Claim the Task (Remote-Branch Lease)
Before writing any code or plans, ensure no other agent already owns the task. **The remote branch is the lock — creating it is the atomic claim.**
1. Sync: `git checkout main && git pull origin main --rebase`.
2. Check `docs/phases/manifest.yaml`. If the phase is `IN_PROGRESS`, **STOP** — another agent owns it.
3. Check for an existing lease: `git ls-remote --heads origin 'phase-XX*'`. If any branch matches, **STOP** — someone is already on it.
4. Claim it: create `phase-XX-<desc>` and push it immediately (an empty commit, `git commit --allow-empty`, is fine). The push **is** the claim — if two agents race, git rejects the loser's push, serialising them for free with no CI cost.
5. Mark ownership in your first real commit by setting that phase's status to `IN_PROGRESS` in the manifest (human/agent visibility). Do **not** open a separate status-only PR — that burns a full CI run to flip one line.

### Step 2 — Write the Plan
1. Create the phase document at `docs/phases/PHASE_XX.md` using the standard template: Goal, Scope, Implementation plan, Test strategy, Acceptance criteria, Out of scope.
2. Present the plan to the user with a brief summary: *"Here is the plan — please review before I begin."*

### Step 3 — Wait for explicit approval
Do **not** proceed until the user gives a clear go-ahead (e.g., "looks good", "proceed", "yes"). If changes are requested, update `PHASE_XX.md` and re-present.

### Step 4 — Implement
Only after written approval: create your feature branch, write code, write tests, and follow the Phase Close-Out Checklist.

---

## 🐳 Container-Strict Execution (No Host Python)

**Virtual environments on the host are strictly forbidden.** The host runs Python 3.10, but production targets Python 3.14.* (the test/tools images are pinned to `python:3.14`). Running tests, linters, or scripts on the host leads to severe version-skew bugs and polluted state.

- **Rule 1:** NEVER create a virtual environment (e.g., `uv venv`, `python -m venv`) on the host.
- **Rule 2:** NEVER run `pip install`, `pytest`, `ruff`, or `mypy` directly on the host machine.
- **Rule 3:** Run Python through the **`make` targets** — they execute inside the pinned `ja4proxy-tools` image (`Dockerfile.tools`, Python 3.14) via `docker run`, building it on demand. This is the canonical, CI-identical path.
  - *Wrong:* `python3 -m pytest tests/`
  - *Right:* `make test` (Go native + Python in-container) · `make test-unit` · `make test-chaos` · `make lint` · `make sync`
  - Need an ad-hoc command? `docker run --rm -v "$PWD":/src -w /src ja4proxy-tools pytest <args>` (this is what `$(TOOLS_RUN)` expands to).
- **Rule 4:** The full multi-service integration stack (`deploy/docker/docker-compose.test.yml`) is for integration/chaos tests that need Redis + the Go proxy; drive it with `docker compose exec <service> …`, not for unit/lint runs.
- **Note on Go:** Go tests run **natively** (`go test ./...`) — Go has no venv fragility, so the container rule is Python-only.

---

## 🛠️ Tool Usage & Communication

- **Bash Tool:** Under **opencode**, omit the `description` field — it currently triggers a validation error there. Under **Claude Code** the `description` field is supported and *should* be used (it surfaces intent in the permission prompt).
- **High-Signal Output:** Adopt a Senior Engineer persona. Be concise, direct, and technical. Avoid conversational filler.
- **Efficiency:** Parallelize independent searches (`Grep`, `Glob`) and file reads.

---

## Roadmap & Task Management

The project uses a **Manifest-Driven Roadmap**.
- **Single source of truth:** `docs/phases/manifest.yaml`.
- **Validation:** Run `make lint-phases` (which wraps Docker execution) to catch broken action_plan paths and stale status values. Must exit 0 before close-out.

### Phase Documentation Rules
**Rule 1:** Phase number lives in the FILENAME only (e.g., `# Core Features`, not `# Phase 22: Core Features`).
**Rule 2:** Status lives in `docs/phases/manifest.yaml` only. Do NOT include a `Status:` line in phase doc files.
**Rule 3:** To rename/renumber, rename the file, update the `action_plan:` path in the manifest, and run `make lint-phases`.
**Rule 4:** When a phase reaches a terminal status (`COMPLETE`, `CANCELLED`), move it to the corresponding subfolder (`docs/phases/complete/`) and update the manifest path in the exact same commit.

### Phase Close-Out — use `/close-phase` (mandatory)

Use the `/close-phase` slash command. If running outside Claude Code, run `bash scripts/close-phase.sh` and follow the manual steps:

1. **Pre-flight:** Feature branch active, working tree clean, documentation fragments created, manifest has `status: COMPLETE`.
2. **Local gate:** `bash scripts/close-phase.sh`. **Must exit 0.** (Ensure this script wraps containerized commands).
3. **Push & PR:** `gh pr create --base main`. (`main` is branch-protected; direct pushes are rejected).
4. **CI Checks:** Meta-Validation, Full Lint, Full Test, Security Scan must pass.
5. **Merge:** `gh pr merge --auto --squash --delete-branch`.

**Required Documentation Checks (The Fragment Pattern):**
DO NOT edit global shared files (`CHANGELOG.md`, `README.md`, `docs/REDIS_SCHEMA.md`) directly. To prevent merge conflicts between parallel agents:
1. Write updates to uniquely named files in `docs/fragments/` (e.g., `docs/fragments/phase_131_changelog.md`).
2. State which shared document the changes belong to and the exact text to be modified.

---

## Git & Version Control

- **Pre-Flight Synchronization:** `git checkout main && git pull origin main --rebase`.
- **Strict Branch Naming:** Format: `phase-<number>-<brief-description>` (e.g., `phase-131-tls-fuzzing`). Use hyphens throughout — never `phase_131`.
- **Atomic Commits:** One commit per phase or logical sub-task. Use `type(scope): brief description`.

> ### ⚠ Branch protection is ENFORCED on `main`
>
> `main` is branch-protected with **`enforce_admins: on`**, so the rule binds
> *everyone*, admins included. A direct `git push origin main` is rejected, and
> a PR cannot merge until the four required checks pass (Meta-Validation, Full
> Lint, Full Test, Security Scan). There is no admin direct-merge shortcut.
>
> **Emergency override** (use only when `main` is broken and a fix cannot wait
> for normal CI): temporarily lift admin enforcement, land the fix, then
> re-enable it immediately in the same sitting:
> ```bash
> gh api -X DELETE repos/seanpor/JA4proxy/branches/main/protection/enforce_admins
> # land the emergency fix
> gh api -X PATCH  repos/seanpor/JA4proxy/branches/main/protection/enforce_admins
> ```
> Never leave enforcement disabled. Prefer re-running a flaky check over bypassing it.

---

## Testing, Linting & Validation (TDD)

- **Zero-Tolerance Policy:** No skipped tests without explicit approval. Zero warnings, zero errors in linters.
- **Approved Exception Workflow:** Present justification, get user approval, log in `docs/security/EXCEPTIONS.md` (skipped tests / ignored warnings), and annotate the code with the exception ID. CVEs that fail CI are tracked separately in `docs/security/CVE_EXCEPTIONS.md` (90-day expiry).

### Web Service / Python UI TDD (Management & Wizard)
Every Python web service must include:
1. **HTML page rendering tests:** GET route with auth (`assert status_code == 200`, `"text/html"` in headers), and without auth (`assert status_code < 500`).
2. **Container config parity:** Read compose files and verify `REDIS_URL` or database strings correctly map password environment variables.
3. **Mocking:** Unit tests in `tests/unit/` **must not** reach any external process. Patch all clients. `os.access` mocks must use bitmask matching (`mode & os.W_OK`).

### `make test` Blockers
Before any PR merges to main, `make test` must be run locally and be 100% green. If `make test` executes Python tooling, it MUST be configured in the Makefile to execute inside the Docker container. 

### Python Import Hygiene (Containerized)
Every new `.py` file must pass ruff immediately, via the tools image:
```bash
docker run --rm -v "$PWD":/src -w /src ja4proxy-tools ruff check --select I001 --fix <file>
docker run --rm -v "$PWD":/src -w /src ja4proxy-tools mypy <file>
```
(Or just `make lint`, which runs the same checks in the same image.)

---

## Go Proxy (the production runtime)

The proxy is **Go-only** (`cmd/ja4pd`, `internal/`). The former Python proxy
(`proxy.py`) was deprecated and deleted — there is no cross-language parity to
maintain. Python that remains is **not** the proxy: the Management API
(`management/`), analytics, and supporting tooling under `src/`.

- **GOROOT gotcha:** snap-installed Go sets `GOROOT=/usr/share/go`, which is
  wrong and breaks `go build`/`go test`. Use the snap path:
  ```bash
  export GOROOT=/snap/go/current
  ```
  The Makefile already threads `GOROOT=$(GOROOT)` through Go targets; export it
  in your shell (`~/.bashrc`) so direct `go` invocations work too.
- **Go tests run on the host** — `go test ./...` has no virtualenv fragility, so
  the container-strict rule above applies to Python only, not Go.