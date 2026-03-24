# JA4proxy Agent Protocol

This document defines the mandatory operational standards for AI agents working on the JA4proxy project. Adherence to these rules ensures architectural consistency, security, and a high-quality handoff for human developers.

---

## 🛠️ Tool Usage & Communication

- **Bash Tool:** Strictly only use the `command` field. Do not include `description` as it triggers validation errors.
- **High-Signal Output:** Adopt a Senior Engineer persona. Be concise, direct, and technical. Avoid conversational filler, apologies, or "I will now..." preambles.
- **Explain Before Acting:** Briefly explain the intent and potential impact of any command that modifies the filesystem or system state.
- **Efficiency:** Parallelize independent searches (`grep_search`, `glob`) and file reads to minimize turn overhead.

---

## 📑 Roadmap & Task Management

The project uses a **Manifest-Driven Roadmap** to prevent documentation drift.

- **Source of Truth:** `docs/phases/manifest.yaml`
- **Synchronization:** You MUST run `python3 scripts/sync-roadmap.py` after any change to the manifest. This updates `docs/phases/TODO.md` and `docs/PROJECT_STATUS.md`.

### Phase Close-Out Checklist (mandatory — run in order, do not skip steps)

Every phase must be closed by completing **all** of the following before the next phase begins:

1. **Tests pass:** `make test` — zero failures, zero warnings.
2. **CHANGELOG.md:** Add a standard entry for the phase (see `docs/DOCUMENTATION_STANDARDS.md`).
3. **REDIS_SCHEMA.md:** Document every new Redis key introduced.
4. **manifest.yaml:** Set `status: COMPLETE`. Remove any gaps that were resolved during the phase. Add any new gaps discovered to the appropriate future phase.
5. **Sync:** Run `python3 scripts/sync-roadmap.py` to regenerate `docs/phases/TODO.md` and `docs/PROJECT_STATUS.md`.
6. **Atomic commit:** Commit code, `CHANGELOG.md`, `manifest.yaml`, `TODO.md`, and `PROJECT_STATUS.md` together in a single commit.

> **Why this matters:** `manifest.yaml` is the only document downstream tooling reads. If it is not updated at phase-close, `TODO.md` and `PROJECT_STATUS.md` will show stale state, and future sessions will have incorrect context about what work remains.

---

## 📜 Git & Version Control

- **Atomic Commits:** One commit per phase or logical sub-task. Do not bundle unrelated refactors with feature work.
- **Commit Preparation:** Always run `git status && git diff HEAD` to review changes before committing.
- **Commit Messages:**
  - Propose a draft message before executing the commit.
  - Follow the format: `type(scope): brief description` (e.g., `feat(security): add JA4X fingerprinting`).
  - Focus on **why** a change was made, not just **what** changed.
- **No Pushing:** Never push to a remote repository or stage changes unless explicitly directed.

---

## 🧪 Testing, Linting & Validation (TDD)

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

---

## 🏗️ Build & Compilation

- **Strict Compilation:** All compiled code (Go, etc.) must compile with the equivalent of `-Wall` (all warnings enabled).
- **Zero-Warning Build:** The build process must produce **zero warnings**. Any compiler warning is a blocking failure that must be resolved before the code is considered valid.

---

## 🛡️ Security & Coding Standards (Phase 18 Alignment)

- **Logging:** **Never use f-strings or `.format()` in logging calls.** Use lazy formatting to prevent overhead and accidental data exposure.
  - `logger.info("Connection from %s", ip)` ✅
  - `logger.info(f"Connection from {ip}")` ❌
- **Exception Handling:** **Never use broad `except Exception:` blocks.**
  - Catch specific exceptions (e.g., `redis.ConnectionError`, `aiohttp.ClientError`).
  - Implement "Fail-Open" for enrichment: if an external API/Redis fails, log a WARNING, increment a counter, and allow the connection without that specific signal.
- **Secrets:** Never log, print, or commit API keys, Redis passwords, or TLS private keys. Check `.env.example` for required variables.
- **Naming:** Follow `docs/STYLE_GUIDE.md` strictly (e.g., `PascalCase` for classes, `snake_case` for metrics with `ja4proxy_` prefix).

---

## 📖 Documentation Maintenance

Every phase completion requires updating the following (per `docs/DOCUMENTATION_STANDARDS.md`):

1.  **CHANGELOG.md:** Standard entry under the correct version/phase.
2.  **docs/REDIS_SCHEMA.md:** Document every new key, its type, TTL, and owner.
3.  **README.md:** Update the "Security Pipeline" or "Services" tables if architecture changed.
4.  **ADRs:** Create a new Architectural Decision Record in `docs/decisions/` for any non-obvious design choices (e.g., choosing a specific library or algorithm).

---

## 📈 Strategic Review Protocol

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

## 🗂️ Project Context Hierarchy


If instructions conflict, use this priority:
1.  **User Hints** (Directives in the current session)
2.  **docs/phases/PHASE_XX.md** (Current phase mandate)
3.  **AGENTS.md** (This document)
4.  **docs/STYLE_GUIDE.md** / **docs/DOCUMENTATION_STANDARDS.md**
5.  **General System Prompt**
