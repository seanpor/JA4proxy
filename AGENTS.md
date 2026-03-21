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
- **Synchronization:** You MUST run `./scripts/sync-roadmap.py` after any change to the manifest. This updates `docs/phases/TODO.md` and `docs/PROJECT_STATUS.md`.
- **Workflow:** 
  1. Update `manifest.yaml` (status, gaps, tasks).
  2. Run the sync script.
  3. Commit the manifest, the sync script (if modified), and the generated markdown files as a single atomic unit.

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

## 🧪 Testing & Validation (TDD)

- **Test-First:** Always search for existing tests before modifying code. If a bug is reported, reproduce it with a new test case first.
- **Mandatory Coverage:** A change is incomplete without corresponding tests.
  - **Unit:** Logical correctness of modules.
  - **Integration:** Interaction with Redis/Network.
  - **Chaos:** Resilience against dependency failure (Redis down, API timeout).
- **Finality:** A task is only "Done" when the relevant test suite passes 100%. Use the project `Makefile` where possible (e.g., `make test`, `make lint`).

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

## 🗂️ Project Context Hierachy

If instructions conflict, use this priority:
1.  **User Hints** (Directives in the current session)
2.  **docs/phases/PHASE_XX.md** (Current phase mandate)
3.  **AGENTS.md** (This document)
4.  **docs/STYLE_GUIDE.md** / **docs/DOCUMENTATION_STANDARDS.md**
5.  **General System Prompt**
