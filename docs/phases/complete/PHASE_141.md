# Phase 141: Repository Path Sanitization

> **Status:** COMPLETE
> **Size:** SMALL
> **Depends on:** Phase 140
> **Owner:** Gemini CLI

## Goal
Identify and remediate absolute filesystem paths (e.g., `/home/sean`) within documentation and configuration files to ensure project portability and maintain user privacy.

## Scope
- **Markdown Docs**: All `.md` files in `docs/` and the root.
- **Configurations**: `.yml`, `.yaml`, `.json`.
- **Source Code**: `.go`, `.py`.
- **Exclusions**: `.git/` metadata, `node_modules/`, `archive/`, and compiled binaries.

---

## Actions Taken

1. **Global Search**: Performed a recursive search for `/home/sean` across the entire workspace.
2. **Automated Remediation**: Implemented a multi-pattern replacement script to convert absolute paths to relative ones:
   - `/home/sean/LLM/JA4proxy2` -> `.` (Repository root)
   - `/home/sean/LLM/JA4proxy` -> `.`
   - `/home/sean/LLM/` -> `../` (Parent workspace folder)
   - `/home/sean/` -> `~/` (User home directory shortcut)
3. **Verification**: Confirmed that all remaining occurrences are either in git internal metadata (`.gitdir`) or legitimate container environment variables (`HOME=/home/nonroot`).

## Deliverables
- [x] Sanitized `docs/` tree.
- [x] Portabilized `.claude/settings.local.json`.
- [x] Cleaned `.aider.chat.history.md`.
