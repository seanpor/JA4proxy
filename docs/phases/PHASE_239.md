---
phase: 239
title: Configuration Schema Migration & Upgrade Utility
status: PROPOSED
size: SMALL
created: 2026-06-13
audience: [developer, operator, secops]
dependencies: [231b]
---

# PHASE 239 — Configuration Schema Migration & Upgrade Utility

This document outlines the design and step-by-step implementation plan for the configuration auto-upgrade utility. It is written as a guide for junior engineers to understand the mechanics of comment-preserving YAML parsing, transactional backups, and fail-secure configuration upgrades.

---

## 📖 Architectural Concepts Explained

Upgrading software often introduces new configuration keys or default parameters (for example, adding `write_proxy_protocol` in Phase 231). In an enterprise production deployment, manually editing configuration files is highly error-prone. This phase implements an automated configuration migrator to make this process safe and friction-free.

### 1. Comment-Preserving YAML Parsing (AST Merging)
Standard YAML parsers (like simple JSON-to-YAML converters) strip out comments, reformats indentation, and reorder keys when writing back to disk. For human-maintained configuration files containing valuable operator notes and commented-out bypass rules, this is unacceptable.
*   **The Solution:** Abstract Syntax Tree (AST) parsing. 
*   We use Go's standard `gopkg.in/yaml.v3` parser, which reads the YAML document into a tree of nodes (`Node` objects) representing values, maps, sequences, and comments.
*   By traversing both the active user config's AST and the new template config's AST, we identify missing keys and inject them (along with their original template comments) directly into the user's AST while keeping the user's custom values and comments completely untouched.
*   **Key Type Conflicts:** If a key exists in both but their types mismatch (e.g. template changes a key from a scalar to a map/sequence), the migrator must overwrite the user node with the template's structure. The user's original conflicting value must be moved to a commented-out line adjacent to the key (e.g., `# Conflict: user value was '...'`) and a warning printed.
*   **List/Sequence Node Merging:** If a list/sequence key exists in both, preserve the user's list in its entirety. Do not attempt element-wise merging unless a unique key-identity field is explicitly specified.
*   **Deduplication & Layout Validation:** Pre-scan and deduplicate keys in user mappings (taking the last defined key, matching standard YAML behavior). Post-merge, verify structural layout integrity (e.g., ensure `len(MappingNode.Content) % 2 == 0`).

### 2. Transactional Backup & Rollback (Fail-Secure)
When editing configuration files, there is a risk that a write failure, disk full condition, or validation error results in a corrupt or unstartable configuration.
*   **Same-Directory Temp Files (EXDEV Safety):** To avoid `EXDEV` cross-device link errors when renaming across different mount points (such as moving from `/tmp` to `/etc/`), the temporary file `proxy.yml.tmp-[suffix]` must be created in the **same directory** as the active `proxy.yml`.
*   **Metadata (Permissions & Ownership) Preservation:** Before swapping the files, the utility must read the permissions, owner UID, and group GID of the active `proxy.yml` (using `os.Lstat`). It must apply the exact permissions to the temp file using `os.Chmod` and `os.Chown` (if running as root) to prevent the daemon from losing read access.
*   **Hard-Fail Backups:** The utility must create a secure backup copy of `proxy.yml` and `.env` in the backup directory with a timestamp and a calculated SHA-256 hash. If backup creation or the SHA-256 verification of the backup copy fails, the utility must abort immediately and not touch the active configuration.
*   **Disk Flush:** The utility must call `file.Sync()` on the temporary file before closing and renaming it to ensure data is physically written to disk.
*   **Fail-Secure Verification:** Only after the loader validator (`config.Load`) parses the temporary file with zero errors does it atomically replace the active configuration. If validation fails, it aborts, deletes the temp files, and keeps the original configuration untouched.

### 3. Dry-Run Mode
Operators must be able to review proposed changes before they are committed to disk.
*   **How it works:** The CLI command supports a `--dry-run` flag. In dry-run mode, the migrator performs the AST comparison, generates the merged output in memory, and prints a standard diff showing exactly which keys and comments will be added.

### 4. Backwards-Compatible Schema Parsing (Zero-Downtime Safe)
Even if the binary is upgraded *before* the configuration file is migrated, the daemon must not crash.
*   **How it works:** The configuration parser in `internal/config/loader.go` must fall back to sensible hardcoded default values for any missing schema keys. If `write_proxy_protocol` is absent, the daemon initializes it as `false` and emits a non-fatal `INFO` log on startup. This allows operators to upgrade binaries first, then perform configuration migrations, minimizing service interruption.

### 5. Automated Hot-Reload Integration
Whenever a configuration migration completes successfully on disk, the daemon should be notified to reload the configuration without process restarts.
*   **How it works:** The migrator can optionally send a `SIGHUP` signal to the local `ja4pd` process or broadcast a config-reload command over the Redis pubsub channel. This triggers a zero-downtime hot-reload of the new settings (e.g. new CIDR whitelists or enforcement flags) without dropping active TLS connections.

### 6. Human-Readable Diagnostic Errors (Production Troubleshooting Assistance)
If an operator accidentally deletes or corrupts a configuration parameter that is required and has no default fallback (e.g., `proxy.backend_addr`, Redis credentials, or TLS certificate paths), the standard loader must fail cleanly and helpfully.
*   **How it works:** Rather than printing raw YAML formatting exceptions or unhandled parser stack traces, the validator catches missing required keys and prints a highly structured, colorized diagnostic report. 
*   **Diagnostic Report Schema:** Reports must format:
    *   `Error Code`: Unique identifier (e.g., `ERR_CONFIG_REQUIRED_FIELD_MISSING`).
    *   `Field Path`: Dotted path notation of the parameter (e.g., `redis.password`).
    *   `Location`: The line and column number of the parent block (derived from AST node info).
    *   `Details`: Concise explanation of why the field is required.
    *   `Remediation`: Actionable fix instructions, including references to templates.

### 7. Interactive Configuration Doctor (`ja4p config doctor`)
To assist production SREs whose configuration files have become damaged, the CLI provides an interactive troubleshooting utility.
*   **TTY Detection & Non-Interactive Failsafe:** The utility must detect if stdin is a terminal using `golang.org/x/term` (or checking `os.Stdin.Fd()`). If not in a TTY, the command must fail-closed immediately unless a `--yes` or `--non-interactive` flag is explicitly passed, protecting automation scripts from hanging.
*   **Syntax Error Recovery:** If the configuration file contains raw syntax errors, the doctor must block auto-repair operations, print exact line/column details of the syntax error, and guide the user to resolve them first.
*   **Placeholder Value Protection:** When the doctor injects placeholder values (e.g., `password: "ENTER_REDIS_PASSWORD"`), the configuration loader must explicitly validate and reject these literal patterns to prevent weak security states.
*   **Auto-Repair Validation Gate:** Any interactive repair must first be written to a temp file and passed through the `config.Load` validator before being atomically moved into place.
*   **How it works:** The operator runs `ja4p config doctor`. The command analyzes the active configuration file against the canonical reference template, finds any deleted/missing keys, warns about fields using defaults, and offers to automatically repair missing sections. For optional keys or keys with defaults, it restores them with their comments. For required keys without defaults (e.g. `redis.password`), it appends a placeholder line (e.g. `password: "ENTER_REDIS_PASSWORD"  # REQUIRED: Enter Redis password`) and alerts the engineer to edit it.

---

## 📋 Scope

- `internal/cli/commands/config.go` (Add `ja4p config upgrade` with `--check`/`--reload` flags, and the new `ja4p config doctor` sub-command)
- `internal/config/migrator.go` (New package containing the comment-preserving YAML merging, `.env` merging, check/diff logic, and auto-repair doctor logic)
- `internal/config/loader.go` (Ensure fallback defaults exist for all optional parameters, and implement detailed human-readable validation error messages for missing required keys)
- `docs/phases/manifest.yaml` (Proposed entry for Phase 232)
- `docs/PROJECT_STATUS.md` (Roadmap synchronization)
- `docs/phases/TODO.md` (Roadmap synchronization)

---

## 🛠️ Implementation Plan

### A — Interactive CLI Command
*   **CLI Structure:** Add `ja4p config upgrade [--dry-run] [--check] [--reload] [--backup-dir=<path>] [--config=<path>]` and `ja4p config doctor [--config=<path>]` commands in the operational CLI commands package.
*   **Dry-run Output:** If `--dry-run` is active, calculate the changes and display them using a unified diff format, exiting 0 without writing to disk.
*   **Upgrade Checking:** If `--check` is active, compare the active config with the target template. If any keys are missing, output the drift summary and exit with code `2` (drift found); if configurations are in sync, exit with code `0`.
*   **Interactive Doctor Mode:** If `config doctor` is executed, parse the active configuration. Perform interactive verification:
    *   List all missing keys with no defaults.
    *   Prompt the user to automatically inject placeholders for missing required keys with their relevant comments.
    *   Warn if optional keys are missing and list the values being assumed.

### B — Transactional Backups
*   **Backup Execution:** Compute a timestamped backup name (e.g. `proxy.yml.backup-2026-06-11T09:30:00Z`). Write copies of the active `proxy.yml` and `.env` to the backup directory before starting any merge operations.
*   **Integrity Hash:** Calculate the SHA-256 hash of the files before backing them up and print it to the logs for audit trail verification.

### C — Comment-Preserving YAML Merging
*   **AST Parsing:** Read the user's active `proxy.yml` and the target template `proxy.yml` into `yaml.Node` structures.
*   **Recursive Merging:** Recursively compare keys. If a map key exists in the template but is missing in the user config:
    *   Inject the key node, value node, and any leading/inline comment nodes into the user config node slice at the correct logical position.
    *   If a key exists in both, preserve the user's value node intact.
*   **Format Integrity:** Output the modified AST back to disk, preserving block comments, inline comments, and indentation.

### D — Environment File Merging
*   **Variables Matching:** Read the active `.env` and the reference `template.env`.
*   **Appending Defaults:** For any environment variable defined in the template but missing in the user's `.env`, append the declaration (e.g. `NEW_VARIABLE=default_value`) at the bottom of the active `.env` file under a `# Migrated Keys (Upgrade)` comment block.

### E — Validation Gate & Atomicity
*   **Temp Validation:** Write the proposed merged contents to a temporary file `proxy.yml.tmp`.
*   **Loader Verification:** Call `config.Load("proxy.yml.tmp")` to verify that the config parses correctly and passes all validation rules.
*   **Atomic Move:** If validation passes, overwrite the active `proxy.yml` using `os.Rename`. If validation fails, log the error, delete the temp file, and fail-secure (retaining the original active config).
*   **Hot-Reload Trigger:** If `--reload` is specified and the config was updated, find the local `ja4pd` process PID and send a `SIGHUP` signal to force a zero-downtime hot-reload of the configuration.
*   **Detailed Diagnostics Output:** If validation fails, format the parsing errors with the key path and custom recovery suggestions, printing them directly to stderr.

---

## 🧪 Test Strategy

- **YAML AST Merge Tests (`internal/config/migrator_test.go`):**
    *   Verify that merging a template with missing keys adds the keys and their comments.
    *   Verify that existing user values and custom comments are not overwritten.
    *   Verify that nested maps are merged recursively.
- **Backwards Compatibility Tests (`internal/config/loader_test.go`):**
    *   Verify that the configuration loader successfully parses an older schema format with missing keys, initializing all parameters with their correct default fallback values, and emitting an info log.
- **Environment Merge Tests:**
    *   Verify that missing variables are appended correctly to the bottom of the `.env` file.
    *   Verify that existing values are not modified.
- **Fail-Secure Integration Tests:**
    *   Verify that if the merged temp file fails config validation (e.g. invalid port number, missing required fields), the migrator aborts and the original configuration files remain unmodified.
- **CLI Integration & Check Tests:**
    *   Verify the `--dry-run` diff output matches the standard git-diff format.
    *   Verify that `ja4p config upgrade --check` returns code `2` on mismatched schemas and `0` on aligned schemas.
- **Diagnostic Output & Doctor Tests:**
    *   Verify that deleting a required field (e.g. `redis.password`) and running validation outputs a detailed error message containing the missing key name, line offset, and a remediation suggestion.
    *   Verify that running `ja4p config doctor` on a configuration with missing required keys correctly inserts the comments and placeholder values on disk.
- **Hot-Reload Verification:**
    *   Verify that invoking `ja4p config upgrade --reload` successfully updates the file and triggers the SIGHUP signal on `ja4pd`, resulting in zero connection drops.

---

## 📋 Acceptance Criteria

### Functional
- [ ] Running `ja4p config upgrade` successfully backs up the configuration, merges new keys, and writes the upgraded configuration.
- [ ] All custom user values are preserved exactly.
- [ ] All custom user comments are preserved exactly.
- [ ] New keys injected from the template include their original comments.
- [ ] Running with `--dry-run` shows a diff of the proposed updates but does not write to the filesystem.
- [ ] Running with `--check` returns exit code `2` if the active configuration is missing schema keys, and `0` if it is fully updated.
- [ ] Specifying `--reload` notifies the local daemon to reload its configuration dynamically via `SIGHUP` upon a successful upgrade.
- [ ] The `ja4p config doctor` command correctly scans, identifies, and interactively restores missing required and optional schema elements to the configuration file with clean placeholder values and comments.

### Configuration & Validation
- [ ] If the merged configuration is invalid (fails `config.Load`), the upgrade is aborted and the active configuration is restored.
- [ ] The backup files are written with mode `0600` (read/write by owner only) to protect embedded secrets.
- [ ] The Go proxy daemon starts and operates correctly with built-in default values if it runs against a configuration file that lacks newly introduced schema keys (backwards-compatible schema parsing).
- [ ] Any validation failure due to missing required configuration elements without defaults causes the daemon to print a highly structured, clear diagnostic error message outlining the exact missing key path and the corrective action.

---

## 🚫 Out of Scope

- Performing version-downgrade migrations (rolling back schema keys).
- Modifying database schemas or Redis key definitions.
- Managing configurations for other system services (e.g., systemd unit files, logrotate definitions) during configuration upgrade.
