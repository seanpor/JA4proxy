# Custom Rules
- When using the bash tool, strictly only use the `command` field.
- Do not include `description` in the tool call JSON as it triggers a validation error.

# Manifest-Driven Roadmap Workflow
The project roadmap, phase statuses, and historical gaps are managed via a central manifest to prevent documentation drift.

- **Source of Truth:** `docs/phases/manifest.yaml`
- **Synchronization:** All agents must run `./scripts/sync-roadmap.py` after modifying the manifest to update `docs/phases/TODO.md` and `docs/PROJECT_STATUS.md`.
- **Modifying Phases:** 
  1. Update `docs/phases/manifest.yaml` with the new status, gaps, or tasks.
  2. Run the sync script.
  3. Commit all three files together.
- **Junior Handoffs:** Detailed TDD work plans are linked in the manifest and generated into the `Action Plan` sections of `TODO.md`.
