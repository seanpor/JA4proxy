# Manifest Gap Cleanup — Phase 103

## Goal
Clean up 5 stale gap entries in `docs/phases/manifest.yaml` that were resolved post-merge but never removed from the manifest, keeping phase records accurate.

## Scope
- `docs/phases/manifest.yaml` — remove or resolve stale gap entries in phases 33, 36, 57, 87, 93

## Implementation plan
1. Read current manifest entries for phases 33, 36, 57, 87, 93
2. Remove gap entries that are documented as resolved (phase 36: "FIXED" entries)
3. Remove gap entries whose deferred work is now COMPLETE (phase 57: gaps moved to phase 58 which is COMPLETE)
4. Remove gap entries resolved in subsequent phases (phase 87: resolved in phase 91)
5. Leave external-process notes intact (phase 93: Terraform Registry review is truly external)
6. Run `make lint-phases` to validate
7. Run `make sync` to regenerate TODO.md

## Test strategy
- `make lint-phases` must exit 0 — structural validation
- No code changes, so no unit tests needed
- Manual review of manifest diff before commit

## Acceptance criteria
- [ ] `make lint-phases` exits 0
- [ ] `make sync` exits 0
- [ ] No stale gap entries remain for phases 33, 36, 57, 87
- [ ] Phase 93 external-process note preserved (legitimate external dependency)

## Out of scope
- No code changes to any proxy, test, or script
- No changes to phase statuses — only gap list cleanup
- No new features or functionality
