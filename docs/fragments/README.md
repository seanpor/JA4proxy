# Changelog fragments

This directory holds **news fragments** — one small file per change, instead of
editing `CHANGELOG.md` directly.

## Why

`CHANGELOG.md` prepends every entry under the same `## [Unreleased]` → `### Added`
heading. With several agents working phases in parallel, that one location
conflicts on almost every merge. Dropping a *uniquely named* fragment here
sidesteps it — unique filenames never collide, so phases stop conflicting on the
changelog.

## How to add an entry (per phase)

1. Create `docs/fragments/phase-<NN>-<slug>.md` (any unique, descriptive name
   ending in `.md`).
2. Put one or more Markdown bullets in it — the same text you'd otherwise add
   under `### Added`:

   ```markdown
   - **Short title (Phase NN)**: one-line description. See `docs/phases/PHASE_NN.md`.
   ```

3. **Do not edit `CHANGELOG.md`** for routine phase work — the fragment is your
   changelog entry.

## How fragments become CHANGELOG.md

Assembly is a **serialized** step (release time, or run by the orchestrator) —
never per-phase, so the one place that edits `CHANGELOG.md` is never contended:

```bash
make changelog-assemble
```

This folds every fragment into `## [Unreleased]` → `### Added` (ordered by
filename) and deletes the consumed fragments.

A unit test (`tests/unit/test_changelog_fragments.py`) keeps fragments
well-formed and the assembler honest; it runs in the `make test` gate.
