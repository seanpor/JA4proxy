# PHASE 232 — Security Foundations & Quick Wins (Index)

> **Lineage:** This phase is part of the **Container & Interface Consolidation** programme (see [PHASE_231.md](complete/PHASE_231.md)). Following a request for more granular, reviewable units and dedicated operational documentation updates, the original monolithic Phase 232 plan has been split into smaller sub-phases:
>
> - **[PHASE_232a](PHASE_232a.md)** — Frontend Asset Vendoring & Static Compilation (Size: SMALL).
> - **[PHASE_232b](PHASE_232b.md)** — Threat Posture Situation Bar & Heartbeat Alerting (Size: SMALL).
> - **[PHASE_232c](PHASE_232c.md)** — Container Networking & Port Hardening (Size: SMALL).
> - **[PHASE_232d](PHASE_232d.md)** — Admin-API Decommissioning (Size: SMALL).
> - **[PHASE_232e](PHASE_232e.md)** — Legacy Management Module Removal (Size: SMALL) —
>   the deferred source-deletion tail of 232d (deletes the orphaned
>   `src/management/` package once the container that ran it is gone).
>
> Each sub-phase is signed off and landed independently. No code until a
> sub-phase is approved.

## Why split

Splitting the original monolithic phase ensures:
1. **Clear operational document updates**: Each task specifies its exact impact on operational manuals and checklists (like `docs/operations/OPERATIONS_GUIDE.md` and `docs/reference/DOCKER_IMAGES.md`).
2. **Reviewable chunks**: Each sub-phase deals with a single logical concern (vendoring, UI widgets, port binding, container removal), ensuring high code quality and test compliance without overwhelming PR reviews.
3. **Focused test gates**: Verification can be targeted to specific integration and unit tests for each sub-phase.
