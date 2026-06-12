# PHASE 313 — Go Backup / Restore (index)

> This umbrella was split into small, independently-reviewable sub-phases after a
> critical design review (see the review findings folded into each). The original
> single-phase draft is superseded by:
>
> - **[PHASE_313a](PHASE_313a.md)** — Redis **Backup** engine (native DUMP,
>   AES-256-GCM encryption, all backup+restore metrics defined, textfile-collector
>   delivery wiring).
> - **[PHASE_313b](PHASE_313b.md)** — Redis **Restore** (selective allow-vs-block,
>   GDPR-erasure-aware, integrity-verified, authz/audit, locking). Depends on 313a.
>
> Both are **PROPOSED — awaiting sign-off. No code until approved.**

## Why split

Restore is the dangerous half (it can re-block real users and resurrect
GDPR-erased data), so it gets its own focused review separate from the backup
engine. Each sub-phase is small enough to land and review cleanly.
