# PHASE 315 — Go Backup / Restore (index)

> **Lineage:** this is the resurrected **Go Backup/Restore** work originally
> drafted as Phase 313. Phase numbers 313/314 were later repurposed (313 →
> CI lint/scan fix, #140; 314 → third-party image HIGH-CVE remediation, #141),
> orphaning this plan. It is restored here under fresh number **315** (sub-phases
> **315a/315b**), recovered verbatim from git `53a8e14` and renumbered. The Go
> proxy still has **no backup implementation**, and
> `deploy/monitoring/alertmanager/rules/backup.rules.yml` still alerts on
> `ja4proxy_backup_*` / `ja4proxy_restore_*` metrics that nothing emits.

> This umbrella was split into small, independently-reviewable sub-phases after a
> critical design review (see the review findings folded into each). The original
> single-phase draft is superseded by:
>
> - **[PHASE_315a](PHASE_315a.md)** — Redis **Backup** engine (native DUMP,
>   AES-256-GCM encryption, all backup+restore metrics defined, textfile-collector
>   delivery wiring).
> - **[PHASE_315b](PHASE_315b.md)** — Redis **Restore** (selective allow-vs-block,
>   GDPR-erasure-aware, integrity-verified, authz/audit, locking). Depends on 315a.
>
> Both are **PROPOSED — awaiting sign-off. No code until approved.**

## Why split

Restore is the dangerous half (it can re-block real users and resurrect
GDPR-erased data), so it gets its own focused review separate from the backup
engine. Each sub-phase is small enough to land and review cleanly.
