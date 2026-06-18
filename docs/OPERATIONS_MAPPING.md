<!--
title: JA4proxy — SecOps Triage & Remediation Playbooks
audience: security
last_reviewed: 2026-06-18
phase: v2.0
-->

# JA4proxy — SecOps Triage & Remediation Playbooks

> **The authoritative MITRE ATT&CK technique mapping is
> [ATTACK_MAPPING.md](ATTACK_MAPPING.md)** (signal → technique, with honest
> confidence labels — the single source of truth, CI-gated). This page is the
> operational companion: what to *do* when an alert fires. The per-signal →
> ATT&CK technique tables that previously lived here were consolidated into
> ATTACK_MAPPING.md to avoid two diverging mappings.

## Remediation Playbooks

| Alert Type | Suggested Action | Playbook |
| :--- | :--- | :--- |
| **Critical JA4 Match** | Increase Dial to 100; verify the JA4 in TI feeds. | [High Block Rate](runbooks/ja4proxy_block_rate_high.md) |
| **Mesh Drift Alert** | Check configuration consistency; inspect Redis health. | [Unexpected Dial Change](runbooks/ja4proxy_dial_change_unexpected.md) |
| **Tarpit Overflow** | Scale proxy instances; inspect for a Slowloris attack. | [Tarpit Pool Full](runbooks/ja4proxy_tarpit_pool_full.md) |

## See also

- [ATTACK_MAPPING.md](ATTACK_MAPPING.md) — authoritative MITRE ATT&CK technique mapping.
- [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md) — the full incident-response runbook.
- [runbooks/](runbooks/) — the complete operational runbook set.
