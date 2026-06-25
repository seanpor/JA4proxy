<!--
title: GDPR_Erasure
audience: Operators, Data Protection Officers
last_reviewed: 2026-04-06
phase: 91
-->

# GDPR Subject Erasure — Runbook

## Purpose

Fulfils the GDPR "Right to be Forgotten" (Article 17) for live Redis state.
For backup archive redaction, see `ja4p restore --help` (Go backup tool).

## Live Redis Erasure

### Delete all data for an IP (production)
```
make gdpr-delete IP=1.2.3.4
```

### Preview what would be deleted (dry run)
```
make gdpr-delete IP=1.2.3.4 DRY_RUN=1
```

### Get a machine-readable JSON report
```
python3 scripts/gdpr_delete.py --ip 1.2.3.4 --report
```

## What Gets Deleted

| Key category | Example | Action |
|---|---|---|
| Exact match IP keys | `ban:1.2.3.4`, `session:1.2.3.4`, `return_visitor:1.2.3.4`, `dns:fcrdns:1.2.3.4`, `audit:last_score:1.2.3.4` | Deleted |
| Wildcard IP keys | `beacon:1.2.3.4:*` | Scanned and deleted |
| ZSET members | `behavioral:burst:example.com` (member `1.2.3.4:ts`) | ZREM |
| HyperLogLog sketches | `hll:cidr48:1.2.3.0/24` | NOT deleted (see limitations) |

## Known Limitations

### HyperLogLog CIDR sketches cannot be individually erased

`hll:cidr48:*` keys use a probabilistic sketch (Redis HyperLogLog). Individual
contributors cannot be removed from a HyperLogLog — only the entire key can be
deleted, which would remove all contributors' data (disproportionate under GDPR).

These keys carry a 24-hour TTL and expire naturally. Document this limitation in
any Data Protection Authority (DPA) correspondence. The erasure report explicitly
lists skipped HLL keys so the limitation is auditable.

### Backup archives are a separate concern

Running `make gdpr-delete` erases **live Redis state only**. Backup archives created
by Phase 19/40 must be separately redacted using `ja4p restore --help` (Go backup tool).

## Audit Trail

Every invocation (including dry runs) writes an entry to Redis:

```
LRANGE management:gdpr_erasure_log 0 -1
```

Entry format:
```json
{
  "timestamp": "2026-04-06T19:53:30+00:00",
  "ip": "1.2.3.4",
  "dry_run": false,
  "keys_deleted": 12,
  "keys_skipped_hll": 1,
  "zset_members_removed": 3,
  "invoked_by": "gdpr_delete.py"
}
```

The log retains the last 1,000 entries with no TTL.

## Related

- Phase 40: Backup archive DSAR redaction — `ja4p restore --help` (Go backup tool)
- Phase 91: This runbook was introduced
- Redis key: `management:gdpr_erasure_log`
