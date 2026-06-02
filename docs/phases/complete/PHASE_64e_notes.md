# Phase 64e — Credential Rotation Notes

## Artifacts Created

| File | Purpose |
|------|---------|
| `docs/runbooks/credential_rotation.md` | 3 rotation procedures with rollback |

## Acceptance Checklist

- [x] Redis ACL rotation: dual-auth period, hot-reload, rollback
- [x] AbuseIPDB API key rotation: verify before revoke, rollback
- [x] Cloud storage credentials rotation: IAM key creation, backup verify, rollback
- [x] All hot-reload commands use Go-production form only
- [x] Each procedure has an explicit "Rollback" subsection
- [x] No `kill -HUP $(pgrep -f proxy.py)` references
- [x] Temporary key files securely deleted (`shred -u`)
- [x] Rotation schedule summary table with frequency and zero-downtime status

## Out of Scope

- TLS certificate rotation (Phase 64f — separate runbook)
- mTLS CA certificate rotation (Phase 64f — separate runbook)
- Kubernetes Secret management automation (deferred)
