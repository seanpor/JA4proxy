# Phase 64e -- Credential rotation notes

> **Sub-phase of:** Phase 64 (Deployment Validation & Disaster Recovery)
> **Size:** XS
> **Status:** COMPLETE

## Deliverable
- `docs/runbooks/credential_rotation.md` -- three rotation procedures with rollback

## What was done
- Created `docs/runbooks/credential_rotation.md` covering:
  1. Redis auth password rotation (zero-downtime via dual-password ACL)
  2. AbuseIPDB API key rotation (verify, hot-reload, observe, revoke)
  3. Cloud storage credentials (S3/GCS IAM key rotation for backup service)
- Each procedure has numbered steps and an explicit Rollback subsection.
- All hot-reload commands use Go-production form (`docker kill --signal=HUP`,
  `systemctl kill --signal=HUP`, `kubectl exec -- kill -HUP 1`).
- No Python proxy (`proxy.py`) references in any hot-reload command.
- Cloud storage section correctly references `src/backup/worker.py` and
  `src/backup/restorer.py` (Python backup service, not Go proxy).
- Rotation schedule table included with recommended and mandatory intervals.

## Decisions made
- Used `docker compose` (v2) throughout; no `docker-compose` (v1) references.
- Backup container restart is required (no hot-reload support) -- documented
  as a container restart, not a proxy restart. Proxy traffic is unaffected.
- Included both AWS S3 and GCS commands in the cloud storage section since
  Phase 57 supports both providers.

## Reviewer checklist (complete before merging)
- [x] All three rotation procedures documented with numbered steps
- [x] All hot-reload commands use Go-production form
- [x] Each procedure has an explicit "Rollback" subsection
- [x] No `kill -HUP $(pgrep -f proxy.py)` references

## Phase 101 entries surfaced
- Automated credential rotation (e.g., HashiCorp Vault integration) not in scope.
- Redis ACL user per proxy instance (instead of `default` user) would improve
  audit trail -- consider for a future hardening phase.
