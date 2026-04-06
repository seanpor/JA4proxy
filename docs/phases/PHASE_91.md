# PHASE 91 — GDPR Live Data Erasure & Operational Script Gap Remediation

> **Prerequisites:** Phase 40 (backup archive redaction), Phase 87 (observability).
>
> **Discovery basis:** Phase 89 Makefile audit (2026-04-06) found three broken `make`
> targets. Two were caused by scripts that were never created; one was a reference to a
> deleted file. All three are documented here with full remediation requirements.

---

## Background — What Was Found

During the Phase 89 Makefile reference audit, the following gaps were discovered:

| Broken target | Root cause | Severity |
|--------------|-----------|---------|
| `make gdpr-delete IP=x.x.x.x` | `scripts/gdpr_delete.py` never created | **HIGH** — GDPR Article 17 "right to erasure" for live Redis state was completely unimplemented |
| `make test-phase-87-integration` | `tests/integration/phase-87/` directory never created | **MEDIUM** — Phase 87 integration test target was broken since Phase 87 shipped |
| `make lint-docker` (one step) | `docker/docker-compose.go.yml` referenced after deletion | LOW — fixed in Phase 89 |

Phase 40 (COMPLETE) implemented DSAR for **backup archives** via `src/backup/redactor.py`.
It did not implement erasure of **live Redis state**. The `make gdpr-delete` target was
added to the Makefile at some point without any backing implementation. An operator
running `make gdpr-delete IP=1.2.3.4` would have received a file-not-found error.

Phase 87 (COMPLETE) met all its declared success criteria. However, the Makefile shipped
with `test-phase-87-integration` pointing to shell scripts that were never written. The
unit tests (`make test-phase-87`) pass; the integration target does not run.

---

## 91a. GDPR Live Redis Erasure — Complete Implementation

### Current state (created in Phase 89 cleanup)

`scripts/gdpr_delete.py` was created as an initial implementation:
- `--ip IP` and `--dry-run` flags
- Deletes exact-match and wildcard per-IP key patterns from `REDIS_SCHEMA.md`
- Basic IP validation (IPv4 and IPv6)

### Known gaps in the initial implementation

**Gap 1 — `behavioral:burst:{sni}` members are not addressable by key name**

`behavioral:burst:{sni}` is a Sorted Set keyed by SNI hostname, not by IP. IP addresses
appear as **member values** in the format `{ip}:{ts_ms}`. A key-name scan for the IP
will never find these entries.

To erase an IP's contribution from beaconing data, every `behavioral:burst:*` key must
be scanned and ZREM applied to any member matching `{ip}:*`.

**Gap 2 — HyperLogLog keys cannot be individually erased**

`hll:cidr48:{cidr}` keys use HyperLogLog, which is a probabilistic sketch. Individual
contributors cannot be removed from a HyperLogLog. The only option is to delete the
entire key (losing all contributors' data), which is disproportionate and must not be
done automatically. The current `gdpr_delete.py` has this key listed with an incorrect
comment — it must be removed from the deletion list and the limitation documented in
the erasure report.

**Gap 3 — No audit log**

GDPR compliance requires that erasure actions are themselves logged: who requested
deletion, when, for which IP, and how many records were removed. Without an audit
trail, the operator cannot demonstrate compliance to a regulator.

The audit log must be written to Redis:
```
management:gdpr_erasure_log  →  LIST of JSON entries (last 1000, no TTL)
{
  "timestamp": "ISO-8601",
  "ip": "canonical IP string",
  "dry_run": false,
  "keys_deleted": 12,
  "keys_skipped_hll": 1,
  "zset_members_removed": 3,
  "invoked_by": "make gdpr-delete / management-ui / api"
}
```

**Gap 4 — No tests**

`scripts/gdpr_delete.py` has no unit tests. A GDPR erasure tool that silently fails
(e.g. Redis connection error) without a test is a compliance risk.

### Implementation requirements

#### Fix `scripts/gdpr_delete.py`

1. **Remove the HyperLogLog pattern** from `_IP_KEY_PATTERNS`. Add a `_HLL_PATTERNS`
   list and a `_ZSET_MEMBER_PATTERNS` list as separate categories:

   ```python
   # Keys that cannot be per-IP deleted; erasure is documented but not performed
   _HLL_PATTERNS = [
       "hll:cidr48:*",    # Probabilistic sketch — individual removal impossible
   ]

   # Sorted sets where the IP appears as a member, not a key
   _ZSET_MEMBER_PATTERNS = [
       ("behavioral:burst:*", "{ip}:*"),  # (key glob, member prefix)
   ]
   ```

2. **Add ZREM handling** for sorted set member patterns:

   ```python
   def _purge_zset_members(r, ip: str, dry_run: bool) -> int:
       """Remove IP-prefixed members from sorted sets keyed by something other than IP."""
       removed = 0
       for key_glob, member_prefix in _ZSET_MEMBER_PATTERNS:
           member_pattern = member_prefix.replace("{ip}", ip)
           cursor = 0
           while True:
               cursor, keys = r.scan(cursor, match=key_glob, count=100)
               for key in keys:
                   # Get all members matching the IP prefix
                   members = [m for m in r.zrange(key, 0, -1)
                              if m.startswith(ip + ":")]
                   if members:
                       if dry_run:
                           print(f"  [dry-run] would ZREM {len(members)} member(s) from: {key}")
                       else:
                           r.zrem(key, *members)
                           removed += len(members)
                           print(f"  ZREM {len(members)} member(s) from: {key}")
               if cursor == 0:
                   break
       return removed
   ```

3. **Add audit logging**:

   ```python
   def _write_audit_log(r, ip: str, dry_run: bool, keys_deleted: int,
                        hll_skipped: int, zset_removed: int) -> None:
       entry = json.dumps({
           "timestamp": datetime.utcnow().isoformat() + "Z",
           "ip": ip,
           "dry_run": dry_run,
           "keys_deleted": keys_deleted,
           "keys_skipped_hll": hll_skipped,
           "zset_members_removed": zset_removed,
       })
       r.lpush("management:gdpr_erasure_log", entry)
       r.ltrim("management:gdpr_erasure_log", 0, 999)  # keep last 1000
   ```

4. **Add `--report` flag** that writes a JSON summary to stdout (useful for management
   UI integration and compliance evidence packs).

5. **Normalise the IP** to its canonical form before scanning:
   ```python
   import ipaddress
   ip = ipaddress.ip_address(ip.strip()).compressed
   ```
   This prevents `::ffff:1.2.3.4` and `1.2.3.4` from being treated as different subjects.

#### Add tests — `tests/unit/test_gdpr_delete.py`

Required test cases (using `fakeredis`):

| Test | Description |
|------|-------------|
| `test_exact_key_deletion` | Seed `ban:{ip}`, `visitor:{ip}` etc.; run purge; assert all gone |
| `test_wildcard_key_deletion` | Seed `session:ip:{ip}:ja4:abc123`; run purge; assert gone |
| `test_zset_member_removal` | Seed `behavioral:burst:example.com` with members `1.2.3.4:1000`, `5.5.5.5:2000`; purge `1.2.3.4`; assert `5.5.5.5:2000` remains |
| `test_hll_keys_not_deleted` | Seed `hll:cidr48:1.2.3.0/24`; run purge for `1.2.3.4`; assert HLL key still exists |
| `test_dry_run_deletes_nothing` | Seed keys; run with `dry_run=True`; assert all keys still exist |
| `test_audit_log_written` | Run purge; assert `management:gdpr_erasure_log` contains one entry with correct IP and count |
| `test_audit_log_dry_run_flagged` | Run with `dry_run=True`; assert audit log entry has `"dry_run": true` |
| `test_ipv6_canonical_form` | Purge `::ffff:1.2.3.4`; assert it resolves to canonical and deletes the right keys |
| `test_empty_redis_no_error` | No keys seeded; assert exit code 0 and "No keys found" message |
| `test_invalid_ip_exits_nonzero` | `--ip not-an-ip`; assert exit code 1 |

#### Update `docs/REDIS_SCHEMA.md`

Add the erasure audit log key:

```
| `management:gdpr_erasure_log` | LIST of JSON | no TTL (last 1000 entries) | scripts/gdpr_delete.py | Audit trail of GDPR erasure requests |
```

#### Update runbook

Add a section to `docs/runbooks/infrastructure.md` (or create
`docs/runbooks/gdpr_erasure.md`):

```markdown
## GDPR Subject Erasure (Right to be Forgotten)

### Live Redis erasure
make gdpr-delete IP=1.2.3.4           # delete
make gdpr-delete IP=1.2.3.4 DRY_RUN=1 # preview

### Known limitations
- HyperLogLog CIDR sketch keys (hll:cidr48:*) cannot be individually erased.
  The IP's approximate count remains in the sketch. HLL keys have a 24h TTL
  and will naturally expire. Document this limitation in any DPA correspondence.
- Backup archives must be separately redacted: src/backup/redactor.py
  See Phase 40 documentation for archive redaction.

### Audit trail
redis-cli LRANGE management:gdpr_erasure_log 0 -1
```

### Acceptance criteria

- [ ] `scripts/gdpr_delete.py` correctly handles all key categories (exact, wildcard, ZSET members)
- [ ] HLL keys are NOT deleted; their limitation is logged in the erasure report
- [ ] Audit log entry written to `management:gdpr_erasure_log` after every invocation (including dry-run)
- [ ] `make gdpr-delete IP=127.0.0.1` runs without error against a live Redis
- [ ] `make gdpr-delete IP=127.0.0.1 --dry-run` prints a complete key list and exits 0
- [ ] All 10 unit tests in `tests/unit/test_gdpr_delete.py` pass
- [ ] `python3 scripts/gdpr_delete.py --help` documents `--dry-run` and `--report` flags
- [ ] `docs/REDIS_SCHEMA.md` updated with erasure audit log key
- [ ] Runbook section written

---

## 91b. Phase 87 Integration Test Gap — Retrospective Verification

### What happened

Phase 87 was marked COMPLETE on 2026-04-06. Its declared success criteria (in
`docs/phases/manifest.yaml`) specified `make test-phase-87 passes`, not
`make test-phase-87-integration passes`. However, the Makefile shipped a
`test-phase-87-integration` target pointing to:

```
tests/integration/phase-87/check_cadvisor_metrics.sh
tests/integration/phase-87/check_haproxy_exporter.sh
```

Neither file nor the directory existed. The target has been broken since Phase 87
was merged.

### What was created in Phase 89 cleanup

Both scripts were created as functional integration checks:
- `check_cadvisor_metrics.sh` — verifies Prometheus scrape target health and
  presence of `container_cpu_usage_seconds_total` for ja4proxy containers
- `check_haproxy_exporter.sh` — verifies scrape target health and `haproxy_up=1`

### Remaining work for Phase 91

1. **Verify Phase 87 success criteria are all actually met** by running
   `make test-phase-87` and `make test-phase-87-integration` against a running
   monitoring stack. Confirm the six declared criteria hold.

2. **Extend `check_cadvisor_metrics.sh`** to also verify:
   - At least one `ContainerOOMKilled` alert rule is loaded in Prometheus
     (`/api/v1/rules?type=alert`)
   - The `ja4proxy-infrastructure` Grafana dashboard exists
     (`GET /api/dashboards/uid/ja4proxy-infra`)

3. **Extend `check_haproxy_exporter.sh`** to also verify:
   - `haproxy_frontend_bytes_in_total` metric is present (proves HAProxy is
     actually serving traffic to the exporter, not just the exporter being healthy)

4. **Add Phase 87 integration to the CI success gate** — update manifest
   `success_criteria` to include `make test-phase-87-integration passes` once
   the scripts are verified working against the monitoring stack.

### Acceptance criteria

- [ ] `make test-phase-87` passes (already should)
- [ ] `make test-phase-87-integration` passes against a running monitoring stack
- [ ] Alert rule presence verified in both scripts
- [ ] Grafana dashboard accessibility verified in cadvisor script
- [ ] Phase 87 manifest `success_criteria` updated to include integration target

---

## Testing Requirements

| Test file | Type | Runs without Docker |
|-----------|------|-------------------|
| `tests/unit/test_gdpr_delete.py` | Unit (fakeredis) | Yes |
| `tests/integration/phase-87/check_cadvisor_metrics.sh` | Integration | No — requires monitoring stack |
| `tests/integration/phase-87/check_haproxy_exporter.sh` | Integration | No — requires monitoring stack |

---

## Makefile Targets (add at bottom)

```makefile
## Phase 91 targets
test-phase-91:
	python3 -m pytest tests/unit/test_gdpr_delete.py -v

gdpr-delete:
	@[ -n "$(IP)" ] || (echo "Usage: make gdpr-delete IP=1.2.3.4"; exit 1)
	@python3 scripts/gdpr_delete.py --ip $(IP) $(if $(DRY_RUN),--dry-run,)
```

(The `gdpr-delete` target already exists at line ~900; do not duplicate it. Update
the existing target only if the `$(DRY_RUN)` flag support is added.)
