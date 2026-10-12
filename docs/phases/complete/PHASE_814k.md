# Pentest: Data Layer — Redis, Analytics Stream, Backup/Restore

> Sub-phase 814k of the Phase 814 penetration testing programme (`PHASE_814.md` §5).
> Preceded by Phase 814j (Resource Exhaustion & Availability) and Phase 814g (Agent Instruction Surface).

## 1. Goal

Execute a comprehensive adversarial penetration test of JA4proxy's data layer:
1. **Redis Access Control & Transport Security**: Verify least-privilege ACL enforcement across all components (Go proxy, management console, analytics worker, TAP sensor, Redis exporter, CLI).
2. **Pub/Sub Control Plane Integrity**: Test whether co-located clients or rogue actors with Redis write access can forge control-plane messages (`dial_change`, `config_reload`, list modifications) when HMAC signing is missing or unconfigured.
3. **Namespace Collision & Key Injection**: Test whether attacker-supplied parameters (SNI with colons/newlines, arbitrary headers, malicious client IPs) can escape intended Redis key namespaces.
4. **GDPR Erasure & Backup Resurrection Invariants**: Test whether GDPR Right-to-Erasure (`scripts/gdpr_delete.py`, `management/compliance/purge.py`) and backup restore (`internal/backup/restore.go`, `internal/backup/classify.go`) guarantee that erased subject data is completely removed and never resurrected during disaster recovery.
5. **Analytics Stream Ingestion Robustness**: Test whether `src/analytics/stream_consumer.py` enforces payload size bounds, type safety, and signature validation under hostile stream payloads.

---

## 2. Scope

### In Scope
- `config/redis_acl.conf.template` and `scripts/redis-acl-setup.sh`: ACL grants and command/key restrictions for all system users.
- `internal/redis/pubsub.go`: Pub/sub message handling, critical channel authentication, and HMAC verification fail-safe behavior.
- `internal/backup/classify.go` & `internal/backup/restore.go`: Key classification, IP extraction, tombstone filtering, and restore replace validation.
- `scripts/gdpr_delete.py` & `management/compliance/purge.py`: Subject IP key deletion coverage across all Redis namespaces.
- `src/analytics/stream_consumer.py`: Payload parsing, HMAC signature enforcement, and memory exhaustion defenses.
- Adversarial test suites with two-state proofs (`scripts/verify_revert.sh`).

### Out of Scope
- Go proxy TLS termination (proxy runs as pure TCP passthrough; tested in Phase 814h).
- Webhook delivery queuing internals (tested in Phase 814j).
- Third-party Redis engine C vulnerabilities (handled via container base image scanning).

---

## 3. Discovered Findings & Threat Vectors

### Finding 1: Unauthenticated Control-Plane Pub/Sub Forgery (JA4PROXY-2026-0121)
- **Severity**: HIGH (CVSS 8.2)
- **Vector**: When `pubsub_hmac_secret` is unset or empty, `internal/redis/pubsub.go` logs a warning and accepts unsigned messages on critical channels (`config:reload`, `dial:change`, blacklist/whitelist updates). Any co-located service or container with Redis publish access can manipulate proxy enforcement posture or trigger reload loops.
- **Remediation**: Require HMAC authentication on critical channels in production posture; enforce fail-closed validation unless an explicit test flag is active; ensure Redis ACL restricts PUBLISH on `&config:*` and `&ja4:*` channels strictly to `management`.

### Finding 2: GDPR Erasure Bypass via Incomplete Backup Tombstone Extraction (JA4PROXY-2026-0122)
- **Severity**: HIGH (Regulatory GDPR Art 17/5(1)(e))
- **Vector**: `internal/backup/classify.go` only registers 4 key prefixes in `perIPExtractors` (`ban:`, `fp:os:ip:`, `fp:ip:`, `beacon:`). All other PII-bearing per-IP keys (`session:{ip}`, `concurrent:{ip}`, `return_visitor:{ip}`, `dns:fcrdns:{ip}`, `audit:last_score:{ip}`, `rdap:ip:{ip}`, `abuseipdb:{ip}`, `ratelimit:ip:{ip}`, `offense:{ip}`) return `("", false)` from `SubjectIP()`. During a disaster recovery restore, tombstoned IPs are not skipped for these keys and are resurrected in Redis.
- **Remediation**: Expand `perIPExtractors` in `internal/backup/classify.go` to comprehensively cover all IP-keyed namespaces in `REDIS_SCHEMA.md`.

### Finding 3: GDPR Deletion Script Namespace Coverage Drift (JA4PROXY-2026-0123)
- **Severity**: MEDIUM (Regulatory)
- **Vector**: `scripts/gdpr_delete.py` `_IP_KEY_PATTERNS` omits `ratelimit:ip:{ip}`, `ratelimit:ip_ja4:{ip}:*`, and `offense:{ip}`. Right-to-erasure invocations fail to purge historical rate limiting and offense state for the target subject IP.
- **Remediation**: Update `_IP_KEY_PATTERNS` to include `ratelimit:ip:{ip}`, `ratelimit:ip_ja4:{ip}:*`, and `offense:{ip}`.

---

## 4. Implementation Plan

1. **Pub/Sub Security Hardening**:
   - Update `internal/redis/pubsub.go` to enforce that critical channels (`ChannelConfigReload`, `ChannelDialChange`, list changes) drop unsigned messages when no HMAC secret is configured unless explicitly permitted by an insecure dev configuration option.
   - Add invariant tests for HMAC signature validation and unauthorized channel publication rejection.
2. **Backup Tombstone IP Extraction Completeness**:
   - Update `internal/backup/classify.go` `perIPExtractors` with complete coverage of all per-IP namespaces:
     `session:`, `concurrent:`, `return_visitor:`, `dns:fcrdns:`, `audit:last_score:`, `rdap:ip:`, `abuseipdb:`, `ratelimit:ip:`, `ratelimit:ip_ja4:`, `offense:`.
   - Add unit tests in `internal/backup/classify_test.go` and `internal/backup/restore_test.go` asserting that every IP-keyed namespace is correctly identified and filtered against tombstones.
3. **GDPR Deletion Coverage Synchronization**:
   - Update `scripts/gdpr_delete.py` to delete rate-limiting and offense counter keys.
   - Add regression tests in `tests/unit/test_gdpr_delete.py` verifying full keyspace deletion.
4. **Register Findings & Two-State Revert Verification**:
   - Register all findings in `docs/security/findings.yaml`.
   - Validate two-state revert proofs via `scripts/verify_revert.sh`.

---

## 5. Test Strategy

1. **Adversarial Pub/Sub Attack Tests** (`internal/redis/pentest_pubsub_hmac_regression_test.go`):
   - Forge messages on `ja4proxy:dial:change` and `ja4proxy:config:reload` with no signature, invalid signature, and expired timestamp.
   - Assert all forged messages are dropped.
2. **Backup Tombstone Resurrection Tests** (`internal/backup/restore_test.go`):
   - Create backup containing `session:192.0.2.1`, `ratelimit:ip:192.0.2.1`, `offense:192.0.2.1`, and `audit:last_score:192.0.2.1`.
   - Add `192.0.2.1` to tombstone file.
   - Run `Restore` and assert zero keys for `192.0.2.1` are written to Redis.
3. **GDPR Deletion Coverage Tests** (`tests/unit/test_gdpr_delete.py`):
   - Populate mock Redis with entries across all 18 IP-keyed namespaces.
   - Run `scripts/gdpr_delete.py --ip 192.0.2.1`.
   - Assert all keys matching the target IP are purged.
4. **Two-State Revert Proofs**:
   - Run `scripts/verify_revert.sh` for every registered finding.

---

## 6. Acceptance Criteria

- [ ] All critical Pub/Sub channels enforce HMAC signature verification.
- [ ] `internal/backup/classify.go` `perIPExtractors` covers all 10+ IP-keyed namespaces defined in `REDIS_SCHEMA.md`.
- [ ] Backup restore test proves tombstoned IPs cannot resurrect `ratelimit`, `session`, `offense`, or `audit` keys.
- [ ] `scripts/gdpr_delete.py` purges all active IP-keyed namespaces.
- [ ] All findings registered in `docs/security/findings.yaml` with passing two-state proofs (`scripts/verify_revert.sh`).
- [ ] Full `make preflight` (lint, scan, test, test-race) passes 100%.

---

## 7. Out of Scope

- Upstream Redis C-level memory corruption bugs.
- Network routing layer sniffing (Redis TLS encryption configuration covered in deployment manifests).