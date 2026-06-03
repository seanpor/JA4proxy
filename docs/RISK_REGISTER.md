<!--
title: Risk Register
audience: Security Teams, Auditors, Procurement, Engineering Management
last_reviewed: 2026-04-24
phase: 106b
-->

# JA4proxy Risk Register

This document is a curated, consolidated index of risks already documented
elsewhere in the repository — the canonical findings register, the threat
model, the comprehensive security audit, the DMZ deployment readiness
assessment, the dependency exception files, and the operational runbooks.
It is the artefact a SOC 2 / ISO 27001 auditor or a procurement team expects
to see.

This register is **not** a new risk analysis. Every row traces to an
existing source document. Where multiple documents describe the same
underlying risk, the most authoritative source is cited and the others are
listed under "See also". For the live, machine-readable backlog of every
specific vulnerability, see
[`docs/security/findings.yaml`](security/findings.yaml) and its rendered
view in
[`docs/security/FINDINGS_REGISTER.md`](security/FINDINGS_REGISTER.md).

## Deduplication methodology

Two risks are treated as the same entry if they share **(attack surface,
failure mode, primary mitigation)**. When duplicates collapse, the most
authoritative source is cited and the others are listed in the row's
"Source" cell or in the prose under "See also". A single canonical
finding (e.g. `JA4PROXY-2026-0001`) may already aggregate several
phase-specific entries; this register goes one level higher and groups
multiple canonical findings whose root cause and remediation are the
same (for example, the four distinct "untrusted-input becomes a security
bypass" findings collapse into one register row about ALPN/JA4-header
spoofing). When an aggregated row covers more than one finding ID, the
specific IDs are listed in the row.

## Categories

The six categories below are mutually exclusive at the register level:

- **Technical** — resource exhaustion, race conditions, leaks, parsing
  defects, evasion of detection signals.
- **Operational** — failure modes that show up at runtime and are owned
  by the on-call: outage scenarios, dependency outages, capacity
  saturation, configuration drift, certificate expiry.
- **Security** — vulnerabilities and weaknesses in the codebase that
  give an attacker a privilege, identity, integrity, confidentiality,
  or availability advantage they should not have.
- **Compliance** — gaps against GDPR, PCI-DSS, SOC 2 and similar
  frameworks where the system would not pass an audit today.
- **Supply-chain** — risks originating outside the codebase: third-party
  dependencies, container base images, build provenance, threat
  intelligence feed integrity.
- **Commercial** — risks to the project's continuity, support model,
  and user adoption that affect buyers and operators.

## Pre-disclosure embargo

Pre-disclosure findings — those whose status is `embargoed`, `private`,
or `draft` — are excluded from this public register. The canonical
findings register (`docs/security/findings.yaml`) does not currently
carry a `disclosure_status` field; every finding present at the time
of publication is `FIXED` or `CLOSED` and has been disclosed publicly
(see `notes` on each entry and the corresponding regression test). If
a future finding is added in an embargoed state, its row in this
register MUST be omitted until disclosure. The intake runbook
(`docs/security/INTAKE_RUNBOOK.md`) is the authoritative gate.

## The register

| ID | Risk | Category | Likelihood | Impact | Owner | Mitigation | Residual | Status | Source |
|----|------|----------|------------|--------|-------|------------|----------|--------|--------|
| RR-001 | TLS ClientHello fragmentation or attacker-controlled hint (ALPN, X-JA4 header) bypasses JA4 fingerprinting and the entire scoring pipeline | Security | Medium | High | Security lead | Reassembly loop with protocol lockdown (first byte must be 0x16); ALPN bypass disabled by default; X-JA4 HTTP header path removed; regression tests `JA4PROXY-2026-0003`, `0004`, `0005`, `0011` | Low | Mitigated | [findings.yaml JA4PROXY-2026-0003/0004/0005/0011](security/findings.yaml) |
| RR-002 | PROXY protocol v2 spoofing or smuggling from untrusted source forges the source IP seen by the proxy and backend | Security | Medium | High | Security lead | Header strip + anti-smuggling check on all data from untrusted CIDRs; fail-closed on trusted CIDRs that omit the header; rightmost-IP rule for `X-Forwarded-For`; CIDR `/0` rejected at config load | Low | Mitigated | [findings.yaml JA4PROXY-2026-0001/0002/0006/0022](security/findings.yaml) |
| RR-003 | Webhook URL accepts attacker-controlled URLs and turns the proxy into an SSRF gadget against internal metadata services | Security | Low | High | Security lead | Pydantic validator rejects non-http(s) schemes, loopback / link-local / RFC1918 / reserved IP literals, and DNS resolutions that land in internal ranges | Low | Mitigated | [findings.yaml JA4PROXY-2026-0007](security/findings.yaml) |
| RR-004 | Unauthenticated `/metrics` and `/health/deep` endpoints leak operational state usable for reconnaissance | Security | High | Medium | Security lead | Metrics bind defaults to loopback; remote bind requires authentication.enabled=true; Phase 118h adds shared-secret auth and per-IP rate limiting on the observability port | Low | Mitigated | [findings.yaml JA4PROXY-2026-0008/0026](security/findings.yaml) |
| RR-005 | Redis fail-open behaviour silently tolerates a misconfigured (passwordless or remote) Redis, exposing all security state | Security | Low | High | Security lead | Startup validation refuses to boot when Redis target is non-loopback and password is missing; ACL users disabled-by-default warning at startup; per-service ACL passwords with distinct credentials | Low | Mitigated | [findings.yaml JA4PROXY-2026-0010/0043/0050/0052](security/findings.yaml) |
| RR-006 | Test-mode authentication fallback (`MANAGEMENT_TEST_MODE=1` with hardcoded JWT secret) reachable in production builds | Security | Low | High | Security lead | `_enforce_no_test_mode_in_production()` refuses to boot the FastAPI app if `ENVIRONMENT=production` and test mode is set; OIDC signature verification skip disabled in prod | Low | Mitigated | [findings.yaml JA4PROXY-2026-0023/0032](security/findings.yaml) |
| RR-007 | Stored XSS in management UI via attacker-controlled fields (e.g. banned IP) rendered inside Alpine.js click handlers | Security | Low | Medium | Security lead | All client-controlled values rendered with `tojson` filter inside JavaScript contexts; CSP and HTML-escape defaults retained | Low | Mitigated | [findings.yaml JA4PROXY-2026-0020](security/findings.yaml) |
| RR-008 | In-memory rate limiting on the management API allows distributed brute force across worker processes and resets across restarts | Security | Medium | Medium | Security lead | Redis-backed sliding-window rate limiter with per-IP bucketing and per-user account lockout shared across workers | Low | Mitigated | [findings.yaml JA4PROXY-2026-0021](security/findings.yaml) |
| RR-009 | JWT cookie missing `Secure` flag in production HTTPS deployments allows session interception by network-path attacker | Security | Low | Medium | Security lead | Cookie `secure` flag gated to `ENVIRONMENT=production`; default-on with explicit dev-mode opt-out | Low | Mitigated | [findings.yaml JA4PROXY-2026-0024](security/findings.yaml) |
| RR-010 | JWT with unrecognised role claim escalated silently to admin (fail-open authorisation) | Security | Low | High | Security lead | Unknown role claim now defaults to `Role.auditor` (lowest privilege) with a warning log | Low | Mitigated | [findings.yaml JA4PROXY-2026-0034](security/findings.yaml) |
| RR-011 | Redis pub/sub on security-critical channels (dial change, whitelist add) accepted without authentication, allowing on-network attacker to disable enforcement | Security | Low | High | Security lead | HMAC-SHA256 signing on every critical pub/sub message; verification on every message type; unsigned messages dropped; pub/sub only accepted from authenticated Redis clients | Low | Mitigated | [findings.yaml JA4PROXY-2026-0019](security/findings.yaml) |
| RR-012 | Verbose error logging and unsanitised log output exposes internal paths, Redis keys, control characters, and ANSI escapes that hide log entries | Security | Medium | Low | Security lead | Production log sanitiser strips C0/C1, ANSI, NULs; structured JSON logging redacts paths in production; client-controlled fields routed through `_sanitize_log` | Low | Mitigated | [findings.yaml JA4PROXY-2026-0029/0048](security/findings.yaml) |
| RR-013 | Goroutine leak in `forward()` and `tarpit()`, plus unbounded accept loop, exhaust memory under sustained connection load | Technical | High | High | Maintainer | `<-done; <-done` (or `sync.WaitGroup`) drains both copy goroutines; admit-conn semaphore caps in-flight connections; per-connection buffer accounting | Low | Mitigated | [findings.yaml JA4PROXY-2026-0009/0012](security/findings.yaml) |
| RR-014 | Tarpit slot exhaustion via timeout-free "stall after 1 byte" connections permanently fills the tarpit pool | Technical | High | Medium | Maintainer | `SetReadDeadline` in `tarpit()` with 60s default inactivity timeout; per-IP cap; overflow action; concurrent slot accounting | Low | Mitigated | [findings.yaml JA4PROXY-2026-0013](security/findings.yaml) and [`docs/runbooks/ja4proxy_tarpit_pool_full.md`](runbooks/ja4proxy_tarpit_pool_full.md) |
| RR-015 | XADD fire-and-forget without backpressure accumulates goroutines holding marshalled events when Redis is slow | Technical | Medium | Medium | Maintainer | Buffered channel (cap 1000) with single writer goroutine; events dropped on overflow; 1-second XADD timeout | Low | Mitigated | [findings.yaml JA4PROXY-2026-0031](security/findings.yaml) |
| RR-016 | Python TLS parser executed in `ThreadPoolExecutor` shares the proxy heap with malicious-input parsing paths | Technical | Low | Medium | Maintainer | 16KB max pre-parse size guard before Scapy; Phase 15 Go rewrite removes Scapy entirely from the data path | Low | Mitigated | [findings.yaml JA4PROXY-2026-0033](security/findings.yaml) |
| RR-017 | Beaconing detector evaded by jitter-injecting bots that hold the IAT coefficient of variation above the residential threshold | Technical | Medium | Low | Security lead | Dual-window detection (1h and 24h); composite scorer aggregates across signals so single-signal evasion is not a full bypass; campaign detection in analytics node | Medium | Accepted | [threat-model.md §Phase 9](security/threat-model.md) |
| RR-018 | Unbounded `behavioral:known_ja4` Redis SET grows without TTL/cap, exhausting Redis memory under random ClientHello attacks | Technical | Medium | Medium | Maintainer | 90-day TTL via timestamp-scored ZSET; periodic trimming; capped maximum size with `ZREMRANGEBYRANK` | Low | Mitigated | [findings.yaml JA4PROXY-2026-0030](security/findings.yaml) |
| RR-019 | IPv6 burst detection parsing bug aliases all `/16` IPv6 addresses to the same key, breaking per-IP enforcement on dual-stack deployments | Technical | Low | Medium | Maintainer | `rsplit(':', 1)[0]` (split on last colon) preserves IPv6 canonical form; SNI-derived Redis keys hashed with SHA-256[:16] to avoid collisions | Low | Mitigated | [findings.yaml JA4PROXY-2026-0036/0027](security/findings.yaml) |
| RR-020 | Race conditions on the security path: blocklist double-check between PubSub updates and rate-limit INCR/EXPIRE non-atomic | Technical | Low | Low | Maintainer | Single-call `Check()` in `pipeline.go` returns combined block-and-signals; rate limiter Lua script does INCR+EXPIRE atomically; legacy non-atomic path removed | Low | Mitigated | [findings.yaml JA4PROXY-2026-0037/0038](security/findings.yaml) |
| RR-021 | Redis outage degrades the security pipeline (no enforcement state, no rate limit history); fail-open path is correct but reduces protection | Operational | Medium | High | Operations | Local LRU cache for whitelist decisions; ALLOW cached 30 min, BLOCK 30 s, "Redis blocks but cache allows → cache wins"; circuit breaker on Redis errors; runbook with restart procedure | Medium | Accepted | [`docs/runbooks/disaster_recovery.md`](runbooks/disaster_recovery.md) |
| RR-022 | High Redis latency (>10 ms p99) stalls the proxy hot path and inflates latency SLO burn | Operational | Medium | Medium | Operations | Latency SLO + alert with diagnosis runbook; UNIX-socket option for collocated Redis; pipeline timeouts; switch to read-only fail-open under sustained latency | Medium | Mitigated | [`docs/runbooks/ja4proxy_redis_latency_high.md`](runbooks/ja4proxy_redis_latency_high.md) |
| RR-023 | Total proxy fleet failure (all instances down) cuts traffic at the LB; HAProxy returns 503 to every connection | Operational | Low | High | Operations | Disaster-recovery runbook with rebuild path; horizontal scaling on independent nodes; multi-DC failover playbook for cross-AZ outages | Medium | Mitigated | [`docs/runbooks/disaster_recovery.md`](runbooks/disaster_recovery.md) and [`docs/runbooks/multidc.md`](runbooks/multidc.md) |
| RR-024 | TLS server certificate or mTLS CA expiry causes outage at midnight on the renewal date | Operational | Low | High | Operations | Prometheus metric `ja4proxy_certificate_expiry_seconds` with 30-day and 7-day alert thresholds; renewal runbook; certificate rotation runbook with mTLS dual-trust window | Low | Mitigated | [`docs/runbooks/tls_certificate_rotation.md`](runbooks/tls_certificate_rotation.md) and [`docs/runbooks/ja4proxy_certificate_expiring.md`](runbooks/ja4proxy_certificate_expiring.md) |
| RR-025 | Threat-intelligence feed (Spamhaus DROP/EDROP, MaxMind ASN, AbuseIPDB) becomes stale, poisoned, or unavailable, leading to over-block or under-block | Operational | Medium | Medium | Operations | ETag-based feed manager with leader election; size-sanity check (>50% shrink or >300% growth flagged); per-RIR token bucket; emergency disable via SIGHUP; ALPN browser bypass cannot be hard-blocked by feed poisoning | Low | Mitigated | [`docs/runbooks/feed_management.md`](runbooks/feed_management.md) and [threat-model.md §Phase 8](security/threat-model.md) |
| RR-026 | External API (AbuseIPDB, RDAP) outage or quota exhaustion degrades enrichment signals and may starve the lookup queue | Operational | Medium | Low | Operations | Fail-open: missing enrichment returns neutral score; daily quota counter with backoff; queue-depth metric and alert; emergency disable via config + SIGHUP | Low | Mitigated | [`docs/runbooks/external_api_failures.md`](runbooks/external_api_failures.md) |
| RR-027 | Configuration drift or malformed dial value pushed via SIGHUP / pub/sub takes the proxy out of policy (e.g. dial=0 monitor, or unintended block) | Operational | Medium | Medium | Operations | Dial validator clamps to 0–100; counterfactual logging records "what would have happened"; policy audit trail in `management:policy_audit`; gameday exercise covers dial corruption | Low | Mitigated | [`docs/runbooks/security_policy.md`](runbooks/security_policy.md) and [`docs/runbooks/gameday_scenarios.md`](runbooks/gameday_scenarios.md) |
| RR-028 | Operator errors during scaling, rolling upgrade, or credential rotation cause connection drops or stale credentials in flight | Operational | Medium | Medium | Operations | Graceful drain with HAProxy socket and `drain_timeout_seconds`; zero-downtime rollout runbook; staged credential rotation runbook; gameday exercises | Low | Mitigated | [`docs/runbooks/scaling.md`](runbooks/scaling.md), [`docs/runbooks/zero_downtime_rollouts.md`](runbooks/zero_downtime_rollouts.md), and [`docs/runbooks/credential_rotation.md`](runbooks/credential_rotation.md) |
| RR-029 | Unpinned Python dependencies (`>=` minimums with no upper bound) leave the management API exposed to dependency confusion and malicious version uploads | Supply-chain | Low | Medium | Maintainer | All `management/requirements.txt` entries pinned with `==`; long-term target is `pip-compile --require-hashes`; CVE exception process gates HIGH/CRITICAL CVEs in CI | Low | Mitigated | [findings.yaml JA4PROXY-2026-0044](security/findings.yaml) |
| RR-030 | Container base images use mutable tags (`python:3.11-slim`, `redis:7-alpine`); registry-level image swap or accidental rebuild changes the running image | Supply-chain | Low | Medium | Maintainer | Phase 14 deferred to Phase 15 with rationale; CI uses Trivy to scan resulting images; production images target SHA256 digest pinning post-Go-rewrite | Medium | Accepted | [COMPREHENSIVE_SECURITY_AUDIT.md §2](security/COMPREHENSIVE_SECURITY_AUDIT.md) and [DMZ_READINESS.md §Image signing](DMZ_READINESS.md) |
| RR-031 | No SBOM or container image signing for distributed images; downstream operators cannot prove provenance or audit the dependency tree | Supply-chain | Low | Medium | Maintainer | Roadmap item (Phase 106-series): Syft for SBOM and Cosign for image signing in CI; in the interim, source builds are reproducible from a pinned commit | Medium | Open | [DMZ_READINESS.md §SBOM/Cosign](DMZ_READINESS.md) |
| RR-032 | Vulnerable third-party component (CVE in a pinned dependency or Go module) reaches production before the next dependency-roll cycle | Supply-chain | Medium | Medium | Maintainer | CVE triage SLA (HIGH/CRITICAL ≤7 days, MEDIUM ≤30 days, LOW best-effort); Dependabot / renovate enabled; CVE-exception template with mandatory ≤90-day expiry | Low | Mitigated | [`docs/security/CVE_EXCEPTIONS.md`](security/CVE_EXCEPTIONS.md) |
| RR-033 | Spamhaus DROP/EDROP feed poisoning via DNS hijack of the feed hostname causes legitimate CDN ranges to be hard-blocked | Supply-chain | Low | High | Security lead | HTTPS feed source with cert validation; ETag mismatch alerting; size-sanity check; ALPN browser-bypass means real browsers cannot be hard-blocked even on a poisoned feed; manual operator review on large CIDR-count drift | Medium | Accepted | [threat-model.md §Phase 8](security/threat-model.md) |
| RR-034 | Test secret fallback or test fixtures shipped in production container by mistake (CI/CD or supply-chain compromise) | Supply-chain | Low | High | Security lead | Production startup gate refuses test mode; `.env` files never committed (regression test on git history); CI/CD tokens passed via env-var blocks not CLI; test data isolated outside container build context | Low | Mitigated | [findings.yaml JA4PROXY-2026-0018/0023/0025](security/findings.yaml) |
| RR-035 | GDPR exposure: client IP addresses logged and stored in Redis without an articulated retention policy or right-to-erasure path | Compliance | Medium | Medium | Security lead | Sensitive-data filter on log output; Redis keys carry TTLs; DSAR endpoint with bounded XRANGE pagination; GDPR erasure runbook; documented retention windows in `REDIS_SCHEMA.md` | Low | Mitigated | [COMPREHENSIVE_SECURITY_AUDIT.md §Compliance Gaps](security/COMPREHENSIVE_SECURITY_AUDIT.md) and [`docs/runbooks/gdpr_erasure.md`](runbooks/gdpr_erasure.md) |
| RR-036 | PCI-DSS exposure: credit-card-shaped strings in logs (false-positive or true-positive) and unencrypted Redis traffic between containers | Compliance | Low | Medium | Security lead | Luhn-validated card-number redaction; Redis confined to internal Docker network; Redis TLS on the Phase 15 roadmap; backend TLS is the backend's responsibility (proxy is passthrough) | Medium | Mitigated | [COMPREHENSIVE_SECURITY_AUDIT.md §Compliance Gaps](security/COMPREHENSIVE_SECURITY_AUDIT.md) |
| RR-037 | SOC 2 readiness: gaps in MFA enforcement, in-transit encryption, and continuous monitoring versus CC6.x and CC7.x criteria | Compliance | Medium | Medium | Project sponsor | OIDC + JWT with role-based access; Prometheus + Loki + Alertmanager continuous monitoring; quarterly review against this register and `SERVICE_TARGETS.md`; gap roadmap captured in DMZ readiness | Medium | Open | [COMPREHENSIVE_SECURITY_AUDIT.md §SOC 2 Compliance Issues](security/COMPREHENSIVE_SECURITY_AUDIT.md) |
| RR-038 | Approved security/testing exception (`pytest.PytestUnraisableExceptionWarning`) suppresses an upstream pycares teardown warning that masks future regressions in async DNS handling | Compliance | Low | Low | Maintainer | Single tracked exception (#001) with owner, expiry 2026-12-31, and audit-trail entry; renewed only on explicit user approval | Low | Accepted | [`docs/security/EXCEPTIONS.md`](security/EXCEPTIONS.md) |
| RR-039 | Privileged cAdvisor container and Docker socket mount on Promtail give an in-container attacker container-escape and env-var leakage paths | Security | Low | High | Security lead | cAdvisor dropped to non-privileged with explicit caps (`SYS_PTRACE`, `DAC_READ_SEARCH`) and read-only `/var/run`; Promtail switched to logging driver / docker-socket-proxy with restricted endpoints; Redis Unix-socket perms tightened to 770 with `group_add` | Low | Mitigated | [findings.yaml JA4PROXY-2026-0016/0017/0042](security/findings.yaml) |
| RR-040 | Committed `.env` and password echoes in start scripts surface real credentials in git history, terminal scrollback, and CI logs | Security | Low | Medium | Security lead | `.env` purged from history; pre-commit secret scan; `start-poc.sh`, `status.sh`, `start-monitoring.sh` replace password echoes with `[see .env]` placeholders; HAProxy stats `:?` syntax forces fail-fast on missing credentials | Low | Mitigated | [findings.yaml JA4PROXY-2026-0015/0025/0040](security/findings.yaml) |
| RR-041 | Python-runtime-in-DMZ surface: large stdlib, interpreted code, no static binary; security teams reject on principle | Commercial | Medium | Medium | Project sponsor | Phase 15 Go rewrite is the strategic answer (single static binary, no shell); interim mitigations are read-only filesystem, dropped capabilities, distroless option; documented workaround in DMZ readiness | Medium | Open | [DMZ_READINESS.md §Python Runtime in DMZ](DMZ_READINESS.md) |
| RR-042 | No external-secret-manager integration (Vault, AWS Secrets Manager, Azure Key Vault); enterprise buyers expect secrets at rest off the filesystem | Commercial | Medium | Medium | Project sponsor | Existing env-var injection works with any secret manager that can populate env vars or files at start; documented in DMZ readiness; Vault adapter on the post-Phase-15 roadmap | Medium | Open | [DMZ_READINESS.md §No External Secret Manager Integration](DMZ_READINESS.md) |
| RR-043 | SLSA Level 3 build provenance not yet shipped; container images today carry only SLSA L2 (keyless cosign + SBOM via Phase 202), so a compromised CI runner could in principle emit a backdoored image with a valid signature but no non-falsifiable source-binding attestation | Supply-chain | Low | Medium | Maintainer | ADR-107a (Proposed) records the L3 design via `slsa-github-generator`; verification workflow `slsa-verify.yml` already in place (`workflow_dispatch`); 107c.3/.4 release-pipeline wiring deferred to human-led execution | Medium | Open | [ADR-107a](decisions/ADR-107a-slsa-level-3.md) and [SSDF_MAPPING.md](compliance/SSDF_MAPPING.md) PS.2 / PW.5 |
| RR-044 | No service-level commitments on CVD acknowledgement, triage, or fix timelines; reporters who require a guaranteed response cannot get one from this project | Compliance | Low | Low | Maintainer | Documented as a deliberate position in [CVD_POLICY.md](security/CVD_POLICY.md) §3-4 with a "why no SLA" rationale (self-funded, no oncall rotation, no commercial entity); reporters know in advance, so no false expectations are set; fake SLAs would do more harm than acknowledged absence | Low | Accepted | [CVD_POLICY.md §3-4](security/CVD_POLICY.md) |
| RR-045 | No formal root-cause-analysis template or central RCA register; per-incident RCAs land ad-hoc in finding YAML or per-phase notes, making cross-incident pattern detection harder | Operational | Low | Low | Maintainer | Findings register (`docs/security/findings.yaml`) carries `notes` per finding which serve as informal RCA capture; retrospective stream in `docs/engineering-method/retrospectives/` is the long-term home; formal template is a future enhancement | Low | Open | [SSDF_MAPPING.md](compliance/SSDF_MAPPING.md) RV.3 |

## Review cadence

This register is reviewed **quarterly** by the **maintainer and security
lead**. The review checks for: new canonical findings to incorporate
(via the deduplication rule above), risks whose status moved between
`Open`/`Mitigated`/`Accepted`/`Transferred`, owners that have changed,
and rows whose linked source has been moved or deleted. Findings of the
review are recorded in the same retrospective stream cited by
[`docs/SERVICE_TARGETS.md`](SERVICE_TARGETS.md) — `docs/engineering-method/retrospectives/`
once that directory is populated, otherwise in the per-phase notes
file that triggers the change. Numeric or status changes to a row
must either accompany a finding-register update or cite a runbook
change in the same commit.
