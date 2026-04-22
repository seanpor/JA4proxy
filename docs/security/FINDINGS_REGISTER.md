# JA4proxy Findings Register

> **Source of truth:** [`findings.yaml`](findings.yaml). This markdown file is
> a generated human-readable view. Regenerate with
> `python3 scripts/findings_register.py render`.

The findings register is the single canonical list of every security finding
the project has ever acknowledged — whether discovered by an internal pentest
campaign, an external red team, a vendor audit, or a routine code review. A
finding is opened once, fixed once, tested once, and closed once.

## Why this exists

Between April 2026 pentest campaigns and red team assessments, roughly 98
sub-phase entries accumulated across 13 separate phase documents with no
shared IDs and heavy duplication (see `docs/phases/PHASE_121.md` §1 for the
full context). The register collapses that pile into a managed backlog with
canonical IDs, unambiguous severity, SLA tracking, and a regression-test
requirement for closure.

## ID scheme

`JA4PROXY-YYYY-NNNN` where `YYYY` is the calendar year the canonical ID was
allocated (not the year of discovery — a finding discovered in 2024 and
canonicalised in 2026 is a 2026 ID). `NNNN` is a zero-padded monotonic
counter, never reused. IDs are allocated by `scripts/findings_register.py add`;
never assigned by hand.

## Workflow

```
           ┌──────┐ add       ┌─────────────┐ PR opened  ┌───────┐
report ──▶ │ OPEN │ ────────▶ │IN_PROGRESS  │ ─────────▶ │ FIXED │
           └──────┘           └─────────────┘            └───┬───┘
                                                             │ reviewer
                                                             │ verifies
                                                             ▼
                            ┌────────┐  14 days no    ┌──────────┐
                            │ CLOSED │◀───regression──│ VERIFIED │
                            └────────┘                └──────────┘
```

Promotion rules live in `docs/security/CLOSURE_VERIFICATION.md`. The key
enforcement rule is: **a finding cannot reach `CLOSED` without a populated
`regression_test` that exists and is green** (checked by `make verify-findings`).

## Severity and SLA

Severity labels are assigned per `docs/security/SEVERITY_RUBRIC.md`, not
copied from external CVSS scores. Each level carries an SLA measured from the
earliest `discovered` date across the finding's `source_refs`:

| Severity | SLA (fix → verified) |
|----------|----------------------|
| CRITICAL | 7 days fix / 14 days verified |
| HIGH     | 30 days |
| MEDIUM   | 60 days |
| LOW      | 120 days |

`scripts/findings_register.py list --sla-breach` returns all entries past
their `due` date.

## Lanes (owner split)

Findings are assigned to one of three lanes for ownership purposes, even
while a single engineer may hold all three hats:

| Lane | Scope |
|------|-------|
| `go-proxy` | Everything under `cmd/proxy/`, `cmd/syncagent/`, `cmd/ja4check/`, `cmd/ja4proxy-cli/`, `internal/` |
| `python-management` | `management/`, `src/analytics/`, `src/security/`, `src/tap/`, `src/tls/` |
| `infrastructure` | `Dockerfile*`, `docker-compose*.yml`, `deploy/`, `scripts/`, `.github/`, Jenkins, Redis config, HAProxy config |

Full ownership policy in `docs/security/OWNERSHIP.md`.

## Intake

When a new report arrives, follow `docs/security/INTAKE_RUNBOOK.md`. The
short version: run `dedup-hint` against each reported finding, append to an
existing canonical entry via `source_refs` if it's a duplicate, or `add` a
new canonical ID if it's novel.

## Schema

See header comments at the top of [`findings.yaml`](findings.yaml) for the
authoritative schema. Minimum required fields at creation time: `id`,
`title`, `severity`, `severity_rationale`, `source_refs`, `discovered`,
`due`, `status`, `lane`. Other fields populate as the finding moves
through the workflow.

## Migration plan

Markdown + YAML is fine up to ~100 canonical entries. When the register
exceeds 100 entries, migrate to a GitHub Projects board with custom fields
matching this schema and regenerate this markdown from the Projects API.
The migration trigger is documented in `INTAKE_RUNBOOK.md` so it does not
get forgotten.

---

<!-- BEGIN GENERATED: findings_register.py render -->

## Register snapshot (2026-04-22)

**Total:** 54 canonical finding(s).

| Severity | Count | Status | Count |
|----------|-------|--------|-------|
| CRITICAL | 10 | OPEN | 0 |
| HIGH | 14 | IN_PROGRESS | 0 |
| MEDIUM | 21 | FIXED | 54 |
| LOW | 9 | VERIFIED | 0 |
|  |  | CLOSED | 0 |
|  |  | DUPLICATE | 0 |

### SLA breaches (5)

| ID | Severity | Due | Title |
|----|----------|-----|-------|
| JA4PROXY-2026-0001 | CRITICAL | 2026-04-16 | PROXY Protocol v2 Spoofing from Untrusted Source |
| JA4PROXY-2026-0002 | CRITICAL | 2026-04-16 | PROXY Protocol v2 Smuggling via Double Header Injection |
| JA4PROXY-2026-0003 | CRITICAL | 2026-04-16 | TLS ClientHello Fragmentation Bypass |
| JA4PROXY-2026-0006 | CRITICAL | 2026-04-16 | X-Forwarded-For Header IP Spoofing (Python Proxy) |
| JA4PROXY-2026-0007 | CRITICAL | 2026-04-16 | Webhook URL SSRF (Management API) |

### All findings

| ID | Severity | Status | Lane | Due | Title |
|----|----------|--------|------|-----|-------|
| JA4PROXY-2026-0001 | CRITICAL | FIXED | go-proxy | 2026-04-16 | PROXY Protocol v2 Spoofing from Untrusted Source |
| JA4PROXY-2026-0002 | CRITICAL | FIXED | go-proxy | 2026-04-16 | PROXY Protocol v2 Smuggling via Double Header Injection |
| JA4PROXY-2026-0003 | CRITICAL | FIXED | go-proxy | 2026-04-16 | TLS ClientHello Fragmentation Bypass |
| JA4PROXY-2026-0004 | CRITICAL | FIXED | go-proxy | 2026-04-24 | ALPN Browser Bypass Trusts Attacker-Controlled Signal |
| JA4PROXY-2026-0005 | CRITICAL | FIXED | go-proxy | 2026-04-24 | X-JA4-Fingerprint HTTP Header Injection Bypass |
| JA4PROXY-2026-0006 | CRITICAL | FIXED | python-management | 2026-04-16 | X-Forwarded-For Header IP Spoofing (Python Proxy) |
| JA4PROXY-2026-0007 | CRITICAL | FIXED | python-management | 2026-04-16 | Webhook URL SSRF (Management API) |
| JA4PROXY-2026-0008 | CRITICAL | FIXED | go-proxy | 2026-04-24 | Unauthenticated /metrics and /health/deep Endpoints |
| JA4PROXY-2026-0009 | CRITICAL | FIXED | go-proxy | 2026-04-24 | Goroutine Leak in forward() and tarpit() |
| JA4PROXY-2026-0010 | CRITICAL | FIXED | go-proxy | 2026-04-24 | Redis Fail-Open Masks Misconfiguration |
| JA4PROXY-2026-0011 | HIGH | FIXED | go-proxy | 2026-05-17 | TLS Record Reassembly and Protocol Lockdown |
| JA4PROXY-2026-0012 | HIGH | FIXED | go-proxy | 2026-05-17 | Unbounded Goroutines from Accept Loop |
| JA4PROXY-2026-0013 | HIGH | FIXED | go-proxy | 2026-05-17 | Tarpit Slot Exhaustion via Timeout-Free Connections |
| JA4PROXY-2026-0015 | HIGH | FIXED | infrastructure | 2026-05-17 | HAProxy Stats Default Credentials |
| JA4PROXY-2026-0016 | HIGH | FIXED | infrastructure | 2026-05-17 | Privileged cAdvisor Container |
| JA4PROXY-2026-0017 | HIGH | FIXED | infrastructure | 2026-05-17 | Docker Socket Exposed to Promtail |
| JA4PROXY-2026-0018 | HIGH | FIXED | infrastructure | 2026-05-17 | CI/CD Token Exposed on Command Line |
| JA4PROXY-2026-0019 | HIGH | FIXED | go-proxy | 2026-05-17 | Redis PubSub Poisoning (No HMAC on Critical Channels) |
| JA4PROXY-2026-0020 | HIGH | FIXED | python-management | 2026-05-17 | Stored XSS in Management UI (Ban IP in Alpine.js) |
| JA4PROXY-2026-0021 | HIGH | FIXED | python-management | 2026-05-17 | In-Memory Rate Limiting Bypass (Management API) |
| JA4PROXY-2026-0022 | HIGH | FIXED | python-management | 2026-05-17 | Trusted CIDR /0 Acceptance (Python Proxy) |
| JA4PROXY-2026-0023 | HIGH | FIXED | python-management | 2026-05-17 | Test Secret Fallback in Production Path |
| JA4PROXY-2026-0024 | HIGH | FIXED | python-management | 2026-05-17 | JWT Cookie Secure Flag Not Gated to Production |
| JA4PROXY-2026-0025 | MEDIUM | FIXED | infrastructure | 2026-06-16 | Committed .env With Real Credentials |
| JA4PROXY-2026-0026 | MEDIUM | FIXED | go-proxy | 2026-06-16 | Unauthenticated Health/Metrics Endpoints Missing Rate Limiting |
| JA4PROXY-2026-0027 | MEDIUM | FIXED | python-management | 2026-06-16 | Redis Key Injection via SNI Hostnames |
| JA4PROXY-2026-0028 | MEDIUM | FIXED | python-management | 2026-06-16 | Python Backend Connection Timeout Missing |
| JA4PROXY-2026-0029 | MEDIUM | FIXED | python-management | 2026-06-16 | Log Sanitisation Incomplete (Control Characters, ANSI Escapes) |
| JA4PROXY-2026-0030 | MEDIUM | FIXED | python-management | 2026-06-16 | Unbounded behavioral:known_ja4 Redis SET |
| JA4PROXY-2026-0031 | MEDIUM | FIXED | go-proxy | 2026-06-16 | XADD Fire-and-Forget Without Backpressure (Go) |
| JA4PROXY-2026-0032 | MEDIUM | FIXED | python-management | 2026-06-16 | OIDC Token Signature Not Verified |
| JA4PROXY-2026-0033 | MEDIUM | FIXED | python-management | 2026-06-16 | Python TLS Parser Runs in ThreadPool Without Memory Isolation |
| JA4PROXY-2026-0034 | MEDIUM | FIXED | python-management | 2026-06-16 | Invalid JWT Role Defaults to Admin |
| JA4PROXY-2026-0035 | MEDIUM | FIXED | python-management | 2026-06-16 | DSAR Export Reads Entire Redis Stream Into Memory |
| JA4PROXY-2026-0036 | MEDIUM | FIXED | python-management | 2026-06-16 | IPv6 Burst Detection Parsing Bug |
| JA4PROXY-2026-0037 | MEDIUM | FIXED | go-proxy | 2026-06-16 | Blocklist Double-Check with Stale Signals |
| JA4PROXY-2026-0038 | MEDIUM | FIXED | python-management | 2026-06-16 | Rate Limit TOCTOU Race (INCR/EXPIRE Non-Atomic) |
| JA4PROXY-2026-0039 | LOW | FIXED | python-management | 2026-08-15 | Sensitive Data Filter Matches Timestamps (False Positive) |
| JA4PROXY-2026-0040 | LOW | FIXED | infrastructure | 2026-08-15 | start-poc.sh Echoes Passwords to Console |
| JA4PROXY-2026-0041 | LOW | FIXED | go-proxy | 2026-08-15 | Config Reload Path Hardcoded (Ignores CONFIG_PATH) |
| JA4PROXY-2026-0042 | LOW | FIXED | infrastructure | 2026-08-15 | Redis Unix Socket Permissions 777 |
| JA4PROXY-2026-0043 | LOW | FIXED | infrastructure | 2026-08-15 | Redis ACL Users All Share Same Password |
| JA4PROXY-2026-0044 | LOW | FIXED | python-management | 2026-08-15 | Unpinned Python Dependencies (Management API) |
| JA4PROXY-2026-0045 | LOW | FIXED | infrastructure | 2026-08-15 | Grafana Bound to All Interfaces in Monitoring Stack |
| JA4PROXY-2026-0046 | LOW | FIXED | infrastructure | 2026-08-15 | K8s DaemonSet Missing Probes and NetworkPolicy |
| JA4PROXY-2026-0047 | MEDIUM | FIXED | infrastructure | 2026-06-16 | Redis TLS Binds to All Interfaces (Duplicate/Related to 0015) |
| JA4PROXY-2026-0048 | HIGH | FIXED | go-proxy | 2026-05-17 | Verbose Error Logging Exposes Internals |
| JA4PROXY-2026-0049 | MEDIUM | FIXED | go-proxy | 2026-06-16 | Weak AbuseIPDB API Key Handling |
| JA4PROXY-2026-0050 | MEDIUM | FIXED | infrastructure | 2026-06-16 | Redis ACLs Disabled by Default |
| JA4PROXY-2026-0051 | MEDIUM | FIXED | go-proxy | 2026-06-16 | Webhook Secrets in Memory |
| JA4PROXY-2026-0052 | MEDIUM | FIXED | infrastructure | 2026-06-16 | No Per-Service Redis User Enforcement |
| JA4PROXY-2026-0053 | LOW | FIXED | python-management | 2026-08-15 | Redis Password in Log Messages (Partial) |
| JA4PROXY-2026-0054 | MEDIUM | FIXED | python-management | 2026-06-16 | Configuration Path Traversal Prevention |
| JA4PROXY-2026-0055 | MEDIUM | FIXED | infrastructure | 2026-06-16 | Integration TLS Verification Missing |

<!-- END GENERATED -->
