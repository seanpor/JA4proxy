# Remediation Waves & Sequencing DAG

> **Purpose:** Concrete, ordered execution plan for the 54 canonical findings in
> `docs/security/findings.yaml`. Groups them into four waves aligned with the
> SLA tiers from `docs/security/SEVERITY_RUBRIC.md` and shows the blocking
> relationships that govern execution order.
>
> **Source of truth:** `docs/security/findings.yaml`. This document is a human
> view — regenerate it from the register when material additions land. A diff
> on this file without a matching diff on `findings.yaml` is suspicious.
>
> **Authored under:** Phase 121f (2026-04-19).

---

## 1. How waves work

Each finding carries a CVSS v3.1 severity. The rubric (`SEVERITY_RUBRIC.md`)
maps severity to an SLA. Waves are SLA-aligned batches, not strict time gates
— if a wave-3 finding gets fixed alongside a wave-1 item because they share a
file, that's fine. The point of wave labelling is:

- **Prioritisation:** wave 1 is what on-call should be looking at this week.
- **Dependency visibility:** a wave-2 fix that blocks a wave-1 fix is
  surfaced, not discovered two days before the SLA breach.
- **Accounting:** "Wave N complete" is a single predicate the close-out gate
  (Phase 121k) can verify.

| Wave | SLA window | Severity | Count | Definition of done |
|------|-----------|----------|-------|--------------------|
| **1 — Now**        | 7 days   | CRITICAL | 10 | Every listed canonical ID has `status ≥ VERIFIED` |
| **2 — Next 30d**   | 30 days  | HIGH     | 14 | Every listed canonical ID has `status ≥ VERIFIED` |
| **3 — Next 60d**   | 60 days  | MEDIUM   | 21 | Every listed canonical ID has `status ≥ VERIFIED` |
| **4 — Next 120d**  | 120 days | LOW      |  9 | Every listed canonical ID has `status ≥ VERIFIED` |

Promotion from `VERIFIED` to `CLOSED` happens automatically 14 days after
verification (see `CLOSURE_VERIFICATION.md`). Wave completion uses `≥ VERIFIED`
so the 14-day cool-off does not stall the gate.

---

## 2. Dependency DAG (load-bearing edges only)

Not every finding has a real predecessor. The edges below are the ones where
executing B before A produces duplicate work, regressions, or a verification
gap. Everything not drawn here is independent.

```
Wave 1 (CRITICAL — 7d)
─────────────────────────────────────────────────────────────
 0001 PROXY v2 spoofing ────┐
 0002 PROXY v2 smuggling ───┼──▶ share cmd/proxy PROXY parser; fix in one PR
 0006 XFF IP spoofing ──────┘

 0003 TLS ClientHello frag ─┬──▶ 0011 (HIGH) TLS record reassembly
 0004 ALPN browser bypass ──┤    ── 0003 seals the byte-level evasion; 0004
 0005 X-JA4 header bypass ──┘       closes the API-level evasion. Do 0003
                                    before 0011 to avoid redoing the reassembler.

 0007 Webhook SSRF (mgmt API) ── independent; Python-only
 0008 /metrics+/health unauth ── blocks 0026 (MEDIUM rate-limit hardening)
 0009 goroutine leak ─────────── blocks 0012 (HIGH unbounded accept loop)
 0010 Redis fail-open ────────── blocks 0019 (HIGH PubSub HMAC) — PubSub work
                                  assumes Redis failures are surfaced, not swallowed

Wave 2 (HIGH — 30d)
─────────────────────────────────────────────────────────────
 0011 TLS record reassembly       ◀── 0003
 0012 unbounded goroutines        ◀── 0009
 0013 tarpit slot exhaustion      ── independent
 0015 HAProxy default creds ──┐
 0016 privileged cAdvisor     ├── docker-compose.poc.yml; land as one infra PR
 0017 Docker socket to Promtail─┤
 0018 CI/CD token on cmdline ─┘
 0019 Redis PubSub HMAC          ◀── 0010
 0020 stored XSS (ban IP)        ── independent; Python React UI
 0021 mgmt API in-mem rate limit ── blocks 0038 (MEDIUM TOCTOU race)
 0022 trusted CIDR /0            ◀── 0006 (share parser hardening)
 0023 test secret fallback       ── independent
 0024 JWT cookie secure flag     ── blocks 0034 (MEDIUM default-admin)
 0048 verbose error logging      ── blocks 0029 (MEDIUM log sanitisation)

Wave 3 (MEDIUM — 60d)
─────────────────────────────────────────────────────────────
 0025 committed .env              ◀── 0018 (rotate before scrub)
 0026 health/metrics rate limit   ◀── 0008
 0027 Redis SNI key injection     ── independent
 0028 Python backend timeout      ── independent
 0029 log sanitisation complete   ◀── 0048
 0030 unbounded known_ja4 SET     ── independent
 0031 XADD no backpressure (Go)   ◀── 0010
 0032 OIDC signature not verified ── independent (Python mgmt API)
 0033 Python TLS thread isolation ── independent
 0034 JWT role defaults admin     ◀── 0024
 0035 DSAR export OOM             ── independent
 0036 IPv6 burst parse bug        ── independent
 0037 blocklist double-check      ◀── 0010 (Redis fail-closed assumption)
 0038 rate limit TOCTOU race      ◀── 0021
 0047 Redis TLS binds all ifaces  ◀── 0015 (related, land together)
 0049 weak AbuseIPDB key handling ── independent
 0050 Redis ACLs disabled default ── blocks 0052 (per-service users)
 0051 webhook secrets in memory   ── independent
 0052 per-service Redis users     ◀── 0050
 0054 config path traversal       ── independent
 0055 integration TLS verify      ── independent

Wave 4 (LOW — 120d)
─────────────────────────────────────────────────────────────
 0039 sensitive-data regex FP     ── independent
 0040 start-poc.sh echoes pw      ── independent
 0041 config reload path hardcoded── independent
 0042 Redis Unix socket 777       ◀── 0050 (ACL work touches same config)
 0043 Redis ACL users share pw    ◀── 0050
 0044 unpinned Python deps        ── independent
 0045 Grafana bound to all ifaces ◀── 0016 (same compose file as cAdvisor)
 0046 K8s DaemonSet probes/NetPol ── independent
 0053 Redis password in logs      ◀── 0029 (sanitisation covers this)
```

**Legend:**
- `A ── independent`: no predecessors; can start today.
- `A ◀── B`: A is blocked by B. Do B first.
- `{A,B,C} ──▶ X`: A/B/C share a fix surface with X; bundle them.

---

## 3. Wave 1 — Now (CRITICAL, 7d SLA)

Ten findings. Expected ordering: drive the three PROXY/XFF parser items as
one cmd/proxy PR, the three TLS/ALPN/header-injection items as another,
then the four independents.

| ID | Title | Predecessors | Bundle |
|----|-------|--------------|--------|
| `JA4PROXY-2026-0001` | PROXY v2 spoofing from untrusted source | — | PROXY parser |
| `JA4PROXY-2026-0002` | PROXY v2 smuggling (double header)      | — | PROXY parser |
| `JA4PROXY-2026-0003` | TLS ClientHello fragmentation bypass    | — | TLS reassembly |
| `JA4PROXY-2026-0004` | ALPN browser bypass                     | — | TLS reassembly |
| `JA4PROXY-2026-0005` | X-JA4-Fingerprint HTTP header injection | — | TLS reassembly |
| `JA4PROXY-2026-0006` | X-Forwarded-For spoofing (Python proxy) | — | PROXY parser |
| `JA4PROXY-2026-0007` | Webhook URL SSRF (Management API)       | — | Mgmt API |
| `JA4PROXY-2026-0008` | Unauthenticated /metrics, /health/deep  | — | Mgmt API |
| `JA4PROXY-2026-0009` | Goroutine leak in forward()/tarpit()    | — | Go runtime |
| `JA4PROXY-2026-0010` | Redis fail-open masks misconfig         | — | Redis |

**Done when:** all 10 are `status: VERIFIED` or `CLOSED` in the register, and
`make verify-findings-green` includes at least one regression test per ID.

---

## 4. Wave 2 — Next 30d (HIGH, 30d SLA)

Fourteen findings. The infra cluster (0015/0016/0017/0018) is a single
`docker-compose.poc.yml` + CI review PR. The Go runtime cluster
(0012 ← 0009; 0021 blocks 0038) should land after its Wave-1 predecessors.

| ID | Title | Predecessors | Notes |
|----|-------|--------------|-------|
| `JA4PROXY-2026-0011` | TLS record reassembly + protocol lockdown | `0003` | Finish the reassembler |
| `JA4PROXY-2026-0012` | Unbounded goroutines from accept loop     | `0009` | Needs goroutine leak fix first |
| `JA4PROXY-2026-0013` | Tarpit slot exhaustion via no timeout     | — | — |
| `JA4PROXY-2026-0015` | HAProxy stats default credentials         | — | Infra bundle |
| `JA4PROXY-2026-0016` | Privileged cAdvisor container             | — | Infra bundle |
| `JA4PROXY-2026-0017` | Docker socket exposed to Promtail         | — | Infra bundle |
| `JA4PROXY-2026-0018` | CI/CD token on command line               | — | Infra bundle |
| `JA4PROXY-2026-0019` | Redis PubSub poisoning (no HMAC)          | `0010` | HMAC work assumes Redis errors are loud |
| `JA4PROXY-2026-0020` | Stored XSS in Management UI              | — | Python/React UI |
| `JA4PROXY-2026-0021` | Mgmt API in-memory rate limit bypass      | — | — |
| `JA4PROXY-2026-0022` | Trusted CIDR /0 acceptance                | `0006` | Share XFF parser hardening |
| `JA4PROXY-2026-0023` | Test secret fallback in prod path         | — | — |
| `JA4PROXY-2026-0024` | JWT cookie Secure flag not gated to prod  | — | Blocks `0034` |
| `JA4PROXY-2026-0048` | Verbose error logging exposes internals   | — | Blocks `0029` |

**Done when:** all 14 are `status ≥ VERIFIED`.

---

## 5. Wave 3 — Next 60d (MEDIUM, 60d SLA)

Twenty-one findings. Several are chained behind Wave-1/2 work (marked with ◀).
The rest can be parallelised across available owners.

| ID | Title | Predecessors |
|----|-------|--------------|
| `JA4PROXY-2026-0025` | Committed .env with real credentials       | `0018` (rotate before scrub) |
| `JA4PROXY-2026-0026` | Health/metrics endpoints missing rate limit | `0008` |
| `JA4PROXY-2026-0027` | Redis key injection via SNI hostnames      | — |
| `JA4PROXY-2026-0028` | Python backend connection timeout missing  | — |
| `JA4PROXY-2026-0029` | Log sanitisation incomplete (ctrl chars)   | `0048` |
| `JA4PROXY-2026-0030` | Unbounded behavioral:known_ja4 Redis SET   | — |
| `JA4PROXY-2026-0031` | XADD fire-and-forget without backpressure  | `0010` |
| `JA4PROXY-2026-0032` | OIDC token signature not verified          | — |
| `JA4PROXY-2026-0033` | Python TLS parser thread isolation         | — |
| `JA4PROXY-2026-0034` | Invalid JWT role defaults to admin         | `0024` |
| `JA4PROXY-2026-0035` | DSAR export reads entire stream (OOM)      | — |
| `JA4PROXY-2026-0036` | IPv6 burst detection parsing bug           | — |
| `JA4PROXY-2026-0037` | Blocklist double-check with stale signals  | `0010` |
| `JA4PROXY-2026-0038` | Rate-limit TOCTOU race (INCR/EXPIRE)       | `0021` |
| `JA4PROXY-2026-0047` | Redis TLS binds to all interfaces          | `0015` (infra bundle) |
| `JA4PROXY-2026-0049` | Weak AbuseIPDB API key handling            | — |
| `JA4PROXY-2026-0050` | Redis ACLs disabled by default             | — (blocks `0052`) |
| `JA4PROXY-2026-0051` | Webhook secrets in memory                  | — |
| `JA4PROXY-2026-0052` | No per-service Redis user enforcement      | `0050` |
| `JA4PROXY-2026-0054` | Configuration path traversal prevention    | — |
| `JA4PROXY-2026-0055` | Integration TLS verification missing       | — |

**Done when:** all 21 are `status ≥ VERIFIED`.

---

## 6. Wave 4 — Next 120d (LOW, 120d SLA)

Nine findings. Mostly defence-in-depth. No finding here is on the hot path of
a known exploit; do them as time allows, bundling where the file surface
overlaps with earlier-wave work.

| ID | Title | Predecessors |
|----|-------|--------------|
| `JA4PROXY-2026-0039` | Sensitive-data filter matches timestamps (FP) | — |
| `JA4PROXY-2026-0040` | start-poc.sh echoes passwords to console     | — |
| `JA4PROXY-2026-0041` | Config reload path hardcoded (ignores env)   | — |
| `JA4PROXY-2026-0042` | Redis Unix socket permissions 777            | `0050` |
| `JA4PROXY-2026-0043` | Redis ACL users share same password          | `0050` |
| `JA4PROXY-2026-0044` | Unpinned Python deps (Management API)        | — |
| `JA4PROXY-2026-0045` | Grafana bound to all interfaces              | `0016` (same compose) |
| `JA4PROXY-2026-0046` | K8s DaemonSet missing probes + NetworkPolicy | — |
| `JA4PROXY-2026-0053` | Redis password partial match in logs         | `0029` |

**Done when:** all 9 are `status ≥ VERIFIED`.

---

## 7. Cross-wave observations

- **PROXY/XFF parser (0001, 0002, 0006, 0022)** spans Waves 1 and 2 but is
  one code surface. Fixing 0001/0002/0006 in a single PR and following with
  a small tightening PR for 0022 is the path of least regression risk.
- **Redis fail-closed posture (0010 → 0019, 0031, 0037)** is a policy shift,
  not a patch. Land 0010 first, then the dependents can be routine tests.
- **Docker compose cluster (0015, 0016, 0017, 0018, 0045, 0047)** touches the
  same file(s). Doing these as six separate PRs will cause six merge
  conflicts — bundle them into one wave-2 PR and one wave-3/4 follow-up.
- **ACL/credentials cluster (0018 → 0025; 0050 → 0042, 0043, 0052)**: rotate
  before removing from git history, then harden ACL defaults, then split
  per-service users. Doing these out of order makes the earlier fixes
  pointless (secrets in git history stay compromised if rotated first).

---

## 8. Wave completion gate

The Phase 121k close-out gate (`make phase-121-verify`) will run, for each
wave in scope, the predicate:

```bash
python3 scripts/findings_register.py list --wave=N --not-verified --json \
  | jq 'length == 0'
```

This requires `findings_register.py` to gain a `--wave` filter and a
`--not-verified` flag. That tooling extension belongs to Phase 121k; it is
out of scope for 121f. For now the waves are enumerated here by canonical ID
and each wave's "done" predicate is `all IDs have status ≥ VERIFIED in
findings.yaml`.

---

## 9. Maintenance

- When a new finding lands via `INTAKE_RUNBOOK.md`, assign its wave from
  severity and update the table above.
- When a blocking edge is added or removed, update §2 (ASCII DAG) and the
  per-wave tables in the same commit.
- Waves do not change once declared. A finding moves between waves only if
  its severity is formally reclassified per the rubric.
