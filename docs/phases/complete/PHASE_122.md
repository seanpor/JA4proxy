# Production Security Review — Internet-Facing Attack Surface Audit

## Goal

A critical, independent security review of the internet-facing code in JA4proxy, conducted from the perspective of a senior penetration tester / security architect. The review targets the Go production proxy (`cmd/proxy/`, `internal/`), the Python prototype proxy (`proxy.py`, `src/`), the Management API (`management/`), and supporting infrastructure (`deploy/`). Every finding is verified against the current source tree and assigned a severity rating.

## Scope

### Components reviewed
- **Go production proxy** — `cmd/proxy/main.go`, `internal/` (all packages)
- **Python prototype proxy** — `proxy.py`, `src/security/`, `src/analytics/`, `src/tap/`
- **Management API** — `management/api/` (all routes, auth, middleware, templates)
- **Infrastructure** — `deploy/docker/`, compose files, Dockerfiles, secret management

### Components out of scope
- Terraform provider (separate repo)
- Kubernetes operator (separate repo)
- Documentation and compliance artefacts
- Test infrastructure and CI pipelines (reviewed only for secret leakage)

---

## Findings Register

### CRITICAL

#### C-1: OpenAPI/Swagger Documentation Exposed Without Authentication

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **CVSS 3.1** | 7.5 (High) |
| **Component** | Management API |
| **File** | `management/api/main.py:143-144` |
| **CWE** | CWE-200 (Information Exposure) |

**Description:** The FastAPI auto-generated OpenAPI documentation at `/api/docs` and `/api/redoc` is served without any authentication. This exposes the complete API surface — every endpoint path, request/response schema, parameter names, data types, and error codes — to unauthenticated users.

```python
docs_url="/api/docs",
redoc_url="/api/redoc",
```

**Impact:** This is reconnaissance-grade intelligence for an attacker. A single unauthenticated GET request reveals all 51+ API endpoints, their parameter shapes, RBAC requirements, and response structures. This dramatically reduces the effort required for targeted attacks against any specific endpoint.

**Recommendation:** In production, set `docs_url=None, redoc_url=None, openapi_url=None`. Alternatively, gate them behind the same JWT authentication as the rest of the API.

**Remediation effort:** XS — single-line change.

---

#### C-2: X-Forwarded-For Trusted Unconditionally Across All Management API Routes

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **CVSS 3.1** | 8.1 (High) |
| **Component** | Management API — Authentication, Audit, Rate Limiting |
| **Files** | `management/api/auth.py:196-203`, `management/api/routes/bans.py:49`, `management/api/routes/dial.py:48`, `management/api/routes/canonical_lists.py:92`, `management/api/routes/config_ops.py:30`, `management/api/routes/lists.py:93`, `management/api/routes/threat_intel.py:123`, `management/api/routes/compliance.py:176` |
| **CWE** | CWE-348 (Use of Less Trusted Source), CWE-290 (Authentication Bypass by Spoofing) |

**Description:** The `_client_ip()` helper (and its 7 duplicated copies across route files) accepts `X-Forwarded-For` from **any** source without verifying that the request arrived through a trusted reverse proxy:

```python
def _client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"
```

**Impact:** An attacker can set `X-Forwarded-For: 127.0.0.1` (or any IP) to:

1. **Bypass the login rate limiter** — each spoofed IP gets its own 5-attempt quota, enabling unlimited credential brute-force from a single source.
2. **Falsify audit log entries** — all mutating operations record the spoofed IP as the actor, destroying forensic value.
3. **Evade IP-based ban enforcement** — banned IPs can re-authenticate by spoofing a different XFF.

The Go proxy correctly guards PROXY protocol behind a trusted-CIDR check (`IsTrustedProxySourceCIDRs`), but the Management API does not apply equivalent logic to XFF.

**Recommendation:** Only trust `X-Forwarded-For` when the socket-level peer is in a configured trusted-proxy CIDR list. Alternatively, configure uvicorn with `--proxy-headers --forwarded-allow-ips=<trusted_cidrs>` and remove the manual XFF parsing.

**Remediation effort:** S — centralize `_client_ip()` into a single module with a trusted-proxy check, remove the 7 duplicates.

---

### HIGH

#### H-1: CORS Configuration Allows Wildcard-Origin Credential Sharing

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **CVSS 3.1** | 7.1 (High) |
| **Component** | Management API |
| **File** | `management/api/main.py:149-156` |
| **CWE** | CWE-942 (Overly Permissive Cross-domain Whitelist) |

**Description:**

```python
cors_origins = os.environ.get("MANAGEMENT_CORS_ORIGINS", "http://localhost:8090")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins.split(","),
    allow_credentials=True,
    ...
)
```

`allow_credentials=True` combined with operator-configurable origins via environment variable. If an operator sets `MANAGEMENT_CORS_ORIGINS=*` or includes an attacker-controlled domain, the browser will send the `token` cookie cross-origin. There is no validation that configured origins are HTTPS or non-wildcard.

**Recommendation:** Validate that origins are HTTPS in production. Reject wildcard `*` when `allow_credentials=True`. Log a startup warning for non-localhost HTTP origins.

**Remediation effort:** XS — add validation loop after `cors_origins.split(",")`.

---

#### H-2: Login Rate Limiter Fails Open on Redis Errors

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **CVSS 3.1** | 6.5 (Medium) |
| **Component** | Management API Authentication |
| **File** | `management/api/auth.py:206-225` |
| **CWE** | CWE-799 (Improper Control of Interaction Frequency) |

**Description:** When Redis is unreachable, the login rate limiter silently disengages (`return` without raising):

```python
async def _check_rate_limit(ip: str, redis) -> None:
    try:
        ttl = await redis.ttl(f"{LOGIN_LOCKOUT_KEY_PREFIX}{ip}")
    except Exception:
        logger.warning(...)
        return  # <-- no rate limit applied
```

**Impact:** In the exact scenario where rate limiting matters most (Redis degradation, possibly attacker-caused), the limiter silently disengages. Combined with C-2 (XFF spoofing), an attacker could brute-force credentials without any lockout.

**Recommendation:** Fail closed — return HTTP 503 when the rate limiter cannot verify the caller is not locked out. The login flow already requires Redis for token blacklisting, so a missing Redis is already a wider outage.

**Remediation effort:** XS — change `return` to `raise HTTPException(503)`.

---

#### H-3: F-String Logging in Python Proxy — 39 Instances Violate Project Standard

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **CVSS 3.1** | 5.3 (Medium) |
| **Component** | Python Proxy |
| **File** | `proxy.py` (39 instances, e.g., lines 328, 331, 470, 622, 1089, 1265, 1667) |
| **CWE** | CWE-532 (Insertion of Sensitive Information into Log File) |

**Description:** AGENTS.md (Phase 18 alignment) explicitly prohibits f-strings in logging calls. 39 instances remain in `proxy.py`:

```python
self.logger.info(f"GeoIP database hot-reloaded: {p}")
self.logger.error(f"Error parsing Client Hello: {e}")
self.logger.info(f"Applying TARPIT delay of {delay}s")
```

**Impact:** F-strings evaluate eagerly, materializing the full message string even when the log level would suppress it. Exception objects (`{e}`) can contain Redis passwords, TLS key material, or other sensitive data from underlying library tracebacks. The `SensitiveDataFilter` cannot redact data that is already embedded in the message string before the filter runs.

**Recommendation:** Convert all 39 f-string logging calls to lazy `%`-style formatting: `self.logger.info("GeoIP database hot-reloaded: %s", p)`.

**Remediation effort:** S — mechanical search-and-replace.

---

#### H-4: Webhook Dispatcher Creates Unauthenticated Redis Client

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **CVSS 3.1** | 7.5 (High) |
| **Component** | Go Proxy Webhook Dispatcher |
| **File** | `internal/webhook/delivery.go:124-125`, `cmd/proxy/main.go:274` |
| **CWE** | CWE-306 (Missing Authentication for Critical Function) |

**Description:** The webhook dispatcher creates its own Redis client using only `addr` (host:port) with **no password, no TLS, no username**:

```go
// delivery.go:125
rc := redis.NewClient(&redis.Options{Addr: addr})

// main.go:274 — password from cfg.Redis.Password is never passed
redisAddr := fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port.Int())
```

This client is separate from the main proxy Redis client (which has full auth/TLS). If webhooks are enabled, the dispatcher connects to Redis without authentication.

**Impact:** On any Redis instance that requires a password (the production norm since Phase 202), the webhook dispatcher will fail to connect, silently disabling webhook delivery. On a Redis instance that does not require a password but is network-accessible, the dispatcher operates without encryption, exposing webhook payloads (which may contain security event data) to network sniffing.

**Recommendation:** Pass the full Redis configuration (password, username, TLS) to `NewDispatcher`, or accept an existing `redis.UniversalClient` instead of creating a new one.

**Remediation effort:** S — change `NewDispatcher` signature to accept `redis.UniversalClient`.

---

#### H-5: OIDC Test Mode Skips ID Token Signature Verification

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **CVSS 3.1** | 6.8 (Medium) |
| **Component** | Management API SSO |
| **File** | `management/api/routes/oidc.py:232-244` |
| **CWE** | CWE-347 (Improper Verification of Cryptographic Signature) |

**Description:** When `MANAGEMENT_TEST_MODE=1` is set (and `ENVIRONMENT` is not production), OIDC ID token signatures are not verified:

```python
if is_test_mode():
    parts = id_token.split(".")
    padding = "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(parts[1] + padding))
```

**Impact:** An attacker who can set `MANAGEMENT_TEST_MODE=1` (e.g., via container orchestration misconfiguration, `.env` file injection, or Kubernetes ConfigMap poisoning) can forge arbitrary OIDC identities in staging environments. The production guard in `_enforce_no_test_mode_in_production()` mitigates this for `ENVIRONMENT=production`, but staging/pre-prod environments remain vulnerable.

**Recommendation:** Remove the test-mode bypass entirely and use proper test fixtures with real JWKS. Alternatively, add a secondary check that the request originates from localhost when test mode is active.

**Remediation effort:** S — replace test-mode bypass with JWKS mock fixtures in tests.

---

### MEDIUM

#### M-1: SAML Strict Mode Controllable via Environment Variable Without Production Guard

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **CVSS 3.1** | 5.9 (Medium) |
| **Component** | Management API SSO |
| **File** | `management/api/routes/saml.py:78` |
| **CWE** | CWE-347 (Improper Verification of Cryptographic Signature) |

**Description:** The SAML `strict` flag (which controls whether IdP signatures are verified) defaults to `true` but can be disabled by setting `MANAGEMENT_SAML_STRICT=false`. Unlike test mode, there is **no production guard** preventing this in `ENVIRONMENT=production`:

```python
strict = os.environ.get("MANAGEMENT_SAML_STRICT", "true").lower() == "true"
```

**Impact:** An attacker who can influence environment variables can disable SAML signature verification even in production, accepting forged SAML assertions from any source.

**Recommendation:** Add a production guard that refuses to set `strict=false` when `ENVIRONMENT=production`, matching the pattern used for `MANAGEMENT_TEST_MODE` and `MANAGEMENT_DISABLE_CSRF`.

**Remediation effort:** XS — add 5 lines to `_enforce_no_test_mode_in_production()`.

---

#### M-2: Redis Password Interpolated into URL String in Analytics Node

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **CVSS 3.1** | 5.3 (Medium) |
| **Component** | Analytics Node |
| **File** | `src/analytics/main.py:55-62` |
| **CWE** | CWE-532 (Insertion of Sensitive Information into Log File) |

**Description:** The Redis password is interpolated directly into a URL string via f-string:

```python
redis_url = (
    f"redis://:{self.config['redis']['password']}"
    f"@{self.config['redis']['host']}:{self.config['redis']['port']}"
)
```

This string can leak into exception tracebacks, debug logging, process inspection tools (`/proc/<pid>/environ`, core dumps), and Python garbage collector inspection. The Management API's `redis_client.py` has already been hardened against this (JA4PROXY-2026-0053 with `_redact_redis_url`), but the analytics node has not received the same treatment.

**Recommendation:** Pass Redis connection parameters (host, port, password) as discrete arguments to `redis.asyncio.Redis()` instead of constructing a URL string.

**Remediation effort:** XS — replace `from_url()` with keyword arguments.

---

#### M-3: Login Page Loads External CDN Resources with Fake SRI Hash

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **CVSS 3.1** | 5.3 (Medium) |
| **Component** | Management UI Templates |
| **File** | `management/templates/login.html:8-9` |
| **CWE** | CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) |

**Description:** The login page loads JavaScript from `cdn.tailwindcss.com` and `unpkg.com`:

```html
<script src="https://cdn.tailwindcss.com" crossorigin="anonymous"></script>
<script src="https://unpkg.com/alpinejs@3.14.0/dist/cdn.min.js"
    integrity="sha384-6Xh8u3p1iZ6e8q6u5p4v3i2o1n0m9l8k7j6h5g4f3d2s1a0" ...>
```

- **Tailwind CSS** has no SRI hash — the CDN operator can inject arbitrary code.
- **Alpine.js** SRI hash (`sha384-6Xh8u3p1i...`) appears to be a placeholder — it is too short and too regular to be a real SHA-384 hash.
- **Availability risk:** CDN outage breaks the login page.
- **Privacy risk:** CDN operators see requests from the management UI's IP address.

**Recommendation:** Bundle CSS/JS locally for production. Remove or replace the fake SRI hash. Add a CSP `script-src` directive that does not include `cdn.tailwindcss.com` or `unpkg.com` in production.

**Remediation effort:** S — download and vendor the two files, update template references.

---

#### M-4: TAP Enforcement Bridge Lacks HMAC Verification on Pub/Sub Messages

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **CVSS 3.1** | 6.5 (Medium) |
| **Component** | TAP Enforcement Bridge |
| **File** | `src/tap/enforcement_bridge.py:146-156` |
| **CWE** | CWE-345 (Insufficient Verification of Data Authenticity) |

**Description:** The enforcement bridge subscribes to `ja4proxy:bans` and executes `ipset add` / `iptables` commands based on the message content without verifying message authenticity:

```python
async def _handle_message(self, msg: dict) -> None:
    data = json.loads(msg["data"])
    ip = data["ip"]
    ttl = int(data.get("ttl", 3600))
    reason = data.get("reason", "")
    await self._on_ban(ip, ttl, reason)
```

The Go proxy's pub/sub handler has HMAC verification (JA4PROXY-2026-0019), but the Python enforcement bridge does not.

**Impact:** An attacker with Redis write access (e.g., via a compromised application sharing the Redis instance) could publish ban messages to arbitrarily ban IP addresses via iptables, causing denial of service to legitimate users.

**Recommendation:** Add HMAC verification to the enforcement bridge's pub/sub handler, matching the Go proxy's implementation.

**Remediation effort:** S — port the HMAC verification pattern from Go.

---

#### M-5: Python Proxy Health Server Binds to `0.0.0.0` by Default

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **CVSS 3.1** | 4.3 (Medium) |
| **Component** | Python Proxy |
| **File** | `proxy.py` (health server initialization) |
| **CWE** | CWE-668 (Exposure of Resource to Wrong Sphere) |

**Description:** The Python proxy's health server defaults to binding on `0.0.0.0`, exposing health/metrics endpoints to all network interfaces. The Go proxy correctly defaults metrics to `127.0.0.1`.

**Recommendation:** Default the Python health server to `127.0.0.1` to match the Go proxy's secure default.

**Remediation effort:** XS — change default value.

---

### LOW

#### L-1: `MANAGEMENT_ADMIN_PASSWORD` Accepted as Plaintext in POC Compose

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Component** | Management API / Docker Infrastructure |
| **File** | `management/api/auth.py:138`, `deploy/docker/docker-compose.poc.yml` |

**Description:** The POC compose file passes `MANAGEMENT_ADMIN_PASSWORD` as a plaintext environment variable. The password appears in `docker inspect`, process listings, and container environment dumps. While the code prefers bcrypt hash when available, the compose file does not use it.

**Recommendation:** Require `MANAGEMENT_ADMIN_PASSWORD_HASH` (bcrypt) in the compose file. Generate the hash in `start-poc.sh`.

**Remediation effort:** XS.

---

#### L-2: Go Proxy `CountKeys` Uses `KEYS` Command (O(N) Blocking)

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Component** | Go Proxy Redis Client |
| **File** | `internal/redis/client.go:387-396` |

**Description:** `CountKeys` uses the `KEYS` command which is O(N) and blocks Redis. It is called from `/health/deep` which is polled by monitoring. With thousands of ban keys, this can cause latency spikes for all Redis clients.

**Recommendation:** Use `SCAN` or maintain a ban counter key that is incremented/decremented on ban/unban.

**Remediation effort:** S.

---

## Positive Security Observations

The codebase demonstrates extensive, mature security hardening from prior phases (108–121, 200–203). Notable defensive measures already in place:

| # | Control | Reference |
|---|---------|-----------|
| 1 | PROXY protocol spoofing protection — headers always stripped; only trusted peers influence client IP | JA4PROXY-2026-0001, 0002; Phase 200 |
| 2 | TLS protocol lockdown — non-TLS content on TLS listener is dropped | JA4PROXY-2026-0011 |
| 3 | Redis authentication enforcement — remote Redis without password refuses startup | JA4PROXY-2026-0010; Phase 201 |
| 4 | Metrics endpoint authentication — non-loopback bind requires bearer token | JA4PROXY-2026-0008 |
| 5 | Pub/Sub HMAC signing — critical channels reject unsigned messages | JA4PROXY-2026-0019 |
| 6 | Webhook SSRF prevention — URL validation rejects internal/private IPs | JA4PROXY-2026-0007 |
| 7 | OIDC algorithm confusion prevention — symmetric algorithms rejected for ID tokens | JA4PROXY-2026-0032 |
| 8 | JWT role default to least-privileged — missing/invalid role defaults to `auditor` | JA4PROXY-2026-0034 |
| 9 | CSRF double-submit with HMAC — session-bound tokens on all mutating API routes | Phase 101 H8 |
| 10 | Webhook secret redaction — secrets stripped from String/JSON/log output | JA4PROXY-2026-0051 |
| 11 | Bounded accept semaphore — prevents goroutine exhaustion under DDoS | JA4PROXY-2026-0012 |
| 12 | Bounded XADD queue — prevents OOM during Redis slowdowns | JA4PROXY-2026-0031 |
| 13 | Tarpit self-protection — inactivity timeout and lifetime cap prevent slot pinning | JA4PROXY-2026-0013 |
| 14 | Trusted CIDR validation — dangerously broad CIDRs rejected at config load | JA4PROXY-2026-0022 |
| 15 | XSS prevention in templates — ban IP rendered through `tojson` filter | JA4PROXY-2026-0020 |
| 16 | No pickle/unsafe yaml usage — zero instances of `pickle.load`, `yaml.unsafe_load` | Verified |
| 17 | No `shell=True` in subprocess calls — enforcement bridge uses `create_subprocess_exec` | Verified |
| 18 | Docker containers hardened — `read_only: true`, `cap_drop: ALL`, `no-new-privileges`, non-root users, resource limits, network segmentation | Phase 71–75 |
| 19 | Default credential removal — compose files require env vars (no fallback defaults) | Phase 202 |
| 20 | SSL private keys excluded from git — `.gitignore` correctly excludes `deploy/ssl/private/*` | Verified |

---

## Implementation Plan

### A — Management API Hardening (C-1, C-2, H-1, H-2, M-1)

1. **C-1:** Set `docs_url=None, redoc_url=None, openapi_url=None` when `ENVIRONMENT=production`.
2. **C-2:** Centralize `_client_ip()` into `management/api/auth.py` with a trusted-proxy CIDR check. Remove the 7 duplicated copies across route files. Add `MANAGEMENT_TRUSTED_PROXY_CIDRS` env var.
3. **H-1:** Add validation loop rejecting `*` and non-HTTPS origins when `allow_credentials=True` and `ENVIRONMENT=production`.
4. **H-2:** Change `_check_rate_limit` fail-open `return` to `raise HTTPException(503)`.
5. **M-1:** Add `MANAGEMENT_SAML_STRICT=false` to the production guard in `_enforce_no_test_mode_in_production()`.

### B — Go Proxy Webhook Redis Fix (H-4)

1. Change `NewDispatcher` to accept `redis.UniversalClient` instead of `addr string`.
2. Update `cmd/proxy/main.go` to pass the existing authenticated Redis client.
3. Add test verifying webhook dispatcher uses TLS + password.

### C — Python Proxy Logging Hygiene (H-3)

1. Convert all 39 f-string logging calls in `proxy.py` to lazy `%`-style formatting.
2. Add a ruff rule or pre-commit hook to prevent regression.

### D — Analytics Node Redis URL (M-2)

1. Replace `redis_url` f-string construction with discrete keyword arguments to `redis.asyncio.Redis()`.

### E — OIDC Test Mode Removal (H-5)

1. Remove the `is_test_mode()` bypass in `_extract_claims`.
2. Update tests to use JWKS mock fixtures with real signature verification.

### F — Login Page CDN Removal (M-3)

1. Download and vendor Tailwind CSS and Alpine.js into `management/static/`.
2. Update `login.html` to reference local files.
3. Remove fake SRI hash.

### G — TAP Enforcement Bridge HMAC (M-4)

1. Add HMAC verification to `_handle_message` matching the Go proxy's pub/sub pattern.

### H — Python Health Server Bind Default (M-5)

1. Change default health server bind from `0.0.0.0` to `127.0.0.1`.

---

## Test Strategy

| Category | What it verifies |
|----------|-----------------|
| Unit | `_client_ip()` rejects XFF from untrusted peers; CORS validation rejects `*`; rate limiter fails closed; SAML strict guard in production |
| Integration | OpenAPI docs return 404 in production mode; webhook dispatcher connects to Redis with auth |
| Adversarial | XFF spoofing does not bypass rate limiter; OIDC test mode cannot be activated in production; CORS preflight from attacker origin is rejected |
| Regression | All 39 f-string logging calls converted; login page loads no external resources |

---

## Acceptance Criteria

- [ ] All CRITICAL findings (C-1, C-2) remediated
- [ ] All HIGH findings (H-1 through H-5) remediated
- [ ] All MEDIUM findings (M-1 through M-5) remediated or explicitly deferred with rationale
- [ ] `make test` passes with zero failures
- [ ] `make lint-all` exits 0
- [ ] No new f-string logging instances introduced (verified by ruff or grep)
- [ ] OpenAPI docs not accessible in production mode
- [ ] XFF from untrusted source does not influence `_client_ip()` output
- [ ] Webhook dispatcher uses authenticated Redis connection
- [ ] CHANGELOG.md updated
- [ ] docs/phases/manifest.yaml updated with `status: COMPLETE`

---

## Out of Scope

- Terraform provider and Kubernetes operator (separate repos)
- CI/CD pipeline hardening (covered by Phase 61, 202)
- Docker container hardening (covered by Phases 71–75)
- Supply chain / SLSA attestation (covered by Phase 107)
- Network-level DMZ hardening (covered by Phase 117/118)
- Performance or throughput optimization
- New feature development

---

## Summary Table

| ID | Severity | Component | Title | Effort |
|----|----------|-----------|-------|--------|
| C-1 | CRITICAL | Management API | OpenAPI docs exposed without auth | XS |
| C-2 | CRITICAL | Management API | XFF trusted unconditionally (8 files) | S |
| H-1 | HIGH | Management API | CORS wildcard + credentials | XS |
| H-2 | HIGH | Management API | Rate limiter fails open | XS |
| H-3 | HIGH | Python Proxy | 39 f-string logging violations | S |
| H-4 | HIGH | Go Proxy | Webhook Redis client unauthenticated | S |
| H-5 | HIGH | Management API | OIDC test mode skips signature verification | S |
| M-1 | MEDIUM | Management API | SAML strict mode no production guard | XS |
| M-2 | MEDIUM | Analytics Node | Redis password in URL string | XS |
| M-3 | MEDIUM | Management UI | External CDN with fake SRI hash | S |
| M-4 | MEDIUM | TAP | Enforcement bridge no HMAC verification | S |
| M-5 | MEDIUM | Python Proxy | Health server binds 0.0.0.0 | XS |
| L-1 | LOW | Infrastructure | Plaintext admin password in POC compose | XS |
| L-2 | LOW | Go Proxy | CountKeys uses KEYS (O(N) blocking) | S |

**Total:** 2 CRITICAL, 5 HIGH, 5 MEDIUM, 2 LOW — 14 findings.
