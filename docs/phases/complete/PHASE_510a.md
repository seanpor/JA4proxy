---
phase: 510a
title: "Bug Hunt Guide — Python Management API & Analytics"
parent: 500
created: 2026-06-22
audience: [developer, security]
---

# Bug Hunt Guide — Python Management API & Analytics

This guide covers sub-phases **510a–510c**: injection/web security, authentication,
and data exposure in the Python components.

## Before you start

```bash
# Make sure tests pass
make test
# Lint must be clean
make lint
```

---

## 510a — Injection & Web Security

**CWE-79: XSS / CWE-918: SSRF / CWE-78: OS Command Injection**

### What to look for

User-controlled input that reaches a browser (XSS), an outbound HTTP request (SSRF),
or a shell command (injection) without sanitisation.

### Files to read

| File | What to check |
|------|--------------|
| `management/api/routes/webhooks.py` | `_validate_webhook_url()` — is the DNS check TOCTOU-vulnerable? |
| `management/api/routes/partials.py` | HTMX responses — is user input reflected into HTML? |
| `management/templates/*.html` | Jinja2 templates — is auto-escaping on? Is `\|safe` used on user data? |
| `scripts/gdpr_delete.py` | Is the `--ip` argument validated before use in Redis key construction? |
| `scripts/config-signer.py` | File paths from CLI args — can they be used for path traversal? |
| `deploy/ansible/playbooks/apply-policy.yml` | Are variables interpolated into `ansible.builtin.command`? |
| `src/analytics/ti_feeds/` | Are TI feed URLs user-controllable? Can they point to internal services? |
| `config/report_template.html` | Is report data escaped before insertion? |

### Grep commands

```bash
# Find all |safe usage in Jinja2 templates — these bypass auto-escaping
rg '\|safe' management/templates/ -n

# Find all template rendering calls — verify auto-escaping is on
rg 'TemplateResponse|render_template|Jinja2Templates' management/api/ -n

# Find all subprocess/exec calls in Python — potential command injection
rg 'subprocess\.(run|call|Popen|check_output)|os\.system|os\.popen' scripts/ src/ -n

# Find all webhook URL handling — check for SSRF
rg 'webhook|validate.*url|requests\.(get|post|put)' management/api/ -n

# Find all Ansible command tasks — check for variable interpolation in shell
rg 'ansible.builtin.(command|shell)' deploy/ansible/ -n
```

### Checklist

- [ ] All Jinja2 templates have auto-escaping enabled (default for `.html`)
- [ ] No `\|safe` filter on user-controlled data (IP, JA4, hostname)
- [ ] HTMX partial responses escape user input before embedding in HTML
- [ ] `_validate_webhook_url()` resolves DNS and checks IP in the same TCP connection (not TOCTOU)
- [ ] `gdpr_delete.py` validates `--ip` with `ipaddress.ip_address()` before use
- [ ] No `subprocess` call uses `shell=True` with user input
- [ ] Ansible `command` module (not `shell`) is used where possible
- [ ] TI feed URLs are from config, not user input
- [ ] `config/report_template.html` escapes all dynamic values

### Example bug (from prior findings)

```
JA4PROXY-2026-0020: Stored XSS in Management UI — ban IP input in Alpine.js
@click handler was not sanitised, allowing script injection. Fix: escape
user input before embedding in Alpine.js directives.
```

### Regression test template

```python
def test_xss_in_list_parameter():
    """Verify that the list parameter is HTML-escaped in the response."""
    response = client.get("/api/v1/partials/list-table?list=<script>alert(1)</script>")
    assert b"<script>" not in response.content
    assert b"&lt;script&gt;" in response.content
```

---

## 510b — Authentication & Session Management

**CWE-287: Improper Authentication / CWE-613: Insufficient Session Expiration**

### What to look for

Code paths where authentication can be bypassed, sessions can be hijacked, or
identity verification has gaps. Think: can someone log in without MFA? Can a JWT
be forged? Can a session cookie be stolen?

### Files to read

| File | What to check |
|------|--------------|
| `management/api/auth.py` | JWT handling: algorithm allowlist, token expiry, refresh logic, bearer-to-cookie fallback. Login endpoint at `@router.post("/auth/login")` (line 619). Rate limiting and lockout logic also here. |
| `management/api/middleware/csrf.py` | CSRF: HMAC key source, token predictability, same-site policy |
| `management/api/pubsub_signing.py` | HMAC: which channels are signed? Missing-secret behavior? |

### Grep commands

```bash
# Find all JWT operations — verify algorithm restriction
rg 'jwt\.|PyJWT|python-jose|jose' management/api/ -n

# Find all cookie setting — verify secure, httponly, samesite
rg 'set_cookie|Set-Cookie' management/api/ -n

# Find all rate limiting / lockout — verify it cannot be bypassed
rg 'rate.limit|lockout|login_failures' management/api/ -n

# Find all require_role / require_admin decorators — verify every route has one
rg '@require_role|@require_admin|require_role\(' management/api/ -n

# Find all HMAC operations — verify hmac.compare_digest (not ==)
rg 'hmac\.' management/api/ -n
```

### Checklist

- [ ] JWT algorithm is restricted to HS256 (or explicit allowlist, no `none`)
- [ ] JWT tokens expire (8h max)
- [ ] Bearer tokens are exempt from MFA (documented and intentional)
- [ ] OIDC state is stored in Redis with 5min TTL and single-use
- [ ] SAML strict mode cannot be disabled in production (`ENVIRONMENT=production` guard)
- [ ] Login rate limiting: 5 failures = 5min lockout, per-IP
- [ ] CSRF token uses HMAC-SHA256 with same key as JWT
- [ ] All mutating routes have `@require_role` or `@require_admin`
- [ ] Cookies use `secure=True`, `httponly=True`, `samesite="lax"`
- [ ] `MANAGEMENT_TEST_MODE` is ignored when `ENVIRONMENT=production`

### Regression test template

```python
def test_mfa_bypass_blocked():
    """Verify that login without MFA is rejected when MFA is enrolled."""
    # Enroll MFA for user
    # Attempt login without TOTP code
    # Expect 403 or redirect to MFA page
    response = client.post("/api/v1/auth/login", json={"username": "admin", "password": "..."})
    assert response.status_code in (401, 403, 302)  # Must not be 200
```

---

## 510c — Data Exposure & Logging

**CWE-532: Sensitive Info in Logs / CWE-200: Information Exposure**

### What to look for

Sensitive data (passwords, API keys, tokens, PII) that appears in logs, error
messages, or debug output that could be visible to operators or log aggregators.

### Files to read

| File | What to check |
|------|--------------|
| `management/api/routes/*.py` | All `logging.error/warning/info` calls — do they include passwords or tokens? |
| `management/api/auth.py` | Error messages on failed login — do they reveal whether username exists? |
| `management/api/routes/tls_health.py` | Stack traces in error responses — do they leak internal paths? |
| `src/analytics/stream_consumer.py` | Event logging — does it log raw event data with PII? |
| `scripts/*.py` | stdout/stderr output — does it print secrets? |
| `scripts/docker-entrypoint.sh` | Secret injection — are secrets visible in `/proc/*/environ`? |

### Grep commands

```bash
# Find all logging calls — check for credential patterns
rg 'logging\.(error|warning|info|debug)' management/api/ src/analytics/ -n

# Find all str(exc) or str(e) in error responses — may leak internal details
rg 'str\(exc\)|str\(e\)|str\(err\)' management/api/ -n

# Find all password/key/token variables — verify they are not logged
rg 'password|api_key|secret|token' management/api/ src/analytics/ -n | grep -i 'log\|print\|error'

# Find all stack trace exposure — verify production mode hides them
rg 'traceback|stack_trace|exc_info' management/api/ -n
```

### Checklist

- [ ] No `logging` call outputs passwords, API keys, or HMAC secrets
- [ ] Login error messages are generic ("Invalid credentials") — no username enumeration
- [ ] Stack traces are not exposed in HTTP responses (production mode)
- [ ] Redis connection URLs are not logged (they contain passwords)
- [ ] Audit log does not contain sensitive fields (only actions and targets)
- [ ] Docker secrets are not printed to stdout/stderr by entrypoint scripts
- [ ] Analytics event logging does not include raw PII

### Regression test template

```python
def test_error_response_hides_stack_trace():
    """Verify that error responses don't leak internal paths or stack traces."""
    # Trigger an internal error (e.g., invalid Redis connection)
    response = client.get("/api/v1/health/deep")
    assert b"Traceback" not in response.content
    assert b"/home/" not in response.content
    assert b"File \"" not in response.content
```
