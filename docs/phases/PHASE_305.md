---
phase: 305
title: CodeQL Triage — Python Code-Scanning Findings
status: COMPLETE
size: SMALL
created: 2026-06-09
completed: 2026-06-09
audience: [developer, security]
---

# CodeQL Triage — Python Code-Scanning Findings

> Follows [[PHASE_304]]. Phase 304 cleared the *dependency* CVEs; this phase
> works through the **CodeQL code-scanning** findings — bugs in our own code,
> not third-party packages. The discipline here is the same one Phase 304
> taught: **triage before you touch anything**, and (per the project owner)
> *be very critical of any suppression* — every dismissal must be backed by
> evidence you actually checked, not a hunch.

## The rule we followed

A CodeQL alert is a *hypothesis*, not a verdict. For each one there are exactly
three honest outcomes, and you must be able to defend which you picked:

1. **Real bug** → fix the code (and add a regression test).
2. **False positive** → the analyzer's taint path is broken by a sanitizer or a
   constant it can't see. Dismiss as *false positive* **only after reading the
   code and proving the path is safe**.
3. **Won't-fix / used-in-test** → the pattern is real but intentional and
   non-production (e.g. a test tool that deliberately speaks legacy TLS).
   Dismiss with that reason and a one-line justification.

Blanket-dismissing a whole rule is never acceptable — each alert is judged on
its own code.

## The findings (14 Python + 1 Go, all open)

| # | Rule | Location | Verdict |
|---|---|---|---|
| 82 | `py/reflective-xss` | `management/api/routes/partials.py:315` | 🔴 **real → fixed** |
| 83 | `py/stack-trace-exposure` | `management/api/routes/health.py:101` (`/health/deep`, authed) | 🔴 **real → fixed** |
| 84 | `py/stack-trace-exposure` | `management/api/routes/health.py:126` (`/ready`, **unauth**) | 🔴 **real → fixed** |
| 78 | `py/insecure-protocol` | `scripts/mock-backend.py:155` (test server) | 🟠 **hardened** (TLS 1.2 floor) |
| 80 | `py/insecure-protocol` | `tests/docker/tls_backend.py:27` (test server) | 🟠 **hardened** (TLS 1.2 floor) |
| 89 | `py/url-redirection` | `management/api/routes/oidc.py:501` | 🟠 **hardened** — same-site redirect guard (was FP-by-constant) |
| 90 | `py/url-redirection` | `management/api/routes/saml.py:316` | 🟠 **hardened** — same-site redirect guard (was FP-by-constant) |
| 85 | `py/clear-text-logging` | `management/api/auth.py:214` | ⚪ **FP** — logs a config CIDR, not a secret |
| 87 | `py/clear-text-logging` | `management/api/redis_client.py:106` | ⚪ **FP** — logs the *redacted* URL |
| 88 | `py/clear-text-logging` | `management/api/redis_client.py:110` | ⚪ **FP** — logs the *redacted* URL |
| 86 | `py/clear-text-logging` | `deploy/.../splunk-ta/.../ja4proxy_ban_action.py:38` | ⚪ **FP** — the token is never logged |
| 79 | `py/insecure-protocol` | `scripts/test-bot.py:143` | 🟡 **used-in-test** — generator emits legacy TLS by design |
| 81 | `py/insecure-protocol` | `scripts/tls-traffic-generator.py:304` | 🟡 **used-in-test** — same |
| 77 | `py/bind-socket-all-network-interfaces` | `scripts/capture_server.py:35` | 🟡 **used-in-test** — local capture helper |
| — | `go/disabled-certificate-check` | `internal/test/bench/ja4bench.go` | 🟡 **used-in-test** — bench hits the self-signed mock (already `#nosec`) |

Note the shape: **the only genuine bugs are three, all in the Management-API web
layer.** Everything else is a sanitizer CodeQL can't model, a constant it can't
trace, or intentional test tooling. That is the normal distribution for a
first-ever scan — which is exactly why triage matters more than the headline
count.

## The real bugs and their fixes

### 1. Reflected XSS — `partials.py` (`/api/v1/partials/list-table`)
The unknown-list error path interpolated the **unvalidated `list` query
parameter** straight into returned HTML:

```python
content=f'<div ...>Unknown list: {list}</div>'   # ?list=<script>… reflects raw
```

Auth-gated, but still a reflected XSS in the operator console. **Fix:** escape
the value before reflecting it.

```python
f"Unknown list: {html.escape(list)}</div>"
```

> **Why escape rather than drop the value?** Echoing *which* bad list name was
> requested is useful for debugging. `html.escape` keeps that signal while
> turning `<>&"'` into inert entities. The general rule: never put
> request-controlled bytes into an HTML response without escaping at the sink.

### 2 & 3. Error-detail exposure — `health.py` (`/health/deep`, `/ready`)
Both handlers returned `str(exc)` of a Redis failure **to the client**:

```python
content={"ready": False, "reason": str(exc)}   # leaks redis://host:port, errno…
```

`/ready` is explicitly **unauthenticated** (it's a load-balancer probe), so this
handed internal topology to anyone who could reach it. **Fix:** log the full
error server-side (already done via `logger.warning`) and return a generic
status/reason to the caller (`"redis_unavailable"`; `{"status": "error"}` with no
`error` field).

> **The principle:** an exception string is for *operators* (logs), never for
> *callers* (responses). This is "fail closed on information": the detail still
> exists where the on-call engineer can see it, just not where an attacker can.

### Hardening (not strictly bugs) — the two test TLS servers
`mock-backend.py` and `tests/docker/tls_backend.py` built a `PROTOCOL_TLS_SERVER`
context without pinning a floor. A *server* has no reason to accept legacy TLS,
so we set `ctx.minimum_version = ssl.TLSVersion.TLSv1_2`. This clears the alert
*legitimately* (the code genuinely no longer negotiates insecure protocols)
rather than by dismissal. The proxy is a passthrough, so legacy-TLS client
profiles are exercised against the *proxy's detection*, never terminated at these
backends — confirmed by the full management/integration suite staying green.

### Open-redirect guard — OIDC & SAML callbacks (#89, #90)
These two were *almost* dismissed as false positives: the post-login redirect
target read back from server-side state (the OAuth state blob / the SAML
RelayState nonce) is currently a **hardcoded `"/"`**, so there is no live open
redirect. But "safe because the value happens to be a constant today" is a
circumstantial safety — the day someone adds a "return to where you were"
feature and wires a `?next=` parameter into that stored value, it silently
becomes an open redirect (CWE-601), and a *dismissed* alert wouldn't warn them.

> **Why this is a fix, not a dismissal.** The owner's standing rule is to be very
> critical of suppression. Dismissing here would bake in the assumption "nobody
> will ever make this user-controllable." Instead we added
> `auth.safe_relative_redirect(target, default="/")`, applied at both callbacks:
> it returns the target only if it's a same-site root-relative path, else `"/"`.
> It rejects absolute URLs, protocol-relative `//evil`, and backslash variants
> (`/\evil`) that some browsers normalise to `//`. This removes the suppression
> entirely **and** is regression-proof — if the redirect ever does become
> caller-influenced, the guard already contains it.

## The dismissals (each verified, not assumed)

These are dismissed via `gh api … code-scanning/alerts/{n}` with the reason and
justification recorded in the GitHub audit trail (reversible in one click).

**False positives — proven safe by reading the code:**
- **#85 `auth.py:214`** logs `cidr`, a value parsed from the operator-set
  `MANAGEMENT_TRUSTED_PROXY_CIDRS` env var. A network range is configuration,
  not a credential. CodeQL treats any `os.environ` value as sensitive.
- **#87/#88 `redis_client.py`** log `safe_url = _redact_redis_url(url)`. We read
  `_redact_redis_url` and confirmed it replaces the password with `***` via
  `urllib.parse.urlparse` (mitigation tracked as finding JA4PROXY-2026-0053).
  CodeQL doesn't recognise the custom sanitizer.
- **#86 splunk `ja4proxy_ban_action.py:38`** — the only secret in that file is
  `api_token`, which is placed in an `Authorization` header and **never passed
  to `_log`**. The `_log` calls carry IPs, HTTP status codes, and response
  bodies — operational data.

(The OIDC/SAML url-redirection findings #89/#90 were *not* dismissed — they were
**fixed** with a same-site redirect guard; see above. They were the textbook
"don't dismiss a safe-by-constant FP — harden it" case.)

**Used-in-test — intentional and non-production:**
- **#79 `test-bot.py` / #81 `tls-traffic-generator.py`** are TLS *generators*
  whose entire purpose is to emit a spread of ClientHellos — **including legacy
  TLS** — to exercise the proxy's JA4 fingerprint detection. Pinning a floor
  would defeat the tool.
- **#77 `capture_server.py`** binds `0.0.0.0` as a local packet-capture test
  helper (already carries a `# nosemgrep` for the same reason).
- **Go `go/disabled-certificate-check`** in `internal/test/bench/ja4bench.go` —
  the benchmark connects to the self-signed mock backend; `InsecureSkipVerify`
  is correct there and already `#nosec`-annotated.

> **Remember:** none of the production *proxy* runtime is Go-side here — every
> real finding was in the Python Management API web layer. The Go production
> proxy produced no genuine code-scanning bug.

## Verification
- New regression tests: `management/tests/test_codeql_305_regression.py` —
  proving the XSS payload is escaped (and the escaped form is present); that
  neither `/ready` nor `/health/deep` leaks a secret-bearing exception string;
  and that `safe_relative_redirect` rejects every off-site / protocol-relative /
  backslash variant while passing same-site paths unchanged. All pass.
- Existing health/partials/list-table/ready and OIDC/SAML tests still pass (no
  test depended on the leaked `str(exc)`, the raw reflection, or an off-site
  redirect).
- Fixed-in-code alerts (#82, #83, #84, #78, #80, #89, #90) auto-close on the
  next default-branch CodeQL scan after merge; the verified-FP / used-in-test
  ones are dismissed with per-alert justification.

## Acceptance Criteria
1. Every CodeQL Python finding is triaged to fixed / FP / used-in-test, each with
   a written, code-backed justification.
2. The three real bugs (reflected XSS, two error-exposures) are fixed with
   regression tests.
3. No blanket rule-level suppression; dismissals are per-alert with reasons in
   the GitHub audit trail.
4. Management suite green against the fixes; manifest + CHANGELOG + `make sync`
   updated; landed via PR.

## Out of Scope (follow-ups)
- The dead `management/tests/test_phase_122_security_review.py` tests (import
  `src.tap.enforcement_bridge`, `src.security.health`, read `proxy.py` — all
  removed in v2.0.0). They should be deleted or rewritten against the current
  layout; tracked separately.
- `python-jose` → **PyJWT** migration (carried from [[PHASE_304]]).
- The OpenSSF Scorecard advisories that surface as code-scanning "high"
  (`PinnedDependenciesID`, `TokenPermissionsID`, …) — supply-chain *scoring*,
  not code bugs; left as informational.
