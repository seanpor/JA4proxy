# Phase 521 — Aggressive Bug Hunt: Infrastructure & Management API (Red-Team Pass)

> **For the implementing engineer:** written to be actionable with **no prior
> knowledge of this codebase**. Every finding lists the exact file, the exact
> code, why it's wrong, the exact change, and the exact test. Read "How to work
> this phase" first. Do findings in order. Ask before deviating.

## Status: COMPLETE

Finding 1 (`JA4PROXY-2026-0093`) is fixed: a shared `management/api/environment.py`
module (`is_explicit_nonproduction()` / `is_production()`) replaces the three
duplicate `_is_production()` copies (`auth.py`, `main.py`, `middleware/csrf.py`)
plus a fourth inline copy inside `csrf.py`'s `_get_signing_key()`. Unset,
unrecognised, `dmz`, and `staging` `ENVIRONMENT` values now fail **closed** as
production; only an explicit allowlist (`dev`/`development`/`test`/`testing`/
`local`/`ci`) enables the test-mode escape hatches. `_get_secret_key()` adds a
second, independent check before serving the hardcoded JWT secret.
`management/tests/conftest.py` now sets `ENVIRONMENT=test` explicitly (it used
to rely on the flag being unset); `test_test_mode_hardening.py` and
`test_cookie_secure_flag.py` were updated to reflect that `""`/`"staging"` are
now production-equivalent, and `management/tests/test_environment_failclosed.py`
adds the acceptance tests from this doc — verified to fail on revert. OIDC's
signature-verification bypass was already removed in Phase 122 H-5, so it
needed no code change. `docs/security/findings.yaml` 0093 → `FIXED`.

The "Areas NOT fully audited" backlog below (IDOR/authorization,
Redis-outage auth fail-open, callback origin/audience binding, compose
wiring, analytics/tarpit input validation) was picked up by Phase 522, which
cleared most of it and opened two new findings (JA4PROXY-2026-0095,
JA4PROXY-2026-0096) plus its own residual backlog (Phase 523: OIDC aud/iss
binding, WebAuthn origin, analytics input validation, tarpit bounds,
inter-container pubsub HMAC).

## Summary

An adversarial pass over everything that is **not** the Go proxy: the Python
**Management API** (FastAPI — auth, OIDC, SAML, WebAuthn, TOTP, tokens, CSRF,
DSAR/compliance, EDL/threat-intel), the analytics node, the tarpit, the Redis
control plane, and the container/compose wiring between them.

The obvious vuln classes are already closed (no `eval`/`pickle`/unsafe-YAML, no
`shell=True` on user input, no `verify=False`, no naive SSRF; extensive pentest
regression tests exist). The one **real** finding is systemic and high-impact:
**`JA4PROXY-2026-0093`** — every "test-mode" security escape hatch, and the
startup guard meant to catch it, gate on an environment check that **fails open**
for any `ENVIRONMENT` value other than exactly `production`/`prod`. On a DMZ
appliance (this product's whole reason for existing) where `ENVIRONMENT` is
plausibly unset or `dmz`, a stray `MANAGEMENT_TEST_MODE=1` silently activates a
**public hardcoded JWT signing secret** and disables OIDC signature checks →
admin-token forgery.

---

## How to work this phase (read first)

1. **Toolchain — containerized Python (strict).** Do **not** run `pip`, `pytest`,
   `ruff`, or `mypy` on the host, and never create a venv. Everything Python runs
   in the pinned tools image via `make` targets or:
   `docker run --rm -v "$PWD":/src -w /src ja4proxy-tools pytest <args>`.
   The management tests live under `management/tests/`.
2. **Where the code is.** `management/api/` — `main.py` (app factory + startup
   guards), `auth.py` (JWT, admin creds, test-mode), `middleware/csrf.py`,
   `routes/*.py` (one file per feature). `_is_production()` is defined **three
   times** (auth.py, main.py, csrf.py) — all three are part of this finding.
3. **How to run the management tests.**
   `docker run --rm -v "$PWD":/src -w /src ja4proxy-tools pytest management/tests/ -q`.
4. **Definition of done.** Same as Phase 520: code change + a regression test that
   **fails if the fix is reverted** (verify by reverting), tests green, and
   `findings.yaml` entry set to `FIXED` with `regression_test` populated
   (`python3 scripts/findings_register.py validate` exits 0).

---

## Finding 1 — `JA4PROXY-2026-0093` (HIGH): security escape-hatches fail open when `ENVIRONMENT` ≠ `production`

### What's wrong

All three copies of `_is_production()` are:

```python
def _is_production() -> bool:
    env = os.environ.get("ENVIRONMENT", "").strip().lower()
    return env in {"production", "prod"}
```

So **unset**, `staging`, `dmz`, `dev`, `qa`, a typo like `prodction` — anything
that isn't exactly `production`/`prod` — is treated as "not production."

Every test-only escape hatch is gated on `not _is_production()`:

- `management/api/auth.py`, `is_test_mode()`:
  ```python
  if _is_production():
      return False
  return os.environ.get("MANAGEMENT_TEST_MODE") == "1"
  ```
- `management/api/auth.py`, `_get_secret_key()`: when `MANAGEMENT_JWT_SECRET` is
  unset **and** `is_test_mode()`, it returns the **public, hardcoded** string
  `"test-secret-do-not-use-in-production"` as the JWT signing key. OIDC signature
  verification is likewise skipped in test mode (`routes/oidc.py`).
- `management/api/middleware/csrf.py`: `if os.environ.get("MANAGEMENT_DISABLE_CSRF") == "1" and not _is_production(): return await call_next(request)` — CSRF entirely off.
- SAML: `MANAGEMENT_SAML_STRICT=false` disables IdP signature validation
  (guarded only in production).

The startup backstop `_enforce_no_test_mode_in_production()`
(`management/api/main.py`) refuses to boot when these flags are armed — **but only
`if _is_production()`**. With `ENVIRONMENT` unset/`dmz`, the guard is a no-op and
the app boots with authentication disabled.

### Why it matters (attacker's view)

JA4proxy is deployed as a **DMZ security appliance**. It is entirely plausible for
an operator to run the management container with `ENVIRONMENT` unset, or set to
`dmz`/`staging`, while a base image or a copied compose file still carries
`MANAGEMENT_TEST_MODE=1` (it is a "test-only" flag, so it lives in test compose
files). In that state:

- JWTs are signed with a **secret that is published in this source tree**, so an
  attacker mints a valid admin token and takes over the management plane (change
  the dial to 0, clear blocklists, unban IPs, exfiltrate DSAR/compliance data).
- OIDC signature verification is skipped → forged identity assertions accepted.
- CSRF and/or SAML signature checks may also be off.

The failure mode is a **common misconfiguration amplified by a fail-open default**
— exactly the shape that turns "someone forgot an env var" into a full auth
bypass on an internet-facing service.

### The fix (junior: do exactly this)

**Invert the default so security fails closed.** The escape hatches must activate
**only** when the environment is *explicitly* a known non-production value; unset
or unknown must be treated as production.

1. Create one shared helper (do not keep three copies). Put it somewhere both
   `auth.py`, `main.py`, and `csrf.py` already import from, or a new
   `management/api/environment.py`:
   ```python
   # Explicit allowlist of non-production environments where test-only escape
   # hatches (hardcoded JWT secret, OIDC/SAML/CSRF bypass) may activate.
   _NONPROD_ENVIRONMENTS = {"dev", "development", "test", "testing", "local", "ci"}

   def is_explicit_nonproduction() -> bool:
       """True ONLY for a known dev/test environment. Unset or unknown => False
       (treated as production) so security features fail CLOSED."""
       return os.environ.get("ENVIRONMENT", "").strip().lower() in _NONPROD_ENVIRONMENTS

   def is_production() -> bool:
       """True for everything that is not an explicit non-production env."""
       return not is_explicit_nonproduction()
   ```
2. Replace the three `_is_production()` bodies to call the shared `is_production()`
   (or delete them and import the shared one). Replace every `not _is_production()`
   test-hatch gate with `is_explicit_nonproduction()`.
3. Update `_enforce_no_test_mode_in_production()` so it refuses to boot whenever a
   test flag is armed **and** the environment is not an explicit non-prod value
   (i.e. `if not is_explicit_nonproduction() and <flag armed>: raise`). This makes
   the startup guard fire for unset/`dmz`/`staging` too.
4. Add a second, stricter guard: **never** serve with the hardcoded JWT secret
   unless `is_explicit_nonproduction()`. In `_get_secret_key()`, the hardcoded
   branch must require `is_explicit_nonproduction()`, not merely `is_test_mode()`.

### The test (junior: add this — it is the acceptance criterion)

Add `management/tests/test_environment_failclosed.py` (use `monkeypatch` to set
env vars; use the existing test app factory pattern from `management/tests/`):

- **Unset ENVIRONMENT + TEST_MODE=1 must NOT enable test mode.** `monkeypatch.delenv("ENVIRONMENT", raising=False)`, `monkeypatch.setenv("MANAGEMENT_TEST_MODE", "1")`, `monkeypatch.delenv("MANAGEMENT_JWT_SECRET", raising=False)`. Assert that building the app **raises** (startup guard fires) OR — if you keep boot allowed — assert `is_test_mode()` is `False` and `_get_secret_key()` **raises** rather than returning the hardcoded secret.
- **ENVIRONMENT=dmz + TEST_MODE=1** → same assertion (fail closed).
- **ENVIRONMENT=dev + TEST_MODE=1** → test mode allowed (`is_test_mode()` True) — proves you didn't break local development.
- **ENVIRONMENT unset + MANAGEMENT_DISABLE_CSRF=1** → CSRF middleware still enforces (a mutating `/api/v1/*` request without a token gets 403). Copy the request pattern from `management/tests/test_csrf.py`.
- **Verify revert-sensitivity:** restore the old `_is_production()` and confirm these tests fail.

### Acceptance criteria for Finding 1
- [ ] `is_production()` fails **closed**: unset/unknown `ENVIRONMENT` ⇒ production.
- [ ] Test-mode hatches (hardcoded JWT secret, OIDC skip, CSRF disable, SAML
      strict-off) activate **only** for an explicit dev/test `ENVIRONMENT`.
- [ ] Startup guard refuses to boot with any hatch armed unless
      `is_explicit_nonproduction()`.
- [ ] `_get_secret_key()` never returns the hardcoded secret outside an explicit
      dev/test env.
- [ ] `test_environment_failclosed.py` passes and fails on revert; existing
      `test_auth.py` / `test_csrf.py` / `test_oidc.py` still pass.
- [ ] Only **one** definition of the environment check remains (no drift).
- [ ] `findings.yaml` 0093 → FIXED.

---

## Areas reviewed and found clean (do not re-hunt without new information)

- **SAML** (`routes/saml.py`): uses `python3-saml` (`OneLogin_Saml2_Auth`) with
  `strict=true` default; ACS validates a single-use Redis nonce (RelayState) for
  CSRF and checks `is_authenticated()` after `process_response()`. Correct use of
  a vetted library. (The strict-off *escape hatch* is covered by 0093.)
- **CSRF** (`middleware/csrf.py`): double-submit signed token on all mutating
  `/api/v1/*`; Bearer callers exempt (correct — no ambient credential). The
  *disable* hatch is 0093.
- **Injection surface**: no `eval`/`exec`/`pickle`/`marshal`/unsafe `yaml.load`;
  no `shell=True` on user input; no `verify=False`/`CERT_NONE`; no obvious
  user-controlled outbound URL (SSRF). Re-run the sweep:
  `grep -rnE "yaml.load\(|pickle.load|eval\(|exec\(|shell=True|verify=False" management/ src/`.
- **DSAR / compliance** (`routes/compliance.py`, `test_pentest_dsar_bounded_xrange_regression.py`):
  the stream read is already bounded (a prior finding). Not re-opened.
- **Rate limiting** (`test_pentest_mgmt_rate_limit_redis_regression.py`): Redis
  sliding-window limiter with an existing regression test.

## Areas NOT fully audited (explicit continuation backlog for the junior/next pass)

Be honest that this pass was time-boxed. The following are **not cleared** — they
are the highest-value places to look next, with the specific question to ask:

1. **Authorization vs authentication (IDOR / missing role checks).** Confirm every
   *mutating* and *data-returning* route under `routes/` has a role/permission
   dependency, not merely "is authenticated." Method: list each router's
   `Depends(...)`; flag any state-changing route that only requires a valid token.
   Red-team question: *can a read-only viewer hit `POST /api/v1/dial` or the
   ban/blocklist endpoints?*
2. **Rate-limit / lockout fail-open on Redis outage.** Trace what the management
   auth + rate limiter do when Redis is unreachable. If they fail open, an
   attacker who can disrupt Redis removes brute-force protection. (The proxy is
   *meant* to fail open; the **auth** plane should fail **closed**.)
3. **WebAuthn / OIDC / SAML callback origin & audience binding.** Verify
   `redirect_uri`/`aud`/`Audience`/WebAuthn `origin` are validated against an
   allowlist, not reflected. Red-team question: *open-redirect or token-audience
   confusion in the callback handlers?*
4. **Container/compose wiring.** Audit `docker-compose*.yml` and `deploy/docker/*`:
   is Redis reachable without auth/TLS between containers? Are management ports
   bound to `0.0.0.0` or loopback? Are secrets passed via env (visible in
   `docker inspect`) vs files? Is `pubsub_hmac_secret` set so the proxy rejects
   forged control-plane pub/sub messages? (Cross-reference `JA4PROXY-2026-0080`.)
5. **Analytics / tarpit services** (`src/analytics/`, `src/tarpit/`): stream
   consumer input validation, and the tarpit's own resource bounds.

Each of these deserves its own finding if something is found; register with
`python3 scripts/findings_register.py add ...` before fixing.

---

## Critical review of this phase doc (self-audit)

**Suitable for a junior with little codebase knowledge?** The one implemented
finding is fully specified (exact files, the three duplicate helpers called out,
inline buggy code, a concrete fix with sample code, a test with the exact env-var
manipulations and which existing test files to copy patterns from, and a
revert-check). Junior pitfalls pre-empted:
- *"There are three `_is_production()` — which do I change?"* All three; the fix
  says consolidate to one shared helper.
- *"How do I test env-var behaviour without leaking state between tests?"* Use
  `monkeypatch.setenv/delenv` (pytest) — stated; it auto-reverts per test.
- *"Won't failing closed break local dev?"* No — `dev`/`test`/`local`/`ci` are on
  the allowlist; the `ENVIRONMENT=dev` test case proves it.

**Did the requester miss anything?**
- Yes, deliberately flagged above: this pass did **not** finish authorization
  (IDOR), Redis-outage auth fail-open, callback origin/audience binding, or the
  compose/inter-container audit. Those are listed as a concrete backlog rather
  than silently omitted. A follow-on phase (522) should take them.
- The finding is **systemic** (a fail-open primitive reused in ≥3 places), so the
  fix is "fix the primitive once," which is more robust than patching each call
  site — call this out to the junior so they don't just patch `is_test_mode()`.

**Other similar bugs elsewhere in the codebase?**
- Search for other consumers of `ENVIRONMENT` / `_is_production()` /
  `is_test_mode()` after the fix lands:
  `grep -rnE "ENVIRONMENT|_is_production|is_test_mode|TEST_MODE" management/ src/`
  — ensure every security-relevant toggle now routes through the fail-closed
  helper. The Go proxy has its own `os.Getenv("ENVIRONMENT") == "production"`
  checks (`cmd/ja4pd/main.go`, e.g. the `ALLOW_UNAUTH_REDIS` guard and log
  redaction); review those for the same fail-open shape (they gate *hardening on*
  rather than *security off*, so they are lower risk, but confirm).

---

## Out of scope
- Implementation of the fix (this phase documents; implementation is a separate PR).
- The Go proxy hot path — that is **Phase 520**.
- The continuation backlog items above — a future **Phase 522** unless promoted.
