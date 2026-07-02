# Phase 522 — Aggressive Bug Hunt: Management Auth, Access Control & Wiring (Red-Team Pass 2)

> **For the implementing engineer:** written to be actionable with **no prior
> knowledge of this codebase**. Every finding lists the exact file, the exact
> code, why it's wrong, the exact change, and the exact test. Read "How to work
> this phase" first. Do findings in order. Ask before deviating.

## Status: OPEN

## Summary

This phase works the "not fully audited" backlog left open by Phase 521:
authorization/IDOR, Redis-outage auth fail-open, SSO callback binding, and the
container/compose wiring. Most of it held up well (see "reviewed clean"). Two
real findings remain, both about **secure defaults**:

- **`JA4PROXY-2026-0095` (MEDIUM)** — the management plane already decided (in
  `JA4PROXY-2026-0034`) that a missing/invalid role must default to the
  *least*-privileged `auditor`. Three sibling code paths never got that memo:
  bearer-token validation defaults to `operator`, token **rotate** defaults to
  `operator`, and `_create_access_token` defaults to `admin`. A malformed token
  expiry is also treated as "never expires."
- **`JA4PROXY-2026-0096` (MEDIUM)** — the quickstart `docker-compose.yml` ships a
  **committed, known-value** `MANAGEMENT_JWT_SECRET`; nothing refuses to boot on
  it, so a deployment that forgets to override it signs admin JWTs with a public
  key.

Both are **secure-default / fail-closed** fixes and dovetail with the Phase 521
finding `JA4PROXY-2026-0093` (fix that first or alongside — they share a helper).

---

## How to work this phase (read first)

1. **Containerized Python (strict).** Never run `pytest`/`pip`/`ruff`/`mypy` on
   the host and never make a venv. Use the tools image:
   `docker run --rm -v "$PWD":/src -w /src ja4proxy-tools pytest management/tests/ -q`.
2. **Where the code is.** `management/api/auth.py` (JWT, roles, bearer tokens,
   `_create_access_token`, `get_bearer_user`), `management/api/routes/tokens.py`
   (API-token CRUD + rotate), `docker-compose.yml` (quickstart compose, repo
   root). The role hierarchy is `auditor < analyst < operator < admin`
   (`_ROLE_ORDER` in `auth.py`).
3. **The established rule you are enforcing.** Read the `JA4PROXY-2026-0034`
   comment in `auth.py` `get_current_user` (~line 465): "default to the
   least-privileged role … defaulting to `Role.admin` … turned every tampered /
   malformed token into a privilege escalation." Findings here apply that same
   rule to the paths it missed.
4. **Definition of done (per finding).** Code change + a regression test that
   **fails if your fix is reverted** (verify by reverting), management tests
   green, and the `findings.yaml` entry set to `FIXED` with `regression_test`
   populated (`python3 scripts/findings_register.py validate` exits 0).
5. **Do Phase 521's `JA4PROXY-2026-0093` first (or together).** Both 0093 and
   0096 want a single fail-closed "is this an explicit dev/test environment?"
   helper. Build it once (see PHASE_521.md) and reuse it here.

---

## Finding 1 — `JA4PROXY-2026-0095` (MEDIUM): insecure role defaults on the bearer / rotate / create paths

### What's wrong (four spots, one theme)

All in `management/api/`:

1. **Bearer token, missing role** — `auth.py`, `get_bearer_user`:
   ```python
   role_str = fields.get("role", "operator")   # ← should be "auditor"
   try:
       role = Role(role_str)
   except ValueError:
       role = Role.operator                      # ← should be Role.auditor
   ```
   A bearer token whose stored hash has no/invalid `role` field is granted
   **operator** (can create bans, edit lists).
2. **Token expiry, malformed value** — `auth.py`, `get_bearer_user`:
   ```python
   except ValueError:
       pass  # malformed date; ignore   # ← token then treated as NON-expiring
   ```
   An unparseable `expires_at` means the expiry check is skipped and the token is
   accepted.
3. **Token issuance default** — `auth.py`:
   ```python
   def _create_access_token(username: str, role: str = "admin") -> str:   # ← default admin
   ```
   Any caller that forgets the `role=` argument mints an **admin** token. Only
   the admin-only local login relies on this today, but it is a latent footgun.
4. **Token rotate default** — `routes/tokens.py` (rotate handler):
   ```python
   "role": old_fields.get("role", "operator"),   # ← should be "auditor"
   ```

This is the exact class `JA4PROXY-2026-0034` fixed for the cookie path — it just
wasn't applied consistently.

### Why it matters

New tokens created through the API always carry a valid role, so there is no
one-click exploit today. But the management plane's stated posture is
"fail closed to least privilege on any malformed/missing role." A legacy token,
a partially-written Redis hash, a rotated role-less token, or a future caller of
`_create_access_token` silently gains **write** (operator) or **admin** authority
instead of read-only. On a security appliance that is the wrong direction to fail.

### The fix (junior: do exactly this)

1. In `auth.py` `get_bearer_user`: change **both** role fallbacks from
   `operator` to `auditor` (the least-privileged role):
   - `role_str = fields.get("role", "auditor")`
   - `except ValueError: role = Role.auditor`
2. In `auth.py` `get_bearer_user`: on a malformed `expires_at`, **reject** the
   token instead of accepting it — replace `pass` with `continue` (skip this
   token / treat as invalid). Rationale: an unparseable expiry is a corrupt
   credential; fail closed.
3. In `auth.py` `_create_access_token`: remove the `= "admin"` default. Make
   `role` a **required** argument (no default) so every caller states the role
   explicitly; update the one local-login caller (`auth.py`, login handler) to
   pass `role="admin"` explicitly (it is the admin login, so this is correct and
   now visible). If you prefer a default, it must be `"auditor"`, never `"admin"`.
4. In `routes/tokens.py` rotate handler: change
   `old_fields.get("role", "operator")` to `old_fields.get("role", "auditor")`.

### The test (junior: add this — it is the acceptance criterion)

Add `management/tests/test_role_defaults_failclosed.py`. Copy the app/redis
fixture pattern from `management/tests/test_tokens.py` and `test_auth.py`.

- **Bearer token with no `role` field ⇒ auditor, not operator.** Seed a token in
  the fake Redis (`mgmt:token:{id}` hash) with a valid bcrypt `hash` but **no**
  `role` key; add its id to `mgmt:token:idx`. Call any endpoint with
  `Authorization: Bearer <raw>` that requires `operator` (e.g. `POST /api/v1/bans`)
  and assert **403** (auditor is insufficient). Before the fix it would be 2xx.
- **Bearer token with a garbage `role` value ⇒ 403 on an operator route.**
- **Malformed `expires_at` ⇒ token rejected (401).**
- **Rotate a role-less token ⇒ new token is auditor** (assert it cannot hit an
  operator route).
- **`_create_access_token` requires a role** — a unit test asserting it raises
  `TypeError` when called without `role=` (if you made it required).
- **Verify revert-sensitivity:** restore the `operator`/`admin` defaults and
  confirm each test fails.

### Acceptance criteria for Finding 1
- [ ] Every role fallback in token issuance/validation defaults to `auditor`
      (least privilege); `_create_access_token` never defaults to `admin`.
- [ ] A malformed `expires_at` rejects the token.
- [ ] `test_role_defaults_failclosed.py` passes and fails on revert; existing
      `test_tokens.py`/`test_auth.py` still pass.
- [ ] `findings.yaml` 0095 → FIXED.

---

## Finding 2 — `JA4PROXY-2026-0096` (MEDIUM): known-value default `MANAGEMENT_JWT_SECRET` with no boot guard

### What's wrong

`docker-compose.yml` (repo root, the quickstart) sets:

- `MANAGEMENT_JWT_SECRET` default = the committed literal
  `ja4proxy-quickstart-secret-change-me`
- `MANAGEMENT_ADMIN_PASSWORD` default = `changeme`

`management/api/auth.py` `_get_secret_key()` returns whatever
`MANAGEMENT_JWT_SECRET` is set to — it never checks the value. So a deployment
that runs the quickstart compose **without overriding the secret** signs admin
JWTs with a key that is public in this repository. Anyone who can reach the
management port (bound to loopback, but reachable via an SSH tunnel, a
co-located container, or an SSRF pivot) can forge an admin token
(`{"sub":"admin","role":"admin"}` signed with the known secret).

### Why it matters

JA4proxy is a **DMZ appliance**. The quickstart compose is the file an operator
under incident pressure copies. "It boots and the login works" hides that the
signing key is public. This compounds `JA4PROXY-2026-0093` (same fail-open-by-
default theme).

### The fix (junior: do exactly this)

Add a startup guard (in `management/api/main.py` `_enforce_no_test_mode_in_production`
or a new `_enforce_strong_secrets()` called from `create_app`). Refuse to boot
(`raise RuntimeError`) when **any** of these is true, **unless the environment is
an explicit dev/test value** (reuse the fail-closed helper from
`JA4PROXY-2026-0093`):

- `MANAGEMENT_JWT_SECRET` is unset, **or** equals the committed default literal
  `ja4proxy-quickstart-secret-change-me`, **or** is shorter than 32 characters.
- `MANAGEMENT_ADMIN_PASSWORD` equals `changeme` (and no `MANAGEMENT_ADMIN_PASSWORD_HASH`
  is set).

Keep the quickstart working: when `ENVIRONMENT` is an explicit dev/test value the
guard is skipped, so `make start` / CI still boot with the defaults.

### The test (junior: add this)

Add `management/tests/test_secret_boot_guard.py`:

- **Default/known secret + non-dev environment ⇒ `create_app()` raises.** Set
  `MANAGEMENT_JWT_SECRET=ja4proxy-quickstart-secret-change-me`, `ENVIRONMENT`
  unset (or `dmz`); assert `create_app()` raises `RuntimeError`.
- **Unset secret + non-dev ⇒ raises.**
- **Short secret (<32 chars) + non-dev ⇒ raises.**
- **Strong secret + non-dev ⇒ boots.**
- **Default secret + `ENVIRONMENT=dev` ⇒ boots** (quickstart preserved).
- **Verify revert-sensitivity.**

### Acceptance criteria for Finding 2
- [ ] Management refuses to boot on a weak/known/short JWT secret unless
      `ENVIRONMENT` is an explicit dev/test value.
- [ ] Quickstart (`ENVIRONMENT=dev`) still boots.
- [ ] `test_secret_boot_guard.py` passes and fails on revert.
- [ ] `findings.yaml` 0096 → FIXED.

---

## Areas reviewed and found clean (do not re-hunt without new information)

- **RBAC on mutating routes**: dial (`require_role(admin)`), bans/lists
  (`operator`), config reload (`admin`), attack-mode (`admin` + `require_mfa`),
  datacenter-policy (`admin`) all enforce a *role*, not just authentication. The
  role hierarchy `_ROLE_ORDER` is correct. (The earlier "36 routes use
  `get_current_user`" count is mostly GET/read endpoints, which is appropriate.)
- **Login brute-force lockout** (`auth.py` `_check_rate_limit`/`_record_failure`):
  **fails closed** — on a Redis error it raises 503 ("login temporarily
  disabled"), it does not let unlimited attempts through. (Its docstring wrongly
  says "fails open" — a **doc fix** worth making but not a vulnerability.)
- **Bearer-token revocation**: tokens are bcrypt-hashed in Redis and looked up
  per request, so deleting the Redis key revokes immediately; a Redis error makes
  `get_bearer_user` return `None` (rejects — fail closed).
- **OIDC**: PKCE + random `state` in Redis (5-min TTL, CSRF), server-computed
  fixed `redirect_uri`, hard-coded post-login redirect (`/`), and an ID-token
  signature-algorithm allowlist (regression test exists). No open redirect / no
  state fixation found.
- **SAML**: `python3-saml` with `strict=true` default, single-use Redis nonce
  (RelayState) for CSRF, `is_authenticated()` checked. Correct library use.
- **Redis exposure**: `docker-compose.yml` binds Redis to `127.0.0.1:6379` and
  sets `--requirepass`; management/analytics ports are loopback-bound too.

## Areas NOT fully audited (continuation backlog → future Phase 523)

Time-boxed again; be honest. Highest-value remaining:

1. **OIDC ID-token `aud`/`iss` binding.** Confirm the decode
   (`management/api/routes/oidc.py`, `_OIDC_JWT.decode(id_token, key_set)` with
   `client_id` threaded through) actually validates the `aud` claim equals the
   configured client_id and `iss` equals the discovery issuer — not just the
   signature/alg. Red-team question: *is a validly-signed token minted for a
   different client accepted?*
2. **WebAuthn origin/RP-ID binding** (`routes/webauthn.py`): confirm
   registration/authentication verify `origin` and `rpId` against an allowlist,
   and that the challenge is single-use from Redis.
3. **Analytics stream consumer** (`src/analytics/stream_consumer.py`): validate
   that fields read from the Redis stream (attacker-influenced — the proxy writes
   connection metadata incl. SNI) are size-bounded and type-checked before use.
4. **Tarpit resource bounds** (`src/tarpit/tarpit-server.py`): its own
   per-connection / global caps.
5. **Inter-container trust**: does the proxy require `pubsub_hmac_secret` so a
   compromised co-located container cannot forge control-plane pub/sub
   (dial changes, list edits)? Cross-reference `JA4PROXY-2026-0080`.

Register a finding for anything found before fixing.

---

## Critical review of this phase doc (self-audit)

**Suitable for a junior with little codebase knowledge?** Yes: both findings give
exact files, the buggy lines inline, the established rule they enforce
(`0034`), a step-by-step fix, a concrete test with which fixture files to copy,
and a revert check. Pitfalls pre-empted:
- *"Won't defaulting bearer tokens to `auditor` break existing operator tokens?"*
  No — real tokens store an explicit `role`; only role-*less*/corrupt tokens
  change, and they should be read-only. The tests assert both.
- *"How do I seed a fake bearer token in tests?"* Write the `mgmt:token:{id}`
  hash + `mgmt:token:idx` set into the test's fake Redis; pattern is in
  `test_tokens.py`.
- *"Do 0093, 0095, 0096 overlap?"* Yes by design — all three are "fail closed by
  default." Build the one environment helper (0093) first, then 0096 reuses it.
  0095 is independent (role defaults) and can be done in parallel.

**Did the requester miss anything? / similar bugs elsewhere?**
- The role-default bug is **systemic** — after fixing, grep for every
  `get("role", ...)` / `role: str = ` / `Role(` fallback in `management/` and
  make sure none default above `auditor`:
  `grep -rnE "get\(.?role.?, ?.(operator|admin|analyst)|role: str = .(admin|operator)" management/`.
- The known-default-secret bug likely has siblings: audit **all** committed
  compose/env templates (`deploy/docker/docker-compose*.yml`, `template.env`) for
  other `:-changeme`-style secrets that lack a boot guard (Redis password,
  webhook HMAC, `pubsub_hmac_secret`). Each deserves the same fail-closed guard.
- This pass did **not** finish OIDC `aud`, WebAuthn origin, analytics input
  validation, tarpit bounds, or inter-container HMAC — listed above as Phase 523
  rather than silently dropped.

---

## Out of scope
- Implementation (this phase documents; implementation is a separate PR, likely by
  the junior engineer).
- The Phase 523 backlog items above.
