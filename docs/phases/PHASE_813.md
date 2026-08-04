---
phase: 813
title: "Redis ACL authentication fix (production-impacting)"
status: PROPOSED
created: 2026-08-04
audience: [developer]
---

# Redis ACL authentication fix (production-impacting)

## Goal (plain language)

Redis authentication is currently broken in **both** `docker-compose.poc.yml`
and `docker-compose.prod.yml` — not a test-only issue. This was discovered
while investigating a Nightly Benchmark failure (Phase 812's motivating
incident) and traced through several layers before reaching the real root
cause. This phase fixes the whole chain, methodically, with each claim
verified the same way the first bug was found: a direct `redis-cli` auth
test against a real container, not just "the compose file looks right."

## Investigation (what's actually broken, verified)

1. **`--requirepass-file` is not a real Redis directive.** Both compose
   files' `redis` service pass it directly to `redis-server` as a CLI arg.
   Verified directly:
   ```
   docker run redis:7.4.9-alpine redis-server --requirepass-file /run/secrets/redis_password
   *** FATAL CONFIG FILE ERROR (Redis 7.4.9) ***
   >>> 'requirepass-file "/run/secrets/redis_password"'
   Bad directive or wrong number of arguments
   ```
   Redis crash-loops immediately on startup. This is why last night's Nightly
   Benchmark failed at "Checking Redis... ✗ Failed" — the container never
   comes up at all.

2. **`config/redis_acl.conf` is bind-mounted read-only, verbatim**, in both
   compose files (`../../config/redis_acl.conf:/etc/redis/redis_acl.conf:ro`).
   It contains literal placeholders — `user management on
   >${MANAGEMENT_REDIS_PASSWORD} ...`, `>${ANALYTICS_REDIS_PASSWORD}`,
   `>${JA4TAP_REDIS_PASSWORD}`. Redis ACL files do not support shell-style
   variable substitution, and nothing renders this file before Redis reads
   it — grep confirms no `envsubst`/templating step exists anywhere in
   `scripts/` or either compose file. Redis would load these four
   characters `${...}` as the literal password string.

3. **`scripts/start-poc.sh` never generates `MANAGEMENT_REDIS_PASSWORD` or
   `JA4TAP_REDIS_PASSWORD`** — only `REDIS_PASSWORD` and
   `ANALYTICS_REDIS_PASSWORD` exist in its `.env` auto-generation block. Even
   if (2) were fixed, two of the four ACL users' passwords would be empty in
   a from-scratch POC run.

4. **The Go proxy itself authenticates as the disabled `default` user.**
   `config/proxy.yml` sets `username: ""` (default user). `redis_acl.conf`
   explicitly disables it: `user default off nopass ~* -@all`. As currently
   configured, **the proxy can never authenticate to Redis** — in POC or
   prod — regardless of (1)–(3). This is the most severe finding: it means
   the core proxy's Redis connectivity (rate limiting, bans, JA4
   blocklists, session resumption, everything in
   `docs/reference/REDIS_SCHEMA.md`) has never worked against the real ACL
   file, only against test fixtures/fakeredis that don't enforce ACLs.

5. **Secondary wiring inconsistencies found while auditing service-by-service**
   (prod compose file): the `redis` service's own `secrets:` list only
   includes `redis_password` — not `analytics_redis_password` or
   `ja4tap_redis_password` — so even with (2) fixed, the redis *container*
   itself doesn't have those secret files available to read from. Separately,
   `analytics` and `redis-exporter` services both list `secrets: [redis_password]`
   despite not needing the proxy's own password (analytics gets its actual
   working credential via a normal compose-level `${ANALYTICS_REDIS_PASSWORD}`
   interpolation in its `REDIS_URL`, which **does** work correctly — compose-level
   `${VAR}` interpolation in the YAML itself is a different, working mechanism
   from a file bind-mounted into a container, which is the actual point of
   confusion that caused this whole chain of bugs). `promtail` lists
   `secrets: [ja4tap_redis_password]`, which it has no legitimate use for.
   These look like copy-paste artifacts from earlier phases, not
   functional bugs on their own, but are cleaned up here for correctness
   and to stop the pattern from being copied again.

## Root cause, in one sentence

Phase 236 introduced per-service Redis ACL users and hardened the `default`
user off, but the migration was incomplete: nothing renders the ACL file's
templated passwords, the proxy itself was never migrated to a named ACL
user, `start-poc.sh` never learned about two of the four users, and the
compose files still reference a made-up `--requirepass-file` directive.

## Scope

In scope: `config/redis_acl.conf` (renamed to `.template`), a new redis
entrypoint wrapper script, both compose files' `redis` service definition
and `secrets:` blocks, `config/proxy.yml`, `scripts/start-poc.sh`, and the
equivalent prod secrets-file expectations (documented, since prod secret
provisioning is operator-driven, not scripted the way POC is).

Out of scope: any change to the ACL *permission grants* themselves
(`~analytics:*`, `~fp:*`, etc.) — those are correct per Phase 236/809's
reasoning and untouched here. This phase fixes *authentication plumbing*,
not authorization policy.

## Implementation plan

### 813-A — Give the proxy a real ACL user

- `config/redis_acl.conf`: add
  `user proxy on >${REDIS_PASSWORD} ~* +@read +@write -@admin`
  (same permission shape as `management`, but a distinct credential —
  least-privilege still means separate rotatable credentials per service,
  even where the grant looks the same). Reuses the existing `REDIS_PASSWORD`
  variable/secret — no new secret needed for this one, since it's already
  generated and provisioned everywhere.
- `config/proxy.yml`: `username: ""` → `username: "proxy"`.

### 813-B — Render the ACL template at container start

- Rename `config/redis_acl.conf` → `config/redis_acl.conf.template` (the
  `.template` suffix makes it structurally impossible to accidentally
  bind-mount the raw, unrendered file again — the old bug becomes
  unreproducible by construction, not just by convention).
- New `deploy/docker/redis-entrypoint.sh`: a small, dependency-free POSIX
  shell script (no `envsubst`/`gettext` — not present in `redis:7.4.9-alpine`)
  that:
  1. Reads each of `/run/secrets/redis_password`,
     `/run/secrets/management_redis_password`,
     `/run/secrets/analytics_redis_password`,
     `/run/secrets/ja4tap_redis_password`.
  2. Substitutes them into the mounted `.template` file, writing the
     rendered result to `/tmp/redis_acl.conf` — `/tmp` is already
     `tmpfs`-mounted and writable in both compose files despite
     `read_only: true` on the container root, and never persisted to disk
     (appropriate for secret material).
  3. `exec redis-server --aclfile /tmp/redis_acl.conf "$@"` — the `"$@"`
     picks up the *rest* of the flags from the compose file's `command:`
     (maxmemory, hz, tcp-keepalive, etc.), with `--requirepass-file`
     removed from that list entirely (no longer needed — `default` is
     disabled, all real auth goes through named ACL users).
- Both compose files: mount the template at `/etc/redis/redis_acl.conf.template`
  (`:ro`), mount the new script at `/usr/local/bin/redis-entrypoint.sh`
  (`:ro`, executable bit set in git), override `entrypoint:` to point at it,
  and trim `command:` down to the non-auth flags only.

### 813-C — Complete the secrets wiring

- `scripts/start-poc.sh`: add `MANAGEMENT_REDIS_PASSWORD` and
  `JA4TAP_REDIS_PASSWORD` to the `.env` auto-generation block (same
  `openssl rand` pattern already used for the others). Extend the existing
  `deploy/secrets/redis_password.txt` creation block (from PR #381) to also
  write `deploy/secrets/management_redis_password.txt`,
  `deploy/secrets/analytics_redis_password.txt`, and
  `deploy/secrets/ja4tap_redis_password.txt`, using the same
  grep-out-of-.env-into-file approach (JA4PROXY-2026-0040-safe, no
  echo/printf of the secret value).
- `docker-compose.poc.yml`: add a top-level `secrets:` entries for
  `management_redis_password` and `ja4tap_redis_password`
  (`analytics_redis_password` doesn't need a *file* secret in POC context —
  see next bullet); attach all four to the `redis` service's `secrets:` list.
- Both compose files: fix the `redis` service's `secrets:` list to include
  all four password secrets (currently only has `redis_password`). Remove
  the stray `secrets: [redis_password]` from `analytics` and
  `redis-exporter` in `docker-compose.prod.yml` (unused — analytics gets
  its real credential via `${ANALYTICS_REDIS_PASSWORD}` YAML interpolation,
  not a mounted file) and the stray `secrets: [ja4tap_redis_password]` from
  `promtail` (no legitimate use).
- `scripts/start-poc.sh` healthcheck: change
  `redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning ping` to
  `redis-cli --user proxy -a "${REDIS_PASSWORD}" --no-auth-warning ping` —
  authenticating as the real `proxy` ACL user, matching what the actual
  proxy service now does, instead of the disabled `default` user (which
  would reject *any* credential, valid or not).

### 813-D — Prod secrets documentation

- `docker-compose.prod.yml`'s header comment (currently lists
  `deploy/secrets/redis_password.txt` as the only prerequisite) updated to
  list all four required secret files, matching the pattern already
  partially present for `ja4tap_redis_password.txt` (see existing Phase 809
  comment at line ~386).
- `docs/runbooks/` gets a short note (extending the existing tap-mode
  runbook or a new short runbook section) on generating these four secret
  files for a prod deploy, mirroring what `start-poc.sh` now automates for
  POC.

## Test strategy

- **Direct auth verification per user** (the exact technique that found
  this bug): spin up the redis container with the rendered ACL file and
  confirm via `redis-cli --user <name> -a <password> ping`:
  - `proxy` — succeeds with `REDIS_PASSWORD`.
  - `management` — succeeds with `MANAGEMENT_REDIS_PASSWORD`.
  - `analytics` — succeeds with `ANALYTICS_REDIS_PASSWORD`, and confirm it
    is scoped to `analytics:*` only (an out-of-scope key access fails with
    `NOPERM`).
  - `ja4tap` — succeeds with `JA4TAP_REDIS_PASSWORD`, confirm scoped to
    `fp:*` only.
  - `default` — confirm it is *still* rejected outright (the hardening
    from Phase 236 must not regress).
- Full `./scripts/start-poc.sh` end-to-end run, confirming "Checking
  Redis... ✓" and the proxy's own health check succeeds (proxy actually
  connecting to Redis via the new `proxy` ACL user, not just Redis coming
  up).
- Existing `tests/unit/test_pentest_start_scripts_password_echo_regression.py`
  re-run against the expanded secrets-file-writing block in
  `start-poc.sh` (must still avoid echo/printf of secret expansions).
- New `tests/integration/test_redis_acl_auth.py`: brings up a real
  containerized Redis with the rendered ACL file (via
  `docker-compose.test.yml` or a scoped fixture) and asserts all four users'
  auth + scoping programmatically, so this doesn't silently regress again.

## Acceptance criteria

- [ ] `./scripts/start-poc.sh` succeeds end-to-end from a clean checkout
      (no `.env`, no `deploy/secrets/`) on a 4-core runner, with the proxy
      actually reachable and its Redis-backed features (rate limiting,
      blocklist) functioning, not just "container is up."
- [ ] All four ACL users authenticate correctly against a real container;
      `default` remains rejected.
- [ ] `docker-compose.prod.yml` changes reviewed for an operator upgrading
      an existing prod deployment (this changes what secret files are
      required — document the migration step, don't silently break
      existing deployments that only have `redis_password.txt` today).
- [ ] `make test` and `make lint` pass with zero warnings.
- [ ] `docs/reference/REDIS_SCHEMA.md` and
      `docs/runbooks/` updated to reflect the corrected auth chain.
- [ ] CHANGELOG fragment added noting this as a production-impacting fix.

## Out of scope

- Changing any ACL *permission* grant (`~analytics:*`, `~fp:*`, etc.).
- Replacing the `redis:7.4.9-alpine` base image or Redis version.
- Phase 812's CI/automation hardening work, which depends on this phase
  (812-A's cold-start smoke test cannot pass until this lands) but is
  otherwise independent.
