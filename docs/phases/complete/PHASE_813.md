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
   `analytics` lists `secrets: [redis_password]` despite not needing the
   proxy's own password — it gets its actual working credential via a normal
   compose-level `${ANALYTICS_REDIS_PASSWORD}` interpolation in its
   `REDIS_URL`, which **does** work correctly (compose-level `${VAR}`
   interpolation in the YAML itself is a different, working mechanism from a
   file bind-mounted into a container, which is the actual point of confusion
   that caused this whole chain of bugs) — that stray secret mount is an
   unused copy-paste artifact, removed. (Corrected during implementation: an
   earlier draft of this investigation also flagged `promtail` and
   `redis-exporter` here; re-checked and both were wrong. `promtail` never
   had a stray secret at all — a mis-scoped grep matched into the next
   service block (`ja4-tap`), which legitimately owns
   `ja4tap_redis_password`. `redis-exporter`'s `secrets: [redis_password]`
   wasn't stray either — it's a real, if broken, Redis client: it
   authenticates with no username at all via `REDIS_PASSWORD_FILE`, which
   defaults to the disabled `default` user, the same root cause as the
   proxy's own bug. Fixed with its own `exporter` ACL user rather than
   removed.)

## Additional findings during implementation (not in the original investigation)

Four more bugs surfaced only once the fix above was actually run against a
real container — each verified with a minimal, deterministic repro before
being fixed, the same discipline as the original investigation:

6. **Docker Compose's `secrets:` long-form `uid`/`gid`/`mode` fields are
   swarm-only.** First attempt at fixing (7) below used them; Compose logged
   `secrets uid, gid and mode are not supported, they will be ignored` and
   silently fell back to a raw bind-mount. Reverted to short-form `secrets:`
   everywhere and fixed the real problem with `cap_add: [DAC_OVERRIDE]`
   instead (see (7)).
7. **Every service reading a Docker secret alongside `cap_drop: [ALL]` was
   unable to read it.** `deploy/secrets/*.txt` are chmod 600 on the host,
   owned by whichever user ran `start-poc.sh` (policy:
   `deploy/secrets/README.md`, "Files MUST be 600" — not weakened to fix
   this). `docker compose` (non-swarm) bind-mounts secret files with the
   host file's permissions verbatim, and `cap_drop: [ALL]` removes
   `CAP_DAC_OVERRIDE` — so a container process can't read a secret it
   doesn't own, root or not. Affected every hardened service consuming a
   secret: `redis` (new), `proxy`, `redis-exporter`, `grafana`, `ja4-tap`
   (all pre-existing — `ja4-tap`'s own secret read only ever "worked" by
   coincidental UID alignment between its fixed container UID 1000 and the
   common first-non-root-user UID on Debian/Ubuntu hosts and GitHub Actions
   runners, not a real guarantee). Fixed by adding `cap_add: [DAC_OVERRIDE]`
   to each (alongside `NET_BIND_SERVICE` on `proxy` and `NET_RAW` on
   `ja4-tap`, both pre-existing).
8. **Redis's `--aclfile` parser does not support `#` comments at all**
   (unlike `redis.conf`). Isolated with a two-line repro: a comment-free ACL
   file loaded fine; adding one leading `# comment` line broke it with the
   exact "should start with user keyword" error seen throughout this
   investigation. Blank lines are tolerated. Fixed in
   `redis-entrypoint.sh` by stripping comment lines (`grep -v
   '^[[:space:]]*#'`) when rendering — `config/redis_acl.conf.template`
   keeps its full documentation for humans; only the rendered `/tmp` copy
   redis-server reads is stripped.
9. **`+@read`/`+@write` do not imply `+ping`** in Redis's ACL category
   system (`PING` is categorized `@fast @connection`). `proxy`,
   `management`, and `exporter` all authenticated successfully but got
   `NOPERM` on `ping` — including `start-poc.sh`'s own healthcheck, which
   would have reported failure despite auth genuinely working.
   `analytics`'s pre-existing grant already had `+ping` explicitly; mirrored
   that for the three affected users.
10. **`docker-compose.prod.yml`'s `proxy` service never bridged
    `/run/secrets/redis_password` into the `REDIS_PASSWORD` env var**
    `config/proxy.yml`'s `password: "${REDIS_PASSWORD}"` needs. No `_FILE`
    convention exists in the Go binary (`cmd/ja4pd`) or Dockerfile
    entrypoint. `REDIS_PASSWORD` would have resolved to empty, and every
    Redis operation would have failed AUTH — in prod specifically; POC's
    proxy service was already correct (sets `REDIS_PASSWORD` as a plain
    env var directly, no Docker secret involved). Fixed with the same
    shell-wrapper entrypoint pattern `ja4-tap` already used.

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

- [x] `./scripts/start-poc.sh` succeeds end-to-end from a clean checkout
      (no `.env`, no `deploy/secrets/`) — verified in a scratch git
      worktree. `Checking Redis... ✓`, `Checking Backend... ✓`,
      `Checking Proxy... ✓`, and the proxy's own `/health` endpoint reports
      `{"redis":"ok","status":"ok"}` — the actual root-cause failure this
      phase exists to fix. Not yet independently re-verified against a real
      4-core-constrained CI runner (812-A, blocked on this phase, will make
      that a standing regression check going forward).
- [x] All five ACL users (`proxy`, `management`, `analytics`, `ja4tap`,
      `exporter`) authenticate correctly against a real container and can
      perform their intended operations (verified `ping` for all five, plus
      a real `ja4tap` `SET ... EX`); `analytics`'s least-privilege scoping
      confirmed (`NOPERM` on a key outside `analytics:*`); `default` remains
      rejected (`NOAUTH`).
- [x] `docker-compose.prod.yml` changes reviewed for an operator upgrading
      an existing prod deployment — header comment documents all five
      required secret files and an explicit migration note (existing
      deployments must generate the four new files before restarting
      redis, or it refuses to start).
- [x] `make test` and `make lint` pass with zero warnings (verified locally
      after adding `EXPORTER_REDIS_PASSWORD` to `lint-docker`'s
      `docker-compose.monitoring.yml` placeholder set, which my own change
      made a new requirement of).
- [x] `docs/reference/REDIS_SCHEMA.md` and `docs/runbooks/tap_mode.md`
      updated to reflect the corrected auth chain and the
      `redis_acl.conf` → `redis_acl.conf.template` rename.
- [x] CHANGELOG fragment added noting this as a production-impacting fix
      (`docs/fragments/phase-813-redis-acl-auth-fix.md`).

## Out of scope

- Changing any ACL *permission* grant (`~analytics:*`, `~fp:*`, etc.).
- Replacing the `redis:7.4.9-alpine` base image or Redis version.
- Phase 812's CI/automation hardening work, which depends on this phase
  (812-A's cold-start smoke test cannot pass until this lands) but is
  otherwise independent.
