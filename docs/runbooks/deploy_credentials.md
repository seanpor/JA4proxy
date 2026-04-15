<!--
title: "Deploy Credentials Runbook"
audience: operators, sre, ci-maintainers
last_reviewed: 2026-04-15
phase: 202
-->

# Deploy Credentials

> **Scope:** Mandatory environment variables required to bring up the JA4proxy
> Docker Compose stacks after Phase 202b. All prior default fallbacks
> (`:-admin`, `:-admin123`, `:-change-me-in-production`) have been removed and
> replaced with `${VAR:?VAR is required}` — `docker compose up` now fails fast
> if any of these are unset.
>
> **Audience:** Operators deploying via Docker Compose, CI maintainers, dev
> environment setup.
>
> **Last updated:** 2026-04-15 (Phase 202b)

---

## Required environment variables

Six variables become mandatory in Phase 202b. Each MUST be set before invoking
`docker compose -f deploy/docker/docker-compose.{poc,monitoring}.yml up` — the
compose command will exit non-zero with a clear error otherwise.

### 1. `GRAFANA_PASSWORD`

- **Purpose:** Grafana admin account password (`GF_SECURITY_ADMIN_PASSWORD`).
- **Used in:** `deploy/docker/docker-compose.monitoring.yml`
- **Who sets it:** Operator (per deployment) / CI job (via GitHub Actions secret).
- **Failure mode if missing:** `docker compose config` fails with
  `GRAFANA_PASSWORD is required`. Grafana never starts.
- **Strength:** ≥16 chars, mixed case + digits + symbols. Do NOT reuse
  `MANAGEMENT_ADMIN_PASSWORD`.
- **Rotation:** See [`credential_rotation.md`](credential_rotation.md). Rotate
  every 90 days or immediately on suspected compromise. Grafana supports
  admin password change via the UI without restart; update the deployment
  env var afterwards so the next restart doesn't revert.

### 2. `HAPROXY_STATS_USER`

- **Purpose:** Username presented by the HAProxy exporter when scraping
  `/stats;csv`.
- **Used in:** `deploy/docker/docker-compose.monitoring.yml` (HAProxy exporter
  scrape URL).
- **Who sets it:** Operator. Must match the `stats auth` line in
  `deploy/haproxy/haproxy.cfg`.
- **Failure mode if missing:** Exporter starts but every scrape returns 401;
  HAProxy metrics disappear from Prometheus.
- **Rotation:** Rotate together with `HAPROXY_STATS_PASSWORD`. Update both env
  var and the `stats auth` line in `haproxy.cfg`, then
  `docker compose restart haproxy haproxy-exporter`.

### 3. `HAPROXY_STATS_PASSWORD`

- **Purpose:** Password for `HAPROXY_STATS_USER`.
- **Used in:** Same as above.
- **Who sets it:** Operator / CI secret.
- **Failure mode if missing:** As above — scrape returns 401.
- **Strength:** ≥20 chars. This credential only reads metrics, but the stats
  endpoint also exposes backend IPs and session counts.
- **Rotation:** See [`credential_rotation.md`](credential_rotation.md).

### 4. `MANAGEMENT_JWT_SECRET`

- **Purpose:** HMAC signing key for Management API JWT session tokens.
- **Used in:** `deploy/docker/docker-compose.poc.yml` (Management API service).
- **Who sets it:** Operator. **Never commit this value.** In CI, generate
  ephemerally per-run or inject from a dedicated secret store.
- **Failure mode if missing:** Management API refuses to start (compose `:?`
  fails before container boot).
- **Strength:** **MUST be ≥32 random bytes.** Generate via:
  ```
  python3 -c 'import secrets; print(secrets.token_urlsafe(48))'
  ```
  Shorter secrets reduce JWT signature strength and are rejected by the API
  on startup.
- **Rotation:** See [`credential_rotation.md`](credential_rotation.md).
  Rotating invalidates every live session — operators must re-login. Plan
  rotation during a maintenance window or use overlapping-secret support if
  added by a future phase. <!-- TODO: verify after impl -->

### 5. `MANAGEMENT_ADMIN_USER`

- **Purpose:** Bootstrap admin username for the Management API on first
  startup (seeds the initial account).
- **Used in:** `deploy/docker/docker-compose.poc.yml`.
- **Who sets it:** Operator.
- **Failure mode if missing:** Management API refuses to start (compose `:?`
  fails). First-boot account never created.
- **Rotation:** Username can be left stable; rotate only if compromised. To
  change, update env var and restart the Management API — existing admin
  accounts in Redis are not overwritten by a renamed bootstrap var. <!-- TODO: verify after impl -->

### 6. `MANAGEMENT_ADMIN_PASSWORD`

- **Purpose:** Bootstrap admin password for the Management API.
- **Used in:** Same as above.
- **Who sets it:** Operator / CI secret.
- **Failure mode if missing:** Management API refuses to start.
- **Strength:** ≥16 chars, mixed character classes.
- **Rotation:** After first boot, rotate via the Management UI
  (preferred — writes to Redis, does not require restart) then update the env
  var so the next cold-boot account-seed matches. See
  [`credential_rotation.md`](credential_rotation.md).

---

## Setting in dev

Dev environments use a gitignored `.env` file at the repo root. Docker Compose
automatically reads it:

```
# .env (NEVER commit — already covered by .gitignore)
GRAFANA_PASSWORD=dev-only-change-me-before-prod
HAPROXY_STATS_USER=haproxy-exporter
HAPROXY_STATS_PASSWORD=dev-stats-pw
MANAGEMENT_JWT_SECRET=<paste output of python3 -c 'import secrets; print(secrets.token_urlsafe(48))'>
MANAGEMENT_ADMIN_USER=admin
MANAGEMENT_ADMIN_PASSWORD=dev-admin-pw
```

Then:

```
docker compose -f deploy/docker/docker-compose.poc.yml up
```

If any var is missing, compose exits with
`error while interpolating: required variable <NAME> is missing a value`.

---

## Setting in CI

GitHub Actions jobs that invoke these compose files must export the vars at
the top of the job from repository/organisation secrets:

```yaml
jobs:
  e2e:
    runs-on: ubuntu-latest
    env:
      GRAFANA_PASSWORD:          ${{ secrets.GRAFANA_PASSWORD }}
      HAPROXY_STATS_USER:        ${{ secrets.HAPROXY_STATS_USER }}
      HAPROXY_STATS_PASSWORD:    ${{ secrets.HAPROXY_STATS_PASSWORD }}
      MANAGEMENT_JWT_SECRET:     ${{ secrets.MANAGEMENT_JWT_SECRET }}
      MANAGEMENT_ADMIN_USER:     ${{ secrets.MANAGEMENT_ADMIN_USER }}
      MANAGEMENT_ADMIN_PASSWORD: ${{ secrets.MANAGEMENT_ADMIN_PASSWORD }}
    steps:
      - uses: actions/checkout@... # SHA-pinned per phase 202a
      - run: docker compose -f deploy/docker/docker-compose.poc.yml up -d
```

For PR builds from forks (where secrets are unavailable), skip the job or
generate ephemeral values inline:

```yaml
- name: Generate ephemeral secrets for PR smoke
  run: |
    {
      echo "MANAGEMENT_JWT_SECRET=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
      echo "MANAGEMENT_ADMIN_PASSWORD=$(openssl rand -base64 24)"
      # ... etc
    } >> "$GITHUB_ENV"
```

Secrets in the default `GITHUB_TOKEN` context are scoped — the Go proxy image
workflow (Phase 202d) uses `${{ secrets.GITHUB_TOKEN }}` only for GHCR
push; signing uses keyless cosign (see ADR-202d) and requires no
long-lived secret.

---

## Related documents

- [`credential_rotation.md`](credential_rotation.md) — zero-downtime rotation
  procedures.
- [`security_incident_response.md`](security_incident_response.md) — emergency
  rotation after suspected compromise.
- `docs/decisions/ADR-202d.md` — image signing (keyless cosign) rationale.
- `docs/phases/PHASE_202.md` — sub-phase 202b acceptance criteria.
