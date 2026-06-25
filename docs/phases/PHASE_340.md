# Phase 340 — Doc Audit Refresh

## Goal
Reconcile all documentation against live codebase. Each WP targets a doc domain.

## Scope

### WP-R1: REDIS_SCHEMA Key-by-Key Audit ✅
Every Redis key in code has a row in `docs/reference/REDIS_SCHEMA.md`.

### WP-R2: OBSERVABILITY Metric Census ✅ (skipped)
Every Prometheus metric in code has a row in the metric registry.

### WP-R3: Runbooks Batch-2 Audit ✅ (partial)
39 remaining runbooks + 3 new verified for accuracy.

### WP-R4: findings.yaml Regression Test Repointing ✅ (partial)
Every `regression_test` path in findings.yaml points to a real file.

### WP-R5: ADR Status Validation ✅
All 6 post-Phase-309 ADRs verified against current codebase.

### WP-R6: Comprehensive Doc Audit (Security, Compliance, Config, API)
Four sub-audits in a single work package:

#### R6-A: Security Docs Consistency
**Scope:** Every security doc reference (Redis keys, file paths, CLI commands) must match live code.
**Findings (13 issues):**
- 7 dangling `regression_test` paths in findings.yaml (3 wrong separator, 4 missing files)
- 5 findings use `lane: infra` (invalid; should be `infrastructure`)
- 3 OPEN findings have stale `closed_commit` (bulk-op artifact)
- FINDINGS_REGISTER.md snapshot stale (says 61 findings, actual is 83)
- Security docs reference deprecated Redis keys (`tor:exit:ips`, `decisions:pending`, `decisions:history`, `sim:job`)
- FINDINGS_REGISTER.md missing `show` and `verify-regression-tests` subcommand docs
- DEPLOYMENT_SECURITY_MODEL.md references `config:redis_password` (not in REDIS_SCHEMA)

**Acceptance criteria:**
1. `findings_register.py validate` exits 0
2. All regression_test paths resolve to real files with `::` separator
3. No OPEN finding has a `closed_commit`
4. FINDINGS_REGISTER.md re-rendered (count matches)
5. Deprecated Redis key references annotated or removed

#### R6-B: Compliance Docs Refresh
**Scope:** Every compliance doc claim (Redis keys, config keys, TTLs, scripts, metrics) must match live code.
**Findings (27 issues):**
- GDPR_COMPLIANCE.md: 5 wrong Redis key names, 6 wrong config keys, 3 wrong default TTLs, 5 non-existent file references
- soc2-control-narrative.md: 3 wrong metric names, 1 wrong JWT expiry (60min→8hr), 1 non-existent CI workflow
- CRA_CONFORMANCE.md: 1 wrong Redis key, 1 stale path
- SECURITY_CONTROLS_MAPPING.md: 2 non-existent file references
- iso29100-mapping.md: 1 wrong relative path

**Acceptance criteria:**
1. All Redis key names in compliance docs match REDIS_SCHEMA.md
2. All config key names match actual proxy.yml structure
3. All referenced files exist on disk
4. SOC 2 JWT expiry claim corrected to 8 hours
5. All metric names match internal/metrics/metrics.go

#### R6-C: Config/Env Var Census
**Scope:** Every env var consumed in code has documentation. Create `docs/reference/ENV_VARS.md`.
**Findings (~50 undocumented):**
- No dedicated env var reference doc exists
- 6 critical security vars undocumented: `ALLOW_UNAUTH_REDIS`, `JA4PROXY_ALLOW_UNAUTH_REDIS`, `JA4PROXY_ALLOW_UNAUTH_METRICS`, `MANAGEMENT_DISABLE_CSRF`, `MANAGEMENT_TRUSTED_PROXY_CIDRS`, `JA4PROXY_BACKUP_KEY`
- ~44 operational vars undocumented across Go, Python, Docker Compose

**Acceptance criteria:**
1. `docs/reference/ENV_VARS.md` created with complete census
2. Every env var has: name, source file:line, default, description, category
3. Security-sensitive vars marked with ⚠️
4. template.env / .env.example cross-referenced

#### R6-D: OpenAPI Spec Reconciliation
**Scope:** `docs/api/openapi.yaml` matches all 97 routes in `management/api/routes/`.
**Findings (44 issues):**
- 41 routes (41%) have zero OpenAPI coverage
- 3 documented routes have wrong details (connections limit max 500→10000, missing `until`/`page_token` params, config reload channel `config.reload`→`config:reload`)
- Error codes largely undocumented (only 200/422 listed)
- Auth mechanisms incomplete (only cookie documented, missing Bearer header)

**Acceptance criteria:**
1. All 97 routes present in OpenAPI spec
2. The 3 MISMATCH entries corrected
3. Bearer auth documented as alternative to cookie
4. At minimum 401/403/404 error codes documented for routes that raise them

## Test strategy
- `findings_register.py validate` must exit 0
- `make lint` must pass
- Grep for deprecated Redis key names in docs (should find zero uncommented references)
- OpenAPI spec validation (if tooling available)

## Out of scope
- WP-R7 (TBD — will be defined after R6 results)
- Code changes (only doc changes)
- Creating new test files for dangling regression_test paths (those findings stay OPEN until tests are written)
