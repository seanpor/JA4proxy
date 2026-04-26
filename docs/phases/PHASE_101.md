# Phase 101 — Cross-Phase Gap Closure

> **Status:** PROPOSED
> **Parent Size:** LARGE — split into 12 sub-phases below.
> **Dependencies:** Phase 84 (compliance), Phase 85 (threat-intel), Phase 62 (Go parity), Phase 64 (deploy validation), Phase 86i (capacity hardening), Phase 93 (terraform provider).
> **Last revised:** 2026-04-24 (stranded branch review; see §0 below).
>
> **Sub-phases landed on main (reviewed 2026-04-24):**
> 101b (compliance hygiene), 101e (regional endpoints — landed 2026-04-26),
> 101f (TI feed test reshape), 101g (TI feed medium items M8–M14),
> 101h (low items L6–L8), 101i (deferred to Go cycle),
> 101j (deploy validation M18 skipped, M19).
>
> **Still open:** 101a, 101d (H7/H8 — H6 partial done in 101c), 101k (H14/H15/H16/M24/M25/M26), 101l.

## 0. Stranded-branch review — 2026-04-24

A branch `claude/phase-101-cross-phase-gaps` (last commit `5ffb736`, Apr 16)
attempted 101d + 101k and self-declared the parent COMPLETE. That branch was
reviewed on 2026-04-24 and **abandoned without merging**. Summary of why:

| Spec item | Stranded commit | Verdict |
|---|---|---|
| H6 SSRF SafeResolver | none | not attempted |
| H7 manual-poll rate limit | `7734c91` | scoped per user-identity; spec requires per feed_id |
| H8 CSRF double-submit + HMAC | `068ce49` | implemented Origin-header check instead; commit message admits spec test can't pass |
| H14 benchmark honesty | none | not attempted |
| H15 Dynatrace parser robustness | `b20a9f7` | partial — NaN + control-char strip only; no quote-state tracking, no adversarial fixtures |
| H16 capacity runbook | none | not attempted |
| M24 Pushgateway grouping_key + real latencies | `3ad55e7` | partial — only `instance` + `phase`; no uuid, no latency wiring |
| M25 topology entity on scrape failure | `b20a9f7` | alternative design — synthetic sample vs spec's "emit topology before early-return" |
| M26 benchmark test numeric/SHA validation | none | not attempted |

The closing commit claimed delivery of H7, H8, H15, H16, M24, M25, M26; three
of those (H16, M26, and the H6 precondition for 101d) had no implementation on
the branch. Design drift on H7/H8 made cherry-picking worse than starting
clean. When 101d and 101k are picked up, treat them as not-started — ignore
the stranded branch.

The remote branch `origin/claude/phase-101-cross-phase-gaps` is retained as a
historical record; do not revive it.

## Sub-phase index

| ID | Sub-phase | Area | Size | Depends on | Entry point |
|---|---|---|---|---|---|
| **101a** | Phase 84: DSAR correctness fixes (H1, H3, M7) | `management/api/routes/compliance.py`, `management/compliance/` | M | none | §4.1 |
| **101b** | Phase 84: Compliance hygiene (M1, M2, M4, L1, L2, L5) | `management/compliance/` | S | 101a | §4.2 |
| **101c** | Phase 85: Critical safety caps (C4, C5, C6) | `src/analytics/ti_feeds/` | M | none | §5.1 |
| **101d** | Phase 85: SSRF, rate-limit, CSRF (H6, H7, H8) | `src/analytics/ti_feeds/`, `management/api/middleware/` | M | 101c | §5.2 |
| **101e** | Phase 85: Regional endpoints (H9, H10) | `src/analytics/ti_feeds/recorded_future.py`, `crowdstrike.py` | XS | none | §5.3 |
| **101f** | Phase 85: Test reshape (H11, H12) | `tests/integration/test_ti_feeds_*.py`, `tests/chaos/` | M | 101c | §5.4 |
| **101g** | Phase 85: Medium items (M8–M14) | `src/analytics/ti_feeds/`, `management/api/routes/threat_intel.py` | M | none (any order) | §5.5 |
| **101h** | Phase 85: Low items (L6–L8) | docs + metrics registry | XS | 101g | §5.6 |
| **101i** | Phase 62: Go test parity (M15, M16, L9) | `internal/tls/`, `internal/security/` | XS | none | §6 |
| **101j** | Phase 64: Deploy validation (M18, M19) | `scripts/`, `docs/runbooks/` | XS | M18 blocked on Phase 76 quadlets | §7 |
| **101k** | Phase 86i: Capacity hardening (H14, H15, H16, M24, M25, M26) | `scripts/capacity_calculator.py`, `deploy/dynatrace/`, `deploy/datadog/` | M | none | §8 |
| **101l** | Phase 93: Provider publication (H17) | `terraform-provider/` (separate repo) | XS | none | §9 |

**Start here if you're new:** Sub-phases **101c** (safety caps) and **101e** (regional endpoints) are the most impactful — they close production-critical gaps where a misbehaving threat-intel feed could mass-ban legitimate traffic. **101i** and **101l** are quick wins (XS, independent).

### Parallelism

| Stream | Sub-phases | Engineer count |
|--------|-----------|---------------|
| Phase 84 compliance | 101a → 101b | 1 |
| Phase 85 threat-intel | 101c, 101e (parallel) → 101d → 101f, 101g (parallel) → 101h | 2–3 |
| Phase 62 Go parity | 101i | 1 |
| Phase 64 deploy | 101j | 1 |
| Phase 86i capacity | 101k | 1 |
| Phase 93 provider | 101l | 1 |

Up to **6 engineers** can work in parallel with zero file conflicts.

---

## 1. How this phase works

Phase 101 is a rolling register of deferred gaps from completed phase reviews.
Each sub-phase above bundles related gaps into a workable unit. The detailed gap
analysis (original review text, file paths, fix descriptions) is preserved in
§3–§9 below — **do not delete it**, it is the source of truth for exact changes.

When you pick up a sub-phase:
1. Read the sub-phase header in §4–§9 to understand scope.
2. Read the detailed gap analysis below for exact file paths and fix descriptions.
3. Follow the **Verify** commands to confirm your changes work.
4. Move completed items to the **Closed Items** table at the top of their section.

---

## 2. Status summary

### Closed items

| ID | Title | Closed by |
|----|-------|-----------|
| C1 | DSAR erase TOCTOU | Phase 84 review-fixes branch |
| C2 | Monthly/stream fallback misfire | Phase 84 review-fixes branch |
| C3 | Lexicographic timestamp comparison | Phase 84 review-fixes branch |
| C5-partial | 10% deletion cap on differential cleanup | Phase 85 commit 78162eb |
| C7 | Default `threat_intel` + `seed_file` to disabled | Phase 85 commit ee80232 |
| H2 | Logo validation theatre | Phase 84 review-fixes branch |
| H4 | `/signal-categories` bare classifier | Phase 84 review-fixes branch |
| H5 | `int()` crash on non-numeric hash | Phase 84 review-fixes branch |
| H13 | Defer `stix_ids_seen.add()` until mgmt write succeeds | Phase 85 commit 7c8ccac |
| L3 | DSAR erase audit preserves full `skipped` list | Phase 84 review-fixes branch |
| L4 | Module-level classifier cache | Phase 84 review-fixes branch |
| M3 | Token inventory denylist → allowlist | Phase 84 review-fixes branch |
| M5 | `block_rate_pct` clamped to [0, 100] | Phase 84 review-fixes branch |
| M6 | HTML escape in `_render_simple_pdf` | Phase 84 review-fixes branch |
| M17 | `FuzzReadProxyProtocolV2` placeholder → Phase 200 | Filed as hand-off to Phase 200 |
| M20–M23 | Phase 64 CI smoke, infrastructure docs, metrics, MTTR | Phase 64 closeout |

### Open items by severity

| Severity | Count | IDs |
|----------|-------|-----|
| CRITICAL | 3 | C4, C5, C6 |
| HIGH | 9 | H1, H3, H6, H7, H8, H9, H10, H11, H12, H14, H15, H16, H17 |
| MEDIUM | 15 | M1, M2, M4, M7, M8, M9, M10, M11, M12, M13, M14, M18, M19, M24, M25, M26, M27, M28, M29 |
| LOW | 6 | L1, L2, L5, L6, L7, L8, L9, L10, L11 |

### Documented limitations (deferred, not bugs)

| ID | Title | Reason |
|----|-------|--------|
| M27 | Terraform Registry publication | External HashiCorp process |
| M28 | `protect_unmanaged_entries` plan-apply race | Inherent to Terraform's plan-apply model |
| M29 | Null `managed_by` causes false-positive protection | Conservative — safe but documented |
| L10 | Real production-hardware `make bench` run | Blocked on hardware availability |

---

## 3. Sub-phase detail

### 3.1 Sub-phase 101a — Phase 84 DSAR correctness (H1, H3, M7)

**Goal:** Fix three correctness gaps in the DSAR export path that cause
incomplete or misleading compliance evidence.

| Gap | Severity | What | File |
|-----|----------|------|------|
| H1 | HIGH | DSAR issues 2 full XRANGE scans — consolidate to 1 | `management/api/routes/compliance.py` |
| H3 | HIGH | DSAR misses CIDR watchlist entries | `management/api/routes/compliance.py:295-296, 453-454` |
| M7 | MEDIUM | DSAR returns success on Redis failure — needs `partial_failures` | `management/api/routes/compliance.py:408-413` |

**Steps:**

1. In `management/api/routes/compliance.py`, consolidate the two XRANGE calls: replace the separate calls in `_dsar_connection_history` (line ~411) and `_dsar_fingerprint_associations` (line ~480) with a single `XRANGE ja4proxy:events - +` at the top of the DSAR export handler, storing the result in a local variable and passing it to both helpers.
2. Add a `management:dsar:last_xrange_len` gauge — wire it into `src/analytics/metrics.py` as `ja4proxy_dsar_xrange_len` and emit it after the single XRANGE call with the length of the returned list.
3. In `_dsar_watchlist_entries` (lines ~295-296) and the erase path (lines ~453-454), replace the literal string comparison with `ipaddress.ip_address(ip) in ipaddress.ip_network(entry, strict=False)` to match CIDR blocks.
4. Add test vectors for CIDR matching: IPv4 `/32`, IPv4 `/24`, IPv6 `/128`, IPv6 `/48`, and malformed entries (non-CIDR strings that should fall back to literal match or skip with a logged warning).
5. In `_dsar_connection_history` and `_dsar_fingerprint_associations`, replace the bare `except Exception: return []` with a try/except that catches `redis.ConnectionError`, increments a new `ja4proxy_dsar_export_partial_failures_total` counter, and returns a sentinel (e.g. `None`) so the caller can populate a `partial_failures` list in the response.
6. Update the DSAR response builder to include a `partial_failures` list field; when any helper returns the sentinel, add the category name (e.g. `"connection_history"`) to the list and include a `data_unavailable` warning if any category failed.
7. Add a chaos test: mock fakeredis to raise `ConnectionError` on `xrange`, call the DSAR endpoint, and assert HTTP 200 with `partial_failures: ["connection_history"]` in the JSON body.
8. Benchmark: generate a 1M-entry stream fixture, run DSAR export, assert it completes in < 2s.

**Acceptance criteria:**
- [ ] DSAR export issues at most one XRANGE call per request
- [ ] DSAR for `10.0.0.15` includes watchlist entry stored as `10.0.0.0/24`
- [ ] DSAR response includes `partial_failures` list on Redis error
- [ ] `ja4proxy_dsar_export_partial_failures_total` counter wired
- [ ] Chaos test: fakeredis raising `ConnectionError` returns payload with `partial_failures`
- [ ] Benchmark: 1M-entry stream, DSAR export completes in < 2s
- [ ] `make test-phase-84` still passes

---

### 3.2 Sub-phase 101b — Phase 84 compliance hygiene (M1, M2, M4, L1, L2, L5)

**Goal:** Clean up 6 medium/low compliance issues that don't affect correctness
but impact operational clarity and code quality.

| Gap | Severity | What | File |
|-----|----------|------|------|
| M1 | MEDIUM | XTRIM MINID fallback for Redis < 6.2 | `management/compliance/purge.py:168-169` |
| M2 | MEDIUM | Rename `beaconing_records_cleaned` → `beaconing_datapoints_cleaned` | `management/compliance/purge.py:138, 205` |
| M4 | MEDIUM | Paginate audit log reads in pack builder | `management/compliance/pack_builder.py:203` |
| L1 | LOW | Jinja2 Environment cached at module level | `management/compliance/report_renderer.py:129-132` |
| L2 | LOW | JSONL trailing newline documented | `management/compliance/pack_builder.py:293-296` |
| L5 | LOW | DSAR retention strings from config, not hardcoded | `management/api/routes/compliance.py:239-245` |

**Steps:**

1. In `management/compliance/purge.py`, on first invocation of `GDPRPurge.run()`, check Redis version. The redis-py client exposes this as `client.info()["redis_version"]` (a string like `"6.2.14"`). Parse the major.minor with `packaging.version.parse()` or a simple `tuple(int(x) for x in v.split(".")[:2])` comparison. If < 6.2, log a WARN and fall back to a time-based XRANGE + XDEL loop instead of `XTRIM … MINID`. Add a unit test that mocks `client.info()` returning `{"redis_version": "6.0.0"}` and asserts the fallback path is taken. Document the minimum Redis version in `docs/REDIS_SCHEMA.md`. **Note:** the redis-py `info()` method returns a dict, not a string — use `client.info()`, not `client.execute_command("INFO")`.
2. Rename `beaconing_records_cleaned` → `beaconing_datapoints_cleaned` in the Python dataclass (`management/compliance/purge.py:138, 205`) and any exposed Prometheus metric. Add a `CHANGELOG.md` entry noting this as a breaking change for dashboards parsing the old field name.
3. In `management/compliance/pack_builder.py:203`, replace the `LRANGE management:audit_log 0 -1` call with a chunked loop reading 10k entries at a time (`LRANGE start stop`), stopping early when the timestamp drops below the window. Define a documented constant `AUDIT_LOG_CHUNK_SIZE = 10_000`.
4. In `management/compliance/report_renderer.py`, create a module-level `Environment` keyed on `(template_dir, template_name)`. Modify `ReportRenderer.__init__` to reuse the cached Environment. Add a test asserting two `ReportRenderer()` instances share compiled templates (`id(t1.environment) == id(t2.environment)`).
5. In `management/compliance/pack_builder.py`, document the JSONL trailing-newline invariant in the pack_builder docstring. Add a test asserting non-empty JSONL files end in `\n` and empty files are zero bytes.
6. In `management/api/routes/compliance.py:239-245`, replace the hardcoded "90 days" retention strings with values read dynamically from `gdpr.*_retention_days` config. Add a test that changes the config and asserts the DSAR response text matches the new values.

**Acceptance criteria:**
- [ ] GDPRPurge checks Redis version, falls back to XRANGE+XDEL for < 6.2
- [ ] `PurgeSummary.beaconing_datapoints_cleaned` replaces old field, CHANGELOG notes breaking change
- [ ] Pack builder reads audit entries in chunks of 10k
- [ ] Two `ReportRenderer()` instances reuse compiled Jinja2 templates
- [ ] Non-empty JSONL files end in `\n`, empty files are zero bytes
- [ ] DSAR response retention text reflects config values dynamically
- [ ] `make test-phase-84` still passes

---

### 3.3 Sub-phase 101c — Phase 85 critical safety caps (C4, C5, C6)

**Goal:** Close the three CRITICAL gaps where a misbehaving feed could
mass-ban legitimate traffic.

> **⚠️ Do not deploy `dial > 0` with `threat_intel.enabled: true` until
> this sub-phase is complete.**

| Gap | Severity | What | File |
|-----|----------|------|------|
| C4 | CRITICAL | Per-feed safety caps (`max_new_per_poll`, `max_owned_total`, `max_delta_per_poll`) | `src/analytics/ti_feeds/base.py`, `runner.py` |
| C5 | CRITICAL | Two-empty-poll gate before bulk cleanup | `src/analytics/ti_feeds/state.py`, `runner.py` |
| C6 | CRITICAL | `ja4_safe_to_block(ja4)` FP corpus check | `src/analytics/ti_feeds/ja4_safety.py` (new), `taxii.py`, `rest_generic.py`, `seed_file.py` |

**Steps:**

1. In `src/analytics/ti_feeds/base.py`, extend `FeedConfig` with three new fields: `max_new_per_poll: int = 500`, `max_owned_total: int = 50_000`, `max_delta_per_poll: int = 0` (0 = unlimited). Ensure all three honour `from_dict` so YAML can override per-feed.
2. In `src/analytics/ti_feeds/runner.py` `_poll_once`, after `client.poll()` returns and before touching the snapshot: (a) If `len(result.created) > cfg.max_new_per_poll`, log `event=feed_capped_new`, slice `result.created[:cfg.max_new_per_poll]`, increment `ti_feed_caps_hit_total{feed_id, kind="new"}` — truncated indicators are NOT added to the snapshot so next poll retries them. (b) If `len(previous_ids) >= cfg.max_owned_total`, refuse new indicators this cycle, log `event=feed_capped_total`, increment `ti_feed_caps_hit_total{kind="total"}` (cleanup still allowed). (c) If `cfg.max_delta_per_poll > 0` and absolute delta exceeds it, refuse all mutations, log `event=feed_capped_delta`, increment `ti_feed_caps_hit_total{kind="delta"}`.
3. Add all three keys to every example feed entry in `config/proxy.yml` under `threat_intel.feeds[*]`, with conservative defaults and inline comments.
4. Add an Alertmanager `TIFeedCapsHit` warning rule in `monitoring/alertmanager/rules/ti_feed.yml` (`rate(ja4proxy_ti_feed_caps_hit_total[15m]) > 0`) with a runbook link to a new `docs/runbooks/ti_feed_caps_hit.md`.
5. In `src/analytics/ti_feeds/state.py`, add three methods: `get_empty_streak(feed_id)`, `bump_empty_streak(feed_id)`, `reset_empty_streak(feed_id)`, backed by a Redis string `ti_feed:{feed_id}:empty_streak` with no TTL.
6. In `runner.py` `_poll_once`, after computing `dropped` but before applying deletions: if `len(result.stix_ids_seen) == 0`, bump the empty streak; if streak < 2, set `dropped = {}`, log `event=cleanup_skipped_empty_streak`, and do NOT replace the snapshot. If `len(result.stix_ids_seen) > 0`, reset the streak and proceed to the existing 10% cap path.
7. Create `src/analytics/ti_feeds/ja4_safety.py` with a function `ja4_safe_to_block(ja4) -> tuple[bool, str]` that loads the FP corpus once at module import (lru_cache around file read), corpus path configurable via `JA4PROXY_FP_CORPUS_PATH` env var.
8. In `taxii.py` `_apply_indicator` JA4 branch, after `is_valid_ja4(ja4)` and before `post_blocklist`, call `ja4_safe_to_block(ja4)`; if not safe, increment `_INDICATORS_PROCESSED.labels(feed_id=feed_id, outcome="fp_blocked").inc()`, append error, and return. Wire the same check in `rest_generic.py` JA4 branch and `seed_file.py` `run_once`.
9. Wire new metric `ja4proxy_ti_feed_fp_blocked_total{feed_id}` and a `TIFeedFPBlocked` Alertmanager warning rule.
10. Write `tests/unit/test_ti_feed_caps.py` with parametrised cases for all three cap kinds. Write `tests/unit/analytics/ti_feeds/test_runner_empty_streak.py` with cases: first empty poll skips cleanup, second empty allows cleanup (capped at 10%), non-empty poll resets streak. Write `tests/unit/analytics/ti_feeds/test_ja4_safety.py` and `tests/adversarial/test_ti_feeds_fp_block.py` (Chrome 120 JA4 from FP corpus never blocked).

**Acceptance criteria:**
- [x] `max_new_per_poll`, `max_owned_total`, `max_delta_per_poll` enforced with `ja4proxy_ti_feed_caps_hit_total` metric
- [x] Two consecutive empty polls required before cleanup; `empty_streak` persisted in Redis
- [x] `ja4_safe_to_block(ja4)` consulted from taxii.py, rest_generic.py, seed_file.py before every `post_blocklist`
- [x] `ja4proxy_ti_feed_fp_blocked_total{feed_id}` counter wired
- [x] `tests/adversarial/test_ti_feeds_fp_block.py` passes (Chrome 120 JA4 from FP corpus never blocked)
- [x] Alertmanager rules for `TIFeedCapsHit` and `TIFeedFPBlocked`

**Status: COMPLETE — landed 2026-04-26.** C5 dead-`dropped={}` bug fixed
in `runner.py` with proper early-return. C6 corpus path fixed
(parents[2]→parents[3]) so the fixture resolves in production.
TI_SEED_ENTRIES label-mismatch fixed at all 3 call sites in
`seed_file.py`. SafeResolver class exported from
`src/analytics/ti_feeds/safe_resolver.py` and wired into both `taxii.py`
and `rest_generic.py` (H6 partial — the SSRF gap that overlaps with
101d). FP corpus expanded to 12 browser fingerprints (Chrome 119/120,
Firefox 115ESR/121, Safari 17, Edge 120, mobile Safari) plus the
historical pre-phase entry. Alertmanager `TIFeedCapsHit` and
`TIFeedFPBlocked` rules added with full runbooks at
`docs/runbooks/ti_feed_caps_hit.md` and `docs/runbooks/ti_feed_fp_blocked.md`.
Existing runner tests updated for the C5 two-empty-poll gate
(prime-then-execute pattern). Net: 13 new tests pass; full suite
6011/6011 green.

---

### 3.4 Sub-phase 101d — Phase 85 SSRF, rate-limit, CSRF (H6, H7, H8)

**Goal:** Close three HIGH-severity security gaps in the threat-intel
feed infrastructure.

| Gap | Severity | What | File |
|-----|----------|------|------|
| H6 | HIGH | SSRF mitigation via SafeResolver | `src/analytics/ti_feeds/safe_resolver.py` (new), all 4 clients |
| H7 | HIGH | Manual-poll endpoint rate limit (6/min/feed_id) | `management/api/routes/threat_intel.py` |
| H8 | HIGH | CSRF double-submit middleware on `/api/v1/*` mutating routes | `management/api/middleware/csrf.py` (new) |

**Steps:**

1. Create `src/analytics/ti_feeds/safe_resolver.py` with a `SafeResolver(aiohttp.AbstractResolver)` class that wraps the default resolver and checks each resolved IP against `is_publicly_routable_ip()`, raising `aiohttp.ClientConnectorError` with `PermissionError(f"SSRF blocked: {host}")` for private/loopback/link-local IPs.
2. In `src/analytics/ti_feeds/base.py`, extract the `is_publicly_routable_ip` helper from the existing `validate_feed_url` method so the resolver can share it. Ensure it covers IPv4-mapped, 6to4, and Teredo addresses recursively.
3. In all four clients (`taxii.py`, `crowdstrike.py`, `recorded_future.py`, `rest_generic.py`), replace every `aiohttp.TCPConnector()` instantiation with `aiohttp.TCPConnector(resolver=SafeResolver())`.
4. Write `tests/adversarial/test_ti_feeds_ssrf.py`: patch `socket.getaddrinfo` to return `169.254.169.254` for a synthetic hostname, run a real `TAXIIClient.poll()` against it, assert `result.errors` contains `"SSRF blocked"` and `post_ban` was never called.
5. In `management/api/routes/threat_intel.py`, add a rate limiter (slowapi-style or the existing `limit_per_minute` decorator from Phase 79) to `POST /api/v1/threat-intel/feeds/{id}/poll` at 6 requests per minute per feed_id.
6. Write a test in `tests/unit/test_threat_intel_api.py` asserting the 7th request in 60s returns 429 with a `Retry-After` header.
7. Create `management/api/middleware/csrf.py`: on every `GET /api/v1/*` response, set a `csrf_token` cookie (HttpOnly false, SameSite=strict, Secure in prod) and an `X-CSRF-Token` response header with the same value. On every `POST/PUT/PATCH/DELETE /api/v1/*` request, require the `X-CSRF-Token` header to match the cookie; reject 403 with `{"error": "csrf_token_mismatch"}`. Tokens are HMAC over `(username, issued_at)` using `MANAGEMENT_JWT_SECRET` (the same secret from `management/api/auth.py:jwt.encode()`), valid for 1 hour. The `username` comes from the decoded JWT payload's `sub` claim — extract it from the request state that the auth middleware already populates. No session infrastructure needed.
8. Register the middleware in `management/api/main.py` after auth. Update `management/templates/base.html` to read the `csrf_token` cookie in Alpine bootstrap and inject it as a header on every fetch via a global `$fetch` wrapper.
9. Write `tests/unit/test_csrf.py` with full happy/mismatch/expired matrix.

**Acceptance criteria:**
- [ ] SafeResolver rejects RFC1918/loopback/link-local IPs
- [ ] `tests/adversarial/test_ti_feeds_ssrf.py` passes (DNS SSRF blocked)
- [ ] 7th poll request in 60s returns 429 with `Retry-After`
- [ ] CSRF middleware requires `X-CSRF-Token` header matching cookie on all POST/PUT/PATCH/DELETE
- [ ] `tests/unit/test_csrf.py` passes

---

### 3.5 Sub-phase 101e — Phase 85 regional endpoints (H9, H10)

**Goal:** Support regional/GovCloud endpoints for Recorded Future and
CrowdStrike feeds.

| Gap | Severity | What | File |
|-----|----------|------|------|
| H9 | HIGH | Recorded Future regional endpoint support | `src/analytics/ti_feeds/recorded_future.py` |
| H10 | HIGH | CrowdStrike regional / GovCloud endpoint support | `src/analytics/ti_feeds/crowdstrike.py` |

**Steps:**

1. In `src/analytics/ti_feeds/recorded_future.py`, make the TAXII root come from `config.url` first, falling back to the hardcoded `_RF_TAXII_ROOT`. Honour `https://api.eu.recordedfuture.com/taxii2/` and `https://api.apac.recordedfuture.com/taxii2/` literally.
2. In `config/proxy.yml`, update the recorded_future example to show the EU endpoint as a comment with a note about which tenants need it.
3. In `src/analytics/ti_feeds/crowdstrike.py`, pull both `_FALCON_AUTH_URL` and `_FALCON_INDICATORS_URL` from `config.url` with existing values as fallback. Support `api.us-2.crowdstrike.com`, `api.eu-1.crowdstrike.com`, and `api.laggar.gcw.crowdstrike.com` (GovCloud).
4. Write unit tests for both clients covering regional endpoint selection. Run `python3 -m pytest tests/unit/analytics/ti_feeds/test_recorded_future.py -x` and the equivalent CrowdStrike test file.

**Acceptance criteria:**
- [x] RF client honours `config.url` for EU/APAC sub-domains (`_resolve_rf_taxii_root`)
- [x] CrowdStrike client supports US-2, EU-1, and GovCloud (laggar) endpoints (`_resolve_falcon_urls`)
- [x] `config/proxy.yml` examples show regional endpoints as comments (landed 2026-04-26)
- [x] Unit tests pass for both clients (`tests/unit/analytics/ti_feeds/test_phase_101e_regional_endpoints.py`, 10 tests green)

**Status: COMPLETE — landed 2026-04-26.**

---

### 3.6 Sub-phase 101f — Phase 85 test reshape (H11, H12)

**Goal:** Rewrite 5 integration/chaos test files that target a
`FeedRunner(feeds=[...])` constructor that no longer exists.

> **⚠️ Prerequisite:** Read `tests/unit/analytics/ti_feeds/conftest.py` and
> `tests/unit/analytics/ti_feeds/test_runner.py` before starting. These files
> contain the existing fixture definitions (`stub_management_client`,
> `mock_taxii_server`, `_StubMgmt`, `_StubClient`, `_make_runner`) that must
> be promoted to shared fixtures. The test reshape reuses these patterns —
> do not invent new fixture conventions.

| Gap | Severity | What | File |
|-----|----------|------|------|
| H11 | HIGH | TAXII chaos test — assert no mutations during 500 storm | `tests/chaos/test_ti_feed_taxii_unavailable.py` |
| H12 | HIGH | Coordinated reshape of 5 test files against `FeedRunner._poll_once()` | `tests/integration/test_ti_feeds_*.py` |

**Steps:**

1. Create shared fixtures in `tests/integration/conftest.py` or `tests/_helpers/ti_feed_runner.py` by promoting the existing helpers from `tests/unit/analytics/ti_feeds/conftest.py` (`stub_management_client`, `mock_taxii_server`, `_StubMgmt`, `_StubClient`, `_make_runner`). All 5 test files must use these shared fixtures instead of copy-pasted versions.
2. Rewrite `tests/chaos/test_ti_feed_taxii_unavailable.py` first (H11): replace the test body to assert that after a 500 storm, no new bans were created and no existing bans were removed. Pre-populate the snapshot with 100 indicators, configure a TAXII server returning 500 for 10 polls, run the runner for 10 cycles, assert snapshot still has 100 entries, `post_ban` call count is 0, `delete_ban` call count is 0, and circuit state is OPEN.
3. Rewrite the remaining 4 files against `FeedRunner._poll_once(feed_id)` (not the loop), following the pattern in `tests/unit/analytics/ti_feeds/test_runner.py`. Inject a real httpx-backed Management API TestClient in place of unit tests' `_StubMgmt`:
   - `tests/integration/test_ti_feeds_e2e.py`: a real STIX bundle from a mock TAXII server lands in `GET /api/v1/blocklist?managed_by=feed`
   - `tests/integration/test_ti_feeds_cleanup.py`: re-poll with shrunken feed removes the right things, never more than the cap
   - `tests/integration/test_ti_feeds_conflict.py`: only one of two `FeedRunner` instances actually polls per cycle (leader lock)
   - `tests/integration/test_ti_feeds_hot_reload.py`: added feeds spawn tasks; removed feeds stop polling but retain their rules
4. Remove the `pytestmark = pytest.mark.xfail(...)` line from each file in the same commit.
5. Update each file's docstring header to drop the "RED until X exists" language. Replace with a one-line summary of what the file actually asserts post-rewrite.
6. Run all 5 files together: `python3 -m pytest tests/integration/test_ti_feeds_e2e.py tests/integration/test_ti_feeds_cleanup.py tests/integration/test_ti_feeds_conflict.py tests/integration/test_ti_feeds_hot_reload.py tests/chaos/test_ti_feed_taxii_unavailable.py -x`. All 5 must be green, none xfailed, none skipped.

**Acceptance criteria:**
- [ ] All 5 files use `FeedRunner._poll_once(feed_id)` (not the loop)
- [ ] Shared fixtures in `tests/integration/conftest.py` or `tests/_helpers/ti_feed_runner.py`
- [ ] No `pytestmark = pytest.mark.xfail` remains in any file
- [ ] All 5 files pass green

---

### 3.7 Sub-phase 101g — Phase 85 medium items (M8–M14)

**Goal:** Close 7 medium-severity feed quality improvements. All
independent — pick up in any order.

| Gap | Severity | What | File |
|-----|----------|------|------|
| M8 | MEDIUM | TAXII bundle size cap (reject >N MiB before parse) | `src/analytics/ti_feeds/taxii.py` |
| M9 | MEDIUM | Per-feed `User-Agent` header | `src/analytics/ti_feeds/base.py` + 4 clients |
| M10 | MEDIUM | `ti_feed_indicators_managed` Gauge → Counter | `src/analytics/metrics.py` |
| M11 | MEDIUM | `compute_dropped_ids` returns stable-ordered list, not dict | `src/analytics/ti_feeds/state.py` |
| M12 | MEDIUM | Replace `BLE001` `Exception` catches with explicit unions | 4 client files |
| M13 | MEDIUM | `seed_file.run_once` inside leader lock | `src/analytics/ti_feeds/seed_file.py` |
| M14 | MEDIUM | Audit log on feed enable/disable runtime override | `management/api/routes/threat_intel.py` |

**Steps:**

1. **M8 — TAXII bundle size cap:** In `src/analytics/ti_feeds/taxii.py`, before parsing the response body, check `len(response.content)` against a configurable cap (e.g. `max_bundle_bytes = 50 * 1024 * 1024` in `FeedConfig`). If exceeded, log `event=bundle_too_large`, increment a counter, and skip the poll.
2. **M9 — Per-feed User-Agent:** In `src/analytics/ti_feeds/base.py`, add a `user_agent` field to `FeedConfig` defaulting to `f"JA4Proxy/1.0 feed:{feed_id}"`. Pass it as a header to the aiohttp session in each of the 4 clients.
3. **M10 — Gauge → Counter:** In `src/analytics/metrics.py`, replace `ti_feed_indicators_managed` Gauge with a Counter. Update all callers to use `.add()` instead of `.set()`.
4. **M11 — Stable-ordered dropped list:** In `src/analytics/ti_feeds/state.py`, change `compute_dropped_ids` to return a `sorted(list)` instead of a `dict`. Update all callers.
5. **M12 — Replace BLE001 catches:** In all 4 client files (`taxii.py`, `crowdstrike.py`, `recorded_future.py`, `rest_generic.py`), replace bare `except Exception:` with explicit unions of the expected exception types (e.g. `except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError):`).
6. **M13 — seed_file inside leader lock:** In `src/analytics/ti_feeds/seed_file.py`, wrap `run_once` in the existing leader lock acquisition path (same lock used by the FeedRunner poll loop).
7. **M14 — Audit log on enable/disable:** In `management/api/routes/threat_intel.py`, add an audit log entry on every feed `enable` or `disable` runtime override via the API.
8. Run `tests/unit/analytics/ti_feeds/` and `tests/adversarial/test_ti_feeds_*.py` — all pass.

**Acceptance criteria:**
- [ ] All 7 items implemented and tested
- [ ] `tests/unit/analytics/ti_feeds/` and `tests/adversarial/test_ti_feeds_*.py` pass

---

### 3.8 Sub-phase 101h — Phase 85 low items (L6–L8)

**Goal:** Close 3 low-severity documentation and metrics registry items.

| Gap | Severity | What | File |
|-----|----------|------|------|
| L6 | LOW | `_OneShotBundle` adapter docs out of date after H13 | `src/analytics/ti_feeds/` |
| L7 | LOW | Three Phase 85 runbooks need real-deployment dry run | `docs/runbooks/` |
| L8 | LOW | `monitoring/metrics_registry.md` updated with Phase 101 entries | `monitoring/` |

**Steps:**

1. **L6 — `_OneShotBundle` docs:** Update the `_OneShotBundle` docstring in `src/analytics/ti_feeds/` to match the current implementation after H13 (which deferred `stix_ids_seen.add()` until mgmt write succeeds). Verify the docstring accurately describes the adapter's role and lifecycle.
2. **L7 — Runbook dry run:** Verify the three Phase 85 runbooks under `docs/runbooks/` against a live deployment. If a live deployment is not available, document explicitly which steps are untested and what environment would be needed.
3. **L8 — Metrics registry:** Add all new metrics introduced by this phase to `monitoring/metrics_registry.md`: `ja4proxy_ti_feed_caps_hit_total`, `ja4proxy_ti_feed_fp_blocked_total`, `ja4proxy_dsar_export_partial_failures_total`, `ja4proxy_dsar_xrange_len`, and any others added in sub-phases 101c–101g.

**Acceptance criteria:**
- [ ] `_OneShotBundle` docstring matches current implementation
- [ ] Runbooks verified against a live deployment (or documented as untested)
- [ ] All new metrics from this phase documented in `metrics_registry.md`

---

### 3.9 Sub-phase 101i — Phase 62 Go test parity (M15, M16, L9)

**Goal:** Close 3 deferred items from the Phase 62 Go test parity review.

| Gap | Severity | What | File |
|-----|----------|------|------|
| M15 | MEDIUM | JA4 golden file cross-check | `internal/tls/testdata/` |
| M16 | MEDIUM | Redis outage chaos test | `internal/security/` |
| L9 | LOW | Property test generator constraints | `internal/security/` |

**Status: DEFERRED — Go feature gaps require Go implementation.**

These gaps are in the Go codebase which is the primary implementation.
Python tests verify against Python implementation, not Go.
The Go-specific test improvements (JA4 golden file, chaos test, property test) should be
implemented when Go development capacity is available.

---

### 3.10 Sub-phase 101j — Phase 64 deploy validation (M18, M19)

**Goal:** Close 2 deferred items from Phase 64 deployment validation.

| Gap | Severity | What | File |
|-----|----------|------|------|
| M18 | MEDIUM | Podman/Quadlet smoke test — **blocked — no quadlet files exist** | `scripts/smoke/test_podman_quadlet.sh` |
| M19 | MEDIUM | Audit and fix phantom `ja4proxy-cli backup` references — DONE | `docs/runbooks/`, `docs/phases/` |

**M18 — Quadlet smoke test (SKIPPED):**
Phase 76 completed documentation but did not create actual `.container`/
`.network` quadlet files. The quadlet files need to be created as part of a
future deployment automation effort before this smoke test can be implemented.

**M19 — Phantom backup audit (COMPLETE):**
No phantom `ja4proxy-cli backup` references found in runbooks. The
runbooks correctly reference Phase 19's backup/restore system.

**Acceptance criteria:**
- [ ] M18: Quadlet files exist → smoke test created and passes (defer if Phase 76 not done)
- [ ] M19: `grep -rn "ja4proxy-cli backup" docs/runbooks/ docs/phases/` returns zero results (except this PHASE_101 entry)
- [ ] All phantom references replaced with correct Phase 19 Python invocation

---

### 3.11 Sub-phase 101k — Phase 86i capacity hardening (H14, H15, H16, M24, M25, M26)

**Goal:** Close 6 deferred items from the Phase 86i hardening review.

| Gap | Severity | What | File |
|-----|----------|------|------|
| H14 | HIGH | Capacity calculator presents engineering-floor constants as measurements — delete dead code | `scripts/capacity_calculator.py` |
| H15 | HIGH | Dynatrace Prometheus parser robustness (escaped quotes, NaN, commas) | `deploy/dynatrace/ja4proxy-extension/plugin.py` |
| H16 | HIGH | Datadog migration smoke check and runbook | `docs/runbooks/datadog_migration_phase86i.md` |
| M24 | MEDIUM | Pushgateway `grouping_key` + wire real latency samples | `scripts/load_test.py` |
| M25 | MEDIUM | Dynatrace plugin always emits topology entity | `deploy/dynatrace/ja4proxy-extension/plugin.py` |
| M26 | MEDIUM | Benchmarks test validates numeric and SHA shape | `tests/integration/test_phase_86i_benchmarks_populated.py` |

**Steps:**

1. **H14 — Capacity calculator cleanup:** Delete the `_ESTIMATED_BANNER` constant, `_print_estimated_warning()`, the `report.estimated` branch in `print_report`, and the placeholder-detection call in `main()` from `scripts/capacity_calculator.py`. Keep `benchmarks_have_placeholders()` and `--require-measured` as positive CI guards. Verify `grep -n "_ESTIMATED_BANNER\|_print_estimated_warning\|report.estimated" scripts/capacity_calculator.py` returns no results, and `python3 scripts/capacity_calculator.py --require-measured` exits 0 with no banner.
2. **H15 — Dynatrace parser robustness (recommended approach):** Replace the hand-rolled inline Prometheus parser in `deploy/dynatrace/ja4proxy-extension/plugin.py` with a wrapper around `prometheus_client.parser.text_string_to_metric_families()`. If keeping the inline parser (deps allowlist): (a) add `if math.isnan(value): continue` after `float()`, (b) track quote state inside `_parse_labels` so `\"` and `,` inside values are honoured, (c) add adversarial fixture cases to `tests/unit/test_dynatrace_extension.py::test_plugin_parses_prometheus_text_format` covering escaped quotes, commas in values, NaN, summary quantiles, and sample lines with trailing timestamps — each asserting exact key/value pairs, not substring presence.
3. **H16 — Datadog migration runbook:** Create `docs/runbooks/datadog_migration_phase86i.md` with exact pre-flight verification steps: `datadog-agent check openmetrics`, `datadog-agent check ja4proxy`, `datadog-agent status | grep -A5 "openmetrics ja4proxy"`. Document explicit ordering: deploy OpenMetrics first, verify dashboards populate over 24h, then upgrade to the narrowed custom check. Add a test to `tests/unit/test_datadog_integration.py` asserting the runbook exists and references both `datadog-agent check` commands by exact name.
4. **M24 — Pushgateway grouping_key + latencies:** In `scripts/load_test.py::push_loadtest_metrics`, add a `grouping_key` dict with `instance` (`socket.gethostname()`), `scenario`, and `run_id` (`uuid.uuid4().hex[:8]`). Wire real latency samples from the TLS traffic generator's run output JSON into `push_loadtest_metrics()` instead of the hardcoded empty list. Add an end-to-end test that runs `load_test.py` against a stub TLS server (or with `--dry-run`), captures the Pushgateway HTTP request body via a fake server, and asserts histogram bucket counts > 0.
5. **M25 — Topology entity on scrape failure:** In `deploy/dynatrace/ja4proxy-extension/plugin.py`, always emit the topology entity even when `scrape_metrics()` returns an empty sample list. Move `self._emit_topology_entity()` before the early-return. Add a test `test_plugin_emits_topology_even_on_scrape_failure` that mocks a scrape returning `[]`, asserts the topology emit was called, and asserts no metric emit was called.
6. **M26 — Benchmarks test tightening:** In `tests/integration/test_phase_86i_benchmarks_populated.py`: (a) parse throughput and latency fields as floats, reject NaN/Inf/negative/zero, (b) assert the header contains a line matching `r"Git SHA:\s*[0-9a-f]{7,40}\b"`, (c) assert each of `Hardware:`, `OS:`, `Redis:`, `Go:`, `Python:`, `Date:` is present in the header block, (d) add a footer disclaimer assertion if `BenchmarkConstants` are still labeled as engineering floors (cross-tie to H14).
7. Run `python3 -m pytest tests/unit/test_dynatrace_extension.py tests/unit/test_datadog_integration.py tests/unit/test_load_test.py tests/integration/test_phase_86i_benchmarks_populated.py -v` — all pass.

**Acceptance criteria:**
- [ ] H14: `_ESTIMATED_BANNER` dead code deleted, `--require-measured` works correctly
- [ ] H15: Parser handles escaped quotes, commas in values, NaN, summary quantiles — or replaced with `prometheus_client` parser
- [ ] H16: Migration runbook exists with `datadog-agent check` commands
- [ ] M24: `push_to_gateway` uses `grouping_key`, latencies wired from real CLI path
- [ ] M25: Topology entity emitted even on scrape failure
- [ ] M26: Test parses throughput/latency as floats, validates Git SHA shape (`[0-9a-f]{7,40}`)

---

### 3.12 Sub-phase 101l — Phase 93 provider publication (H17)

**Goal:** Push the completed Terraform provider repo to GitHub and
initiate Registry publication.

| Gap | Severity | What | File |
|-----|----------|------|------|
| H17 | HIGH | Provider repo not pushed to GitHub | `/home/sean/LLM/terraform-provider-ja4proxy/` |

**What's ready:**
- 43 Go tests pass, 0 failures, `go vet` clean
- 8 acceptance tests against ManagementAPIMock pass
- 4 ADRs (093a–093d)
- `.github/workflows/test.yml` and `.github/workflows/release.yml` ready
- `.goreleaser.yml` configured

**Steps:**

1. Verify the local repo at `/home/sean/LLM/terraform-provider-ja4proxy/` is clean: run `go vet ./...`, `go test ./...`, and `git status` to confirm all 43 tests pass and there are no uncommitted changes.
2. Create a GitHub repo at `github.com/anomalyco/terraform-provider-ja4proxy` (or `github.com/seanpor/terraform-provider-ja4proxy` if the former org is not available).
3. In the local repo, run `git remote add origin <url>` and `git push -u origin main`.
4. Create a `v1.0.0` tag: `git tag v1.0.0 && git push origin v1.0.0` to trigger the `.github/workflows/release.yml` workflow.
5. Submit the provider to the Terraform Registry via registry.terraform.io (requires HashiCorp partner review, 1-2 weeks). Track separately as M27.

**Acceptance criteria:**
- [ ] Provider repo pushed to GitHub
- [ ] `v1.0.0` tag created to trigger release workflow
- [ ] Terraform Registry submission in progress

---

## 4. Detailed gap analysis (original review text)

> **This section preserves the original review text.** Each gap has file paths,
> exact changes, and verify commands. Do not remove detail from this section —
> it is the working reference for every sub-phase.

---

## Phase 84 Compliance Review (deferred items)

> **Source:** Follow-up to the second critical review of Phase 84 Compliance
> Reporting. Fixes marked `FIXED_IN_REVIEW` in the review report were already
> committed on branch `claude/phase-84-review-fixes`; the items below were
> deferred here because they require architectural change, cross-phase
> coordination, or a design conversation.

### Context

Phase 84 delivered the compliance reporting stack (PCI-DSS, SOC 2, GDPR
evidence artefacts, DSAR endpoints, GDPR retention purge, cross-language
classifier parity). A second critical review after initial merge found a
further set of issues beyond those fixed in the first review pass.

Fixes applied **before** merge (in review-fixes branch — do **not** re-do):

- **C1** (CRITICAL) — DSAR erase TOCTOU on ban preservation: pipeline GET+TTL
- **C2** (CRITICAL) — Monthly/stream fallback misfires on quiet windows:
  check all months missing, not `total==0`
- **C3** (CRITICAL) — Lexicographic ISO timestamp comparison: parse via
  `_parse_ts`/`_ts_in_window`, applied to all stream/audit filters
- **H2** (HIGH) — Logo validation theatre: size cap, magic-byte sniff, proper
  MIME type, logged failures
- **H4** (HIGH) — `/signal-categories` constructed a bare classifier and lied
  about configured overrides: cached `_get_classifier()` loaded from
  `reporting.signal_categories`
- **H5** (HIGH) — `int()` crash on non-numeric hash field: per-field try/except
  with warn-and-continue
- **M3** (MEDIUM) — Token inventory denylist → allowlist (`_TOKEN_SAFE_FIELDS`)
- **M5** (MEDIUM) — `block_rate_pct` clamped to `[0, 100]`
- **M6** (MEDIUM) — HTML escape in `_render_simple_pdf` titles and artefact row
  content (defence in depth for future dynamic titles)
- **L3** (LOW) — DSAR erase audit record preserves full `skipped` list, not
  just its length, so auditors can prove which key was skipped and why
- **L4** (LOW) — Module-level classifier cache via `_get_classifier()`

### Deferred work — Phase 84

#### H1 — DSAR double XRANGE on the full events stream

**File:** `management/api/routes/compliance.py:411, 480`

Each DSAR export issues `XRANGE ja4proxy:events` twice (once in
`_dsar_connection_history`, once in `_dsar_fingerprint_associations`),
full-scan every time. At 90 days of events that can be millions of entries
per call; an auditor firing DSAR requests for 50 IPs in sequence stalls the
management API.

**Fix:** Read the stream once per request, pass the parsed list to both
helpers, or move to Stream consumer-group range queries with server-side
filter by IP. Add a `management:dsar:last_xrange_len` gauge so growth is
observable before it bites.

**Acceptance:**
- DSAR export path issues at most one `XRANGE` call per request
- Benchmark on a 1M-entry stream: DSAR export completes in < 2s
- Prometheus metric exposes XRANGE read length

---

#### H3 — DSAR watchlist export/erase misses CIDR matches

**File:** `management/api/routes/compliance.py:295-296, 453-454`

`_dsar_watchlist_entries` and the erase path compare the watchlist entry
field literally against the DSAR IP. Phase 82 watchlists can store CIDR
blocks (`10.0.0.0/24`); a DSAR for `10.0.0.15` will not match the CIDR, and
the export under-reports coverage — a GDPR Article 15 compliance gap.

**Fix:** Use `ipaddress.ip_network(entry, strict=False).supernet_of(...)` or
`ipaddress.ip_address(ip) in ipaddress.ip_network(entry)`. Coordinate with
Phase 82 authors to confirm the field name and CIDR semantics. Test vectors:
IPv4 `/32`, IPv4 `/24`, IPv6 `/128`, IPv6 `/48`, malformed entries.

**Acceptance:**
- DSAR export for `10.0.0.15` includes a watchlist entry stored as
  `10.0.0.0/24`
- DSAR erase on an IP covered by a CIDR watchlist entry either removes the
  CIDR or records it as `skipped` with reason "CIDR match — requires manual
  review" (to be decided in this phase)
- Parity test vectors for IPv4/IPv6 and malformed entries

---

#### M1 — XTRIM MINID semantics in older Redis

**File:** `management/compliance/purge.py:168-169`

Production Redis 6.2+ supports `XTRIM … MINID`. The test suite uses
`fakeredis` which may diverge subtly across versions, and older real Redis
installations in field deployments may not support MINID at all.

**Fix:** On `GDPRPurge.run()` first invocation, run `INFO server` to check
`redis_version`. If < 6.2, log a WARN and fall back to time-based XRANGE +
XDEL loop (slower but correct on all versions). Document the minimum Redis
version in `docs/REDIS_SCHEMA.md`.

**Acceptance:**
- Startup check emits the Redis version via a log line and a gauge
- Fallback path exists and is covered by a unit test that mocks
  `redis.info()` returning `redis_version: 6.0.0`
- Docs updated

---

#### M2 — Rename `beaconing_records_cleaned` metric

**File:** `management/compliance/purge.py:138, 205`

The metric and summary field `beaconing_records_cleaned` actually counts
*members* removed from sorted sets, not IPs or connections. Operators
reading the value for compliance evidence will misread "records" as "IPs".

**Fix:** Rename to `beaconing_datapoints_cleaned` in both the Python
dataclass and any exposed Prometheus metric. This is a **breaking change**
for dashboards and anyone parsing the JSON summary — coordinate with
Phase 86 (observability) before merging.

**Acceptance:**
- `PurgeSummary.beaconing_datapoints_cleaned` replaces the old field
- `CHANGELOG.md` notes the breaking change with the old name
- Grafana dashboards updated if they reference the old name

---

#### M4 — Paginate audit log reads in pack builder

**File:** `management/compliance/pack_builder.py:203`

`_query_audit_entries` calls `LRANGE management:audit_log 0 -1`. The audit
log is retained 7 years per the DSAR export docstring. At ~10k events/day
that is ~25M entries per evidence pack build. The call blocks the event
loop for seconds and pins memory.

**Fix:** Read in chunks of 10k with `LRANGE start stop`, stop early when the
timestamp drops below the window. Better long-term: migrate audit log from
a Redis List to a Redis Stream with server-side range queries (cross-phase
with 79/100). Document the migration path in an ADR.

**Acceptance:**
- Pack builder loads audit entries in chunks, bounded by a documented
  constant
- Benchmark: 1M audit entries → pack build < 30s, memory < 500MB
- ADR written for the Stream migration path

---

#### M7 — DSAR export returns success on Redis failure

**File:** `management/api/routes/compliance.py:408-413, 478-481`

`_dsar_connection_history` and `_dsar_fingerprint_associations` both catch
all exceptions and return `[]`. A DSAR response then states "no connection
history for this subject" — which for GDPR Article 15 is a false statement
if Redis was just temporarily unreachable.

**Fix:** Either raise `503 Service Unavailable` on partial failure or
include a `data_unavailable` warning field in the response payload listing
which categories failed. The latter is preferred because the auditor still
gets partial data. Add a Prometheus counter
`ja4proxy_dsar_export_partial_failures_total`.

**Acceptance:**
- DSAR response includes a `partial_failures` list on Redis error
- Chaos test: fakeredis raising `ConnectionError` on `xrange` returns a
  payload with `partial_failures: ["connection_history"]` and HTTP 200
- Prometheus counter wired

---

#### L1 — Jinja2 Environment cached at module level

**File:** `management/compliance/report_renderer.py:129-132`

Each `ReportRenderer()` creates a new `Environment` and `FileSystemLoader`.
Jinja2's Environment is the template cache boundary. Fine for correctness,
but every report regenerates the template cache.

**Fix:** Module-level Environment keyed on `(template_dir, template_name)`.
Add a test confirming two renderer instances share compiled templates.

**Acceptance:**
- Two `ReportRenderer()` instances with the same template_dir reuse the
  same compiled Jinja2 template
- Unit test asserts `id(t1.environment) == id(t2.environment)`

---

#### L2 — JSONL trailing-newline behaviour documented

**File:** `management/compliance/pack_builder.py:293-296, 330-333`

The JSONL writer appends a trailing newline when non-empty, no newline when
empty. Consistent behaviour but undocumented. Downstream consumers may
parse lazily and choke on a terminating blank line.

**Fix:** Document the invariant in the artefact inventory table in the
pack_builder docstring; add a test asserting non-empty JSONL files end in
`\n` and empty files are zero bytes.

**Acceptance:**
- Docstring and tests match the documented invariant

---

#### L5 — DSAR retention strings hardcoded

**File:** `management/api/routes/compliance.py:239-245`

The DSAR export payload lists retention periods in prose ("90 days") but
the actual values come from the `gdpr:` config. If an operator raises
`connection_log_retention_days` to 180, the DSAR response still claims 90 —
a documented lie to the data subject.

**Fix:** Read the values from config and format the strings dynamically.
Add a test that changes the config and asserts the DSAR response text
matches.

**Acceptance:**
- DSAR response retention text reflects `gdpr.*_retention_days` config
- Test covers the non-default case

---

## Phase 85 Threat-Intel Hardening (deferred items)

> **Source:** Critical security architect review of Phase 85 conducted on
> 2026-04-09 immediately after the Phase 85 §12 acceptance gate flipped
> COMPLETE. The review found that the §12 functional gate passes but the
> security gate does not. Phase 85 ships an automated mass-banning pipeline
> with no breaker between "feed says X" and "production blocks X".
>
> Do **not** deploy `dial > 0` with `threat_intel.enabled: true` and any
> feed `enabled: true` until C4, C6, and H6 below are closed. C5-partial,
> C7, and H13 were closed in-branch on phase-85 (commits 7c8ccac, 78162eb,
> ee80232) — they are documented for reference only.

### Findings already closed on phase-85 (reference only)

| ID  | Severity | Title | Closed by |
|-----|----------|-------|-----------|
| C5-partial | CRITICAL | 10% deletion cap on differential cleanup | 78162eb |
| C7  | CRITICAL | Default `threat_intel` + `seed_file` to disabled | ee80232 |
| H13 | HIGH | Defer `stix_ids_seen.add()` until mgmt write succeeds | 7c8ccac |

These are listed here only so a reader has a complete view. Do not
re-open them. The structural unit-test gap that left these landed
without test coverage was closed by commit 71f0f7d
(`tests/unit/analytics/ti_feeds/test_runner.py`, 6 tests covering C5
cap math + H13 snapshot integrity).

### Deferred work — Phase 85

#### C4 — Per-feed safety caps (`max_new_per_poll`, `max_owned_total`)

**Severity:** CRITICAL
**Effort:** ~1 day (config schema + runner gate + tests)

##### Context

A misconfigured or compromised feed can today drive an unbounded number of
`POST /api/v1/bans` calls in a single poll. The runner enforces no upper
bound — the only brake is the per-feed circuit breaker, which trips on
*errors*, not on volume. A feed that begins returning legitimate-looking
HTTP 200 with 50 000 indicators per page would happily ban all of them.

This collides head-on with the project's core asymmetry: false positives
are catastrophic, false negatives are recoverable.

##### Exact changes

1. `src/analytics/ti_feeds/base.py` — extend `FeedConfig` with
   ```python
   max_new_per_poll: int = 500
   max_owned_total: int = 50_000
   max_delta_per_poll: int = 0  # 0 = unlimited
   ```
   All three honour `from_dict` so YAML can override per-feed.

2. `src/analytics/ti_feeds/runner.py` `_poll_once` — after `client.poll()`
   returns and *before* we touch the snapshot:
   - If `len(result.created) > cfg.max_new_per_poll`: log
     `event=feed_capped_new`, slice `result.created[: cfg.max_new_per_poll]`,
     and increment a new `ti_feed_caps_hit_total{feed_id, kind="new"}`
     counter. The truncated indicators are *not* added to the snapshot
     (so next poll will retry them).
   - If `len(previous_ids) >= cfg.max_owned_total`: refuse to apply any
     new indicators this cycle, log `event=feed_capped_total`, increment
     `ti_feed_caps_hit_total{kind="total"}`. Cleanup is still allowed.
   - If `cfg.max_delta_per_poll > 0` and the absolute delta
     `|len(seen) - len(previous_ids)|` exceeds it: refuse to apply *any*
     mutations this cycle, log `event=feed_capped_delta`, increment
     `ti_feed_caps_hit_total{kind="delta"}`.

3. `config/proxy.yml` — add the three keys to every example feed entry
   under `threat_intel.feeds[*]`, with conservative defaults and inline
   comments explaining the blast-radius brake.

4. `monitoring/alertmanager/rules/ti_feed.yml` — add a `TIFeedCapsHit`
   warning rule (`rate(ja4proxy_ti_feed_caps_hit_total[15m]) > 0`) with a
   runbook link to `docs/runbooks/ti_feed_caps_hit.md` (new file).

##### Verify

```bash
python3 -m pytest tests/unit/ -k ti_feed_caps -x
make lint-phases
```

A new `tests/unit/test_ti_feed_caps.py` should cover all three cap kinds
with parametrised cases.

---

#### C5 — Two-empty-poll gate before bulk cleanup

**Severity:** CRITICAL
**Effort:** ~2 hours

##### Context

The 10% deletion cap committed in 78162eb (the C5-partial entry above) is
a brake, not a fix. A feed that legitimately shrinks over many cycles
still converges to zero. The real defence is: never act on a *single*
empty/near-empty poll. Wait for two consecutive empties before allowing
any cleanup beyond the cap.

This needs a per-feed counter in `FeedState` so it survives runner
restarts.

##### Exact changes

1. `src/analytics/ti_feeds/state.py` — add
   ```python
   async def get_empty_streak(self, feed_id: str) -> int: ...
   async def bump_empty_streak(self, feed_id: str) -> int: ...
   async def reset_empty_streak(self, feed_id: str) -> None: ...
   ```
   Backed by a Redis string `ti_feed:{feed_id}:empty_streak` with no TTL.

2. `src/analytics/ti_feeds/runner.py` `_poll_once` — after computing
   `dropped` but before applying any deletions:
   - If `len(result.stix_ids_seen) == 0`: `bump_empty_streak`. If the
     resulting streak is `< 2`, set `dropped = {}` and log
     `event=cleanup_skipped_empty_streak | streak=N`. Snapshot is *not*
     replaced (we don't trust the empty result enough to overwrite the
     last good one).
   - If `len(result.stix_ids_seen) > 0`: `reset_empty_streak` and
     proceed to the existing 10% cap path.

3. `tests/unit/analytics/ti_feeds/test_runner_empty_streak.py` — new
   file with cases: first empty poll skips cleanup; second empty allows
   cleanup but capped at 10%; non-empty poll resets the streak.

##### Verify

```bash
python3 -m pytest tests/unit/analytics/ti_feeds/test_runner_empty_streak.py -x
```

---

#### C6 — `ja4_safe_to_block(ja4)` FP corpus check

**Severity:** CRITICAL
**Effort:** ~3 hours

##### Context

The TAXII / REST clients today validate JA4 indicators only by *shape*
(`is_valid_ja4`). There is no FP corpus check. A feed publishing a JA4
that matches Chrome 120 stable would cause a hard block on every Chrome
120 client because the canonical blocklist bypasses the dial.

The FP corpus exists already (`tests/adversarial/ja4_corpus/`) — it just
isn't consulted from the apply path.

##### Exact changes

1. `src/analytics/ti_feeds/ja4_safety.py` — new module:
   ```python
   def ja4_safe_to_block(ja4: str) -> tuple[bool, str]:
       """Return (safe, reason). False if ja4 hits the FP allow corpus."""
   ```
   Loads the FP corpus once at module import (lru_cache around the file
   read). The corpus path is configurable via env var
   `JA4PROXY_FP_CORPUS_PATH` for tests.

2. `src/analytics/ti_feeds/taxii.py` `_apply_indicator` JA4 branch — after
   `is_valid_ja4(ja4)` and before `post_blocklist`:
   ```python
   safe, reason = ja4_safe_to_block(ja4)
   if not safe:
       _INDICATORS_PROCESSED.labels(feed_id=feed_id, outcome="fp_blocked").inc()
       result.errors.append(f"fp_corpus blocked: {reason}")
       return
   ```

3. Same wiring in `src/analytics/ti_feeds/rest_generic.py` JA4 branch.

4. `src/analytics/ti_feeds/seed_file.py` `run_once` — same check before
   each `post_blocklist`. The seed file should *never* be allowed to push
   a known-good JA4 either, even though it's an operator-curated file.

5. New metric `ja4proxy_ti_feed_fp_blocked_total{feed_id}` and a
   `TIFeedFPBlocked` Alertmanager warning rule (any non-zero rate is a
   smoking gun: either the feed is hostile or our FP corpus is wrong).

##### Verify

```bash
python3 -m pytest tests/unit/analytics/ti_feeds/test_ja4_safety.py -x
python3 -m pytest tests/adversarial/test_ti_feeds_fp_block.py -x
```

The adversarial test should construct a synthetic feed that publishes
the Chrome 120 JA4 from the FP corpus, run it through the runner, and
assert that `post_blocklist` is *never* called.

---

#### H6 — Real `aiohttp` resolver / SSRF mitigation

**Severity:** HIGH
**Effort:** ~half a day

##### Context

`base.validate_feed_url` rejects literal RFC1918 / loopback / link-local
hosts but does *not* defend against DNS-based SSRF: a feed configured
with `https://feed.example.com/` whose DNS A record currently points to
`169.254.169.254` (cloud metadata) will be polled successfully.

The fix is to use a custom `aiohttp.TCPConnector(resolver=...)` that
resolves the hostname *and then* checks the resulting IP against the
private/loopback/link-local set before returning it.

##### Exact changes

1. `src/analytics/ti_feeds/safe_resolver.py` — new module:
   ```python
   class SafeResolver(aiohttp.AbstractResolver):
       async def resolve(self, host, port=0, family=socket.AF_UNSPEC):
           hosts = await self._inner.resolve(host, port, family)
           for h in hosts:
               if not is_publicly_routable_ip(h["host"]):
                   raise aiohttp.ClientConnectorError(
                       connection_key=None,
                       os_error=PermissionError(f"SSRF blocked: {h['host']}"),
                   )
           return hosts
   ```

2. `src/analytics/ti_feeds/base.py` `is_publicly_routable_ip` — pull the
   helper out of the existing `validate_feed_url` so the resolver can
   share it. Cover IPv4-mapped, 6to4, Teredo recursively (already done).

3. Every TCPConnector instantiation in the four clients — taxii.py,
   crowdstrike.py, recorded_future.py, rest_generic.py — switches to
   `aiohttp.TCPConnector(resolver=SafeResolver())`.

4. `tests/adversarial/test_ti_feeds_ssrf.py` — new file. Patch
   `socket.getaddrinfo` to return `169.254.169.254` for a synthetic
   hostname, run a real `TAXIIClient.poll()` against that host, assert
   the poll returns a `result.errors` entry containing `"SSRF blocked"`
   and that `post_ban` was never called.

##### Verify

```bash
python3 -m pytest tests/adversarial/test_ti_feeds_ssrf.py -x
```

---

#### H7 — Manual-poll endpoint rate limit

**Severity:** HIGH
**Effort:** ~1 hour

##### Context

`POST /api/v1/threat-intel/feeds/{id}/poll` has no rate limit. An
authenticated Operator (or a stolen Operator token) can XADD to the
trigger stream as fast as they like. Each trigger costs one full poll —
remote API quota burn, mgmt-API write storm, leader-lock contention.

##### Exact changes

1. `management/api/routes/threat_intel.py` — add a
   `slowapi`-style limiter (or the existing `limit_per_minute`
   decorator from Phase 79) at 6/min/feed_id.

2. `tests/unit/test_threat_intel_api.py` — assert that the 7th request
   in 60 s returns 429 with a `Retry-After` header.

##### Verify

```bash
python3 -m pytest tests/unit/test_threat_intel_api.py::test_poll_rate_limit -x
```

---

#### H8 — CSRF middleware on `/api/v1/threat-intel/*` write routes

**Severity:** HIGH
**Effort:** ~2 hours (assuming a CSRF middleware lands as part of this item)

##### Context

The Management API today relies on `SameSite=lax` cookies as its only
CSRF defence. `lax` does not protect POST requests submitted from a
form on an attacker-controlled site. The threat-intel routes are write
endpoints and should additionally require a double-submit CSRF token.

This item also closes the gap for every other Phase 79 mutating route,
not just threat-intel — which is why the effort is non-trivial.

##### Exact changes

1. `management/api/middleware/csrf.py` — new middleware that:
   - On every `GET /api/v1/*` response: set a `csrf_token` cookie
     (HttpOnly false, SameSite=strict, Secure in prod) and an
     `X-CSRF-Token` response header containing the same value.
   - On every `POST/PUT/PATCH/DELETE /api/v1/*` request: require the
     `X-CSRF-Token` header to match the `csrf_token` cookie. Reject 403
     with body `{"error": "csrf_token_mismatch"}`.
   - Tokens are HMAC over `(session_id, issued_at)` with the existing
     `MANAGEMENT_SECRET_KEY`. Validity 1 h.

2. `management/api/main.py` — register the middleware after auth.

3. `management/templates/base.html` — read the `csrf_token` cookie in
   the Alpine bootstrap and inject it as a header on every fetch via a
   global `$fetch` wrapper.

4. `tests/unit/test_csrf.py` — full happy / mismatch / expired matrix.

##### Verify

```bash
python3 -m pytest tests/unit/test_csrf.py -x
python3 -m pytest tests/unit/test_pages_threat_intel.py -x
```

---

#### H9 — Recorded Future regional endpoint support

**Severity:** HIGH
**Effort:** ~1 hour

##### Context

`_RF_TAXII_ROOT` is hardcoded to `https://api.recordedfuture.com/taxii2/`.
RF customers in EU / APAC contractually route through `eu` / `apac`
sub-domains and the global endpoint will return 403 from those tenancies.
This was missed in Chunk G because the verification used a US tenant.

##### Exact changes

1. `src/analytics/ti_feeds/recorded_future.py` — make the TAXII root
   come from `config.url` first, falling back to `_RF_TAXII_ROOT`. Honour
   `https://api.eu.recordedfuture.com/taxii2/` etc. literally.

2. `config/proxy.yml` recorded_future example — show the EU endpoint as
   a comment with a note about which tenants need it.

3. `docs/phases/PHASE_85_notes.md` — append a "Chunk G addendum" line.

##### Verify

```bash
python3 -m pytest tests/unit/analytics/ti_feeds/test_recorded_future.py -x
```

---

#### H10 — CrowdStrike regional / GovCloud endpoint support

**Severity:** HIGH
**Effort:** ~1 hour

Same shape as H9 but for `_FALCON_AUTH_URL` and `_FALCON_INDICATORS_URL`.
Falcon offers `api.us-2.crowdstrike.com`, `api.eu-1.crowdstrike.com`, and
`api.laggar.gcw.crowdstrike.com` (GovCloud). Pull both URLs from
`config.url` with the existing values as fallback.

---

#### H11 — Re-shape `test_ti_feed_taxii_unavailable.py`

**Severity:** HIGH
**Effort:** ~1 hour

##### Context

The chaos test asserts that the runner survives a TAXII server returning
500s. It does not assert what the architect review actually wants: that
*after* a 500 storm, no new bans were created and no existing bans were
removed. As written, the test is satisfied by a runner that crashes the
analytics container — that crash would also leave existing rules intact.

##### Exact changes

Replace the test body with:

```python
async def test_taxii_500_storm_does_not_mutate_state(...):
    # Pre-populate the snapshot with 100 indicators.
    # Configure a TAXII server that returns 500 for the next 10 polls.
    # Run the runner for 10 cycles.
    # Assert: snapshot still has 100 entries.
    # Assert: mgmt.post_ban call count is 0 (no new bans).
    # Assert: mgmt.delete_ban call count is 0 (no cleanups).
    # Assert: circuit state is OPEN.
```

H11 and H12 below overlap on this file: land H11 first and treat it as
the target shape that H12's coordinated rewrite then matches for the
other four files in the same family.

---

#### H12 — Coordinated re-shape of 5 Phase-85 integration / chaos test files

**Severity:** HIGH
**Effort:** ~half a day (one engineer, one sitting — these need to be
done together to share fixtures and stay coherent)

##### Context

Five Phase-85 test files were authored against a `FeedRunner(feeds=[...])`
constructor that no longer exists. The current shape is
`FeedRunner(redis=, mgmt_base_url=, config=, instance_id=)` with work
driven through `_poll_once(feed_id)`. Each file is currently
`pytestmark = pytest.mark.xfail(strict=False)` with a reason string that
points at this item. They all silently pass collection but assert
nothing — i.e. the integration coverage for the runner is 0.

The structural unit-test gap was closed in commit 71f0f7d
(`tests/unit/analytics/ti_feeds/test_runner.py`, 6 tests covering C5 cap
math + H13 snapshot integrity), but unit tests cannot reach the things
these integration files target: real httpx flow, real Management API
TestClient, hot-reload across two FeedConfig snapshots, conflict
resolution between two replicas competing for the leader lock, and
chaos behaviour against an upstream that returns 5xx.

The 5 files (and one test case each) are:

| File | What it should assert |
|------|-----------------------|
| `tests/integration/test_ti_feeds_e2e.py` | a real STIX bundle from a mock TAXII server lands in `GET /api/v1/blocklist?managed_by=feed` |
| `tests/integration/test_ti_feeds_cleanup.py` | re-poll with shrunken feed removes the right things, never more than the cap |
| `tests/integration/test_ti_feeds_conflict.py` | only one of two `FeedRunner` instances actually polls per cycle (leader lock) |
| `tests/integration/test_ti_feeds_hot_reload.py` | added feeds spawn tasks; removed feeds stop polling but retain their rules |
| `tests/chaos/test_ti_feed_taxii_unavailable.py` | snapshot unchanged, no new bans, no cleanup, circuit reaches OPEN under a 500 storm |

The chaos file overlaps in spirit with H11 — H11 is the "no mutations
during 500 storm" guard, H12's chaos entry is the existing-test rewrite.
Land H11 first and make H12 the rewritten version.

##### Exact changes

1. Move all 5 files to use the same shared fixtures already living in
   `tests/unit/analytics/ti_feeds/conftest.py` + `tests/_helpers/`
   (`stub_management_client`, `mock_taxii_server`, `_StubMgmt`,
   `_StubClient`, `_make_runner`). Promote whatever they need into a
   `tests/integration/conftest.py` or `tests/_helpers/ti_feed_runner.py`
   so the shape is shared rather than copy-pasted.

2. Rewrite each file against `FeedRunner._poll_once(feed_id)` (not
   the loop), exactly the way
   `tests/unit/analytics/ti_feeds/test_runner.py` drives it. The
   integration files differ by injecting a real httpx-backed
   Management API TestClient in place of the unit tests' `_StubMgmt`.

3. Remove the `pytestmark = pytest.mark.xfail(...)` line from each
   file in the same commit.

4. Update each file's docstring header to drop the "RED until X
   exists" language. Replace with a one-line summary of what the
   file actually asserts post-rewrite.

##### Verify

```bash
python3 -m pytest tests/integration/test_ti_feeds_e2e.py \
    tests/integration/test_ti_feeds_cleanup.py \
    tests/integration/test_ti_feeds_conflict.py \
    tests/integration/test_ti_feeds_hot_reload.py \
    tests/chaos/test_ti_feed_taxii_unavailable.py -x
```

All 5 files green, none xfailed, none skipped.

##### Why one item, not five

The fixture work is the bulk of the effort. Doing it five times is a
guarantee they will diverge. Doing it once means the next contributor
can write the sixth integration test without re-deriving how to wire
a `FeedRunner` against an httpx Management TestClient.

---

### Phase 85 medium-severity items

These are filed as a single bullet list with one-line summaries because
each is small enough to land independently. Pick them up in any order.

| ID  | Title | File hint |
|-----|-------|-----------|
| M8  | TAXII bundle size cap (reject `> N MiB` responses before parse) | taxii.py |
| M9  | Per-feed `User-Agent` header (currently shared global UA) | base.py + 4 clients |
| M10 | `ti_feed_indicators_managed` Gauge → use `Counter` for delta | metrics.py |
| M11 | `compute_dropped_ids` should return a stable-ordered list, not a dict | state.py |
| M12 | Replace `BLE001` `Exception` catches in clients with explicit unions | 4 clients |
| M13 | `seed_file.run_once` should run inside a leader lock | seed_file.py |
| M14 | Audit log entry on every feed `enable` / `disable` runtime override | threat_intel.py route |

---

### Phase 85 low-severity items

| ID | Title |
|----|-------|
| L6 | `_OneShotBundle` adapter docs out of date after H13 |
| L7 | Three Phase 85 runbooks need a real-deployment dry run |
| L8 | `monitoring/metrics_registry.md` lacks Phase 101 entries (will be added with each item) |

> Note: a Phase 85 entry tracking the `tests/unit/test_pages_threat_intel.py`
> xfail removal was filed as L-tier and immediately closed in branch
> (commits 9aafbd8 + ea66df1, fakeredis injection + httpx AsyncClient +
> per-role JWT cookie fixtures). It is intentionally not given an L-number
> here because it never reached the deferred state.

---

## Phase 62 Go Test Parity (deferred items)

> **Source:** External SRE/security review of the Phase 62 implementation
> on branch `claude/phase-62-go-test-parity` (2026-04-09). The blocking
> finding (dial-flip test under-asserting) was fixed in-branch as commit
> `phase-62: review fixes`. The four items below were deferred here because
> they require cross-phase coordination (M17 → Phase 200), independent
> reference data (M15), or are quality-of-test improvements that do not
> block merge.

### M15 — JA4 golden file lacks an independently-computed cross-check anchor

**File:** `internal/tls/testdata/ja4_fp_golden.txt`, `internal/tls/ja4_fp_corpus_test.go`

The golden file was generated from the same Go parser it tests, so it
locks in *future drift detection* but rubber-stamps any *current* bug
in the JA4 implementation. The Phase 62 reviewer flagged this as a
test-integrity gap.

**Fix:** Add at least one row to the golden file whose JA4 string is
computed by an independent reference implementation — either FoxIO's
canonical `ja4` CLI (`go install github.com/FoxIO-LLC/ja4/...`) or the
Python `ja4` library against the same `.bin` fixture. Mark that row in
the golden header as the cross-checked anchor and the rest as
self-snapshots until each is independently verified.

**Why deferred:** Requires running an external tool against every fixture
and committing results; one-shot work but better as a follow-up because
the team should agree on which reference implementation to canonicalise.

### M16 — Total-outage chaos test passes for the right answer via the wrong mechanism

**File:** `internal/security/pipeline_chaos_test.go::TestPipeline_RedisOutage_FailsOpen`

The test sets `failEvery=1, dial=100` against `faultyRedis`, expecting the
pipeline to allow because every Redis call (including `GetDial`) returns
the zero value, so the dial reads as 0 → monitor mode → allow. **The test
does not isolate fail-open of signal collection from fail-open of the
dial read.** If `GetDial` were ever changed to return the last-known-good
dial on error (a fail-closed alternative), this test would silently still
pass even if signal collection had a real fail-closed bug.

**Fix:** Add a sibling test `TestPipeline_RedisOutage_FailsOpen_DialIntact`
where `GetDial` always returns 100 but every other Redis call fails. The
pipeline must still produce `allow`, proving signal-collection fail-open
independently of dial-read fail-open.

**Why deferred:** ~20 lines of test code; not a production bug; cleanly
separable from the M15 work.

### M17 — `FuzzReadProxyProtocolV2` is a placeholder until Phase 200 lands the v2 reader

**File:** `cmd/proxy/fuzz_test.go::FuzzReadProxyProtocolV2`

Phase 62 doc proposed `proxy.ReadProxyProtocolV1` and `proxy.ReadProxyProtocolV2`
as separate functions; only `proxy.ReadProxyProtocol` (v1) exists in the
current Go tree. The Phase 62 fuzz target calls the existing v1 reader
with v2-shaped seeds, which the v1 reader rejects after the first byte —
so the target compiles and runs panic-free but exercises essentially
zero v2 code path. The fuzz harness exists today so it is ready when
the v2 reader lands.

**Fix:** When [Phase 200](PHASE_200.md) implements the binary v2 PROXY
protocol parser, repoint `FuzzReadProxyProtocolV2` at the new function
and verify execution count climbs into the same range as the v1 target
(~700 k execs / 10 s).

**Why deferred:** This is the explicit hand-off to Phase 200. Filed here
so the contract is visible from both phase reviews — without this entry,
the placeholder fuzz target could be misread as actual v2 coverage.

**Cross-reference:** Phase 200 owns `internal/proxy/proxy_protocol_v2.go`
or equivalent; this gap closes the same day Phase 200 merges.

### L9 — Property test generator allows `Weight=0`, scorer treats it as `1.0`

**File:** `internal/security/property_test.go::genRiskSignal` (~line 33)

The `rapid` generator for `RiskSignal` allows `Weight=0`, but the
production `RiskScorer` substitutes `1.0` whenever `Weight==0`. The
generator therefore tests an input distribution that does not match
production semantics, slightly muddying the property under test.

**Fix:** Constrain the generator to `Weight ∈ [0.1, 5.0]` (or whatever
the scorer's actual valid range is) and document the constraint in a
comment that points at the scorer normalisation rule.

**Why deferred:** Cosmetic. The four properties still pass and still
catch real bugs; this is correctness-of-test-distribution, not
correctness-of-property.

---

## Acceptance criteria (whole register)

Phase 101 is complete when **every section** is closed. To close a section:

- All `C*` items in the section closed.
- All `H*` items in the section closed.
- All `M*` items either closed or explicitly punted to Phase 100 with
  a one-line note in this doc.
- A doc-check verifies the section's stated invariant (Phase 84:
  compliance evidence path; Phase 85: feed runner cannot mass-ban real
  traffic at any step in the deploy sequence).

Per-section acceptance commands:

**Phase 84 section:**
- [ ] All Phase 84 items above have PR-level fixes or explicit, documented
  deferrals
- [ ] No new critical/high findings from a third review pass
- [ ] `make test-phase-84` still passes (Go + Python compliance suites)
- [ ] CHANGELOG.md updated with a Phase 84 closure entry
- [ ] ADRs written for M4 (audit log Stream migration) and M2 (metric
  rename)

**Phase 85 section:**
```bash
python3 -m pytest tests/unit/analytics/ti_feeds/ tests/adversarial/test_ti_feeds_*.py -x
make lint-phases
```
- [ ] Operator's deploy story is: enable `threat_intel.enabled: true`,
  enable a feed, raise the dial — and at no step in that sequence can a
  single misbehaving feed mass-ban real traffic.

---

## Out of scope (whole register)

Phase 84 section:

- Any new compliance framework (stay focused on PCI-DSS / SOC 2 / GDPR)
- Management UI changes (Phase 13/51/52 territory)
- Redis version migrations beyond the check-and-fallback in M1

Phase 85 section:

- **Per-feed signing keys / verifying STIX bundle signatures.** Several
  feeds support detached JWS or PGP signing of bundles. Worth doing but
  belongs in its own phase because it touches every client.
- **GDPR-compliant feed contribution beyond the existing gate.** The
  contribution path landed in Chunk D. Hardening it is Phase 86 or
  later, not 101.
- **Replacing `aiohttp` with `httpx`.** Not a security item.

---

## Phase 64 Deployment Validation (deferred items)

> **Source:** Claude re-plan review of Phase 64, 2026-04-09. Phase 64 was
> restructured from a monolithic document into nine independent sub-phases
> (64a–64i). The items below were dropped because they depend on artefacts
> that do not yet exist in the repository.

### Context

Phase 64 covers deployment smoke tests, DR runbooks, MTTR baselines, and
credential/certificate rotation procedures. The re-plan identified two items
that cannot be addressed because prerequisite artefacts are missing: the
Podman/Quadlet unit files (Phase 76) and the actual backup CLI surface
(Phase 19, Python-only).

---

#### M18 — Podman/Quadlet smoke test blocked

**Severity:** MEDIUM
**Effort:** ~half a day (once prerequisites exist)

##### Context

`scripts/smoke/test_podman_quadlet.sh` (originally in PHASE_64.md §2.3)
copies `deploy/rhel/quadlets/*.{container,network,kube}` to the user's
Quadlet directory and starts the service via systemd. The directory
`deploy/rhel/quadlets/` does not exist. Phase 76 (RHEL/Podman/Quadlet
deployment) was a strategy / best-practices document only — it produced
no Quadlet unit files.

Until Phase 76 (or another RHEL deployment phase) creates real
`.container`, `.network`, and `.kube` files, the smoke test has nothing to
validate.

##### Fix required

Phase 76 (or its successor) must create:
```
deploy/rhel/quadlets/
  ja4proxy.container
  redis.container
  ja4proxy.network
  (any .kube files if Podman pods are used)
```

Once those files exist, 64b can produce `scripts/smoke/test_podman_quadlet.sh`
following the same contract as 64a: exit 0 = pass, exit 1 = fail with
stderr reason, structured output under `test-results/smoke/`.

##### Owner
TBD — Phase 76 owner (Phase 76 was paper-only so far).

---

#### M19 — Phantom `ja4proxy-cli backup` audit

**Severity:** MEDIUM
**Effort:** ~2 hours (audit) + ~1 day (fix any broken runbooks)

##### Context

The Go CLI (`cmd/ja4proxy-cli/main.go`) has the following subcommands:
`ip`, `allowlist`, `blocklist`, `dial`, `config reload`, `health`,
`fingerprint`, `policy`, `simulation`, `compliance`, `report`. It has
**no `backup` subcommand**.

Phase 19's backup system is Python-only: `src/backup/worker.py` and
`src/backup/restorer.py`. The correct invocation is:
```python
python3 -c "from src.backup.restorer import Restorer; \
  Restorer('redis://:PASSWORD@localhost:6379/0', \
  Path('/var/backups/ja4proxy/backups/<filename>.tar.gz')).restore()"
```

However, PHASE_64.md §3.5 and potentially other runbooks (Phase 22, 40,
57) reference phantom commands like `ja4proxy-cli backup list`,
`ja4proxy-cli backup restore`, or `ja4proxy-cli backup run --immediate`.
An operator following these runbooks will get a "unknown command" error
at the worst possible moment (during a DR event).

##### Fix required

1. Audit all runbooks under `docs/runbooks/` and all phase documents
   under `docs/phases/` for `ja4proxy-cli backup` references.
2. Replace each reference with the correct Phase 19 Python invocation.
3. If a long-term plan exists to port backup to the Go CLI, document it
   here. If not, the Python tool is the canonical surface and should be
   noted as such in `docs/runbooks/redis_operations.md` and any DR
   runbook that mentions backups.

##### Verify

```bash
grep -rn "ja4proxy-cli backup" docs/runbooks/ docs/phases/
```

The above should return zero results after the fix (except this PHASE_101
entry itself).

---

#### M20 — CI smoke-k8s job needs kind/helm installation steps — CLOSED

**Severity:** MEDIUM — **CLOSED 2026-04-10**

Fixed in Phase 64 closeout: added SHA-pinned `azure/setup-helm@v4.3.0`
and `helm/kind-action@v1.12.0` to the `smoke-k8s` CI job.

---

#### M21 — `infrastructure.md` still references Python proxy — CLOSED

**Severity:** MEDIUM — **CLOSED 2026-04-10**

Fixed in Phase 64 closeout: replaced all `pgrep -f proxy.py` references
in `docs/runbooks/infrastructure.md` with `pgrep -f bin/proxy`.

---

#### M22 — AbuseIPDB lookups counter missing from Go metrics — CLOSED

**Severity:** MEDIUM — **CLOSED 2026-04-10**

Fixed in Phase 64 closeout: added `ja4proxy_abuseipdb_lookups_total`
counter with `result` label (`hit`/`miss`/`error`) to
`internal/metrics/metrics.go` and instrumented all code paths in
`internal/security/abuseipdb.go`.

---

#### M23 — MTTR test should validate Redis key names — CLOSED

**Severity:** MEDIUM — **CLOSED 2026-04-10**

Fixed in Phase 64 closeout: added 4 tests to `tests/test_phase64h_mttr.py`
in `TestRedisKeyNames` class — asserts `config:dial` and `config:reload`
are present, and rejects phantom `ja4proxy:dial` / `ja4proxy:config_reload`.

---

## Phase 86i Hardening Review (deferred items)

> **Source:** Independent critical review of Phase 86i (architectural
> hardening of Phase 86) on branch `claude/phase-86i-hardening`
> (2026-04-11). The reviewer flagged 3 BLOCKERS, 3 MAJORS, 3 MINORS, and
> 1 NIT. The 3 blockers were fixed in-branch before merge (commits
> `7f752dd` load test scenarios wired through to TLS generator,
> `3bf0b98` Grafana dashboard rewritten against real exported metrics,
> `babcfac` Datadog allowlist trimmed + `type_overrides` added). The 7
> items below were deferred here because they each fall into one of:
> requires production-representative hardware not available on the dev
> host (L10), is parser-robustness work that needs an adversarial test
> corpus (H15), or touches operational tooling/runbooks beyond the
> acceptance criteria of Phase 86i (H14, H16, M24, M25, M26).

### Context

Phase 86i delivered: a two-layer Datadog refactor (built-in OpenMetrics
check + narrowed custom check), a Dynatrace extension that scrapes
`/metrics` instead of polling `/api/v1/health/deep`, a populated
`docs/performance/benchmarks.md` with measured Go microbenchmark numbers,
a four-scenario load test (`bypass-only` / `full-signal` / `attack-wave`
/ `mixed`) with a real `--fingerprint-mix` wired through to the TLS
traffic generator, a `--push-gateway` flag emitting 5 new
`ja4proxy_loadtest_*` metrics, and a new
`monitoring/grafana/dashboards/04_capacity.json` capacity-planning
dashboard.

Two cross-cutting honesty constraints frame the items below:

1. The benchmark numbers committed to `benchmarks.md` are Go microbench
   measurements on a single developer workstation (i9-9900K, Pop!_OS,
   `go1.26.2`, no Redis hop). The 18,400/cps bypass and 6,200/cps
   full-signal ceilings used by `scripts/capacity_calculator.py` and the
   capacity dashboard's `BYPASS_CEILING_CPS` / `SIGNAL_CEILING_CPS`
   variables are **engineering floors derived from the microbench plus
   reserved IO/Redis budget**, not end-to-end load-test measurements.
2. CLAUDE.md's core asymmetry — false positives are catastrophic, false
   negatives are recoverable — must be preserved by every item below.
   None of these introduce new hot-path behavior, so the asymmetry
   continues to hold; H14 is a tooling-honesty issue rather than a
   runtime-behavior issue.

---

### H14 — Capacity calculator still presents engineering-floor constants as measurements

**Severity:** HIGH
**Effort:** ~half a day (clean cleanup) or ~1 day if combined with L10

#### Context

PHASE_86i.md Step 4 said:

> Update `scripts/capacity_calculator.py` — rename `EstimatedConstants`
> back to `BenchmarkConstants`, set fields to measured values, **remove
> the "ESTIMATED — NOT MEASURED" warning path**. The `--require-measured`
> flag becomes effectively a no-op on clean benchmarks.md.

What actually shipped on `claude/phase-86i-hardening`:

1. `BenchmarkConstants` was renamed (with `EstimatedConstants` retained
   as a backward-compat alias for the Phase 86c tests).
2. The values were **kept at the 86h engineering-floor numbers**
   (`go_full_conn_s=6200`, `go_bypass_conn_s=18400`) and *relabelled* as
   measured-via-microbench-plus-reserved-budget. This was an explicit
   judgment call documented in `PHASE_86i_notes.md` Follow-ups section.
3. The "remove the warning path" instruction was not followed:
   `_ESTIMATED_BANNER`, `_print_estimated_warning()`, `report.estimated`
   branches in `print_report`, and the `estimated`/`_print_estimated_warning()`
   call in `main()` are all **still present as dead code** in
   `scripts/capacity_calculator.py` (lines 117–134, 272–275, 283–286,
   370–383 at the time of merge).

The dead code is inert today because `benchmarks.md` has no
`_(measure)_` placeholders. But:

- The combination is the worst of both worlds: we removed the runtime
  warning that 86h added, while keeping the relabeled engineering-floor
  numbers — so the calculator now silently presents "measured" values
  that are not end-to-end measurements.
- A future accidental edit that re-introduces a placeholder marker would
  silently re-activate the banner output.
- `capacity_report.json` will claim these are measured, with no warning.

#### Fix required

Two acceptable shapes — pick one, do not leave both:

**Option A — actually clean up as the plan said.** Delete the
`_ESTIMATED_BANNER` constant, `_print_estimated_warning()`, the
`report.estimated` branch in `print_report`, and the placeholder-detection
call in `main()`. Keep `benchmarks_have_placeholders()` and
`--require-measured` as positive CI guards. Combine with L10 below so
the constants are also actually measured.

**Option B — keep the warning path but flip it on.** Leave the dead code
in place, but change the report header to honestly say
`"BenchmarkConstants — engineering floor (microbench + reserved budget),
not end-to-end load-tested"` whenever the numbers are not the output of a
real `make bench` run. `--require-measured` becomes
`--allow-engineering-floor` (negation), so a CI run guarding against
unverified ceilings can still fail loudly until L10 lands.

#### Verify

```bash
# Option A (recommended):
grep -n "_ESTIMATED_BANNER\|_print_estimated_warning\|report.estimated" \
  scripts/capacity_calculator.py
# expect: no results
python3 scripts/capacity_calculator.py --require-measured
# expect: exit 0 with no banner in stdout

# Option B:
python3 scripts/capacity_calculator.py 2>&1 | grep -i "engineering floor"
# expect: clear honesty line in the report header
```

#### Why deferred

Cleanup that does not change shipped runtime behaviour, and the right
fix is entangled with L10 (we want the cleanup *and* real measured
numbers to land together, not the cleanup then an immediate second cycle
when L10 lands).

---

### H15 — Dynatrace Prometheus parser is dangerously minimal and the test is too easy

**Severity:** HIGH
**Effort:** ~half a day

#### Context

`deploy/dynatrace/ja4proxy-extension/plugin.py` ships an inline
Prometheus text-format parser (~40 lines) introduced in commit `b0dd515`.
It handles the `HELP`/`TYPE` comment lines, counters, gauges, and
histogram `_bucket{le=...}` / `_count` / `_sum` lines well enough to pass
the canonical exposition fixture in
`tests/unit/test_dynatrace_extension.py::test_plugin_parses_prometheus_text_format`.

Failure modes the parser does **not** handle:

- **Escaped quotes inside label values** (`label="he said \"hi\""`) —
  `_parse_labels` does not de-escape; the value will be truncated at the
  first inner quote and the next label parse will desync the line.
- **Commas inside label values** (`label="a,b"`) — splitting on `,`
  drops the second half of the value.
- **`NaN` samples** — `float("NaN")` succeeds, so a `NaN` propagates into
  the metric event sent to Dynatrace, where it poisons aggregates. The
  parser should explicitly drop NaN via `math.isnan`.
- **Summary `{quantile=...}` metrics** — not handled at all; will be
  emitted as raw gauges with no semantics.
- **Multiple metric families per scrape with overlapping prefixes** —
  unverified.
- **Bare timestamps on the sample line** (the spec allows `metric value
  timestamp`) — the parser silently discards the timestamp with no
  validation, so a malformed exposition where the value and timestamp
  are swapped will be accepted as valid.

The unit test is **substring-based** (`assert "pipeline_duration_seconds"
in n for n in names`), which passes even if every histogram bucket was
silently dropped. So the test does not actually validate parser
correctness for the structure that matters most for the proxy
(`ja4proxy_pipeline_duration_seconds_bucket`).

#### Fix required

**Recommended:** stop maintaining a hand-rolled parser. The
`prometheus_client` package is already a dependency in
`requirements.txt`, and it ships
`prometheus_client.parser.text_string_to_metric_families()` which
correctly handles every case above. Replace the inline parser with a
wrapper around it.

If keeping the inline parser for footprint reasons (Dynatrace extensions
have a deps allowlist):

1. Add explicit `if math.isnan(value): continue` after `float()`.
2. Track quote state inside `_parse_labels` so `\"` and `,` inside
   values are honoured.
3. Add adversarial fixture cases to
   `tests/unit/test_dynatrace_extension.py::test_plugin_parses_prometheus_text_format`:
   escaped quotes, commas in values, NaN, summary quantiles, sample
   lines with trailing timestamps. Each case must assert exact key/value
   pairs, not substring presence.

#### Verify

```bash
python3 -m pytest tests/unit/test_dynatrace_extension.py -v
```

The expanded test should fail against the current inline parser and pass
once it's either replaced or hardened.

#### Why deferred

Out of scope for the Phase 86i merge (the basic happy-path parser was
sufficient to close Gap 1) and the right fix needs an adversarial test
corpus written first; the reviewer was clear this is robustness work,
not a shipped runtime bug for typical Prometheus exposition output.

---

### H16 — Datadog two-layer migration has no smoke check or runbook

**Severity:** HIGH
**Effort:** ~2 hours

#### Context

The Phase 86i Datadog refactor splits the previous custom AgentCheck
into two artefacts: a built-in OpenMetrics check
(`deploy/datadog/conf.d/openmetrics.d/ja4proxy.yaml`) that scrapes
`/metrics` and a narrowed custom check
(`deploy/datadog/checks/ja4proxy/check.py`) that emits only service
checks and topology entities. The two are completely decoupled at the
Datadog Agent level — the `ja4proxy.node_health` service check does not
go CRITICAL when the OpenMetrics scrape fails.

The CHANGELOG documents the migration risk:

> **Operators who already have the Phase 86d Datadog custom check
> installed must also deploy the new OpenMetrics check config…
> otherwise per-label metrics will disappear from Datadog dashboards.**

…but **there is no smoke check** that tells the operator their
OpenMetrics scrape is actually working *before* they remove the old
custom-check gauges. There is no runbook either — the migration is a
config copy-paste with no verification step.

The likely production failure mode is: an operator follows the
CHANGELOG, drops the old check, and discovers two days later that
`ja4proxy.block_rate_pct` and friends have been gone since the upgrade,
because their Agent's OpenMetrics integration was disabled or
mis-namespaced and nobody noticed.

#### Fix required

1. **Migration runbook.** Add `docs/runbooks/datadog_migration_phase86i.md`
   (or a section in an existing Datadog runbook if one exists; check
   `docs/runbooks/`) with the exact pre-flight verification steps:

   ```
   # On a Datadog Agent host with both checks installed:
   datadog-agent check openmetrics
   datadog-agent check ja4proxy
   datadog-agent status | grep -A5 "openmetrics ja4proxy"
   ```

   Plus the explicit ordering: deploy OpenMetrics first, verify
   dashboards still populate over a 24h window, *then* upgrade to the
   narrowed custom check.

2. **Smoke check.** Either:
   - Add an Agent-side check_run watchdog: `check.py` queries the
     Datadog Agent's own `/agent/status` endpoint for the openmetrics
     `ja4proxy` instance, and emits a CRITICAL `ja4proxy.openmetrics_health`
     service check if the OpenMetrics scrape is missing or stale, OR
   - Document a Datadog monitor (in `deploy/datadog/monitors/` if that
     directory exists, or as JSON in the runbook) that alerts when
     `ja4proxy_*` metrics stop arriving for >5 minutes.

3. **Add a test** to `tests/unit/test_datadog_integration.py` asserting
   that the new runbook exists and references both `datadog-agent check`
   commands by exact name.

#### Verify

```bash
ls docs/runbooks/datadog_migration_phase86i.md
grep -c "datadog-agent check openmetrics" docs/runbooks/datadog_migration_phase86i.md
# expect: ≥1
python3 -m pytest tests/unit/test_datadog_integration.py -v
```

#### Why deferred

Operational tooling work that does not block the code refactor; the
migration risk is documented in CHANGELOG, but the cost of an operator
silently losing dashboards across an upgrade is high enough that this
should be the first item picked up after Phase 86 closes.

---

### M24 — Pushgateway has no `grouping_key` and `main()` never populates the latency histogram

**Severity:** MEDIUM
**Effort:** ~1 hour

#### Context

`scripts/load_test.py::push_loadtest_metrics` calls
`prometheus_client.push_to_gateway(url, job=job, registry=registry)` with
no `grouping_key`. Two issues fall out of this:

1. **Multiple concurrent runs collide.** Pushgateway groups metrics by
   `(job, grouping_key)`. With no grouping key, every run from every
   host overwrites the previous run's snapshot under the single
   `job="ja4proxy_loadtest"` key. For the short-lived
   load-test-and-push pattern this is actively wrong: the operator
   triggering a `bypass-only` run from host A and a `full-signal` run
   from host B will see one of the two silently disappear.
2. **The latency histogram metric is always empty in practice.** The
   `--push-gateway` call site in `main()` (around line 340 at merge
   time) hardcodes `latencies_seconds=[]`, so the histogram is registered
   and pushed but every bucket count is 0. The unit test
   `tests/unit/test_load_test.py::test_pushgateway_flag_emits_metrics`
   exercises `push_loadtest_metrics()` directly with synthetic
   latencies, so it never catches the empty-list bug from the real CLI
   path.

#### Fix required

1. **Add `grouping_key`.** Use `socket.gethostname()` plus the scenario
   name plus the run UUID:

   ```python
   import socket, uuid
   grouping_key = {
       "instance": socket.gethostname(),
       "scenario": scenario,
       "run_id": uuid.uuid4().hex[:8],
   }
   push_to_gateway(url, job=job, grouping_key=grouping_key, registry=registry)
   ```

2. **Wire real latency samples through.** The TLS traffic generator
   already records per-connection latencies in its run output JSON.
   Read them in `main()` after the run completes and pass the list to
   `push_loadtest_metrics()` instead of `[]`. If the underlying
   generator does not currently expose them, expose them — this is the
   only way the histogram metric is non-trivial.

3. **End-to-end test.** Add a test that runs `load_test.py` against a
   stub TLS server (or with a `--dry-run` flag that synthesizes
   latencies), captures the Pushgateway HTTP request body via a fake
   server, and asserts the histogram bucket counts are > 0.

#### Verify

```bash
python3 -m pytest tests/unit/test_load_test.py::test_pushgateway_flag_emits_metrics -v
# plus the new end-to-end test once it exists
```

#### Why deferred

Bug in load-test tooling, not the proxy. Reviewers correctly classified
this as MINOR because the load test is operator-triggered (not on the
hot path) and the broken case is "metrics silently overwrite", not
"production traffic affected".

---

### M25 — Dynatrace plugin drops the topology entity on every scrape blip

**Severity:** MEDIUM
**Effort:** ~1 hour

#### Context

`deploy/dynatrace/ja4proxy-extension/plugin.py` early-returns when
`scrape_metrics()` returns an empty sample list (around line 184 at
merge time). The early return skips both the metric series **and** the
topology-entity emission for the proxy node. A transient scrape failure
— a 1-second timeout, a single 502 from a load balancer, an Agent
restart — therefore makes the ja4proxy node briefly **disappear from the
Dynatrace topology view**.

Brief topology disappearances cascade into false-positive
"node_missing" / "monitored_entity_disappeared" alerts in Dynatrace
problem detection, which is exactly the failure mode CLAUDE.md's
asymmetry warns against (a recoverable observability blip becoming a
non-recoverable false page).

#### Fix required

Always emit the topology entity even when the metric sample list is
empty. Only the metric series should be skipped on a scrape failure.

```python
# in plugin.py query():
samples = scrape_metrics(self._url)
self._emit_topology_entity()              # always
if not samples:
    self.logger.warning("scrape returned no samples; topology preserved")
    return
self._emit_metric_series(samples)
```

Add a test
`test_plugin_emits_topology_even_on_scrape_failure` that mocks a scrape
returning `[]`, asserts the topology emit was called, and asserts no
metric emit was called.

#### Verify

```bash
python3 -m pytest tests/unit/test_dynatrace_extension.py::test_plugin_emits_topology_even_on_scrape_failure -v
```

#### Why deferred

Quality-of-implementation in a non-critical observability plugin; no
production-traffic effect; clean to fix once H15 (parser robustness)
lands so the same review pass can re-run the broader test matrix.

---

### M26 — `tests/integration/test_phase_86i_benchmarks_populated.py` does not validate numeric or SHA shape

**Severity:** MEDIUM
**Effort:** ~1 hour

#### Context

The integration test that guards `docs/performance/benchmarks.md` has
two test functions:

- `test_benchmarks_md_has_no_placeholders` — asserts the string
  `_(measure)_` does not appear in the Go Proxy Benchmarks section.
- `test_benchmarks_md_has_hardware_header` — asserts the Reference
  Hardware table rows for CPU, OS, Redis, Go, Python are non-empty and
  do not match `_(...)_`, and asserts a `Git SHA:` line is present whose
  value does not start with `_(`.

What this catches: dropped header rows, placeholder rows, missing Git
SHA line, missing scenario tables.

What it does **not** catch:

- Throughput / latency cells parsed as actual floats. `"TODO"`, `"42"`,
  `"0"`, an empty string, or the word `"placeholder"` in a benchmark row
  all pass.
- The Git SHA shape — the regex `[A-Za-z0-9_()]+` accepts almost any
  token, so `"abc"`, `"deadbeef"`, or even `"_placeholder)"` (the leading
  `_(` check is the only filter) would pass.
- An explicit `Date:` header field — the plan required it but neither
  test checks for it.
- A footer disclaimer when the underlying constants are still
  engineering floors (cross-tie to H14 / L10).

#### Fix required

Tighten the test to assert *honesty*, not just absence:

1. **Numeric parsing.** For each row in the benchmark tables, parse the
   throughput and latency fields as floats. Reject `NaN`, `Inf`,
   negative numbers, and zero.
2. **Git SHA shape.** Assert the header contains a line matching
   `r"Git SHA:\s*[0-9a-f]{7,40}\b"`.
3. **Hardware header completeness.** Assert each of `Hardware:`, `OS:`,
   `Redis:`, `Go:`, `Python:`, `Date:` is present in the header block.
4. **Footer disclaimer present** if and only if the `BenchmarkConstants`
   in `scripts/capacity_calculator.py` are still labeled as engineering
   floors (cross-tie to H14 and L10): if the source-of-truth constants
   are floors, the file must say so loudly in the header.

#### Verify

```bash
python3 -m pytest tests/integration/test_phase_86i_benchmarks_populated.py -v
```

#### Why deferred

Test-quality work, not a shipped bug; safer to land alongside H14 and
L10 so the test, the constants, and the file header are all updated in
one coherent commit instead of three drive-by passes.

---

### L10 — Real production-hardware `make bench` run

**Severity:** LOW
**Effort:** ~1 day (assumes representative hardware exists and is
available; otherwise blocked indefinitely)

#### Context

Every other 86i item upstream of this one is a workaround for the same
underlying gap: nobody has run `make bench` against production-
representative hardware with a real Redis hop. Phase 86i shipped:

- Microbenchmark numbers in `benchmarks.md` from a single developer
  workstation (i9-9900K, Pop!_OS, `go1.26.2`, no Redis).
- An `EstimatedConstants` → `BenchmarkConstants` rename that
  *re-labelled* the 86h engineering floors instead of replacing them
  with measurements.
- A capacity dashboard whose `BYPASS_CEILING_CPS` and
  `SIGNAL_CEILING_CPS` template variables default to those floors.

Until L10 lands, **the capacity calculator and the capacity dashboard
both anchor on engineering estimates**, which is exactly the outcome
86h's `--require-measured` flag was designed to make impossible. The
Phase 86i merge accepted this gap explicitly (documented in
`docs/phases/PHASE_86i_notes.md` Follow-ups section) on the grounds that
no representative hardware was available during the phase.

#### Fix required

1. Identify a host that is reasonably representative of production
   (non-NUMA single-socket, ≥8 cores, 32 GB+, 10 GbE NIC, real Redis on
   the same VLAN). A staging fleet host is ideal; a beefy workstation
   is acceptable if labelled honestly.
2. Run `make bench` against that host with all four load-test scenarios
   (`bypass-only`, `full-signal`, `attack-wave`, `mixed`) and a real
   Redis backend.
3. Update `docs/performance/benchmarks.md`:
   - Replace the dev-workstation header with the production-style
     hardware description.
   - Replace every microbench-derived "engineering floor" row with the
     measured load-test number.
   - Drop the "not production-representative" disclaimer block.
4. Update `scripts/capacity_calculator.py` `BenchmarkConstants` to the
   measured ceilings. Combine with H14: at this point delete the
   `_ESTIMATED_BANNER` dead code path entirely.
5. Update `monitoring/grafana/dashboards/04_capacity.json` template
   variable defaults `BYPASS_CEILING_CPS` and `SIGNAL_CEILING_CPS` to
   match the new measured ceilings.
6. Run the H14 / M26 tightened tests against the new file and confirm
   they pass for the right reasons.

#### Verify

```bash
make bench
python3 scripts/capacity_calculator.py --require-measured
python3 -m pytest tests/integration/test_phase_86i_benchmarks_populated.py -v
grep -i "not production-representative" docs/performance/benchmarks.md
# expect: no result
```

#### Why deferred

Blocked on hardware availability, not on engineering effort. This is
the canonical "wait for the right environment" item; doing it on the
dev workstation again would just produce a second set of dishonest
numbers under a different label.

#### Owner

TBD — needs a fleet host; pair with the platform/capacity team that
owns the new Grafana dashboard audience.

---

## Phase 93 Terraform Provider (deferred items)

Phase 93 delivered a fully functional Terraform provider with 43 passing tests,
4 ADRs, and 6 resource types. The implementation is complete and reviewed — the
only gap is that the provider repo has no GitHub remote.

### H17 — Provider repo not pushed to GitHub

**Severity:** HIGH  
**Status:** DEFERRED  
**Source:** Phase 93 expert review (2026-04-11)

The provider repo at `/home/sean/LLM/terraform-provider-ja4proxy/` is complete
but has no `git remote`. All code, tests, ADRs, and CI workflows are committed
locally but not pushed.

**What's ready:**
- 43 Go tests pass, 0 failures, `go vet` clean
- 8 acceptance tests against ManagementAPIMock pass
- 4 ADRs (093a–093d) documenting all design decisions
- `.github/workflows/test.yml` and `.github/workflows/release.yml` ready
- `.goreleaser.yml` configured for multi-arch release + Registry upload
- Module path: `github.com/anomalyco/terraform-provider-ja4proxy`

**What's needed:**
1. Create GitHub repo at `github.com/anomalyco/terraform-provider-ja4proxy`
   (or `github.com/seanpor/terraform-provider-ja4proxy`)
2. `git remote add origin <url>` and `git push -u origin main`
3. Submit to Terraform Registry (requires HashiCorp partner review, 1–2 weeks)
4. Create `v1.0.0` tag to trigger release workflow

**Owner:** Junior engineer — full handoff instructions in Phase 101 action plan
(`docs/phases/PHASE_93.md` §11 "Remaining Work").

### M27 — Terraform Registry publication is external process

**Severity:** MEDIUM  
**Status:** DEFERRED  
**Source:** Phase 93 expert review

Registry publication requires HashiCorp partner review and cannot be automated
within this project. Track separately once the repo is pushed (H17).

### M28 — `protect_unmanaged_entries` plan-apply race

**Severity:** MEDIUM  
**Status:** DEFERRED (documented limitation)  
**Source:** ADR-093d

Between `ModifyPlan` and `Delete`, state is not re-read. If an external process
modifies the ownership marker between plan and apply, the Delete guard uses stale
state. Inherent to Terraform's plan-apply model.

### M29 — Null `managed_by` causes false-positive protection

**Severity:** MEDIUM  
**Status:** DEFERRED (documented limitation)  
**Source:** ADR-093d

If `managed_by` is null in state, `"" != "terraform"` triggers protection.
Conservative false positive — safe but potentially confusing. Resolved by running
`terraform apply` to refresh state.

### L11 — Dial and Webhook have no protect_unmanaged guard

**Severity:** LOW  
**Status:** DEFERRED  
**Source:** Expert review finding #4

Dial (singleton) and Webhook resources have no ownership tracking field and thus
no `protect_unmanaged` protection. Deferred — requires Management API changes to
add `managed_by` or reason prefix to these endpoints.
