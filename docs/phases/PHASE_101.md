# Phase 101 — Cross-Phase Gap Register

> **Status:** PROPOSED
> **Size:** LARGE (rolling register; size grows as sections are added)
> **Dependencies:** every phase that contributes a section (currently 84, 85)
> **Tracking:** A rolling register of deferred gaps from phase reviews. Each
> section below captures one phase's deferred items. Gap IDs are
> letter-prefixed by severity (C/H/M/L) and numbered sequentially across the
> entire register so cross-references stay stable as the register grows.
> **When you add a new section, continue from the highest existing number per
> letter — do not restart at 1.**

## Section index

| Section | Source review | Items |
|---------|---------------|-------|
| [Phase 84 Compliance Review](#phase-84-compliance-review-deferred-items) | 2026-03-?? | C1–C3 (closed), H1/H3 deferred + H2/H4/H5 closed, M1/M2/M4/M7 deferred + M3/M5/M6 closed, L1/L2/L5 deferred + L3/L4 closed |
| [Phase 85 Threat-Intel Hardening](#phase-85-threat-intel-hardening-deferred-items) | 2026-04-09 | C5-partial/C7 closed + C4–C6 deferred, H13 closed + H6–H12 deferred, M8–M14 deferred, L6–L8 deferred |
| [Phase 62 Go Test Parity](#phase-62-go-test-parity-deferred-items) | 2026-04-09 | M15 (golden cross-check), M16 (chaos right-answer-wrong-mechanism), M17 (V2 fuzz target hand-off to Phase 200), L9 (property generator weight semantics) |
| [Phase 64 Deployment Validation](#phase-64-deployment-validation-deferred-items) | 2026-04-10 | M18 (Podman/Quadlet smoke test blocked), M19 (phantom `ja4proxy-cli backup` audit), M20 closed, M21 closed, M22 closed, M23 closed |

When a future phase review surfaces deferred items, append a new section
below and start its severity counters at the next free number across the
whole document. Never recycle IDs.

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
