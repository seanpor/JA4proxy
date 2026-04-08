# Phase 101 — Phase 84 Compliance Review Gap Closure

> **Status:** PROPOSED
> **Size:** MEDIUM
> **Dependencies:** Phase 84 (merged)
> **Tracking:** Follow-up to the second critical review of Phase 84 Compliance
> Reporting. Fixes marked `FIXED_IN_REVIEW` in the review report were already
> committed on branch `claude/phase-84-review-fixes`; the items below were
> deferred here because they require architectural change, cross-phase
> coordination, or a design conversation.

## Context

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

## Deferred work — this phase

### H1 — DSAR double XRANGE on the full events stream

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

### H3 — DSAR watchlist export/erase misses CIDR matches

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

### M1 — XTRIM MINID semantics in older Redis

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

### M2 — Rename `beaconing_records_cleaned` metric

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

### M4 — Paginate audit log reads in pack builder

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

### M7 — DSAR export returns success on Redis failure

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

### L1 — Jinja2 Environment cached at module level

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

### L2 — JSONL trailing-newline behaviour documented

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

### L5 — DSAR retention strings hardcoded

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

## Acceptance criteria

Phase 101 is complete when:

- [ ] All items above have PR-level fixes or explicit, documented deferrals
- [ ] No new critical/high findings from a third review pass
- [ ] `make test-phase-84` still passes (Go + Python compliance suites)
- [ ] CHANGELOG.md updated with a Phase 101 entry
- [ ] ADRs written for M4 (audit log Stream migration) and M2 (metric
  rename)

## Out of scope

- Any new compliance framework (stay focused on PCI-DSS / SOC 2 / GDPR)
- Management UI changes (Phase 13/51/52 territory)
- Redis version migrations beyond the check-and-fallback in M1
