# Phase 84 — Compliance Reporting & Evidence Pack: Implementation Notes

## Summary

Phase 84 delivers the full PCI-DSS / SOC 2 / GDPR compliance stack:
six Management API routes, a complete Python compliance package, Go
cross-language classifier parity, cursor-based pagination for bulk exports,
and supporting docs, ops files, and CLI commands.

## Second critical review (post-merge)

A second critical review pass found an additional set of bugs beyond those
caught in the first review.  Fixes applied in the `claude/phase-84-review-fixes`
branch:

- **C1** — `dsar_erase` ban-preservation TOCTOU: pipeline GET+TTL so ban
  state is coherent; absent ban no longer produces a ghost skip entry.
- **C2** — Monthly/stream fallback misfired on quiet windows. Fixed:
  fall back to stream only when *every* month is missing, not when
  `total == 0`.
- **C3** — ISO timestamp comparison was lexicographic, silently dropping
  events whose timestamps used a different format (`Z` vs `+00:00` vs
  naive) than the route builders.  Added `_parse_ts` / `_ts_in_window`
  helpers and applied them to every stream/audit filter in both
  `compliance.py` routes and `pack_builder.py`.
- **H2** — Logo validation was theatre: no size cap, silent catch-all
  error handler, hardcoded `image/png` MIME type regardless of content.
  Replaced with `_validate_logo()`: 1.4MB base64 cap, 1MB decoded cap,
  magic-byte sniffing (PNG/JPEG/GIF/SVG), proper MIME type, logged
  rejections.
- **H4** — `/signal-categories` endpoint constructed a bare default
  classifier and lied about configured overrides.  Added module-level
  `_get_classifier()` that loads from `reporting.signal_categories` in
  `config/proxy.yml`, with `_reset_classifier_cache()` for tests.
- **H5** — `int()` on monthly aggregate fields crashed the whole report
  on a stray non-numeric value.  Wrapped per-field with try/except and
  a WARN log so the rest of the window still renders.
- **M3** — Pack builder token inventory was a denylist (`pop hash, pop
  token`).  Replaced with `_TOKEN_SAFE_FIELDS` allowlist so future phases
  adding new token fields cannot silently leak them into evidence.
- **M5** — `ReportData.block_rate_pct` now clamps to `[0, 100]`.
- **M6** — HTML escape in `_render_simple_pdf` titles and artefact row
  content (defence in depth for future dynamic titles).
- **L3** — DSAR erase audit record preserves the full `skipped` list
  instead of just its length, so auditors can prove *which* key was
  skipped and *why*.
- **L4** — Module-level classifier cache in `compliance.py`.

### Nine deferred items → Phase 101

The following review findings were deferred because they need architectural
change or cross-phase coordination: H1 (double-XRANGE on DSAR), H3 (CIDR
watchlist match in DSAR), M1 (Redis XTRIM MINID version check), M2 (rename
`beaconing_records_cleaned` — breaking), M4 (paginate audit log reads),
M7 (DSAR partial-failure reporting), L1 (Jinja2 env cache), L2 (JSONL
newline invariant), L5 (DSAR retention text from config).  See
`docs/phases/PHASE_101.md`.

### New tests

`test_compliance_routes.py` picked up 9 new tests covering the fixes:
- `test_dsar_erase_audit_log_preserves_skipped_detail` (L3)
- `test_dsar_erase_absent_ban_not_skipped` (C1)
- `test_report_ignores_events_with_mismatched_tz_format` (C3)
- `test_report_logo_rejects_oversize` (H2)
- `test_report_logo_rejects_unknown_magic` (H2)
- `test_report_logo_accepts_valid_png` (H2)
- `test_report_logo_accepts_valid_svg` (H2)
- `test_signal_categories_reflects_config_override` (H4)
- `test_report_tolerates_corrupt_monthly_aggregate` (H5)

Test count: 112 Python + 36 Go = **148** (was 139).

---

## Key Decisions

### PDF generation is server-side (Python/WeasyPrint)

WeasyPrint requires libpango, libcairo, and libfontconfig — system libs that
don't belong in the Go CLI binary. The Go CLI downloads the already-rendered
binary response via `PostBinaryResponse()`. The `_render_simple_pdf` helper
falls back to HTML bytes when WeasyPrint is unavailable, so the evidence pack
always works in CI/CD even without WeasyPrint installed.

### Cursor-based pagination for compliance exports

`GET /api/v1/connections` uses a base64 JSON cursor (`{"offset", "since", "until"}`)
so new events added after a page is fetched do not appear in subsequent pages
(position-stable). The Go `PageIterator` mirrors this exactly and is used by
`ja4proxy-cli compliance connections-export`.

### SHA-256 footer on evidence artefacts

The SHA-256 is computed over the canonical JSON of the source data dict (not
the rendered PDF file). This means auditors can independently verify the data
matches the report without running WeasyPrint.

### GDPR monthly retention uses calendar months, not days×30

An initial implementation used `timedelta(days=months*30)` which drifts by up
to 31 days over a 24-month window. Fixed to use proper calendar month
subtraction with end-of-month clamping (`_subtract_months()` in purge.py).

### `categories` property returns a defensive copy

The Python `SignalClassifier.categories` property initially returned a direct
reference to the internal dict. A caller could mutate it and corrupt the
classifier for all subsequent requests. Fixed to return `{k: dict(v) for ...}`.
The test was also corrected — it previously changed the `weight` field to 999
which didn't detect the mutation bug since the category name was unchanged.
The new test mutates the `category` *name* to detect the bug correctly.

### RBAC: analyst can access auditor-protected routes

Four tests were initially written asserting that `analyst` is forbidden from
compliance endpoints. The existing RBAC hierarchy (`auditor:0, analyst:1`)
means analyst has more privilege than auditor. `require_role(Role.auditor)`
allows all roles including analyst. The tests were corrected to expect `!= 403`
and documented with a reference to `test_require_role_auditor_accepts_all_roles`
in test_rbac.py which already verifies this behaviour.

### Primary CLI is Go

Per the project architecture (Go moved to production in Phase 15), all CLI
operations are implemented as Go commands in `internal/cli/commands/compliance.go`
and wired via `cmd/ja4proxy-cli/main.go`. The Python `management/compliance/`
package handles server-side rendering (PDF, ZIP generation) which Python is
the right tool for (WeasyPrint ecosystem).

---

## Cross-Language Parity

18 input→output test vectors in `TestCrossLanguageParity_Vectors` (Go) mirror
the Python classifier tests. Any divergence between the two implementations
would cause parity test failures in both languages.

Makefile target: `make test-phase-84-classifier-parity`

---

## Files Added / Modified

**New Python:**
- `management/compliance/__init__.py`
- `management/compliance/classifier.py`
- `management/compliance/purge.py`
- `management/compliance/pack_builder.py`
- `management/compliance/report_renderer.py`
- `management/api/routes/compliance.py`
- `management/tests/test_compliance_classifier.py`
- `management/tests/test_compliance_purge.py`
- `management/tests/test_compliance_pack.py`
- `management/tests/test_compliance_renderer.py`
- `management/tests/test_compliance_routes.py`
- `management/tests/test_connections_pagination.py`

**New Go:**
- `internal/compliance/classifier.go`
- `internal/compliance/classifier_test.go`
- `internal/compliance/pagination.go`
- `internal/compliance/pagination_test.go`
- `internal/cli/commands/compliance.go`
- `internal/cli/commands/compliance_test.go`

**Modified:**
- `internal/cli/client/client.go` — added `PostBinaryResponse()`
- `cmd/ja4proxy-cli/main.go` — wired `buildComplianceCmd()`, `buildReportCmd()`
- `management/api/routes/connections.py` — `?until=`, `?page_token=`, raised limit to 10,000
- `management/api/main.py` — registered compliance router

**New config/docs/ops:**
- `config/proxy.yml` — `gdpr:` and `reporting:` sections
- `config/report_template.html` — Jinja2 executive report template
- `docs/REDIS_SCHEMA.md` — Phase 84 keys
- `docs/compliance/soc2-control-narrative.md`
- `docs/compliance/iso27001-annex-a-mapping.md`
- `deploy/prometheus/alerts/compliance.yml`
- `deploy/ansible/playbooks/monthly-report.yml`
- `Makefile` — `test-phase-84` targets
- `CHANGELOG.md` — Phase 84 entry

---

## Test Stats

| Suite | Tests | Pass |
|-------|-------|------|
| Go compliance (classifier + pagination) | 27 | 27 |
| Go CLI compliance commands | 9 | 9 |
| Python compliance (all 6 files) | 103 | 103 |
| **Total** | **139** | **139** |
