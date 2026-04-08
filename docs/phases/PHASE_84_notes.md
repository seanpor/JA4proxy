# Phase 84 — Compliance Reporting & Evidence Pack: Implementation Notes

## Summary

Phase 84 delivers the full PCI-DSS / SOC 2 / GDPR compliance stack:
six Management API routes, a complete Python compliance package, Go
cross-language classifier parity, cursor-based pagination for bulk exports,
and supporting docs, ops files, and CLI commands.

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
