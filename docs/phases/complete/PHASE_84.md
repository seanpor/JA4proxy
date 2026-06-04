# Phase 84: Compliance & Reporting

> **Prerequisites: Phase 79 (Management API + audit trail) AND Phase 83 (`ja4proxy-cli`
> binary framework) must both be COMPLETE before Phase 84 implementation starts.**
> Both are confirmed COMPLETE as of 2026-04-07.
>
> **CLI language:** `ja4proxy-cli` is a **Go binary** (`cmd/ja4proxy-cli/`). All CLI
> additions in this phase are Go (`internal/cli/commands/compliance.go`, `report.go`).
> `src/cli/` is Python and is for **experimentation only** — it is not the production CLI.
>
> Phase 83 delivers the binary scaffold (Cobra, API client, auth, output formatters).
> Phase 84 adds new command files to that binary (`compliance.go`, `report.go`) and new
> Management API routes (`management/api/routes/compliance.py`). Phase 83 does **not**
> contain the compliance/report commands — they are defined and implemented here.
>
> **Client extension required:** the Go `client.Client` in `internal/cli/client/client.go`
> only handles JSON responses. Phase 84 adds `PostBinaryResponse(ctx, path, body)
> ([]byte, contentType string, error)` for downloading ZIP and PDF binary payloads.

---

## 1. Overview

Enterprise security tools must do two things to survive renewal: block threats and
*prove they block threats*. Compliance teams need evidence packs, auditors need
control narratives, CISOs need executive summaries. If the product cannot generate
these artefacts automatically, a human must spend days assembling them manually —
and that human will eventually recommend replacing the tool with one that does it
for them.

This phase delivers:

1. **PCI-DSS evidence pack** — automated artefacts satisfying PCI-DSS v4.0 requirements
2. **SOC 2 control narrative** — pre-written narrative for Type II auditors, with a
   monthly automated evidence collection workflow
3. **GDPR data retention, purging, and export** — compliance with data subject rights
4. **Executive PDF report** — automated monthly/quarterly PDF for CISO and board
5. **Value-of-product metric** — "threats blocked" translated into business language
6. **ISO 27001 annex mapping** — control evidence for A.8 and A.5

---

## 2. Architecture — How the Pieces Fit

All report generation and data export is **server-side** in the Management API
(Python/FastAPI). The CLI is a thin orchestrator: it calls the Management API,
receives binary (PDF) or JSON responses, and saves them to disk. This keeps the Go
binary free of heavy dependencies (PDF libraries, WeasyPrint system libs) and means
the same generation logic is available to both CLI users and any future UI integration.

```
ja4proxy-cli compliance pci-dss-pack
    │
    ├── POST /api/v1/compliance/pci-dss-pack
    │       Management API (Python) queries Redis, assembles data,
    │       generates PDFs with WeasyPrint, zips the pack
    │
    └── CLI receives ZIP response → extracts to local --output dir

ja4proxy-cli report generate
    │
    ├── POST /api/v1/compliance/report
    │       Management API queries Redis monthly aggregates +
    │       live metrics, renders HTML template → WeasyPrint PDF
    │
    └── CLI receives PDF binary → saves to local --output path
```

The analytics node writes monthly aggregate hashes to Redis
(`reporting:monthly:{YYYY-MM}`) as part of its existing aggregation pipeline.
These hashes are the source of truth for trend data in the executive report.

---

## 3. Management API Additions

Phase 84 adds the following endpoints to `management/api/compliance_routes.py`.
All endpoints require at least Auditor role unless noted.

### 3.1 New Compliance Endpoints

| Endpoint | Methods | Role | Description |
|----------|---------|------|-------------|
| `/api/v1/compliance/pci-dss-pack` | POST | Auditor | Generate PCI-DSS evidence pack (ZIP) |
| `/api/v1/compliance/report` | POST | Auditor | Generate executive PDF report |
| `/api/v1/compliance/dsar/{ip}` | GET | Auditor | Export all stored data for an IP (DSAR) |
| `/api/v1/compliance/dsar/{ip}` | DELETE | Admin | Erase personal data for an IP (right to erasure) |
| `/api/v1/compliance/purge-expired` | POST | Admin | Run GDPR retention purge immediately |
| `/api/v1/compliance/signal-categories` | GET | Auditor | Return configured signal→category mapping |

### 3.2 `GET /api/v1/connections` — Additional Query Parameters

Phase 79 defined `GET /api/v1/connections` with `?ip=`, `?ja4=`, `?since=`,
`?limit=`. Phase 84 adds:

| Parameter | Type | Description |
|-----------|------|-------------|
| `?until=` | ISO-8601 datetime | Upper bound for the query window |
| `?action=` | string | Filter by decision: `blocked`, `allowed`, `flagged`, `rate_limited`, `tarpitted` |
| `?page_token=` | string (opaque) | Cursor for the next page of results |

**Pagination contract:**

```json
{
  "events": [...],
  "total_in_window": 1284700,
  "page_size": 1000,
  "next_page_token": "eyJvZmZzZXQiOiAxMDAwfQ==",
  "has_more": true
}
```

- Default `limit` = 1000. Maximum `limit` = 10 000. Requests above 10 000 return 400.
- When `next_page_token` is present, pass it verbatim to the next call to continue.
- When `has_more` is `false`, all results have been returned.
- Compliance commands in the CLI iterate pages automatically until `has_more=false`.

### 3.3 `POST /api/v1/compliance/pci-dss-pack` — Request/Response

**Request body:**

```json
{
  "from": "2026-01-01T00:00:00Z",
  "to": "2026-03-31T23:59:59Z",
  "format": "pdf+jsonl",
  "include": ["all"]
}
```

`format` options: `"pdf+jsonl"` (default), `"pdf"`, `"jsonl"`. The `include` array
accepts `"all"` or any subset of artefact names from §5.2.

**Response:** `application/zip` binary stream, filename
`pci-dss-v4-{from}-{to}.zip`. Each PDF in the ZIP includes a SHA-256 checksum in
its footer: `Generated: {timestamp} | SHA256: {hex}`.

Generation is synchronous. Timeout: 120 seconds. Above that, return 504 with a
message suggesting `--format jsonl` for large date ranges.

### 3.4 `POST /api/v1/compliance/report` — Request/Response

**Request body:**

```json
{
  "period_label": "Q1 2026",
  "from": "2026-01-01T00:00:00Z",
  "to": "2026-03-31T23:59:59Z",
  "format": "pdf",
  "include_shadow_mode": true
}
```

`format` options: `"pdf"` (default), `"html"`. HTML is useful for inspection
without WeasyPrint dependencies.

**Response:** `application/pdf` or `text/html` binary stream.

### 3.5 `GET /api/v1/compliance/dsar/{ip}` — Response

```json
{
  "subject_ip": "198.51.100.4",
  "exported_at": "2026-04-07T14:23:00Z",
  "legal_basis": "GDPR Article 15 — Right of Access",
  "data_categories": {
    "connection_history": [
      {
        "timestamp": "2026-03-15T10:22:11Z",
        "action": "blocked",
        "ja4": "t13d1516h2_8daaf6152771_b186095e22b6",
        "risk_score": 87,
        "signals": ["spamhaus_drop", "datacenter"]
      }
    ],
    "ban_history": [
      {
        "banned_at": "2026-03-15T10:22:12Z",
        "expires_at": "2026-04-15T10:22:12Z",
        "reason": "scanning activity",
        "active": true,
        "erasure_exempt": true,
        "erasure_exempt_reason": "Active security ban — legitimate interest override"
      }
    ],
    "watchlist_entries": [],
    "beaconing_records": [],
    "fingerprint_associations": [
      {
        "ja4": "t13d1516h2_8daaf6152771_b186095e22b6",
        "first_seen": "2026-03-01T08:11:00Z",
        "last_seen": "2026-03-15T10:22:11Z"
      }
    ]
  },
  "retention_periods": {
    "connection_history": "90 days (legitimate interest — security)",
    "ban_history": "365 days after expiry (legitimate interest)",
    "beaconing_records": "24 hours (legitimate interest)",
    "fingerprint_associations": "90 days (legitimate interest)",
    "audit_trail": "7 years (legal obligation — not exportable, not erasable)"
  }
}
```

### 3.6 `DELETE /api/v1/compliance/dsar/{ip}` — Erasure Behaviour

Erases all personal data except:

- **Active security bans** (`ban:{ip}` with TTL > 0) — cannot be erased while
  active. Response includes `skipped_active_ban: true`.
- **Audit log entries** — cannot be erased. The erasure action itself is logged.

On success returns 200 with a summary:

```json
{
  "erased_ip": "198.51.100.4",
  "ticket": "GDPR-2026-0042",
  "erased_keys": [
    "rv:198.51.100.4",
    "beacon:198.51.100.4:t13d1516h2_8daaf6152771_b186095e22b6"
  ],
  "skipped": [
    {
      "key": "ban:198.51.100.4",
      "reason": "active security ban — legitimate interest override",
      "expires_at": "2026-04-15T10:22:12Z"
    }
  ],
  "audit_log_note": "Audit entries for this IP are exempt from erasure (legal obligation). They remain and record this erasure event."
}
```

### 3.7 `POST /api/v1/compliance/purge-expired` — Purge Behaviour

Runs the GDPR retention purge for all data categories. Idempotent. Returns a summary:

```json
{
  "started_at": "2026-04-07T03:00:01Z",
  "completed_at": "2026-04-07T03:00:04Z",
  "purged": {
    "connection_events_deleted": 142000,
    "beaconing_records_cleaned": 8,
    "rv_hashes_deleted": 23,
    "fingerprint_history_trimmed": 0,
    "monthly_aggregates_deleted": 0
  },
  "errors": []
}
```

Writes `gdpr:purge:last_run` → ISO-8601 timestamp to Redis on completion.
Writes `gdpr:purge:last_summary` → JSON of the summary for observability.

---

## 4. CLI Additions to `ja4proxy-cli`

Phase 83 builds the binary framework. Phase 84 adds two new command files to
`internal/cli/commands/`:

### 4.1 File Layout

```
internal/cli/commands/
  compliance.go          # compliance pci-dss-pack, soc2-evidence, dsar, purge-expired
  compliance_test.go
  report.go              # report generate
  report_test.go

internal/compliance/
  classifier.go          # signal → attack category logic
  classifier_test.go
  pagination.go          # cursor-based page iterator for large exports
  pagination_test.go
```

### 4.2 Command Reference

```
ja4proxy-cli compliance pci-dss-pack \
  --from 2026-01-01 \
  --to 2026-03-31 \
  --output ./reports/pci-dss-v4/ \
  --format pdf+jsonl
  → POST /api/v1/compliance/pci-dss-pack
  → extracts received ZIP into --output directory
  → prints checksum of each extracted file on stdout

ja4proxy-cli compliance soc2-evidence \
  --month 2026-03 \
  --output ./evidence/soc2/2026-03/
  → calls POST /api/v1/compliance/pci-dss-pack (same backend, SOC 2 subset)
  → saves JSON artefacts (no PDF) to --output directory
  → exit 0 = success; exit 1 = API error with message on stderr

ja4proxy-cli compliance dsar export \
  --ip 198.51.100.4 \
  --output dsar-export.json
  → GET /api/v1/compliance/dsar/198.51.100.4
  → saves response JSON to --output path (or stdout if --output -)

ja4proxy-cli compliance dsar erase \
  --ip 198.51.100.4 \
  --ticket GDPR-2026-0042 \
  --confirm
  → DELETE /api/v1/compliance/dsar/198.51.100.4
    body: {"ticket": "GDPR-2026-0042"}
  → requires --confirm flag (no interactive prompt in non-TTY mode)
  → prints erasure summary on stdout

ja4proxy-cli compliance purge-expired
  → POST /api/v1/compliance/purge-expired
  → prints purge summary on stdout
  → designed to run from system cron (see §7.5)
  → exit 0 = success; exit 1 = API error; exit 2 = partial errors in summary

ja4proxy-cli report generate \
  --period Q1-2026 \
  --from 2026-01-01 \
  --to 2026-03-31 \
  --format pdf \
  --output ./reports/ja4proxy-Q1-2026.pdf
  → POST /api/v1/compliance/report
  → saves received binary to --output path
  → --period is a free-form label used in the report title (not parsed)
  → --format pdf|html (default: pdf)
```

### 4.3 Output and Error Handling

All compliance commands obey the standard `--output json|table|csv` flag inherited
from Phase 83 for summary/status lines. The downloaded artefact (ZIP, PDF, JSON) is
always written to the `--output` file path regardless of `--output` format.

If the Management API returns 504 (timeout generating PDF for large date ranges),
the CLI prints:

```
Error: report generation timed out (date range may be too large).
Try: --format html (faster) or narrow the date range.
Alternatively, run: ja4proxy-cli report generate --format jsonl to get raw data.
```

---

## 5. PCI-DSS v4.0 Evidence Pack

### 5.1 Relevant Requirements

| Requirement | Control | JA4proxy Evidence |
|-------------|---------|-------------------|
| 1.3.2 | Network access controls restrict inbound/outbound traffic | Connection log showing blocked/allowed decisions |
| 6.4.1 | Public-facing applications protected by automated technical solution | JA4proxy deployment confirmation |
| 6.4.2 | Automated technical solution detects/prevents web-based attacks | Block event log with attack classification |
| 7.2.x | Access control (management UI) | RBAC configuration export + SSO audit log |
| 10.2.1 | Audit logs capture individual user access | Audit trail export (`GET /api/v1/audit`) |
| 10.3.x | Audit log protection | Append-only Redis Stream, no-delete enforced at API layer |
| 12.6.3.1 | Security awareness | N/A |

### 5.2 Evidence Pack Contents

```
reports/pci-dss-v4/
  01_deployment_confirmation.pdf    # JA4proxy nodes, versions, start time
  02_block_event_log.jsonl          # All blocked connections in the period (paginated)
  03_attack_classification.csv      # Blocked events classified by attack category (§6)
  04_rbac_configuration.json        # Role assignments, token metadata, last_used_at
  05_audit_log_export.jsonl         # Full audit trail for the period
  06_availability_metrics.pdf       # Uptime and deep-health history from /api/v1/nodes
  07_access_denied_summary.pdf      # Summary table: N blocked, by category, by week
  08_configuration_change_log.csv   # All config changes with actor, ticket, timestamp
```

### 5.3 Data Sources for Each Artefact

| Artefact | Source |
|----------|--------|
| 01 deployment | `GET /api/v1/nodes` |
| 02 block log | `GET /api/v1/connections?action=blocked&since=&until=` (paginated) |
| 03 classification | Block log events processed through signal classifier (§6) |
| 04 RBAC config | `GET /api/v1/tokens` + role table from config |
| 05 audit log | `GET /api/v1/audit?since=&until=` (paginated) |
| 06 availability | `GET /api/v1/metrics/summary` for the period |
| 07 summary | Aggregated from artefact 03; generated as PDF by WeasyPrint |
| 08 config changes | Filtered from audit log: `action=config_change` |

PDFs (01, 06, 07) include a SHA-256 checksum in the footer:
`Generated: {timestamp} | SHA256: {hex}`.

---

## 6. Attack Classification

JA4proxy produces risk scores and RiskSignals — not named attack categories.
Artefact 03 and the executive report use a configurable signal→category mapping
to translate these into human-readable classification.

### 6.1 Default Classification

The **highest-weight signal** that fired determines the category. Weight is
configurable; defaults are listed below.

| Category | Default trigger signals | Default weight |
|----------|------------------------|----------------|
| `known_malicious_network` | `spamhaus_drop`, `spamhaus_edrop` | 100 |
| `tor_exit_node` | `tor_exit` | 95 |
| `c2_beaconing` | `beaconing_detected` | 90 |
| `credential_stuffing` | `beaconing_detected` + `abuseipdb_score>=80` | 88 |
| `reported_abuse` | `abuseipdb_score>=50` | 70 |
| `malicious_tls_fingerprint` | `ja4_blacklist` | 85 |
| `obsolete_tls` | `tls_version_old` | 60 |
| `automation_tool` | `sni_missing`, `sni_ip_literal`, `ja4_suspicious` | 55 |
| `datacenter_scanner` | `datacenter`, `asn_datacenter` | 50 |
| `geo_blocked` | `country_blacklist` | 40 |
| `high_risk_score` | (fallback — no specific signal matches above) | 0 |

### 6.2 Configuration

```yaml
# config/proxy.yml
reporting:
  signal_categories:
    # phase-84 — maps signal names to category strings and weights.
    # The category with the highest weight among all fired signals wins.
    # Add new categories at the bottom; built-ins can be overridden here.
    spamhaus_drop:        { category: known_malicious_network, weight: 100 }
    spamhaus_edrop:       { category: known_malicious_network, weight: 100 }
    tor_exit:             { category: tor_exit_node,           weight: 95 }
    beaconing_detected:   { category: c2_beaconing,            weight: 90 }
    abuseipdb_score_high: { category: reported_abuse,          weight: 70 }
    ja4_blacklist:        { category: malicious_tls_fingerprint, weight: 85 }
    tls_version_old:      { category: obsolete_tls,            weight: 60 }
    sni_missing:          { category: automation_tool,         weight: 55 }
    sni_ip_literal:       { category: automation_tool,         weight: 55 }
    datacenter:           { category: datacenter_scanner,      weight: 50 }
    asn_datacenter:       { category: datacenter_scanner,      weight: 50 }
    country_blacklist:    { category: geo_blocked,             weight: 40 }
    # fallback: connections with no matching signal → high_risk_score
```

The classifier is implemented in `internal/compliance/classifier.go` (Go) and
mirrored in `management/compliance/classifier.py` (Python, used by the Management
API for PDF generation). Both read from the same config section.

---

## 7. GDPR Compliance

JA4proxy processes IP addresses, which are personal data under GDPR in the EU/UK.

### 7.1 Data Inventory

| Data element | Redis key pattern | Default retention | Legal basis |
|-------------|------------------|-------------------|-------------|
| Source IP + connection event | `ja4proxy:events` (Stream) | 90 days | Legitimate interest (security) |
| IP + JA4 association | Fingerprint history (Stream entries) | 90 days | Legitimate interest |
| IP + timestamp | `beacon:{ip}:{ja4}` (Sorted Set) | 24 hours | Legitimate interest |
| Return visitor record | `rv:{ip}` (Hash) | 90 days | Legitimate interest |
| IP ban record | `ban:{ip}` (String + TTL) | Ban TTL + 365 days metadata | Legitimate interest |
| Admin user email | Audit trail | 7 years | Legal obligation (audit) |
| API token metadata | `mgmt:token:{id}` | Until revoked | Contract |
| Monthly aggregates | `reporting:monthly:{YYYY-MM}` (Hash) | 24 months | Legitimate interest |

### 7.2 Retention Configuration

```yaml
# config/proxy.yml
gdpr:
  # phase-84
  connection_log_retention_days: 90       # ja4proxy:events stream entries
  ban_metadata_retention_days: 365        # metadata kept after ban TTL expires
  analytics_retention_days: 90           # rv:{ip}, beacon:{ip}:{ja4} entries
  audit_trail_retention_days: 2555        # 7 years — do not reduce (legal obligation)
  monthly_aggregate_retention_months: 24  # reporting:monthly:{YYYY-MM} hashes
  purge_schedule_cron: "0 3 * * *"        # when the analytics node runs scheduled purge
  ip_truncation:
    enabled: false                        # off by default — reduces analytics fidelity
    mode: last_octet                      # 198.51.100.4 → 198.51.100.0 in analytics
    # full IP is always retained for: bans, audit_trail (overrides mode above)
    retain_full_ip_for: ["bans", "audit_trail"]
```

### 7.3 Automated Purge Executor

The purge is executed by the analytics node as a scheduled background task, driven
by `gdpr.purge_schedule_cron`. The analytics node reads this config key on startup
and registers the task with its existing `APScheduler` instance.

The scheduled task calls `POST /api/v1/compliance/purge-expired` on localhost
(the Management API co-located in the analytics container, or via the configured
`management_url`). This means the purge is always executed via the same code path
as the manual CLI command — no separate implementation.

**Config for analytics node:**

```yaml
# config/proxy.yml
gdpr:
  purge_schedule_cron: "0 3 * * *"   # Standard cron expression

management_internal_url: "http://127.0.0.1:8090"
  # URL the analytics node uses for internal API calls.
  # Set to the management container's URL if not co-located.
  # The purge call uses a machine token with Admin role stored in:
  #   MANAGEMENT_INTERNAL_TOKEN env var (required if management is remote)
```

**Purge logic for each data category:**

| Data | Purge method |
|------|-------------|
| `ja4proxy:events` Stream | `XTRIM ja4proxy:events MINID {cutoff_ms}` — removes entries older than retention days |
| `beacon:{ip}:{ja4}` | `ZREMRANGEBYSCORE {key} 0 {cutoff_ms}` — already done by beaconing detector; purge confirms |
| `rv:{ip}` | Scan `rv:*` keys; delete if `Hash.first_seen` older than retention days |
| `ban:{ip}` metadata | Keys have natural TTLs; purge removes any `ban:*` keys with expired TTL and no active ban |
| `reporting:monthly:*` | Delete hashes older than `monthly_aggregate_retention_months` |

### 7.4 Data Subject Access Request (DSAR)

```bash
ja4proxy-cli compliance dsar export --ip 198.51.100.4 --output dsar-export.json
```

Returns all stored data for the given IP address across all stores (§3.5).
Output is GDPR Article 15 compliant JSON — machine-readable, with field labels,
purposes, and retention periods.

The `--output -` flag writes to stdout for piping:

```bash
ja4proxy-cli compliance dsar export --ip 198.51.100.4 --output - | jq '.data_categories.ban_history'
```

### 7.5 Right to Erasure

```bash
ja4proxy-cli compliance dsar erase \
  --ip 198.51.100.4 \
  --ticket GDPR-2026-0042 \
  --confirm
```

Requires `--confirm` flag. The `--ticket` flag is mandatory — the ticket reference
is written to the audit log entry for the erasure. Erasure scope follows §3.6.

The erasure is logged to the audit trail:
```
actor=compliance_admin | action=dsar_erasure | ip=198.51.100.4 | ticket=GDPR-2026-0042
```

### 7.6 Scheduled Purge via System Cron (Alternative)

For operators who prefer not to rely on the analytics node scheduler, the purge
can be run via OS cron:

```cron
# /etc/cron.d/ja4proxy-purge
0 3 * * *  ja4proxy-operator  ja4proxy-cli compliance purge-expired \
    --url https://ja4proxy-mgmt.corp.internal \
    >> /var/log/ja4proxy/purge.log 2>&1
```

The CLI exits with:
- `0` — purge completed with no errors
- `1` — API unreachable or authentication failure
- `2` — purge completed but with partial errors (see `errors` array in response)

---

## 8. Executive PDF Report

Automated monthly/quarterly report for CISO and board distribution.

### 8.1 Report Template

The Management API ships a default HTML template at `config/report_template.html`,
embedded in the Python package via standard file inclusion. The template uses
Jinja2 (already a Management API dependency).

**Custom template override:**

```yaml
# config/proxy.yml
reporting:
  report_template_path: ""    # phase-84 — empty = use built-in default
  # To use a custom template: set to absolute path, e.g. /etc/ja4proxy/my-report.html
  # Template variables are documented in docs/compliance/REPORT_TEMPLATE_VARS.md
```

The template supports:
- `--logo` flag on the CLI (`POST /api/v1/compliance/report` body: `logo_base64`)
  to embed a company logo. The Management API accepts a base64-encoded PNG/SVG up
  to 1MB. Logo is embedded as a data URI in the PDF (no external HTTP requests
  during rendering).

### 8.2 Report Contents

```
JA4proxy Security Summary — Q1 2026
────────────────────────────────────
EXECUTIVE SUMMARY
  Total connections processed:    142,400,000
  Threats blocked:                 1,284,700  (0.90% of traffic)
  Legitimate traffic unaffected:  141,115,300  (99.10%)
  False positive incidents:                 3
  Estimated FP rate:                    0.0002%

VALUE DELIVERED
  Blocked connection categories:
    Known malicious network:         487,000
    Automation tools:                412,000
    Reported abuse:                   89,000
    C2 beaconing:                     31,000
    Other high-risk:                 265,700

  Campaigns detected and blocked:        12
  Largest campaign: 847 IPs, 3 ASNs, 4-hour window (blocked automatically)
  Estimated avoided cost:          $642,350  (see §9)

DIAL CONFIGURATION
  Current dial setting:               70/100
  Shadow mode (dial=80, 30-day sim):  0.12% additional blocks, 2 FP candidates
  Recommendation:                     Safe to raise to 80 after reviewing FP candidates

SECURITY POSTURE
  Active bans:                         234
  Watchlist entries:                    47
  JA4 blocklist entries:               189  (+14 from threat intel feeds)
  JA4 allowlist entries:                23
  Bypass toggles enabled:               4/6

AVAILABILITY
  Uptime (all nodes):               99.98%
  Mean latency added by proxy:       0.3ms
  Peak throughput handled:         8,400 conn/s

COMPLIANCE
  Audit trail entries (period):     1,247
  Config changes requiring 4-eyes:     3  (all approved)
  ITSM tickets attached to changes:    3/3  (100%)

TREND (last 12 months)
  [bar chart — blocks per month, FP rate, dial setting progression]
```

### 8.3 Generation Command

```bash
ja4proxy-cli report generate \
  --period Q1-2026 \
  --from 2026-01-01 \
  --to 2026-03-31 \
  --format pdf \
  --logo ./assets/company-logo.png \
  --output ./reports/ja4proxy-Q1-2026.pdf
```

`--format pdf|html`. HTML output skips WeasyPrint and returns the rendered Jinja2
HTML — useful for CI testing and template development without system library deps.

### 8.4 Container Dependencies

WeasyPrint requires system libraries. Add to the **management container Dockerfile**
(not the proxy container — report generation is management API concern):

```dockerfile
# WeasyPrint system dependencies (phase-84)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libfontconfig1 \
    libffi-dev \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*
```

Add to `requirements.txt`:
```
weasyprint>=60.0         # phase-84 — PDF generation for compliance reports
```

Test PDF generation in CI: the management container test suite must include a test
that calls `POST /api/v1/compliance/report` with a short date range and asserts
the response content-type is `application/pdf` and the body length is > 1024 bytes.

### 8.5 Automated Monthly Distribution

```yaml
# deploy/ansible/playbooks/monthly-report.yml
# Variables: report_month (YYYY-MM), smtp_host, smtp_port, report_distribution_list
# Secrets: ja4proxy_api_token (Auditor-scoped), smtp_password
# Set variables in group_vars/all/compliance.yml or pass --extra-vars at runtime.
---
- name: Generate and distribute monthly JA4proxy report
  hosts: management_nodes
  vars:
    report_month: "{{ lookup('pipe', 'date -d \"last month\" +%Y-%m') }}"
  tasks:
    - name: Generate PDF report via ja4proxy-cli
      command: >
        ja4proxy-cli report generate
        --period "{{ report_month }}"
        --from "{{ report_month }}-01"
        --to "{{ (report_month + '-01') | to_datetime | strftime('%Y-%m-%d', offset='-1 day') }}"
        --format pdf
        --output /tmp/ja4proxy-report-{{ report_month }}.pdf
      environment:
        JA4PROXY_URL: "{{ ja4proxy_mgmt_url }}"
        JA4PROXY_TOKEN: "{{ ja4proxy_api_token }}"

    - name: Email report to distribution list
      community.general.mail:
        host: "{{ smtp_host }}"
        port: "{{ smtp_port | default(587) }}"
        username: "{{ smtp_user | default(omit) }}"
        password: "{{ smtp_password | default(omit) }}"
        secure: starttls
        to: "{{ report_distribution_list }}"
        subject: "JA4proxy Security Summary — {{ report_month }}"
        body: "Please find the monthly JA4proxy security summary attached."
        attach:
          - "/tmp/ja4proxy-report-{{ report_month }}.pdf"
      delegate_to: localhost

    - name: Clean up temp file
      file:
        path: "/tmp/ja4proxy-report-{{ report_month }}.pdf"
        state: absent
```

---

## 9. Value-of-Product Metric

### 9.1 Threat Quantification

```
blocked_connections × cost_per_blocked_connection_usd = estimated_avoided_cost
```

Configurable:

```yaml
# config/proxy.yml
reporting:
  value_model:
    # phase-84
    cost_per_blocked_connection_usd: 0.50
    # Conservative estimate based on analyst triage time per incident.
    # Reference: IBM Cost of a Data Breach 2024 — $4.88M average per breach.
    # Adjust this to match your organisation's internal cost model.
    # Set to 0 to omit the cost estimate from reports entirely.
    currency_symbol: "$"
    currency_code: "USD"
```

Reports include a footnote: *"Estimated avoided cost is based on a configurable
cost model (${cost_per_blocked_connection_usd}/connection). This figure is an
operational estimate, not an actuarial calculation."*

### 9.2 Trend Line Data

The 12-month trend chart in the executive report is driven by Redis hashes written
by the **analytics node** at the end of each month:

**Redis key:** `reporting:monthly:{YYYY-MM}` (Hash)

| Field | Type | Description |
|-------|------|-------------|
| `connections_total` | integer | Total connections processed |
| `connections_blocked` | integer | Blocked connections |
| `connections_flagged` | integer | Flagged (not blocked) |
| `fp_incidents` | integer | False positive incidents reported via UI |
| `fp_rate_ppm` | integer | FP rate in parts-per-million |
| `dial_setting` | integer | Dial setting at end of period |
| `bans_total` | integer | Active bans at end of period |
| `campaigns_detected` | integer | Campaigns detected by analytics node |
| `shadow_mode_simulations` | integer | Shadow mode runs in the period |
| `avoided_cost_usd_cents` | integer | Estimated avoided cost in USD cents |

**Written by:** analytics node, triggered by two mechanisms:
1. Scheduled: `0 5 1 * *` (05:00 UTC on 1st of each month — aggregates the previous month)
2. On-demand: `POST /api/v1/compliance/report` triggers a live aggregation if the
   requested month's hash is missing (fallback for reports run before the scheduled write)

**Retention:** hashes older than `gdpr.monthly_aggregate_retention_months` (default 24)
are pruned by the GDPR purge job.

If a hash for a requested month is missing (e.g. analytics node was down), the
report generation falls back to querying the `ja4proxy:events` stream directly.
The report notes which months used fallback data.

---

## 10. SOC 2 Control Narrative

### 10.1 Applicable TSCs

**CC6.6 — Logical and Physical Access Restrictions**

> JA4proxy restricts access to systems at the network layer using TLS fingerprint
> analysis and IP reputation scoring. All inbound connections pass through the proxy.
> Connections with a risk score exceeding the configured dial threshold are blocked
> before reaching application systems. Block decisions are logged with the source IP,
> TLS fingerprint (JA4), risk score, and triggering signals. The dial setting is
> protected by an Operator/Admin role boundary — only Admin-role users may modify it,
> and all changes require a change ticket and are logged in the append-only audit trail.

**CC7.2 — System Operations Monitoring**

> JA4proxy emits structured Elastic Common Schema (ECS) JSON events for all
> connection decisions. These events are forwarded to the organisation's SIEM
> (Splunk/Sentinel/QRadar) via the Vector sidecar. The Management UI provides
> real-time dashboards. An analytics node performs cross-instance correlation and
> emits campaign detection alerts. Five pre-built correlation searches in the Splunk
> TA fire automatically on anomalous patterns (beaconing, burst blocking, country
> anomalies). On-call engineers are paged via the configured alerting channel
> (PagerDuty/xMatters) with runbook links.

**CC8.1 — Change Management**

> All changes to JA4proxy security rules (allowlist, blocklist, bans, dial setting,
> bypass toggles) are logged in an append-only audit trail. The audit trail records
> the actor identity (email or API token ID), source IP, action, before and after
> values, and ITSM change ticket number if provided. No role (including Admin) can
> delete or edit audit entries. The four-eyes approval workflow (Phase 82) enforces
> peer review for high-impact changes (dial increases, CIDR bans, bypass toggle
> changes) in regulated environments.

### 10.2 Evidence Collection for SOC 2 Type II

The auditor requires evidence that controls operated **continuously** over the audit
period (typically 12 months). A scheduled evidence collection job ships in the repo:

```yaml
# .github/workflows/soc2-evidence.yml
name: SOC 2 Evidence Collection
on:
  schedule:
    - cron: "0 2 1 * *"   # First of each month, 02:00 UTC
  workflow_dispatch:
    inputs:
      month:
        description: "Month to collect (YYYY-MM, default: last month)"
        required: false

jobs:
  collect:
    environment: compliance-evidence   # secrets scoped to this GitHub Environment
    runs-on: ubuntu-latest
    steps:
      - name: Install ja4proxy-cli
        run: |
          curl -sSL "${{ vars.JA4PROXY_CLI_DOWNLOAD_URL }}" -o ja4proxy-cli
          chmod +x ja4proxy-cli
          echo "${{ vars.JA4PROXY_CLI_SHA256 }}  ja4proxy-cli" | sha256sum -c

      - name: Collect monthly evidence
        env:
          JA4PROXY_URL: ${{ vars.JA4PROXY_MGMT_URL }}
          JA4PROXY_TOKEN: ${{ secrets.JA4PROXY_COMPLIANCE_TOKEN }}
        run: |
          MONTH="${{ github.event.inputs.month || '$(date -d "last month" +%Y-%m)' }}"
          mkdir -p evidence/soc2/${MONTH}
          ./ja4proxy-cli compliance soc2-evidence \
            --month ${MONTH} \
            --output evidence/soc2/${MONTH}/

      - name: Upload evidence to compliance store
        # Use the native cloud storage CLI — no S3/GCS SDK in ja4proxy-cli.
        # Replace 'aws s3 sync' with 'gsutil rsync' or 'az storage blob sync' as needed.
        run: |
          aws s3 sync evidence/ s3://${{ vars.COMPLIANCE_EVIDENCE_BUCKET }}/ja4proxy/
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_COMPLIANCE_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_COMPLIANCE_SECRET_KEY }}
          AWS_DEFAULT_REGION: ${{ vars.AWS_REGION }}

      - name: Archive evidence locally
        uses: actions/upload-artifact@v4
        with:
          name: soc2-evidence-${{ env.MONTH }}
          path: evidence/soc2/
          retention-days: 400   # > 1 year for annual audit cycle
```

The upload step uses the native cloud CLI (`aws s3 sync`, `gsutil rsync`,
`az storage blob sync`). `ja4proxy-cli` does not include cloud SDK dependencies.

### 10.3 Compliance Token Management

The GitHub Actions evidence collection workflow uses an Auditor-scoped API token:

1. **Scoped to Auditor** (read-only): evidence collection never needs to mutate state
2. **Stored in a dedicated GitHub Environment** (`compliance-evidence`) — not a
   repository-level secret accessible to all workflows
3. **Rotated quarterly** via a companion workflow:

```yaml
# .github/workflows/rotate-compliance-token.yml
name: Rotate Compliance Evidence Token
on:
  schedule:
    - cron: "0 3 1 */3 *"   # Quarterly: 1st of Jan, Apr, Jul, Oct
  workflow_dispatch:

jobs:
  rotate:
    environment: compliance-evidence
    runs-on: ubuntu-latest
    steps:
      - name: Rotate JA4proxy compliance token
        run: |
          NEW_TOKEN=$(curl -sf -X POST \
            -H "Authorization: Bearer ${{ secrets.JA4PROXY_COMPLIANCE_TOKEN }}" \
            "${{ vars.JA4PROXY_MGMT_URL }}/api/v1/tokens/${{ vars.JA4PROXY_COMPLIANCE_TOKEN_ID }}/rotate" \
            | jq -r '.token')
          if [ -z "$NEW_TOKEN" ]; then exit 1; fi
          gh secret set JA4PROXY_COMPLIANCE_TOKEN \
            --body "$NEW_TOKEN" \
            --env compliance-evidence
        env:
          GH_TOKEN: ${{ secrets.GH_PAT_SECRET_WRITE }}
```

4. **Expiry monitoring:** set token expiry to 400 days (longer than the annual
   evidence cycle). A Prometheus alert fires at ≤ 60 days remaining:

```yaml
# deploy/prometheus/alerts/compliance.yml
- alert: ComplianceTokenExpiringSoon
  expr: ja4proxy_api_token_expiry_seconds{name="compliance-evidence"} < 5184000
  for: 1h
  labels:
    severity: warning
  annotations:
    summary: "JA4proxy compliance API token expires in < 60 days"
    description: "Rotate the token or the SOC 2 evidence collection workflow will fail."
    runbook_url: "docs/runbooks/COMPLIANCE_TOKEN_ROTATION.md"
```

### 10.4 Pre-Written Narrative File

```
docs/compliance/soc2-control-narrative.md
```

Formatted for easy import into a SOC 2 readiness assessment tool (Drata, Vanta,
Secureframe). Includes for each TSC:
- Control description
- Implementation evidence location (API endpoint or file path)
- Monitoring procedure
- Responsible role
- Evidence collection frequency

---

## 11. ISO 27001 Annex A Mapping

| Annex A Control | JA4proxy Evidence |
|-----------------|-------------------|
| A.8.6 Capacity management | Capacity metrics + `GET /api/v1/metrics/summary` *(sizing calculator aspirational — requires Phase 86)* |
| A.8.7 Protection against malware | TLS fingerprint-based bot/malware blocking; Spamhaus DROP/EDROP hard block |
| A.8.16 Monitoring activities | ECS logs, SIEM integration (Phase 80), analytics campaign alerts (Phase 12) |
| A.8.20 Network security | DMZ placement, three-tier network isolation (Phases 72/73) |
| A.8.21 Security of network services | mTLS bypass, TLS version enforcement (Phase 3/5) |
| A.8.22 Segregation in networks | DaemonSet topology, network zone separation (Phase 72) |
| A.5.10 Acceptable use | Policy-as-code with audit trail (Phase 82) |
| A.5.33 Protection of records | Append-only audit trail, 7-year retention, no-delete enforced |

Document delivered as `docs/compliance/iso27001-annex-a-mapping.md`.

---

## 12. New Redis Keys

Document these in `docs/REDIS_SCHEMA.md` in the same phase.

| Key pattern | Type | TTL | Owner | Description |
|-------------|------|-----|-------|-------------|
| `reporting:monthly:{YYYY-MM}` | Hash | `monthly_aggregate_retention_months × 30d` | analytics node | Monthly aggregate data for trend reports |
| `gdpr:purge:last_run` | String | none | analytics node / CLI | ISO-8601 timestamp of last successful purge |
| `gdpr:purge:last_summary` | String (JSON) | 48h | analytics node / CLI | JSON summary of the last purge run |
| `compliance:token:expiry:{id}` | String | none | management API | Token expiry timestamp for alerting queries |

---

## 13. File Locations

```
cmd/ja4proxy-cli/
  main.go                          # unchanged from Phase 83 — no wiring needed, Cobra auto-discovers

internal/cli/commands/
  compliance.go                    # phase-84 CLI commands: pci-dss-pack, soc2-evidence, dsar, purge-expired
  compliance_test.go
  report.go                        # phase-84 CLI command: report generate
  report_test.go

internal/compliance/
  classifier.go                    # signal → attack category mapping (reads proxy.yml reporting.signal_categories)
  classifier_test.go
  pagination.go                    # cursor-based page iterator for GET /api/v1/connections
  pagination_test.go

management/
  api/
    compliance_routes.py           # FastAPI router: /api/v1/compliance/*
    compliance_routes_test.py
  compliance/
    __init__.py
    classifier.py                  # Python mirror of classifier.go — used for PDF generation
    pack_builder.py                # assembles PCI-DSS evidence pack ZIP
    report_renderer.py             # Jinja2 + WeasyPrint PDF/HTML renderer
    purge.py                       # GDPR purge logic — called by compliance_routes.py
    tests/
      test_pack_builder.py
      test_report_renderer.py
      test_purge.py

config/
  report_template.html             # default Jinja2/HTML report template (embedded in management container)
  proxy.yml                        # add gdpr:, reporting.signal_categories, reporting.value_model sections

docs/
  compliance/
    soc2-control-narrative.md      # pre-written SOC 2 narrative
    iso27001-annex-a-mapping.md    # ISO 27001 Annex A control mapping
    REPORT_TEMPLATE_VARS.md        # documents all Jinja2 variables available in custom templates
  REDIS_SCHEMA.md                  # add Phase 84 keys

deploy/
  ansible/playbooks/
    monthly-report.yml             # Ansible playbook for monthly PDF distribution

deploy/
  prometheus/alerts/
    compliance.yml                 # compliance token expiry alert rule

.github/workflows/
  soc2-evidence.yml                # monthly SOC 2 evidence collection
  rotate-compliance-token.yml      # quarterly token rotation
```

---

## 14. Testing

### 14.1 Unit Tests

`compliance_test.go` — table-driven, all against `httptest.NewServer()`:
- `pci-dss-pack` happy path: mock API returns ZIP; assert file count in extracted dir
- `pci-dss-pack` 504 timeout: assert error message with format suggestion
- `dsar export` with `--output -`: assert JSON written to stdout
- `dsar erase` without `--confirm`: assert exit 1 with usage message
- `purge-expired` exit codes: 0 on success, 2 on partial errors

`compliance_test.py` (management):
- `GET /api/v1/compliance/dsar/{ip}`: 200 with full data structure
- `DELETE /api/v1/compliance/dsar/{ip}`: 200 with erasure summary; assert audit log entry
- `POST /api/v1/compliance/purge-expired`: 200 with summary; assert `gdpr:purge:last_run` set
- `POST /api/v1/compliance/report` with `format=html`: 200, content-type `text/html`
- `POST /api/v1/compliance/report` with `format=pdf`: 200, content-type `application/pdf`,
  response body length > 1024 bytes (WeasyPrint actually ran)
- `GET /api/v1/connections?action=blocked&until=`: filter returns only blocked events

`test_purge.py`:
- Purge removes Stream entries older than retention window
- Purge does not remove active ban keys
- Purge leaves entries within retention window untouched
- Partial error (one key fails): returns exit code 2, errors array populated

### 14.2 Classifier Tests

`classifier_test.go` and `classifier_test.py` must both test the same cases:
- Single signal match
- Multiple signals: highest-weight category wins
- No signals match: falls back to `high_risk_score`
- Custom config overrides built-in weight
- Signals from beaconing + abuseipdb together → `credential_stuffing`

Both implementations must produce identical output for the same input. Add a
cross-language parity test to `Makefile`:

```makefile
## Phase 84 targets
test-phase-84:
	python -m pytest management/compliance/tests/ management/api/compliance_routes_test.py -v
	go test ./internal/cli/commands/ ./internal/compliance/ -v -run TestPhase84

test-phase-84-classifier-parity:
	# Run Go classifier on test vectors; run Python classifier on same vectors; diff output
	go run ./internal/compliance/cmd/classify_testdata/main.go > /tmp/go-classifications.json
	python management/compliance/classifier.py --testdata > /tmp/py-classifications.json
	diff /tmp/go-classifications.json /tmp/py-classifications.json

test-phase-84-pdf:
	# Requires management container running with WeasyPrint deps
	./tests/phase-84/test_pdf_generation.sh
```

---

## 15. Acceptance Criteria

- [ ] Prerequisites confirmed: Phase 79 COMPLETE, Phase 83 COMPLETE before implementation starts
- [ ] `compliance.go` and `report.go` added to `internal/cli/commands/` (Phase 83 binary extended, not replaced)
- [ ] `management/api/compliance_routes.py` with all 6 endpoints from §3.1
- [ ] `GET /api/v1/connections` updated with `?action=`, `?until=`, `?page_token=` parameters; pagination contract (§3.2) implemented
- [ ] `POST /api/v1/compliance/pci-dss-pack` generates all 8 artefacts from §5.2; PDFs include SHA-256 checksum in footer
- [ ] Attack classifier implemented in both Go and Python; parity test passes (`make test-phase-84-classifier-parity`)
- [ ] `reporting.signal_categories` config section in `config/proxy.yml` with all default mappings from §6.1
- [ ] `POST /api/v1/compliance/report` returns `application/pdf` with length > 1024 bytes (WeasyPrint exercised in CI test)
- [ ] `POST /api/v1/compliance/report?format=html` returns `text/html` (CI-testable without system libs)
- [ ] WeasyPrint system deps added to management container Dockerfile; `weasyprint>=60.0` in `requirements.txt # phase-84`
- [ ] `config/report_template.html` committed; `docs/compliance/REPORT_TEMPLATE_VARS.md` documents all template variables
- [ ] `reporting.report_template_path` config key in `proxy.yml`; custom template override works end-to-end
- [ ] `reporting.value_model.cost_per_blocked_connection_usd` configurable; setting to 0 omits cost estimate from report
- [ ] `reporting:monthly:{YYYY-MM}` written by analytics node at end of each month; all fields from §9.2 present
- [ ] Report trend chart uses monthly aggregates; falls back to live stream query if hash missing; report notes which months used fallback
- [ ] GDPR: `gdpr:` config section in `proxy.yml` with all keys from §7.2
- [ ] GDPR: `POST /api/v1/compliance/purge-expired` purges all data categories per §7.3; writes `gdpr:purge:last_run`
- [ ] GDPR: purge does not delete active ban records
- [ ] GDPR: analytics node scheduled purge registered via `gdpr.purge_schedule_cron` using existing APScheduler
- [ ] GDPR: `GET /api/v1/compliance/dsar/{ip}` returns full data structure from §3.5; Auditor role required
- [ ] GDPR: `DELETE /api/v1/compliance/dsar/{ip}` erases data per §3.6; Admin role required; audit log entry written
- [ ] GDPR: `dsar erase` requires `--ticket` (mandatory) and `--confirm` (mandatory); erasure ticket recorded in audit log
- [ ] GDPR: IP truncation mode available, off by default, does not truncate `bans` or `audit_trail`
- [ ] SOC 2 narrative committed to `docs/compliance/soc2-control-narrative.md`
- [ ] SOC 2 evidence collection workflow committed to `.github/workflows/soc2-evidence.yml`; uses `compliance-evidence` GitHub Environment
- [ ] SOC 2 workflow uploads via native cloud CLI (not ja4proxy-cli); documented for AWS/GCS/Azure variants
- [ ] Token rotation workflow committed to `.github/workflows/rotate-compliance-token.yml`
- [ ] Prometheus alert rule for compliance token expiry ≤ 60 days in `deploy/prometheus/alerts/compliance.yml`
- [ ] ISO 27001 Annex A mapping committed to `docs/compliance/iso27001-annex-a-mapping.md`; A.8.6 noted as aspirational pending Phase 86
- [ ] Monthly distribution playbook committed to `deploy/ansible/playbooks/monthly-report.yml`; variables documented
- [ ] New Redis keys documented in `docs/REDIS_SCHEMA.md` (§12)
- [ ] `make test-phase-84` passes: all unit and integration tests for this phase
- [ ] `CHANGELOG.md` updated with Phase 84 entry
- [ ] `docs/phases/manifest.yaml` updated: `status: COMPLETE`; `make sync` run; all four status files committed atomically
