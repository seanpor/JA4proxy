# Phase 84: Compliance & Reporting

> **Prerequisite: Phase 79 (Management API + audit trail) must be complete.**

---

## 1. Overview

Enterprise security tools must do two things to survive renewal: block threats and
*prove they block threats*. Compliance teams need evidence packs, auditors need
control narratives, CISOs need executive summaries. If the product cannot generate
these artifacts automatically, a human must spend days assembling them manually —
and that human will eventually recommend replacing the tool with one that does it
for them.

This phase delivers:

1. **PCI-DSS evidence pack** — automated artefacts satisfying PCI-DSS v4.0 requirements
2. **SOC 2 control narrative** — pre-written narrative for Type II auditors
3. **GDPR data retention, purging, and export** — compliance with data subject rights
4. **Executive PDF report** — automated monthly/quarterly PDF for CISO and board
5. **Value-of-product metric** — "threats blocked" translated into business language
6. **ISO 27001 annex mapping** — control evidence for A.8 (asset management) and
   A.8.16 (monitoring activities)

---

## 2. PCI-DSS v4.0 Evidence Pack

JA4proxy operates in the Cardholder Data Environment (CDE) network path for any
customer accepting card payments. PCI-DSS v4.0 requires evidence for several
requirements that JA4proxy directly satisfies or contributes to.

### 2.1 Relevant Requirements

| Requirement | Control | JA4proxy Evidence |
|-------------|---------|-------------------|
| 1.3.2 | Network access controls restrict inbound/outbound traffic | Connection log showing blocked/allowed decisions |
| 6.4.1 | Public-facing applications protected by automated technical solution | JA4proxy deployment confirmation |
| 6.4.2 | Automated technical solution detects/prevents web-based attacks | Block event log with attack classification |
| 6.4.3 | All scripts loaded on payment pages managed and authorised | N/A (out of scope for proxy layer) |
| 7.2.x | Access control (management UI) | RBAC configuration export + SSO audit log |
| 10.2.1 | Audit logs capture individual user access | Audit trail export (`GET /api/v1/audit`) |
| 10.3.x | Audit log protection | Append-only Redis Stream evidence |
| 12.6.3.1 | Security awareness training | N/A |

### 2.2 Evidence Pack Contents

```
reports/pci-dss-v4/
  01_deployment_confirmation.pdf    # JA4proxy is deployed on CDE ingress path
  02_block_event_log.jsonl          # All blocked connections in the period
  03_attack_classification.csv      # Blocked events classified by attack type
  04_rbac_configuration.json        # Current role assignments + last login dates
  05_audit_log_export.jsonl         # Full audit trail for the period
  06_availability_metrics.pdf       # Uptime and health check history
  07_access_denied_summary.pdf      # Summary table: N connections blocked, by category
  08_configuration_change_log.csv   # All config changes with actor, ticket, timestamp
```

### 2.3 Automated Generation

```bash
ja4proxy-cli compliance pci-dss-pack \
  --from 2026-01-01 \
  --to 2026-03-31 \
  --output ./reports/pci-dss-v4/ \
  --format pdf+jsonl
```

The command calls:
- `GET /api/v1/connections?action=blocked&since={from}&until={to}&limit=0` (all blocked events)
- `GET /api/v1/audit?since={from}&until={to}`
- `GET /api/v1/tokens` (for active token/role inventory)
- `GET /api/v1/metrics/summary` (uptime and throughput summary)

And assembles the results into the pack. Each PDF is signed with a SHA-256 checksum
embedded in the footer: `Generated: 2026-04-04T14:23Z | SHA256: abc123...`

---

## 3. SOC 2 Control Narrative

SOC 2 auditors require a written control narrative describing how each Trust Services
Criterion (TSC) is met. Ship a pre-written narrative that the customer's compliance
team can adopt with minimal editing.

### 3.1 Applicable TSCs

**CC6.6 — Logical and Physical Access Restrictions**

> JA4proxy restricts access to cardholder systems at the network layer using TLS
> fingerprint analysis and IP reputation scoring. All inbound connections pass through
> the proxy. Connections with a risk score exceeding the configured dial threshold are
> blocked before reaching application systems. Block decisions are logged with the
> source IP, TLS fingerprint (JA4), risk score, and triggering signals. The dial
> setting is protected by an Operator/Admin role boundary — only Admin-role users
> may modify it, and all changes require a change ticket and are logged in the
> append-only audit trail.

**CC7.2 — System Operations Monitoring**

> JA4proxy emits structured Elastic Common Schema (ECS) JSON events for all connection
> decisions. These events are forwarded to the organisation's SIEM (Splunk/Sentinel/QRadar)
> via the Vector sidecar. The Management UI provides real-time dashboards. An analytics
> node performs cross-instance correlation and emits campaign detection alerts. Five
> pre-built correlation searches in the Splunk TA fire automatically on anomalous patterns
> (beaconing, burst blocking, country anomalies). On-call engineers are paged via the
> configured alerting channel (PagerDuty/xMatters) with runbook links.

**CC8.1 — Change Management**

> All changes to JA4proxy security rules (allowlist, blocklist, bans, dial setting,
> bypass toggles) are logged in an append-only audit trail. The audit trail records
> the actor identity (email or API token ID), source IP, action, before and after
> values, and ITSM change ticket number if provided. No role (including Admin) can
> delete or edit audit entries. The four-eyes approval workflow (Phase 82) enforces
> peer review for high-impact changes (dial increases, CIDR bans, bypass toggle
> changes) in regulated environments.

### 3.2 Pre-Written Narrative File

```
docs/compliance/soc2-control-narrative.md
```

Formatted for easy copy-paste into a SOC 2 readiness assessment tool (Drata, Vanta,
Secureframe). Includes:
- Control description
- Implementation evidence location (API endpoint or file path)
- Monitoring procedure
- Responsible role
- Evidence collection frequency

### 3.3 Evidence Collection for SOC 2 Type II

The auditor requires evidence that controls operated **continuously** over the audit
period (typically 12 months). Ship a scheduled evidence collection job:

```yaml
# .github/workflows/soc2-evidence.yml
name: SOC 2 Evidence Collection
on:
  schedule:
    - cron: "0 2 1 * *"   # First of each month, 02:00 UTC

jobs:
  collect:
    runs-on: ubuntu-latest
    steps:
      - name: Collect monthly evidence
        run: |
          ja4proxy-cli compliance soc2-evidence \
            --month $(date -d "last month" +%Y-%m) \
            --output evidence/soc2/$(date -d "last month" +%Y-%m)/ \
            --upload-to s3://company-compliance-evidence/ja4proxy/
```

---

## 4. GDPR Compliance

JA4proxy processes IP addresses, which are personal data under GDPR in the EU/UK.
The following capabilities are required.

### 4.1 Data Inventory

JA4proxy stores the following personal data:

| Data element | Location | Retention | Legal basis |
|-------------|----------|-----------|-------------|
| Source IP address | Connection logs, ban records, watchlist | Configurable, default 90 days | Legitimate interest (security) |
| IP + JA4 association | Fingerprint history | 90 days | Legitimate interest |
| IP + timestamp | Beaconing records | 24 hours | Legitimate interest |
| IP + ASN + country | Analytics events | 90 days | Legitimate interest |
| Admin user email | Audit trail | 7 years | Legal obligation (audit) |
| API token metadata | Token store | Until revoked | Contract |

### 4.2 Retention Configuration

```yaml
# config/proxy.yml
gdpr:
  connection_log_retention_days: 90    # phase-84
  ban_record_retention_days: 365       # After ban expires
  analytics_retention_days: 90
  audit_trail_retention_days: 2555     # 7 years (legal obligation)
  purge_schedule_cron: "0 3 * * *"     # Daily at 03:00 UTC
```

### 4.3 Data Subject Access Request (DSAR)

```bash
ja4proxy-cli compliance dsar export --ip 198.51.100.4 --output dsar-export.json
```

Returns all stored data for the given IP address across all stores:
- Connection history
- Ban history (active and expired)
- Watchlist entries
- Beaconing records
- Fingerprint associations

Output is GDPR Article 15 compliant JSON — machine-readable, with field labels,
purposes, and retention periods.

### 4.4 Right to Erasure

```bash
ja4proxy-cli compliance dsar erase --ip 198.51.100.4 --ticket GDPR-2026-0042 --confirm
```

Erases all personal data for the IP except:
- Active security bans (cannot be erased while active — legitimate interest override)
- Audit log entries (cannot be erased — legal obligation)

The erasure is logged to the audit trail: `actor=gdpr_team, action=dsar_erasure, ip=198.51.100.4, ticket=GDPR-2026-0042`.

### 4.5 Privacy-Preserving Analytics

For organisations that cannot retain full IPs beyond 30 days, enable IP truncation:

```yaml
gdpr:
  ip_truncation:
    enabled: false       # off by default (reduces analytics fidelity)
    mode: last_octet     # 198.51.100.4 → 198.51.100.0 in analytics
    retain_full_ip_for: ["bans", "audit_trail"]   # never truncate these
```

---

## 5. Executive PDF Report

Automated monthly/quarterly report for CISO and board distribution. This is the
artifact that justifies the product's continued budget allocation.

### 5.1 Report Contents

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
    Known scanners (Spamhaus DROP):   487,000
    Automation tools (fingerprint):   412,000
    Credential stuffing attempts:      89,000
    C2 beaconing:                      31,000
    Other high-risk:                  265,700

  Campaigns detected and blocked:        12
  Largest campaign: 847 IPs, 3 ASNs, 4-hour window (blocked automatically)

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
```

### 5.2 Generation

```bash
ja4proxy-cli report generate \
  --period Q1-2026 \
  --from 2026-01-01 \
  --to 2026-03-31 \
  --format pdf \
  --logo ./assets/company-logo.png \
  --output ./reports/ja4proxy-Q1-2026.pdf
```

PDF generation uses `WeasyPrint` (Python, no external process dependencies) with a
clean corporate template. The template is configurable at `config/report_template.html`.

### 5.3 Automated Monthly Distribution

```yaml
# deploy/ansible/playbooks/monthly-report.yml
- name: Generate and distribute monthly JA4proxy report
  hosts: analytics_nodes
  tasks:
    - name: Generate PDF report
      command: >
        ja4proxy-cli report generate
        --period "{{ report_month }}"
        --format pdf
        --output /tmp/ja4proxy-report-{{ report_month }}.pdf

    - name: Email report to distribution list
      mail:
        host: "{{ smtp_host }}"
        to: "{{ report_distribution_list }}"
        subject: "JA4proxy Security Summary — {{ report_month }}"
        attach: "/tmp/ja4proxy-report-{{ report_month }}.pdf"
      delegate_to: localhost
```

---

## 6. Value-of-Product Metric

The most important number in the executive report is "what would have happened without
this product?" This is the metric that wins budget renewals.

### 6.1 Threat Quantification

```
blocked_connections × estimated_cost_per_incident = avoided_cost
```

The `estimated_cost_per_incident` is configurable:
```yaml
reporting:
  value_model:
    cost_per_blocked_connection_usd: 0.50  # Conservative estimate
    # Based on: analyst time to investigate + potential breach cost amortised
    # Industry reference: IBM Cost of a Data Breach 2024 — $4.88M average
```

This produces: "Last quarter, JA4proxy blocked 1.28M threats, avoiding an estimated
$640,000 in incident response costs."

### 6.2 Trend Line

The report includes a 12-month trend showing:
- Blocks per month (absolute)
- FP rate (should trend toward zero as allowlist matures)
- Dial setting changes (should trend toward higher values as confidence grows)
- Shadow mode simulations run (shows active engagement with the tool)

This trend line is the CISO's evidence that the product is increasing in effectiveness
over time — not static or decaying.

---

## 7. ISO 27001 Annex A Mapping

For customers pursuing ISO 27001 certification, provide a mapping from JA4proxy
controls to Annex A controls in the 2022 edition:

| Annex A Control | JA4proxy Evidence |
|-----------------|-------------------|
| A.8.6 Capacity management | Capacity metrics + sizing calculator (Phase 86) |
| A.8.7 Protection against malware | TLS fingerprint-based bot/malware blocking |
| A.8.16 Monitoring activities | ECS logs, SIEM integration, analytics alerts |
| A.8.20 Networks security | DMZ placement, network isolation (Phase 72/73) |
| A.8.21 Security of network services | mTLS bypass, TLS version enforcement |
| A.8.22 Segregation in networks | DaemonSet topology, network zone separation |
| A.5.10 Acceptable use | Policy-as-code with audit trail (Phase 82) |
| A.5.33 Protection of records | Append-only audit trail, 7-year retention |

Document delivered as `docs/compliance/iso27001-annex-a-mapping.md`.

---

## 8. Acceptance Criteria

- [ ] `ja4proxy-cli compliance pci-dss-pack` generates all 8 artefacts in §2.2
- [ ] PCI-DSS pack PDFs include SHA-256 checksum in footer
- [ ] SOC 2 narrative file committed to `docs/compliance/soc2-control-narrative.md`
- [ ] SOC 2 evidence collection GitHub Actions workflow ships in repo
- [ ] GDPR: configurable retention with automated purge (cron schedule)
- [ ] GDPR: `dsar export` returns all IP data across all stores
- [ ] GDPR: `dsar erase` removes data, preserves active bans and audit entries
- [ ] GDPR: IP truncation mode available but off by default
- [ ] Executive PDF report generated by `ja4proxy-cli report generate`
- [ ] Report includes: summary stats, value-of-product metric, trend chart, dial guidance
- [ ] Monthly distribution playbook ships in `deploy/ansible/playbooks/`
- [ ] `cost_per_blocked_connection_usd` configurable in `config/proxy.yml`
- [ ] ISO 27001 Annex A mapping document committed to `docs/compliance/`
- [ ] All compliance commands tested with synthetic data in CI
- [ ] `docs/compliance/` directory with all three compliance documents committed
