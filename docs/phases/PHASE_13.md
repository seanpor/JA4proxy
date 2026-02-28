# Phase 13 — Management UI

## Goal
Single web interface for the secops admin. Manages all aspects without editing YAML or
running Redis commands. All actions via Redis + pub/sub (never touches proxy code).

## 13a. Architecture
Backend: FastAPI (Python). Frontend: React + Tailwind CSS.
Auth: API key (`UI_API_KEY` env var; required, no default). Port: 8090.

## 13b. UI Sections

**Live Connection Feed** — SSE from `ja4proxy:events`. Per row: IP, country, ASN type,
JA4 name, risk score bar, action, signals. Click IP → detail view. Click-to-block
with confirmation. Filter by action/country/ASN/JA4.

**Intelligence Dashboard** — analytics data: top attacking subnets (v4 + v6), active
campaigns, slow scan suspects, risk score histogram, action breakdown, 7-day trend.
Dial-aware: shows "at current dial, N% of traffic blocked".

**IP & CIDR Management** — IP bans (add, release, search) + CIDR blocks (add, remove,
source column: manual|rdap_expansion|spamhaus). Release triggers pub/sub invalidation.

**JA4 Fingerprint Management** — blacklist, whitelist, candidate review queue.
Approve candidate → blacklist + pub/sub. Dismiss → remove from queue.
Whitelist remove → immediate pub/sub cross-instance eviction.

**Blocking Dial Control** — prominent dial widget (0–100 slider). Shows "at this
setting, N% of last-hour traffic would be blocked" before applying. Enforces
`max_dial_change_per_hour` increment limit with confirmation. Requires
`blocking_acknowledged: true` to enable.

**Integration Management** — AbuseIPDB (key, quota, test), Spamhaus (counts, refresh),
RDAP (queue depth, registry status, org list editor, expansion audit log), analytics
node (status, stream lag, module toggles).

**Configuration** — live risk scorer threshold sliders (no restart). Feature toggles.
GeoIP country lists. Config change history (last 20 with timestamp + secops admin session IP).

**Health** — proxy instances (count, uptime, conn/s), Redis (memory, evictions, stream
length), analytics node, tarpit connections. Embedded Grafana iframe.

## Redis Key Schema

| Key | Type | TTL | Written by | Notes |
|-----|------|-----|------------|-------|
| `management:audit_log` | List (capped at 1000, LPUSH + LTRIM) | none (no expiry) | Management UI | All secops admin actions; entry: `{ts, event, actor_ip, detail}` |
| `management:policy_audit` | List (capped at 1000, LPUSH + LTRIM) | none (no expiry) | Management UI, config reload | Security policy bypass changes; entry: `{ts, bypass, old_value, new_value, actor_ip}` |

## Config

```yaml
management_ui:
  enabled: true
  port: 8090                    # Default: 8090. Management UI listen port.
  api_key: ""                   # Set via UI_API_KEY environment variable. No default.
  session_timeout_seconds: 3600 # Default: 3600 (1h). Idle session expiry.
  allowed_cidr: "0.0.0.0/0"    # Default: all. Restrict UI access to specific CIDRs.
                                # CAUTION: leave default only in trusted network environments.
  audit_log_max_entries: 1000   # Default: 1000. Entries retained in management:audit_log.
```

Environment variable required before starting the management UI:
```bash
UI_API_KEY=<strong-random-secret>   # Required. No default. Proxy refuses to start without this.
```

## Chaos Scenarios

| Scenario | Expected behaviour |
|----------|--------------------|
| Redis: connection refused when UI action submitted | Action fails with 503; error returned to secops admin; audit log not written for failed action |
| Analytics node down | Management UI shows stale data with last-updated timestamp; no crash |
| `UI_API_KEY` env var not set | Process exits with FATAL before accepting connections |
| SSE client disconnects | Server removes subscriber cleanly; no goroutine/task leak |

## Acceptance Criteria

### Functional
- [ ] FastAPI server on port 8090; `UI_API_KEY` required on all routes; missing or wrong key → 401
- [ ] Live SSE connection feed: each connection appears within 1s; click-to-block triggers pub/sub
- [ ] Click-to-block: confirmation dialog required; action logged to `management:audit_log`
- [ ] IP ban: add, search, release; release triggers pub/sub cross-instance eviction
- [ ] CIDR block: add, remove; source column shows `manual | rdap_expansion | spamhaus`
- [ ] IPv4 and IPv6 entries displayed and managed correctly in all IP/CIDR panels
- [ ] JA4 candidate: approve → add to blacklist + pub/sub; dismiss → remove from queue
- [ ] Dial control: counterfactual shown (% traffic blocked) before applying; increment limit enforced
- [ ] `blocking_acknowledged` guard: dial cannot exceed 0 until guard explicitly enabled
- [ ] AbuseIPDB panel: API key input (masked), quota display, test-connection button
- [ ] Spamhaus panel: entry counts, last refresh timestamp, manual refresh button
- [ ] RDAP panel: queue depth, registry status table, org list editor, expansion audit log viewer
- [ ] Security Policy panel: all bypass conditions shown with current state (enabled/disabled)
- [ ] Security Policy: disable any bypass → confirmation dialog shows effect of disabling
- [ ] Security Policy: policy change written to `management:policy_audit` LIST
- [ ] Startup warnings visible in UI when any high-risk bypass is currently disabled
- [ ] Threshold sliders apply via pub/sub without restart; change history shown (last 20)
- [ ] GeoIP country list editable; changes apply via pub/sub
- [ ] All management actions written to `management:audit_log` (last 1000 entries, no TTL)

### Configuration
- [ ] `management_ui.port`, `session_timeout_seconds`, `allowed_cidr` configurable
- [ ] `UI_API_KEY` loaded from environment variable; startup fails with FATAL if not set
- [ ] All config values in this phase are hot-reloadable; changes apply to the next connection without restart
- [ ] `management_ui.port` requires restart; all other management UI config is hot-reloadable

### Observability
- [ ] Prometheus counter: `ja4proxy_policy_changes_total{bypass}` — bypass state changes
- [ ] Health endpoint `/health` at port 9090 reflects UI backend status

- [ ] JSON log: `{"type":"system","level":"INFO","subsystem":"management_ui","event":"action_taken"}` emitted for every secops admin action with `actor_ip`, `action_type`, and `target`
- [ ] JSON log: `{"type":"system","level":"WARN","subsystem":"policy","event":"bypass_disabled"}` emitted with `bypass` and `effect` when any bypass is disabled via the UI

### Unit Tests  (`tests/unit/test_management_ui.py`)
- [ ] Auth: missing API key → 401; wrong key → 401; correct key → 200
- [ ] Each API router returns correct structure for valid input
- [ ] IP ban release: pub/sub message published to correct channel
- [ ] JA4 whitelist remove: pub/sub cross-instance eviction message published
- [ ] Policy change: `management:policy_audit` entry written with timestamp and session IP

### Integration Tests  (`tests/integration/test_bypass_rules.py`)
- [ ] UI disables bypass → pub/sub propagates → proxy rebuilds bypass list within 100ms
