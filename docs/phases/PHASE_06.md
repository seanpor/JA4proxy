# Phase 6 — ASN & Datacenter Classification

## Goal

Classify the origin ASN of every connection. Consumer browsers almost never connect
directly from datacenter IP ranges — this is one of the strongest single signals for
distinguishing bots from real users. Everything is local: MaxMind database, curated
config files, and a downloaded Tor exit list. Zero external API calls on the hot path.

## 6a. Module: `src/security/asn_classifier.py`

### 6a. MaxMind GeoLite2-ASN Classification

```python
@dataclass
class ASNClassification:
    asn: int           # e.g. 15169
    asn_str: str       # e.g. "AS15169"
    org_name: str      # e.g. "GOOGLE"
    category: str      # residential|mobile|datacenter|vpn|tor|unknown

class ASNClassifier:
    def classify(self, ip: str) -> ASNClassification:
        # Sub-millisecond. In-process only. Never touches Redis or network.
```

**Classification priority order** (first match wins):
1. IP in Tor exit node set → `tor`
2. ASN in `asn_datacenter_list.yml` → `datacenter`
3. ASN in VPN provider list → `vpn`
4. MaxMind org name pattern match → `datacenter` or `mobile`
5. Default → `unknown` (not `residential` — unknown is more honest)

Residential is only classified when the org name positively matches known ISP
residential patterns (`.dsl.`, `.cable.`, `.broadband.`, named ISPs).

### 6b. `config/asn_datacenter_list.yml`

The agent must research and populate this file with at least 80 entries. Seed list:
AWS (16509), Google Cloud (15169), Azure (8075), DigitalOcean (14061), Hetzner (24940),
OVH (16276), Vultr (20473), Linode/Akamai (63949), plus hosting providers including
Frantech/BuyVM (53667), M247 (9009), Serverius (50673), Leaseweb (60781), Choopa (20473),
Psychz (40676), QuadraNet (8100), Sharktech (23473).

Research sources: BGP.tools, ipinfo.io/ASN listings, Spamhaus ASN-DROP list.

```yaml
asns:
  16509: "Amazon AWS"
  15169: "Google Cloud"
  # ... ≥80 entries total
```

### 6c. Tor Exit Node List

Download `https://check.torproject.org/tor-exit-consensus` hourly. Parse IPv4 and
IPv6 exit addresses. Store as in-process `frozenset` for O(1) lookup.

**Leader election** — one instance downloads and writes to `tor:exit:ips` Redis SET.
Others pull from Redis. Consistent with the pattern used for Spamhaus in Phase 8.

**Download failure:** keep last known list in memory. Never clear it on failure.
Increment error counter. Do not release leader lock — let TTL expire for retry.

**IPv6 exits:** the consensus includes IPv6 addresses in `[::1]` bracket notation.
Parse and normalise to canonical form (Phase 0 `ip_address().compressed`).

### 6d. Risk Score Contributions

```python
RISK_SCORES = {
    "tor": 40, "datacenter": 20, "vpn": 10,
    "unknown": 5, "residential": 0, "mobile": 0,
}
```

Output: single `RiskSignal(name="asn_classification", score=N, reason="AS15169 (GOOGLE): datacenter")`

---

## Redis Key Schema

| Key | Type | TTL | Written by | Notes |
|-----|------|-----|------------|-------|
| `tor:exit:ips` | Set of IP strings | 3900s (1h + 5m buffer) | Leader instance | Tor exit node IP addresses; refreshed hourly |
| `leader:tor_exit_download` | String (instance_id) | 3600s (1h) | Leader instance | Leader election lock for Tor consensus download |

Add both to `docs/REDIS_SCHEMA.md`.

---

## Config

```yaml
asn_classifier:
  enabled: true
  tor_exit_list:
    enabled: true
    refresh_interval_seconds: 3600
  risk_contributions:
    tor: 40, datacenter: 20, vpn: 10, unknown: 5, residential: 0, mobile: 0
  pattern_matching:
    enabled: true
```

---

## Chaos Scenarios

| Scenario | Expected behaviour |
|----------|--------------------|
| Tor consensus URL unreachable | Keep last list; log warning; do NOT clear |
| MaxMind DB missing at startup | Fatal error with clear path message |
| All instances restart simultaneously | Leader election — only one downloads |
| Redis unreachable during Tor refresh | Keep in-memory list; skip Redis write |

---

## Acceptance Criteria

### Functional
- [ ] `ASNClassifier.classify(ip) -> ASNClassification` completes sub-millisecond, in-process only
- [ ] Classification priority order enforced: Tor → datacenter list → VPN pattern → residential pattern → unknown
- [ ] IPv4 and IPv6 addresses classified correctly using canonical form from Phase 0
- [ ] `config/asn_datacenter_list.yml` populated with ≥ 80 researched ASN entries before phase completes
- [ ] Tor exit list: downloaded on startup, refreshed every hour, IPv4 and IPv6 exits parsed
- [ ] Tor list leader election: one instance downloads and writes to Redis; others read from Redis
- [ ] Tor list download failure: last known list retained; no crash; error counter incremented
- [ ] Redis unreachable during Tor refresh: in-memory list used; no crash; WARN logged
- [ ] Missing MaxMind database file: FATAL error logged with file path; process exits (not silent)
- [ ] All risk score contributions configurable in `config/proxy.yml`
- [ ] Phase 0 LRU cache (`LocalCache.asn_class`, TTL 1h) used for repeated lookups
- [ ] Output is `RiskSignal` with correct `name` and `score` consumed by Phase 1 scorer

### Configuration
- [ ] `risk_contributions` block in config; all classification scores hot-reloadable
- [ ] `tor_exit_list.refresh_interval_seconds` configurable

### Observability
- [ ] Prometheus counter: `ja4proxy_asn_classification_total{asn_type}` — connections by classification
- [ ] Prometheus gauge:   `ja4proxy_tor_exit_list_entries` — current Tor exit address count
- [ ] Prometheus gauge:   `ja4proxy_tor_list_last_refresh_success_seconds` — Unix timestamp of last successful refresh
- [ ] Prometheus counter: `ja4proxy_tor_list_download_errors_total` — failed Tor consensus download attempts
- [ ] `docs/REDIS_SCHEMA.md` updated with `tor:exit:ips` and `leader:tor_exit_download` keys

- [ ] JSON log: `{"type":"system","level":"INFO","subsystem":"asn","event":"tor_list_refreshed"}` emitted with `entries` and `elapsed_ms` fields
- [ ] JSON log: `{"type":"system","level":"ERROR","subsystem":"asn","event":"tor_list_download_failed"}` emitted with `error` and `entries_retained` fields

### Unit Tests  (`tests/unit/test_asn_classifier.py`)
- [ ] `ASNClassifier.classify()`: known Tor exit IPv4 → category=tor, correct score
- [ ] `ASNClassifier.classify()`: known Tor exit IPv6 → category=tor, correct score
- [ ] `ASNClassifier.classify()`: ASN in datacenter list → category=datacenter, correct score
- [ ] `ASNClassifier.classify()`: ASN matching VPN pattern → category=vpn, correct score
- [ ] `ASNClassifier.classify()`: residential hostname pattern → category=residential, correct score
- [ ] `ASNClassifier.classify()`: unlisted ASN, no pattern match → category=unknown, correct score
- [ ] `ASNClassifier.classify()`: priority order — Tor exit overrides datacenter classification

### Integration Tests  (`tests/integration/test_pipeline.py`)
- [ ] Tor exit IP: correct `RiskSignal(name="asn_tor")` flows through to Phase 1 scorer

### Chaos Tests  (`tests/chaos/test_feed_staleness.py`)
- [ ] Tor consensus URL returns HTTP 503: last known list retained; `ERROR asn event=tor_list_download_failed` logged
- [ ] Redis unreachable during Tor list write: in-memory list used; no crash; WARN logged
- [ ] Leader election race (two instances start simultaneously): single download occurs; no duplicate writes
