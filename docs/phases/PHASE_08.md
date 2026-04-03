# Phase 8 — Spamhaus DROP/EDROP & Blocklist Feed Framework

## Goal

Add a hard-block layer for netblocks that are provably operated by professional
spam/abuse/bulletproof hosting infrastructure. Spamhaus DROP (Don't Route Or Peer)
and EDROP (Extended) have near-zero false-positive rates — these netblocks have no
legitimate end-user traffic by design. This makes them safe to block as a scorer bypass
by default — though the secops admin can route them through the scorer instead via `security_policy.spamhaus_bypass.enabled: false`.

This phase also establishes an extensible feed framework so future threat intel feeds
slot in without code changes.

## 8a. Module: `src/security/blocklists.py`

### 8a. CIDR Trie Architecture

All blocklist lookups happen against an in-process `pytricia` trie. Redis stores the
list data for persistence and cross-instance sharing, but **never for lookup** — CIDR
matching is always local.

```python
import pytricia

class BlocklistManager:
    def __init__(self):
        # Separate tries for IPv4 and IPv6
        self._trie_v4 = pytricia.PyTricia(32)
        self._trie_v6 = pytricia.PyTricia(128)

    def is_blocked(self, ip: str) -> tuple[bool, str]:
        """Returns (blocked, list_name). O(log n)."""
        trie = self._trie_v6 if ":" in ip else self._trie_v4
        match = trie.get(ip)
        if match:
            return True, match  # match is the list_name stored as value
        return False, ""

    def load_cidrs(self, cidrs: list[str], list_name: str) -> int:
        """Atomically replace entries for one list. Returns count loaded."""
        # Build new trie entries, then swap atomically
        ...
```

`pytricia` handles both IPv4 (32-bit) and IPv6 (128-bit) with separate trie instances.
Always create both. An IPv6 address queried against an IPv4 trie returns no match
safely — do not rely on this; always route to the correct trie.

### 8b. Download and Parse

**DROP format** (plain text, one CIDR per line):
```
; Spamhaus Don't Route Or Peer List
; Last-Modified: Mon,  1 Jan 2024 00:00:00 GMT
1.10.16.0/20 ; SBL123456
2.57.96.0/22 ; SBL789012
```

Parse: strip lines starting with `;`, split on space, take first field (the CIDR).

**Download with ETag caching:**

```python
async def download_with_etag(url: str, last_etag: str | None) -> tuple[str | None, str | None]:
    """Returns (content, new_etag). Content is None if 304 Not Modified."""
    headers = {}
    if last_etag:
        headers["If-None-Match"] = last_etag
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, timeout=30) as resp:
            if resp.status == 304:
                return None, last_etag
            resp.raise_for_status()
            return await resp.text(), resp.headers.get("ETag")
```

Store ETag in Redis: `blocklist:etag:{list_name}`. On 304 Not Modified, skip parse
and load — no update needed. This reduces unnecessary processing on each refresh.

### 8c. Leader Election and Redis Distribution

Same leader election pattern as Phase 6 (Tor list):

```
leader:blocklist_download:{list_name}  →  instance_id  TTL: refresh_interval_seconds / 2
```

Leader downloads, parses, and writes raw CIDR list to Redis:
```
blocklist:cidrs:{list_name}  →  JSON list of CIDR strings  TTL: refresh_interval_seconds + 1800s
```

Non-leaders pull from Redis on startup and on refresh tick (if Redis key exists, use
it; if not, become leader by trying SET NX).

**Startup sequence:**
1. Try to load from Redis (fast path — avoids download on every restart)
2. If Redis empty or expired: attempt leader election, download if won
3. If election lost: wait up to 30s for Redis to be populated by winner, then load

### 8d. Pipeline Integration

Spamhaus match is a **scorer bypass** (hard-block), not a `RiskSignal`. It appears
in the bypass check list *before* the scorer is called. From `CLAUDE.md`:

```python
ALWAYS_BLOCK = [
    lambda conn: conn.ja4 in blacklist_set,
    lambda conn: conn.country in country_blacklist,
    lambda conn: blocklist_manager.is_blocked(conn.ip)[0],  # ← Phase 8
]
```

Log format on Spamhaus match (bypass enabled, default):
```
BYPASS   | 1.10.16.0     | score=N/A | dial=N/A | bypass=spamhaus_drop | ref=SBL123456
```

Log format when bypass disabled (routes through scorer):
```
BLOCK    | 1.10.16.0     | score=82  | dial=60  | signals=[spamhaus_drop(+80), missing_sni(+15)]
```

When `security_policy.spamhaus_bypass.enabled: false`, Spamhaus matches produce a
`RiskSignal(name="spamhaus_drop", score=80)` instead of a hard block. At dial=60
with a threshold of ~88, score 82 passes. At dial=80, threshold ~84, score 82 blocks.
This allows investigation of Spamhaus-listed traffic without hard-blocking it.

### 8e. Extensible Feed Framework

New feeds require only config, no code changes:

```yaml
blocklists:
  feeds:
    spamhaus_drop:
      enabled: true
      url: "https://www.spamhaus.org/drop/drop.txt"
      format: "spamhaus"          # Parser variant
      action: "block"             # Action when matched. Options: block | tarpit | flag. Default: block.
      refresh_interval_seconds: 43200
      is_bypass: true             # If true: scorer bypass. If false: scored RiskSignal

    spamhaus_edrop:
      enabled: true
      url: "https://www.spamhaus.org/drop/edrop.txt"
      format: "spamhaus"
      action: "block"
      refresh_interval_seconds: 43200
      is_bypass: true

    custom_example:
      enabled: false
      url: ""
      format: "cidr"              # cidr: one CIDR per line, no comments
                                  # ipset: ipset save format
                                  # spamhaus: Spamhaus drop format with SBL refs
      action: "block"
      score: 60                   # Risk score contribution when is_bypass is false. Default: 60.
      refresh_interval_seconds: 3600
      is_bypass: false
```

`is_bypass: false` feeds produce a `RiskSignal` instead of a hard block, allowing
lower-confidence feeds to contribute to the score without triggering false positives.

### 8f. Metrics and Health

```python
# After each successful refresh:
await metrics.set_gauge("ja4proxy_blocklist_entries",
    value=entry_count, labels={"list": list_name})
await metrics.set_gauge("ja4proxy_blocklist_last_refresh_success_seconds_success_seconds",
    value=time.time(), labels={"list": list_name})
```

Add a Grafana panel: "Blocklist Health" showing entries per list and last refresh
time. An old `last_refresh_timestamp` is an early warning that downloads are failing.

---

## Redis Key Schema

| Key | Type | TTL | Written by | Notes |
|-----|------|-----|------------|-------|
| `blocklist:cidrs:{list_name}` | JSON list of CIDR strings | `refresh_interval_seconds` + 1800s | Leader instance | Parsed CIDR list for one feed; distributed to all instances |
| `blocklist:etag:{list_name}` | String (HTTP ETag) | `refresh_interval_seconds` + 1800s | Leader instance | Last ETag for conditional HTTP download |
| `leader:blocklist_download:{list_name}` | String (instance_id) | `refresh_interval_seconds` / 2 | Leader instance | Leader election lock for blocklist download |

Add all to `docs/REDIS_SCHEMA.md`.

---

## Config

```yaml
blocklists:
  feeds:
    - name: spamhaus_drop
      url: "https://www.spamhaus.org/drop/drop.txt"
      format: spamhaus            # Options: spamhaus | cidr | ipset
      is_bypass: true             # Default: true. Hard-block matches, no scoring.
      action: block               # Action when matched. Options: block | tarpit | flag. Default: block.
      refresh_interval_seconds: 43200   # Default: 43200 (12h).

    - name: spamhaus_edrop
      url: "https://www.spamhaus.org/drop/edrop.txt"
      format: spamhaus
      is_bypass: true
      action: block
      refresh_interval_seconds: 43200

    - name: custom_blocklist        # Example of a scored (non-bypass) feed
      url: "https://example.com/threats.txt"
      format: cidr                  # Options: cidr | ipset | spamhaus
      is_bypass: false              # Default: false for custom feeds.
      action: block
      score: 60                     # Risk score contribution when is_bypass is false. Default: 60.
      refresh_interval_seconds: 3600
```

## Chaos Scenarios

| Scenario | Expected behaviour |
|----------|--------------------|
| Download URL returns 404 | Log error, keep last known list, increment counter |
| Download times out (>30s) | Abort, log, keep last known list |
| Spamhaus returns malformed CIDR | Skip malformed line, log warning, load rest |
| Redis unavailable at startup | Download directly (bypass leader election), load into process |
| All instances restart simultaneously | Leader election; only one downloads |
| Feed URL changes or moves | Config update + SIGHUP — no code change needed |
| ETag not supported by server | 304 handling absent — full download every time (correct fallback) |

---

## Acceptance Criteria

### Functional
- [x] `BlocklistManager.is_blocked(ip) -> tuple[bool, str]`: O(log n), in-process only
- [x] Separate `pytricia` tries for IPv4 (32-bit) and IPv6 (128-bit); both loaded correctly
- [x] Spamhaus DROP and EDROP formats parsed: `;` comment lines stripped; SBL refs stripped
- [x] ETag-based conditional download: HTTP 304 Not Modified skips parse and trie reload
- [x] Leader election per feed independently; non-leader loads from Redis on startup
- [x] Startup fast path: trie loaded from Redis if available; direct download only if Redis empty
- [x] Download failure: last known trie retained; `ERROR blocklist event=feed_download_failed` logged
- [x] Spamhaus match with `is_bypass: true`: hard-block bypass (not a `RiskSignal`)
- [x] Custom feed with `is_bypass: false`: `RiskSignal` emitted with configured score
- [x] Bypass enabled: log line includes `bypass=spamhaus_{feed_name}` field
- [x] Bypass disabled: Spamhaus IPs routed through scorer (not bypassed)
- [x] New feed added via config only; no code change required
- [x] All three format parsers operational: `spamhaus`, `cidr`, `ipset`

### Configuration
- [x] `feeds` list in config; each feed has `enabled`, `url`, `format`, `is_bypass`, `score`, `refresh_interval_seconds`
- [x] Feed config hot-reloadable (new URL takes effect on next refresh)

### Observability
- [x] Prometheus gauge:   `ja4proxy_blocklist_entries{feed}` — current loaded CIDR count per feed
- [x] Prometheus gauge:   `ja4proxy_blocklist_last_refresh_success_seconds{feed}` — last successful refresh timestamp
- [x] Prometheus counter: `ja4proxy_blocklist_download_errors_total{feed}` — failed download attempts
- [x] Prometheus counter: `ja4proxy_blocklist_matches_total{feed}` — connections matched per feed
- [ ] Grafana: Blocklist Health panel showing entries and last refresh per feed (Phase 13)
- [x] `docs/REDIS_SCHEMA.md` updated with `blocklist:cidrs:{list_name}`, `blocklist:etag:{list_name}`, `leader:blocklist_download:{list_name}`

- [x] JSON log: `{"type":"system","level":"INFO","subsystem":"blocklist","event":"feed_refreshed"}` emitted with `feed`, `entries`, and `elapsed_ms` after each successful download
- [x] JSON log: `{"type":"system","level":"ERROR","subsystem":"blocklist","event":"feed_download_failed"}` emitted with `feed`, `http_status`, and `entries_retained` on failure

### Unit Tests  (`tests/unit/test_blocklists.py`)
- [x] `BlocklistManager.is_blocked()`: IPv4 address inside loaded CIDR → (True, feed_name)
- [x] `BlocklistManager.is_blocked()`: IPv6 address inside loaded CIDR → (True, feed_name)
- [x] `BlocklistManager.is_blocked()`: address not in any CIDR → (False, "")
- [x] Spamhaus format parser: strips `;` comment lines and SBL reference suffixes correctly
- [x] ETag 304 response: trie not re-parsed; `ja4proxy_blocklist_entries` count unchanged
- [x] Malformed CIDR line: skipped; valid lines loaded; no crash
- [x] `is_bypass: false` feed: match produces `RiskSignal` not bypass

### Integration Tests  (`tests/integration/test_bypass_rules.py`)
- [x] Blocked IP (`is_bypass: true` feed): connection rejected before scorer is called

### Chaos Tests  (`tests/chaos/test_feed_staleness.py`)
- [x] Feed URL returns HTTP 503: last known trie retained; error counter incremented
- [x] Feed download times out after 30s: last known trie retained; timeout counter incremented
- [x] Feed returns invalid CIDR data: valid lines loaded; invalid lines skipped; no crash
- [x] Redis unavailable at startup: direct download attempted; trie loaded from network

### Performance Tests  (`tests/performance/bench_cidr_lookup.py`)
- [x] `BlocklistManager.is_blocked()`: CIDR trie lookup p99 < 10µs for 50k entries
- [x] Full blocklist pipeline (all feeds): p99 < 15µs per connection on hot path
