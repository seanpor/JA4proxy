# Phase 11 — RDAP Enrichment & Block Expansion

## Goal

Pivot from individual bad IPs to their containing netblock and owning organisation.
RDAP (Registration Data Access Protocol — the modern replacement for WHOIS) lets you
discover who owns a netblock, when it was registered, and what organisation controls
it. When a confirmed attacker IP is enriched via RDAP, the proxy can score every other
IP in their netblock higher, flag brand-new netblocks registered within 90 days, and
optionally auto-expand blocks to the whole /24 when confidence is high. This is entirely
an offline enrichment loop — the hot path never awaits RDAP results.

---

## 11a. Module: `src/security/rdap_enrichment.py`

### Class Interface

```python
class RDAPEnricher:
    """
    Async RDAP enrichment module.

    Maintains a background worker pool that enriches IPs with RDAP org/netblock
    data. get_signal() is the only hot-path entry point — it returns immediately
    from cache and never makes a network call.
    """

    def __init__(
        self,
        config: RDAPConfig,
        redis: Redis,
        local_cache: LocalCache,
        session: aiohttp.ClientSession,  # shared, injected at startup
    ) -> None: ...

    async def start(self) -> None:
        """Download/load IANA bootstrap, start background workers. Called once at startup."""

    async def stop(self) -> None:
        """Drain queue and cancel workers. Called on shutdown."""

    def get_signal(self, ip: str, trigger_score: int) -> list[RiskSignal]:
        """
        Hot-path entry point. Returns cached signals (possibly empty). Never blocks.
        Checks LocalCache.rdap_results (in-process LRU) only — no Redis on hot path.
        Enqueues background lookup on cache miss if trigger_score >= min_enqueue_score.
        """

    def on_config_reload(self, new_config: dict) -> None:
        """Apply hot-reloadable config changes. Logs WARN for non-hot-reloadable keys."""

    async def record_browser_subnet(self, ip: str) -> None:
        """
        Called by the proxy hot path for every h2/h1 ALPN connection.
        Sets browser:seen:subnet:{subnet} in Redis with 24h TTL.
        Prevents block expansion for subnets with known browser traffic.
        """
```

**Wiring into `../../src/security/pipeline.py`:**
- `RDAPEnricher.get_signal(ip, trigger_score)` is called **last** in `_collect_signals()`,
  after all other signal collectors have run. This is essential: `trigger_score` is the
  running subtotal from all preceding signals, making the `min_enqueue_score` gate
  meaningful (IPs that already look suspicious get enriched; clean IPs don't).
- `RDAPEnricher.record_browser_subnet(ip)` called fire-and-forget (`asyncio.create_task`)
  at the start of every connection where `alpn in ("h2", "h1")`.
- `start()`/`stop()` called in `ProxyServer.initialize()` / shutdown.
- `on_config_reload()` called by the config loader on SIGHUP / pub/sub config reload.

**In-process cache (`LocalCache.rdap_results`):**
`get_signal()` must be synchronous (no `await`) to keep the hot path non-blocking.
Add `rdap_results` as a new `LRUCache` entry in `LocalCache` (same pattern as
`abuseipdb_scores`, TTL 24h, max 20,000 entries). Background workers write RDAP
results to both Redis and `LocalCache.rdap_results`. `get_signal()` reads only the
in-process LRU — Redis is never touched on the hot path.

**`min_enqueue_score`:** `get_signal()` only enqueues a background RDAP lookup when
`trigger_score >= config.min_enqueue_score` (default 20). Low-score IPs (e.g. plain
unknown browsers) are not worth enriching — only connections that already show some
suspicion are enqueued. This conserves RDAP quota and keeps queue depth manageable.

---

## 11b. Architecture: Offline Enrichment Queue

```
Hot path:  connection arrives → check Redis cache → return signal (or [])
                                                         ↓ cache miss + score ≥ min_enqueue_score
Background: ip added to queue → Bloom filter check → IANA bootstrap → RIR query
                                                         ↓ result
                                              write to Redis → maybe block expansion
```

The queue is an `asyncio.Queue`. Workers consume it. Queue overflow drops silently
(new items simply not enriched — correct behaviour; they'll be picked up next
connection that qualifies).

---

## 11c. Background Worker Lifecycle

```python
async def start(self) -> None:
    self._queue: asyncio.Queue[str] = asyncio.Queue(maxsize=self._config.queue_size)
    await self._load_bootstrap()  # Load from Redis or download via leader election
    self._workers = [
        asyncio.create_task(self._lookup_worker(), name=f"rdap-worker-{i}")
        for i in range(self._config.worker_count)
    ]

async def stop(self) -> None:
    for w in self._workers:
        w.cancel()
    await asyncio.gather(*self._workers, return_exceptions=True)
    remaining = self._queue.qsize()
    if remaining:
        log.warning("rdap", event="shutdown_queue_not_empty", depth=remaining)

async def _lookup_worker(self) -> None:
    while True:
        try:
            ip = await self._queue.get()
            try:
                await self._process_lookup(ip)
            except Exception as exc:
                log.error("rdap", event="worker_unhandled_error", error=str(exc))
                METRICS.rdap_lookup_total.labels(registry="unknown", result="error").inc()
            finally:
                self._queue.task_done()
        except asyncio.CancelledError:
            break  # Graceful shutdown
```

---

## 11d. IANA Bootstrap

RDAP queries must go to the correct Regional Internet Registry. The IANA bootstrap
file maps IP prefixes to RIR RDAP base URLs:

```python
BOOTSTRAP_URL_V4 = "https://data.iana.org/rdap/ipv4.json"
BOOTSTRAP_URL_V6 = "https://data.iana.org/rdap/ipv6.json"

async def get_rdap_base_url(self, ip: str) -> str:
    """Find the correct RIR for this IP using IANA bootstrap."""
    # Walk bootstrap entries, find longest matching prefix
    # Returns e.g. "https://rdap.arin.net/registry/"
```

Use the same leader election pattern as the Tor exit list (Phase 6) and blocklists
(Phase 8): one instance acquires `leader:rdap_bootstrap_download` lock, downloads and
writes to Redis (`rdap:bootstrap:v4`, `rdap:bootstrap:v6`, TTL 24h). All other
instances load from Redis. On startup, try Redis first; download only on miss or expiry.

---

## 11e. Per-Registry Rate Limiting

Each RIR has different rate limits. Implement independent in-process asyncio semaphores
per registry (not Redis-based — rate limits are per-deployment, and with
`delegate_to_analytics: true` all workers run in one process anyway):

```python
class RegistryRateLimiter:
    LIMITS: dict[str, tuple[int, int]] = {
        "rdap.arin.net":    (60, 60),   # 60 requests per 60 seconds
        "rdap.ripe.net":    (60, 60),
        "rdap.apnic.net":   (30, 60),
        "rdap.lacnic.net":  (20, 60),
        "rdap.afrinic.net": (20, 60),
    }

    async def acquire(self, registry_host: str) -> None:
        """Sleeps until a token is available for this registry."""
        limit, window = self.LIMITS.get(registry_host, (10, 60))
        # In-process token bucket via asyncio.Semaphore + scheduled release
```

---

## 11f. RDAP Response Parsing

RDAP returns JSON following RFC 7483. Key fields to extract:

```python
@dataclass
class RDAPResult:
    netblock: str                   # e.g. "185.220.0.0/15"
    org_name: str                   # e.g. "Frantech Solutions"
    org_handle: str                 # e.g. "FRANK-1"
    asn: str | None                 # e.g. "AS53667"
    country: str | None             # e.g. "US"
    registration_date: str | None   # ISO date of netblock registration
    fetched_at: float               # unix timestamp
    is_unknown: bool = False        # True when RDAP returned 404
```

Handle RDAP quirks:
- Some registries return `entities` with `vcardArray` for org data — parse vCard
- ARIN uses `handle` for org identifier; RIPE uses `nic-hdl`
- Registration date may be in `events` array with `eventAction: "registration"`
- Some lookups return 404 (IP not in any database) — store as `is_unknown=True`,
  not an error, not retried
- Some return 301 redirects — follow up to 3 hops; fourth hop raises error and fails open

---

## 11g. Known-Bad Org Detection

`config/known_bad_orgs.yml` must be populated with ≥ 30 entries of known bulletproof
hosting providers, abuse-tolerant VPS providers, and attack infrastructure operators.
Research sources: Spamhaus ASN-DROP list, abuse.ch, public reporting on bulletproof
hosting. Example entries:

```yaml
orgs:
  - handle: "FRANC-1"         # ARIN handle
    name: "Frantech Solutions"
    reason: "Bulletproof hosting provider"
    score: 45
  - handle: "M247-MNT"        # RIPE mntner
    name: "M247 Ltd"
    reason: "Known bulletproof / abuse-tolerant hosting"
    score: 45
  # ... ≥30 entries total
```

Matching logic (first match wins):
1. Exact `org_handle` match (most reliable — registry-stable identifier)
2. Case-insensitive substring match on `org_name` (catches aliases and subsidiaries)

Known-bad org match produces `RiskSignal(name="rdap_known_bad_org", score=config.org_reputation.score)`.

---

## 11h. Block Expansion — Safety Is Paramount

Block expansion automatically adds a /24 (IPv4) or /48 (IPv6) CIDR to the blocklist
when a confirmed bad actor is enriched. It is **off by default** and has four
independent safety guards that must ALL pass:

```python
async def maybe_expand_block(
    self, ip: str, rdap: RDAPResult, trigger_score: int, is_known_bad: bool
) -> bool:
    if not self._config.block_expansion.enabled:
        return False

    # Guard 1: Score threshold
    if trigger_score < self._config.block_expansion.min_trigger_score:  # default 75
        return False

    # Guard 2: Network prefix size — reject if the discovered netblock is
    # broader than the configured max expansion prefix.
    # max_prefix_length_v4=24 means: only expand if the block is /24 or smaller
    # (prefixlen >= 24). A /16 (prefixlen=16 < 24) is too broad — skip.
    net = ip_network(rdap.netblock, strict=False)
    if net.version == 4 and net.prefixlen < self._config.block_expansion.max_prefix_length_v4:
        return False  # Netblock broader than /24 — too risky
    if net.version == 6 and net.prefixlen < self._config.block_expansion.max_prefix_length_v6:
        return False  # Netblock broader than /48 — too risky

    # Guard 3: No browser traffic from this subnet (set by record_browser_subnet())
    subnet = get_analysis_subnet(ip)  # /24 or /48 (Phase 0 utility)
    if await self._redis.exists(f"browser:seen:subnet:{subnet}"):
        return False  # Browser traffic observed here — do NOT expand

    # Guard 4: Confirmed known-bad org required
    if not is_known_bad:
        return False  # High score alone is insufficient for expansion

    # Cross-instance hourly cap (Redis atomic counter)
    if not await self._check_expansion_rate_limit():
        return False

    expansion_cidr = _compute_expansion_cidr(ip, net, self._config)
    await self._apply_expansion(expansion_cidr, rdap, trigger_score)
    await self._log_expansion_audit(ip, expansion_cidr, rdap, trigger_score)
    return True
```

**`expansion_ban_duration`:** When a CIDR is expanded, `_apply_expansion()` does three
things:
1. Writes `ban_cidr:{cidr}` to Redis with TTL = `expansion_ban_duration` seconds (default 3600).
   Note: uses prefix `ban_cidr:` (not `ban:`) to avoid collision with per-IP ban keys
   (`ban:{ip}`) which are processed differently by the existing `ban_release` pub/sub handler.
2. Calls `BlocklistManager.load_cidrs([cidr], list_name="rdap_expansion", ...)` to insert
   the CIDR into the local in-process pytricia trie immediately. This reuses the Phase 8
   `BlocklistManager` API — no new trie needed.
3. Publishes `{"type": "cidr_ban_add", "value": cidr}` to the existing `ja4proxy:invalidate`
   pub/sub channel. All other proxy instances receive this and call their own
   `BlocklistManager.load_cidrs()` to update their tries. `PubSubHandler` must be extended
   with a new `case "cidr_ban_add"` that calls a `blocklist_manager` reference injected
   into the handler.

**Hot-path CIDR ban checking:** The pipeline already checks `BlocklistManager.get_signals(ip)`
(O(log n), in-process pytricia trie) on every connection as part of Phase 8. RDAP-expanded
CIDRs are loaded into the same trie and therefore checked automatically with no pipeline
changes. On startup, proxy SCANs `ban_cidr:*` keys from Redis and loads unexpired ones into
the trie.

**`_compute_expansion_cidr()` logic:**
```python
def _compute_expansion_cidr(ip: str, rdap_net: IPv4Network | IPv6Network, config) -> str:
    """
    Always expand to the configured prefix length, not necessarily the RDAP netblock.
    If RDAP says the org owns 185.220.0.0/15, still only expand to the /24 containing
    the trigger IP (185.220.101.0/24). Guard 2 already verified rdap_net is /24 or
    smaller, so the expansion is always a supernet of rdap_net or equal to it.
    """
    addr = ip_address(ip)
    if addr.version == 4:
        return str(ip_network(f"{ip}/{config.block_expansion.max_prefix_length_v4}", strict=False))
    else:
        return str(ip_network(f"{ip}/{config.block_expansion.max_prefix_length_v6}", strict=False))
```

**Cross-instance hourly expansion cap:**

```python
async def _check_expansion_rate_limit(self) -> bool:
    """
    Redis atomic counter. Prevents runaway automated expansion across all instances.
    Uses a sliding 1-hour window via a Redis key with 3600s TTL.
    """
    from datetime import datetime, timezone
    hour_key = f"rdap:expansions:count:{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H')}"
    count = await self._redis.incr(hour_key)
    if count == 1:
        await self._redis.expire(hour_key, 3600)
    if count > self._config.block_expansion.max_expansions_per_hour:
        await self._redis.decr(hour_key)
        return False
    return True
```

**Audit log:**

```
Redis key: rdap:expansions → LIST (capped at 1000 via LPUSH + LTRIM)  no TTL

Each entry (JSON):
{
    "timestamp", "trigger_ip", "trigger_score", "expansion_cidr",
    "org_name", "org_handle", "netblock", "guards_checked": {...},
    "instance_id"
}
```

---

## 11i. New Netblock Flagging

Netblocks registered within the last 90 days (configurable) are higher risk — attack
infrastructure is often registered shortly before use.

```python
def new_netblock_signal(
    registration_date: str | None,
    max_age_days: int,
    score: int,
) -> RiskSignal | None:
    if not registration_date:
        return None
    from datetime import datetime, timezone
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(registration_date)).days
    if age < max_age_days:
        return RiskSignal(
            name="rdap_new_netblock",
            score=score,
            reason=f"Netblock registered {age} days ago (< {max_age_days} day threshold)",
        )
    return None
```

---

## 11j. Mock Server for Tests

Create `tests/mocks/rdap_mock.py`. The mock must support:
- Returning a configurable `RDAPResult` per IP (or per CIDR prefix)
- Returning HTTP 404 (IP not found)
- Returning HTTP error codes (5xx)
- Simulating network timeout
- Simulating redirects (up to N hops)
- Recording which IPs were requested (for assertion)

Implement as a class with `make_session()` returning an aiohttp-compatible mock
(use `unittest.mock.AsyncMock` / `MagicMock` on the session's `get()` method).

---

## Redis Key Schema

| Key | Type | TTL | Written by | Notes |
|-----|------|-----|------------|-------|
| `rdap:ip:{ip}` | JSON (RDAPResult) | 86400s (24h) | RDAP worker | Full RDAP enrichment result for one IP |
| `rdap:org:{org_handle}` | JSON (org_name, known_bad, reason, score, netblocks[]) | 604800s (7d) | RDAP worker | Org reputation cache |
| `rdap:expansions` | List of JSON audit entries (LPUSH+LTRIM to 1000) | none | RDAP worker | Audit trail of all block expansions |
| `rdap:expansions:count:{YYYY-MM-DDTHH}` | String (integer count) | 3600s | RDAP worker | Per-hour expansion rate limiter; cross-instance |
| `rdap:bootstrap:v4` | JSON IANA bootstrap (IPv4) | 86400s (24h) | RDAP worker (leader) | IP → RDAP registry URL mapping |
| `rdap:bootstrap:v6` | JSON IANA bootstrap (IPv6) | 86400s (24h) | RDAP worker (leader) | IP → RDAP registry URL mapping |
| `browser:seen:subnet:{subnet}` | String ("1") | 86400s (24h) | Proxy hot path | h2/h1 ALPN seen from this subnet today; blocks expansion |
| `bloom:rdap_enriched` | Bloom filter | 86400s (24h) | RDAP worker | Dedup; prevents re-enqueuing already-enriched IPs; fallback: SET+TTL |
| `ban_cidr:{cidr}` | String ("1") | `expansion_ban_duration`s | RDAP worker | CIDR-level ban from block expansion; `ban_cidr:` prefix distinguishes from per-IP `ban:{ip}` keys; checked via pytricia trie loaded at startup and updated via pub/sub |
| `analytics:enrich:rdap` | Set of IPs | none (managed) | Proxy (delegate mode) | RDAP enrichment queue when delegated to analytics node |

Add all to `docs/REDIS_SCHEMA.md`.

---

## Config

```yaml
rdap_enrichment:
  enabled: true
  queue_size: 500                # Max pending IPs; new items dropped silently if full; requires restart to change
  worker_count: 3                # Background worker coroutines; requires restart to change
  min_enqueue_score: 20          # Only enqueue IPs whose current composite score >= this value
  lookup_timeout_seconds: 15     # aiohttp request timeout per RDAP API call
  delegate_to_analytics: false   # Set true when Phase 12 analytics node is deployed

  org_reputation:
    enabled: true
    score: 45                    # Risk contribution for known-bad org match

  new_netblock_flagging:
    enabled: true
    max_age_days: 90             # Netblocks younger than this are flagged
    score: 20                    # Risk contribution for new netblock signal

  block_expansion:
    enabled: false               # Default: false. Read operational guidance before enabling.
    min_trigger_score: 75        # Composite score the trigger IP must have reached
    max_prefix_length_v4: 24     # Only expand if discovered netblock is /24 or smaller
    max_prefix_length_v6: 48     # Only expand if discovered netblock is /48 or smaller
    require_no_browser_traffic: true   # Guard 3: abort if browser seen in subnet
    require_known_bad_org: true        # Guard 4: abort if org not in known_bad_orgs.yml
    expansion_ban_duration: 3600       # TTL (seconds) for ban_cidr:{cidr} key written on expansion
    max_expansions_per_hour: 10        # Cross-instance safety cap; enforced via Redis counter
```

**Hot-reload caveats:** `worker_count` and `queue_size` are **not** hot-reloadable —
they require a restart. If either changes during a hot reload, the proxy logs a WARN
and keeps the running values. All other keys are hot-reloadable.

---

## Chaos Scenarios

| Scenario | Expected behaviour |
|----------|--------------------|
| RIR RDAP API unreachable | Fail open; skip enrichment; error counter incremented |
| RDAP returns 404 (IP unknown) | Store `is_unknown=True`; no signal; no error counter; not retried |
| IANA bootstrap download fails on startup | Use cached bootstrap from Redis; WARN logged; if Redis also empty, startup continues without RDAP (disable self) |
| Queue full | Drop silently; `rdap_queue_dropped_total` incremented; no crash |
| Block expansion guard race | `browser:seen:subnet` check is an atomic Redis GET — no race condition |
| Known-bad org file missing | Fatal error on startup with clear actionable message |
| Registry returns unexpected JSON | Parse error counter incremented; fail open; worker continues |
| `max_expansions_per_hour` reached | Expansion skipped; WARN logged; hourly counter rolled back via DECR |
| Worker unhandled exception | Exception logged; worker continues (does not crash proxy) |

---

## Acceptance Criteria

### Functional
- [x] Async queue with configurable workers; queue overflow drops silently with `rdap_queue_dropped_total` increment
- [x] `min_enqueue_score`: IPs whose current composite score is below threshold are not enqueued for RDAP
- [x] IANA bootstrap downloaded via leader election (same pattern as Phase 6/8); one instance downloads, writes to Redis; others load from Redis
- [x] Bootstrap cached in Redis (`rdap:bootstrap:v4`, `rdap:bootstrap:v6`) with 24h TTL; loaded from Redis on restart (avoids re-download)
- [x] Per-registry rate limiting: independent in-process token buckets per RIR with configured rates
- [x] RDAP 404: stored as `is_unknown=True`; not retried; not counted as error
- [x] RDAP response parsed: vCard format, ARIN/RIPE handle variations, event registration dates
- [x] Up to 3 redirect hops followed; fourth hop raises error and fails open
- [x] Bloom filter dedup (`bloom:rdap_enriched`, 24h TTL) before enqueue; fallback to SET+TTL when RedisBloom unavailable
- [x] Known-bad org detection: exact `org_handle` match OR case-insensitive `org_name` substring match
- [x] `config/known_bad_orgs.yml` populated with ≥ 30 researched bulletproof hosting entries
- [x] New netblock signal: registration age < `max_age_days` → `RiskSignal(name="rdap_new_netblock")`
- [x] New netblock signal: no registration date → no signal (not an error)
- [x] `record_browser_subnet(ip)`: sets `browser:seen:subnet:{subnet}` with 24h TTL on h2/h1 ALPN connections; called fire-and-forget from pipeline
- [x] Block expansion guard 1: trigger IP composite score < `min_trigger_score` → no expansion
- [x] Block expansion guard 2 (IPv4): discovered netblock prefixlen < `max_prefix_length_v4` (i.e. broader than /24) → no expansion
- [x] Block expansion guard 2 (IPv6): discovered netblock prefixlen < `max_prefix_length_v6` (i.e. broader than /48) → no expansion
- [x] Block expansion guard 3: `browser:seen:subnet:{subnet}` key present → no expansion
- [x] Block expansion guard 4: org not confirmed known-bad → no expansion (high score alone insufficient)
- [x] `max_expansions_per_hour` enforced cross-instance via Redis hourly counter; rollback on rejection
- [x] Block expansion audit: JSON entry written to `rdap:expansions` LIST (LPUSH+LTRIM to 1000) on every expansion
- [x] `expansion_ban_duration`: expanded CIDR written as `ban_cidr:{cidr}` (not `ban:{cidr}`) with this TTL; `ban_cidr:` prefix avoids collision with existing per-IP ban handler
- [x] Block expansion propagation: CIDR loaded into local `BlocklistManager` pytricia trie AND `{"type":"cidr_ban_add","value":cidr}` published to `ja4proxy:invalidate` channel; `PubSubHandler` extended with `cidr_ban_add` case that calls `BlocklistManager.load_cidrs()`
- [x] `PubSubHandler` receives injected `BlocklistManager` reference for the new `cidr_ban_add` handler
- [x] On startup, proxy SCANs `ban_cidr:*` keys from Redis and loads unexpired CIDRs into `BlocklistManager` trie
- [x] `LocalCache.rdap_results` LRU added (TTL 24h, max 20,000 entries); background workers write results to it; `get_signal()` reads from it synchronously
- [x] `get_signal()` called last in `_collect_signals()`, after all other signal collectors, so `trigger_score` reflects preceding signals
- [x] `_compute_expansion_cidr()`: always expands to the configured prefix length (/24 IPv4, /48 IPv6) containing the trigger IP — not necessarily the full RDAP netblock
- [x] `delegate_to_analytics: true`: IPs published to `analytics:enrich:rdap` Set; local workers idle
- [x] `config/known_bad_orgs.yml` missing at startup: fatal error with clear message
- [x] Output: `list[RiskSignal]` from `get_signal()`; consumed by Phase 1 scorer

### Configuration
- [x] `block_expansion.enabled: false` by default; must be explicitly set to enable
- [x] All score contributions, `max_age_days`, `min_trigger_score`, rate limits configurable
- [x] `worker_count` and `queue_size` changes during hot reload: WARN logged; old values kept until restart
- [x] All other config values hot-reloadable; changes apply to next connection without restart

### Observability
- [x] Prometheus gauge:   `ja4proxy_rdap_enrichment_queue_depth` — current queue depth
- [x] Prometheus counter: `ja4proxy_rdap_lookup_total{registry,result}` — lookups by registry and result (`ok`, `not_found`, `error`, `timeout`, `redirect_limit`)
- [x] Prometheus counter: `ja4proxy_rdap_block_expansions_total` — automatic block expansions applied
- [x] Prometheus counter: `ja4proxy_rdap_parse_errors_total` — response parse failures
- [x] Prometheus counter: `ja4proxy_rdap_queue_dropped_total` — items dropped due to full queue
- [x] Prometheus gauge:   `ja4proxy_rdap_expansions_this_hour` — current hourly expansion count vs cap
- [x] `docs/REDIS_SCHEMA.md` updated with all nine key patterns
- [x] `CHANGELOG.md` updated with Phase 11 entry

- [x] JSON log: `{"type":"system","level":"INFO","subsystem":"rdap","event":"block_expansion_applied","ip":"...","cidr":"...","org_handle":"..."}` on expansion
- [x] JSON log: `{"type":"system","level":"ERROR","subsystem":"rdap","event":"registry_error","registry":"...","error":"..."}` on RDAP lookup failure

### Unit Tests  (`tests/unit/test_rdap_enrichment.py`)
- [x] Known-bad org: exact `org_handle` match → `RiskSignal(name="rdap_known_bad_org")`
- [x] Known-bad org: `org_name` substring match (case-insensitive) → signal emitted
- [x] Known-bad org: neither handle nor name matches → no signal
- [x] New netblock: age < `max_age_days` → `RiskSignal(name="rdap_new_netblock")`
- [x] New netblock: age ≥ `max_age_days` → no signal
- [x] New netblock: no registration date → no signal
- [x] `min_enqueue_score`: score below threshold → IP not enqueued
- [x] Block expansion guard 1: score below `min_trigger_score` → no expansion
- [x] Block expansion guard 2 (v4): netblock broader than /24 (e.g. /16, prefixlen=16 < 24) → no expansion
- [x] Block expansion guard 2 (v6): netblock broader than /48 → no expansion
- [x] Block expansion guard 2 (v4): netblock exactly /24 (prefixlen=24 ≥ 24) → passes guard
- [x] Block expansion guard 3: `browser:seen:subnet` key present → no expansion
- [x] Block expansion guard 4: org not known-bad → no expansion
- [x] All four guards pass + rate limit not exceeded → expansion occurs; `ban_cidr:{cidr}` written to Redis; audit entry written; `cidr_ban_add` published to `ja4proxy:invalidate`
- [x] `get_signal()`: in-process LRU hit → returns immediately, no Redis call, no enqueue
- [x] `get_signal()`: LRU miss, trigger_score < min_enqueue_score → returns []; not enqueued
- [x] `get_signal()`: LRU miss, trigger_score ≥ min_enqueue_score → returns []; enqueues background lookup
- [x] `PubSubHandler` `cidr_ban_add` message → calls `BlocklistManager.load_cidrs()` with the CIDR
- [x] `_compute_expansion_cidr()`: trigger IP 1.2.3.4 with max_prefix_length_v4=24 → "1.2.3.0/24"
- [x] `_compute_expansion_cidr()`: trigger IP 2001:db8::1 with max_prefix_length_v6=48 → correct /48
- [x] `max_expansions_per_hour` exceeded → expansion skipped; counter rolled back via DECR
- [x] RDAP 404 response → `is_unknown=True`; no error counter increment; not retried
- [x] IANA bootstrap routing: IPv4 address → correct RIR URL selected
- [x] IANA bootstrap routing: IPv6 address → correct RIR URL selected
- [x] Worker `CancelledError` → exits cleanly without re-raising
- [x] Queue full → item dropped; `rdap_queue_dropped_total` incremented

### Adversarial / False Positive Tests  (`tests/adversarial/test_rdap_fp.py`)
- [x] Legitimate ISP org name substring match: test that a common word in a legitimate org's name (e.g. "Solutions") does not match unrelated bad org entries — substring match is against known-bad names only, never against a legit lookup
- [x] Browser IP from bad-org subnet: block expansion guard 3 fires; no expansion even when org is confirmed bad and score is high
- [x] Only one attacker in a /24 shared with legitimate IPs: guard 3 (`browser:seen:subnet`) prevents expansion
- [x] No combination of RDAP signals alone exceeds block threshold (70) at dial=100 — org reputation (45) + new netblock (20) = 65 < 70; verified by scorer

### Integration Tests  (`tests/integration/test_pipeline.py`)
- [x] With `RDAPMock` from `tests/mocks/rdap_mock.py`: enqueue → lookup → signal emitted → consumed by scorer → block expansion audit written to Redis

### Chaos Tests  (`tests/chaos/test_external_api_failure.py`)
- [x] RIR RDAP API unreachable: fail open; `rdap_lookup_total{result="error"}` incremented; queue drains normally
- [x] IANA bootstrap download fails at startup: last known bootstrap used from Redis; WARN logged; no crash
- [x] RDAP response is malformed JSON: `rdap_parse_errors_total` incremented; fail open; worker continues
- [x] Queue overflow: items dropped silently; `rdap_queue_dropped_total` incremented; no crash
