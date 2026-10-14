"""Declarative catalogue of Prometheus metrics and dashboard panels for the management console.

Phase 821a:
- Strict allowlist of Tile IDs. The console never accepts PromQL from client requests.
- Each tile declares mandatory 'means' and 'when_red' operational context.
- Panel 4: 'Can I trust what it's telling me?' (Reliability, silent degradation, queues, staleness).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Tile:
    id: str
    title: str
    expr: str
    means: str
    when_red: str
    unit: str = ""
    panel: int = 4
    renders_empty_as_no_rows: bool = False


# Panel 4: "Can I trust what it's telling me?"
# All expressions use valid selectors, or vector(0) for absent series resilience,
# and __name__ regex for multi-counter aggregation without binary '+' hazard.
PANEL_4_TILES: dict[str, Tile] = {
    # 1. Silent degradation light — aggregates the 8 load shedding / drop counters
    "panel4_silent_degradation_rate": Tile(
        id="panel4_silent_degradation_rate",
        title="Shed Load / Drops Rate",
        expr=(
            'sum(rate({__name__=~"ja4proxy_(workchan_dropped|stream_event_drops|rdap_queue_dropped|'
            'beaconing_jobs_dropped|dns_enrichment_queue_drops|abuseipdb_queue_dropped|'
            'tap_packets_dropped|audit_jobs_dropped|tarpit_overflow)_total"}[5m])) or vector(0)'
        ),
        means="Rate of silently dropped packets, events, audit jobs, or queue overflows across all internal pipelines.",
        when_red="Investigate queue saturations or downstream consumer bottlenecks; system is shedding work.",
        unit="drops/s",
        panel=4,
    ),

    # 2. Blocklist staleness (max age in seconds)
    "panel4_blocklist_staleness_seconds": Tile(
        id="panel4_blocklist_staleness_seconds",
        title="Blocklist Staleness",
        expr="max(time() - ja4proxy_blocklist_last_refresh_success_seconds)",
        means="Seconds elapsed since the last successful blocklist feed refresh.",
        when_red="Check external feed provider availability, network egress, or feed downloader logs.",
        unit="s",
        panel=4,
    ),

    # 3. Blocklist active feeds count
    "panel4_blocklist_active_feeds": Tile(
        id="panel4_blocklist_active_feeds",
        title="Active Blocklist Feeds",
        expr="count(ja4proxy_blocklist_last_refresh_success_seconds) or vector(0)",
        means="Number of blocklist feeds that have successfully refreshed at least once.",
        when_red="If fewer feeds are reporting than configured (expected 2), at least one feed has never succeeded.",
        unit="feeds",
        panel=4,
    ),

    # 4. Redis health gauge (1 = ok, 0 = stale/error)
    "panel4_redis_health_ok": Tile(
        id="panel4_redis_health_ok",
        title="Redis Proxy Connection Health",
        expr='min(ja4proxy_redis_health{status="ok"}) or vector(0)',
        means="Proxy instance connection status to Redis (1 indicates healthy, 0 indicates failure or disconnected).",
        when_red="Verify Redis service reachability, credentials, and memory limits; proxy may fail open or reject commands.",
        unit="",
        panel=4,
    ),

    # 5. Enrichment Queue Depths
    "panel4_dns_queue_depth": Tile(
        id="panel4_dns_queue_depth",
        title="DNS Queue Depth",
        expr="sum(ja4proxy_dns_enrichment_queue_depth) or vector(0)",
        means="Current depth of pending asynchronous DNS enrichment queries.",
        when_red="DNS resolver is responding slowly or saturated; queue may drop incoming enrichment jobs.",
        unit="queries",
        panel=4,
    ),

    "panel4_abuseipdb_queue_depth": Tile(
        id="panel4_abuseipdb_queue_depth",
        title="AbuseIPDB Queue Depth",
        expr="sum(ja4proxy_abuseipdb_enrichment_queue_depth) or vector(0)",
        means="Current depth of pending AbuseIPDB reputation lookups.",
        when_red="AbuseIPDB API is rate limited, down, or API key quota is exhausted.",
        unit="lookups",
        panel=4,
    ),

    "panel4_rdap_queue_depth": Tile(
        id="panel4_rdap_queue_depth",
        title="RDAP Queue Depth",
        expr="sum(ja4proxy_rdap_enrichment_queue_depth) or vector(0)",
        means="Current depth of pending RDAP ASN/registration lookups.",
        when_red="RDAP bootstrap authorities are slow or rate limiting lookups.",
        unit="lookups",
        panel=4,
    ),

    # 6. AbuseIPDB / DNS error rates
    "panel4_dns_errors_rate": Tile(
        id="panel4_dns_errors_rate",
        title="DNS Enrichment Error Rate",
        expr='sum(rate(ja4proxy_dns_enrichment_total{result="error"}[5m])) or vector(0)',
        means="Rate of DNS enrichment query failures.",
        when_red="DNS server failing to resolve upstream queries or timing out.",
        unit="errors/s",
        panel=4,
    ),

    "panel4_abuseipdb_errors_rate": Tile(
        id="panel4_abuseipdb_errors_rate",
        title="AbuseIPDB Lookup Error Rate",
        expr='sum(rate(ja4proxy_abuseipdb_lookups_total{result="error"}[5m])) or vector(0)',
        means="Rate of failed AbuseIPDB API calls.",
        when_red="Check network egress and API key validity for AbuseIPDB.",
        unit="errors/s",
        panel=4,
    ),

    # 7. Clock drift seconds
    "panel4_clock_drift_seconds": Tile(
        id="panel4_clock_drift_seconds",
        title="NTP Clock Drift",
        expr="abs(ja4proxy_sync_clock_drift_seconds) or vector(0)",
        means="Measured clock drift between proxy host and NTP reference in seconds.",
        when_red="Host clock synchronization is drifting; risk of token and timestamp skew across cluster.",
        unit="s",
        panel=4,
    ),
}

CATALOGUE: dict[str, Tile] = {**PANEL_4_TILES}


def get_tile(tile_id: str) -> Optional[Tile]:
    return CATALOGUE.get(tile_id)
