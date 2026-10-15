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

# Panel 1: "Is it hurting real users?"
PANEL_1_TILES: dict[str, Tile] = {
    "panel1_whitelist_ratio": Tile(
        id="panel1_whitelist_ratio",
        title="JA4 Whitelist Share",
        expr="sum(rate(ja4proxy_bypass_total{rule=~\"ja4_whitelist.*\"}[5m])) / sum(rate(ja4proxy_connections_total[5m])) or vector(0)",
        means="Fraction of incoming connections bypassed via JA4 whitelist rules (ja4_whitelist, ja4_whitelist_pattern).",
        when_red="High ratio indicates large volume of traffic bypassing inspection, or unexpected drop in total connections.",
        unit="ratio",
        panel=1,
    ),
    "panel1_bypasses_by_rule": Tile(
        id="panel1_bypasses_by_rule",
        title="Bypasses by Rule",
        expr="sum by (rule) (rate(ja4proxy_bypass_total[5m]))",
        means="Per-second rate of bypass events broken down by rule name.",
        when_red="Spike in bypass rates for unexpected rules or total silence when traffic expected.",
        unit="ops/s",
        panel=1,
        renders_empty_as_no_rows=True,
    ),
    "panel1_tls_ja4_mismatch": Tile(
        id="panel1_tls_ja4_mismatch",
        title="TLS / JA4 Mismatches",
        expr="sum(rate(ja4proxy_ja4_tls_mismatch_total[5m])) or vector(0)",
        means="Rate of connections where observed TLS parameters conflict with the computed JA4 fingerprint.",
        when_red="Investigate fingerprint spoofing, proxy-protocol smuggling, or middlebox TLS tampering.",
        unit="events/s",
        panel=1,
    ),
}

# Panel 2: "What is it deciding?"
PANEL_2_TILES: dict[str, Tile] = {
    "panel2_traffic_by_action": Tile(
        id="panel2_traffic_by_action",
        title="Traffic by Action",
        expr="sum by (action) (rate(ja4proxy_connections_total[5m]))",
        means="Rate of connection decisions broken down by enforcement action (allow, flag, rate_limit, tarpit, block, ban).",
        when_red="Unexpected shift in traffic proportions (e.g. sudden drop in allow or surge in block/ban).",
        unit="conn/s",
        panel=2,
        renders_empty_as_no_rows=True,
    ),
    "panel2_bypasses_by_rule": Tile(
        id="panel2_bypasses_by_rule",
        title="Bypasses by Rule",
        expr="sum by (rule) (rate(ja4proxy_bypass_total[5m]))",
        means="Rate of bypassed connections grouped by rule.",
        when_red="Investigate uncharacteristic bypass rule patterns.",
        unit="ops/s",
        panel=2,
        renders_empty_as_no_rows=True,
    ),
    "panel2_tarpit_concurrent": Tile(
        id="panel2_tarpit_concurrent",
        title="Tarpit Active Sessions",
        expr="sum(ja4proxy_tarpit_concurrent) or vector(0)",
        means="Number of concurrent connection sessions currently held in the proxy tarpit delay loop.",
        when_red="Tarpit capacity approaching max concurrency limits; incoming malicious traffic may overflow to block/drop.",
        unit="sessions",
        panel=2,
    ),
    "panel2_dial_max": Tile(
        id="panel2_dial_max",
        title="Enforcement Dial (Fleet Max)",
        expr="max(ja4proxy_dial_current) or vector(0)",
        means="Highest enforcement dial setting reported across all active proxy instances (up to 60s reporting latency).",
        when_red="Discrepancy with fleet min indicates partial rollout or stale instance config.",
        unit="dial",
        panel=2,
    ),
    "panel2_dial_min": Tile(
        id="panel2_dial_min",
        title="Enforcement Dial (Fleet Min)",
        expr="min(ja4proxy_dial_current) or vector(0)",
        means="Lowest enforcement dial setting reported across all active proxy instances (up to 60s reporting latency).",
        when_red="Instance dial divergence detected; some replicas enforcing at a lower posture.",
        unit="dial",
        panel=2,
    ),
    "panel2_dial_count": Tile(
        id="panel2_dial_count",
        title="Proxy Fleet Reporting Dial",
        expr="count(count by (instance) (ja4proxy_dial_current)) or vector(0)",
        means="Count of distinct proxy instances currently exporting the dial metric.",
        when_red="Replica count dropped below minimum expected fleet size; check proxy pod health.",
        unit="replicas",
        panel=2,
    ),
}

# Panel 3: "Is it alive and keeping up?"
PANEL_3_TILES: dict[str, Tile] = {
    "panel3_active_connections": Tile(
        id="panel3_active_connections",
        title="Active Connections",
        expr="sum(ja4proxy_active_connections) or vector(0)",
        means="Total number of client TCP connections currently open and being serviced by the proxy fleet.",
        when_red="Connection spikes exhausting file descriptor limits or backend capacity.",
        unit="conns",
        panel=3,
    ),
    "panel3_panics_24h": Tile(
        id="panel3_panics_24h",
        title="Proxy Panics (24h)",
        expr='sum(increase({__name__=~"ja4proxy_(handler|health_check)_panics_total"}[24h])) or vector(0)',
        means="Total count of recovered runtime panics across handlers and health checks in the last 24 hours.",
        when_red="Any panics indicate unhandled exceptions or memory safety defects in Go proxy routines.",
        unit="panics",
        panel=3,
    ),
    "panel3_connection_errors": Tile(
        id="panel3_connection_errors",
        title="Connection Errors",
        expr="sum(rate(ja4proxy_connection_errors_total[5m])) or vector(0)",
        means="Rate of unhandled errors prior to policy decisions (client read timeouts, backend dial failures, resets).",
        when_red="Upstream backend failures, network path degradation, or SYN flood attacks.",
        unit="errors/s",
        panel=3,
    ),
    "panel3_redis_health": Tile(
        id="panel3_redis_health",
        title="Redis Proxy Connectivity",
        expr='min(ja4proxy_redis_health{status="ok"}) or vector(0)',
        means="Fleet-wide minimum health state for Redis connectivity (1=healthy, 0=disconnected/error).",
        when_red="Proxy instances cannot communicate with Redis; cache and dynamic policy enforcement degraded.",
        unit="",
        panel=3,
    ),
    "panel3_latency_p99": Tile(
        id="panel3_latency_p99",
        title="Pipeline Latency p99",
        expr="histogram_quantile(0.99, sum by (le) (rate(ja4proxy_pipeline_duration_seconds_bucket[5m]))) or vector(0)",
        means="99th percentile duration spent in the inspection and scoring pipeline.",
        when_red="Pipeline processing latency exceeding operational SLOs (target < 5ms).",
        unit="s",
        panel=3,
    ),
    "panel3_latency_p50_le5ms": Tile(
        id="panel3_latency_p50_le5ms",
        title="Pipeline Latency <= 5ms Share",
        expr="sum(rate(ja4proxy_pipeline_duration_seconds_bucket{le=\"0.005\"}[5m])) / sum(rate(ja4proxy_pipeline_duration_seconds_count[5m])) or vector(0)",
        means="Fraction of connections processed within the <= 5ms target bucket (histogram resolution floor is 5ms).",
        when_red="Significant drop in fast-path processing; complex rules or queue delays slowing inspection.",
        unit="ratio",
        panel=3,
    ),
    "panel3_cert_expiry": Tile(
        id="panel3_cert_expiry",
        title="TLS Cert Expiry Timestamp",
        expr="ja4proxy_tls_cert_expiry_timestamp_seconds",
        means="Epoch timestamp of the proxy listener TLS certificate NotAfter attribute (0 if passthrough/unconfigured).",
        when_red="Certificate nearing expiration (< 14 days) or failed to reload fresh cert.",
        unit="timestamp",
        panel=3,
    ),
}

# Panel 5: "What changed?"
PANEL_5_TILES: dict[str, Tile] = {
    "panel5_config_reloads": Tile(
        id="panel5_config_reloads",
        title="Config Reloads (24h)",
        expr="sum(increase(ja4proxy_config_reloads_total[24h])) or vector(0)",
        means="Number of successful proxy configuration reloads in the last 24 hours.",
        when_red="High reload frequency or unexpected reloads in a stable deployment.",
        unit="reloads",
        panel=5,
    ),
    "panel5_config_reload_failures": Tile(
        id="panel5_config_reload_failures",
        title="Config Reload Failures (24h)",
        expr="sum(increase(ja4proxy_config_reload_failures_total[24h])) or vector(0)",
        means="Count of failed configuration reload attempts (invalid YAML, unreadable cert, invalid rule syntax).",
        when_red="Configuration errors preventing new policy rollouts; investigate reload logs.",
        unit="failures",
        panel=5,
    ),
    "panel5_signal_drift": Tile(
        id="panel5_signal_drift",
        title="Signal Drift Events",
        expr="sum(rate(ja4proxy_signal_drift_total[5m])) or vector(0)",
        means="Rate of detected score divergences across mesh nodes or cluster instances.",
        when_red="Score divergence between nodes indicates state drift, partitioned cache, or out-of-sync feeds.",
        unit="events/s",
        panel=5,
    ),
}

CATALOGUE: dict[str, Tile] = {
    **PANEL_1_TILES,
    **PANEL_2_TILES,
    **PANEL_3_TILES,
    **PANEL_4_TILES,
    **PANEL_5_TILES,
}


def get_tile(tile_id: str) -> Optional[Tile]:
    return CATALOGUE.get(tile_id)

