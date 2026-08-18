# Redis Stream Consumer for Analytics Node
# Phase 12a: Foundation

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional

import redis
import redis.asyncio as aioredis
from jsonschema import ValidationError, validate
from prometheus_client import Counter, Gauge

from .aggregation import AggregationManager, HyperLogLogManager
from .authentication import HMACAuthenticator
from .detection import (
    CampaignDetector,
    DistributedClientDetector,
    JA4FingerprintIntelligence,
    SlowScanDetector,
)
from .ecs_envelope import is_ecs_envelope, verify_envelope_signature
from .ecs_envelope import normalise as normalise_ecs
from .event_schemas import EVENT_SCHEMA
from .output_writer import (
    update_heartbeat,
    write_active_connections,
    write_finding,
)
from .validation import validate_event_comprehensive

# Stream lag: seconds between the most recent event's Redis timestamp and now.
# Exposed on the /metrics endpoint alongside the monitoring.py registry.
_STREAM_LAG = Gauge(
    "ja4proxy_analytics_stream_lag_seconds",
    "Seconds between the latest processed stream event and now",
)

# phase-826. The whole failure this phase exists to fix was invisible because
# the consumer's only signal was a print() into a container log: it rejected
# 7,749 consecutive events while every health check stayed green. Ingest is now
# a first-class metric so "the pipeline is running but discarding everything"
# is a state that can be alerted on rather than discovered by reading logs.
_EVENTS_INGESTED = Counter(
    "ja4proxy_analytics_events_ingested_total",
    "Stream events successfully validated and processed",
)
_EVENTS_REJECTED = Counter(
    "ja4proxy_analytics_events_rejected_total",
    "Stream events discarded before processing",
    ["reason"],
)

# A blocking XREADGROUP must be able to sit on the socket for LONGER than the
# server-side block window, or the client's read deadline fires first and every
# single poll raises TimeoutError.
#
# redis-py 8.x's from_url() defaults socket_timeout to 5s. consume_events()
# blocks for 5000ms. Identical values -> the socket deadline and the block
# window expire together, the client always loses the race, and the consumer
# raised "Timeout reading from redis:6379" on a 1s retry loop forever. It never
# ingested a single event, so no detection ran, no findings were written, and
# the console's Intelligence panel read "No high-confidence findings active"
# permanently. Silent because the consumer caught, printed and retried.
#
# Fix has two halves so it cannot drift back:
#   1. connect() pins an explicit socket timeout, not the library default.
#   2. consume_events() clamps its block to stay inside that budget, so a
#      hot-reloaded stream.timeout_ms can never exceed the socket deadline.
_SOCKET_TIMEOUT_S = 30.0
_BLOCK_MARGIN_S = 5.0
MAX_BLOCK_MS = int((_SOCKET_TIMEOUT_S - _BLOCK_MARGIN_S) * 1000)

# How long a written finding suppresses an identical one (same type + subject).
# Long enough that a persistently-offending fingerprint does not re-post every
# detection cycle, short enough that it reappears if still offending an hour on.
_FINDING_DEDUP_TTL_S = 3600


class StreamConsumer:
    """Redis Stream consumer for analytics events."""

    def __init__(
        self,
        redis_url: str,
        stream_key: str = "events:connection",
        consumer_group: str = "analytics",
        consumer_name: str = "analytics-1",
        hmac_secret: Optional[str] = None,
        hmac_required: bool = True,
        aggregation_window: int = 300,
        campaign_detection: bool = True,
        slow_scan_detection: bool = True,
        ja4_intelligence: bool = True,
        monitoring_enabled: bool = True,
        monitoring_config: Optional[Dict[str, Any]] = None,
        detection_config: Optional[Dict[str, Any]] = None,
    ):
        self.redis_url = redis_url
        self.stream_key = stream_key
        self.consumer_group = consumer_group
        self.consumer_name = consumer_name
        self.redis = None
        self.logger = None
        # Hot-reloadable via SIGHUP → AnalyticsNode._handle_reload()
        self.batch_size: int = 100
        self.timeout_ms: int = 5000
        self.hmac_auth = HMACAuthenticator(hmac_secret or "", hmac_required)
        self.aggregation_manager = AggregationManager(aggregation_window)
        self.hll_manager = HyperLogLogManager()

        # Initialize detection modules
        #
        # phase-827: thresholds come from config. They used to be the
        # constructors' hardcoded defaults with nothing ever passing a value,
        # so tuning meant editing source.
        #
        # Read with per-key fallbacks rather than trusting the config merge:
        # load_config()'s default merge is only two levels deep, so an operator
        # setting a single threshold (detection.campaign.min_unique_ips) would
        # otherwise silently drop every sibling key in that block and fall back
        # to the constructor defaults for them — the confusing half-applied
        # case. Defaults here equal the historical values, so an absent config
        # block changes nothing.
        dcfg = detection_config or {}
        self.detection_config = dcfg

        def _cfg(section: str, key: str, default):
            return (dcfg.get(section) or {}).get(key, default)

        self.campaign_detector = (
            CampaignDetector(
                min_unique_ips=_cfg("campaign", "min_unique_ips", 10),
                density_threshold=_cfg("campaign", "density_threshold", 0.15),
                block_rate_threshold=_cfg("campaign", "block_rate_threshold", 0.70),
                window_seconds=_cfg("campaign", "window_seconds", 300),
            )
            if campaign_detection
            else None
        )
        self.slow_scan_detector = (
            SlowScanDetector(
                min_unique_ips=_cfg("slow_scan", "min_unique_ips", 20),
                max_requests_per_ip=_cfg("slow_scan", "max_requests_per_ip", 3),
                window_seconds=_cfg("slow_scan", "window_seconds", 300),
            )
            if slow_scan_detection
            else None
        )
        # phase-827: catches one fingerprint operating across many separate
        # networks — the case the subnet-bucketed detectors are blind to by
        # construction.
        self.distributed_detector = (
            DistributedClientDetector(
                min_subnets=_cfg("distributed", "min_subnets", 10),
                min_observations=_cfg("distributed", "min_observations", 20),
                window_seconds=_cfg("distributed", "window_seconds", 3600),
            )
            if ja4_intelligence
            else None
        )
        self.ja4_intelligence = (
            JA4FingerprintIntelligence(
                min_observations=_cfg("ja4_intelligence", "min_observations", 10),
                block_rate_threshold=_cfg(
                    "ja4_intelligence", "block_rate_threshold", 0.95
                ),
                window_seconds=_cfg("ja4_intelligence", "window_seconds", 3600),
            )
            if ja4_intelligence
            else None
        )

        # Initialize monitoring system (Phase 12c)
        self.monitoring_enabled = monitoring_enabled
        self.monitoring_system = None
        self.monitoring_config = monitoring_config or {}

    def apply_detection_config(self, detection_config: Optional[Dict[str, Any]]) -> None:
        """Re-apply detection thresholds to the live detectors (SIGHUP).

        phase-827. Mutates the existing detector instances rather than
        rebuilding them: each one holds accumulated per-subnet and
        per-fingerprint state, and replacing them would silently discard the
        observation history a detection is built from. An operator lowering a
        threshold expects the change to apply to what has already been seen,
        not to reset the window.
        """
        dcfg = detection_config or {}
        self.detection_config = dcfg

        def _cfg(section: str, key: str, default):
            return (dcfg.get(section) or {}).get(key, default)

        if self.campaign_detector is not None:
            self.campaign_detector.min_unique_ips = _cfg("campaign", "min_unique_ips", 10)
            self.campaign_detector.density_threshold = _cfg("campaign", "density_threshold", 0.15)
            self.campaign_detector.block_rate_threshold = _cfg("campaign", "block_rate_threshold", 0.70)
        if self.slow_scan_detector is not None:
            self.slow_scan_detector.min_unique_ips = _cfg("slow_scan", "min_unique_ips", 20)
            self.slow_scan_detector.max_requests_per_ip = _cfg("slow_scan", "max_requests_per_ip", 3)
        if self.ja4_intelligence is not None:
            self.ja4_intelligence.min_observations = _cfg("ja4_intelligence", "min_observations", 10)
            self.ja4_intelligence.block_rate_threshold = _cfg("ja4_intelligence", "block_rate_threshold", 0.95)

    async def connect(self):
        """Establish connection to Redis."""
        # socket_timeout must exceed the XREADGROUP block window — see
        # _SOCKET_TIMEOUT_S. Never rely on the library default here.
        self.redis = await aioredis.from_url(
            self.redis_url,
            socket_timeout=_SOCKET_TIMEOUT_S,
            health_check_interval=30,
        )

        # Create consumer group if it doesn't exist
        try:
            await self.redis.xgroup_create(
                self.stream_key,
                self.consumer_group,
                id="$",  # Start from the end
                mkstream=True,
            )
        except aioredis.ResponseError as e:
            # Group already exists, which is fine
            if "BUSYGROUP" not in str(e):
                raise

        # Initialize monitoring system (Phase 12c)
        if self.monitoring_enabled:
            from .monitoring import MonitoringSystem

            self.monitoring_system = MonitoringSystem(
                self.redis, self.monitoring_config
            )

    async def validate_event(
        self, event_data: Dict[str, Any], *, signature_verified: bool = False
    ) -> bool:
        """Validate event against schema and business rules.

        ``signature_verified`` is set by the ECS path, where the HMAC has
        already been checked against the RAW envelope bytes. Re-running
        ``hmac_auth.verify`` on the normalised dict would recompute the digest
        over a reconstructed object and always fail — the signature covers the
        wire bytes, not the mapped fields. Replay protection is not lost: the
        timestamp window is enforced by validate_event_comprehensive below.
        """
        try:
            # 1. HMAC verification
            if not signature_verified and not self.hmac_auth.verify(event_data):
                raise InvalidEventError("HMAC verification failed")

            # 2. JSON Schema validation
            validate(instance=event_data, schema=EVENT_SCHEMA)

            # 3. Comprehensive validation
            return await validate_event_comprehensive(event_data)

        except ValidationError as e:
            raise InvalidEventError(f"Schema validation failed: {e}")
        except Exception as e:
            raise InvalidEventError(f"Event validation failed: {e}")

    async def process_event(self, event_id: str, event_data: Dict[str, Any]):
        """Process a single validated event."""
        try:
            # Update aggregation
            self.aggregation_manager.update_aggregation(event_data)

            # Update HyperLogLog — in-process (fast) + Redis (cross-instance, fail-open)
            subnet = self.aggregation_manager.get_subnet(event_data["src_ip"])
            self.hll_manager.add_ip(subnet, event_data["src_ip"])
            try:
                hll_key = f"analytics:hll:{subnet}"
                await self.redis.pfadd(hll_key, event_data["src_ip"])
                await self.redis.expire(hll_key, 86400)  # 24 h TTL per REDIS_SCHEMA.md
            except redis.RedisError:
                pass  # Fail open; in-process HLL still accurate for this instance

            # Update detection modules
            if self.campaign_detector:
                self.campaign_detector.update_with_event(event_data)

            if self.slow_scan_detector:
                self.slow_scan_detector.update_with_event(event_data)

            if self.ja4_intelligence:
                self.ja4_intelligence.update_with_event(event_data)

            if self.distributed_detector:
                self.distributed_detector.update_with_event(event_data)

            # Update monitoring system (Phase 12c)
            if self.monitoring_enabled and self.monitoring_system:
                await self.monitoring_system.update_with_event(event_data)

            # Store results in Redis (will be implemented in Phase 12b)
            # For Phase 12a, we just log the aggregation periodically
            results = self.aggregation_manager.get_aggregation_results()
            total_events = sum(r["total_events"] for r in results.values())
            if total_events % 100 == 0:  # Log every 100 events
                print(
                    f"Aggregation results: {len(results)} subnets tracked, {total_events} total events"
                )

            return True
        except Exception as e:
            print(f"Error processing event {event_id}: {e}")
            return False

    async def consume_events(
        self,
        batch_size: int = 100,
        timeout_ms: int = 5000,
        detection_interval: int = 60,
        monitoring_interval: int = 60,
    ):
        """Consume events from the stream in batches."""
        if not self.redis:
            await self.connect()

        # Track timing for various cycles
        last_detection_time = time.time()
        last_monitoring_time = time.time()

        while True:
            try:
                # Run detection cycle periodically
                current_time = time.time()
                if current_time - last_detection_time >= detection_interval and (
                    self.campaign_detector
                    or self.slow_scan_detector
                    or self.ja4_intelligence
                ):
                    await self.run_detection_cycle()
                    last_detection_time = current_time

                # Run monitoring cycle periodically (Phase 12c)
                if (
                    self.monitoring_enabled
                    and self.monitoring_system
                    and current_time - last_monitoring_time >= monitoring_interval
                ):
                    await self.monitoring_system.run_monitoring_cycle()
                    last_monitoring_time = current_time

                # Read events from the stream
                events = await self.redis.xreadgroup(
                    self.consumer_group,
                    self.consumer_name,
                    {self.stream_key: ">"},  # Read new events
                    count=batch_size,
                    # Clamped: a block >= the socket timeout makes every poll
                    # raise TimeoutError. timeout_ms is hot-reloadable, so this
                    # is enforced per call, not once at construction.
                    block=min(timeout_ms, MAX_BLOCK_MS),
                )

                if not events:
                    continue

                stream, messages = events[0]

                for event_id, event_data in messages:
                    try:
                        # Parse event data
                        data = {
                            k.decode(): v.decode() if isinstance(v, bytes) else v
                            for k, v in event_data.items()
                        }

                        # Update stream lag from the Redis Stream message ID.
                        # Message IDs have the form "<ms_timestamp>-<seq>"; the
                        # ms part is the wall-clock time when the event was XADD'd.
                        try:
                            msg_id_str = (
                                event_id.decode()
                                if isinstance(event_id, bytes)
                                else event_id
                            )
                            msg_ms = int(msg_id_str.split("-")[0])
                            lag = max(0.0, time.time() - msg_ms / 1000.0)
                            _STREAM_LAG.set(lag)
                            if lag > 300:
                                logging.getLogger(__name__).warning(
                                    "analytics | event=stream_lag_high | lag_seconds=%.1f",
                                    lag,
                                )
                        except (ValueError, AttributeError):
                            pass

                        # phase-826: the proxy writes ONE field holding an ECS
                        # JSON document, not the flat schema this consumer was
                        # written against. Translate before validating, and
                        # check the signature over the raw envelope bytes.
                        signature_verified = False
                        if is_ecs_envelope(data):
                            if self.hmac_auth.required and not verify_envelope_signature(
                                data, self.hmac_auth.secret
                            ):
                                _EVENTS_REJECTED.labels(reason="hmac").inc()
                                raise InvalidEventError(
                                    "HMAC verification failed (ECS envelope)"
                                )
                            signature_verified = True
                            data = normalise_ecs(data)

                        # Validate event
                        await self.validate_event(
                            data, signature_verified=signature_verified
                        )

                        # Process event
                        success = await self.process_event(event_id.decode(), data)
                        if success:
                            _EVENTS_INGESTED.inc()

                        if success:
                            # Acknowledge successful processing
                            await self.redis.xack(stream, self.consumer_group, event_id)

                    except InvalidEventError as e:
                        # Log invalid event but don't crash
                        _EVENTS_REJECTED.labels(reason="invalid").inc()
                        print(f"Invalid event {event_id.decode()}: {e}")
                        # Don't acknowledge - will be retried

                    except Exception as e:
                        # Log error and continue
                        print(f"Error processing event {event_id.decode()}: {e}")
                        # Don't acknowledge - will be retried

            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Stream consumer error: {e}")
                await asyncio.sleep(1)

    async def get_detection_results(self) -> Dict[str, Any]:
        """Get current detection results."""
        results = {}

        # Campaign detection results
        if self.campaign_detector:
            campaigns = self.campaign_detector.detect_campaigns()
            results["campaigns"] = campaigns
            results["campaign_count"] = len(campaigns)
        else:
            results["campaigns"] = []
            results["campaign_count"] = 0

        # Slow scan detection results
        if self.slow_scan_detector:
            slow_scans = self.slow_scan_detector.detect_slow_scans()
            results["slow_scans"] = slow_scans
            results["slow_scan_count"] = len(slow_scans)
        else:
            results["slow_scans"] = []
            results["slow_scan_count"] = 0

        # Distributed-client results (phase-827)
        if self.distributed_detector:
            distributed = self.distributed_detector.detect_distributed()
            results["distributed"] = distributed
            results["distributed_count"] = len(distributed)
        else:
            results["distributed"] = []
            results["distributed_count"] = 0

        # JA4 intelligence results
        if self.ja4_intelligence:
            ja4_candidates = self.ja4_intelligence.identify_candidates()
            results["ja4_candidates"] = ja4_candidates
            results["ja4_candidate_count"] = len(ja4_candidates)
        else:
            results["ja4_candidates"] = []
            results["ja4_candidate_count"] = 0

        return results

    async def _claim_finding(self, kind: str, subject: str) -> bool:
        """True if this (kind, subject) has not been reported recently.

        phase-827. Detection runs on a timer, and a subnet or fingerprint that
        qualifies once generally qualifies on EVERY subsequent cycle — so
        writing unconditionally produces a column of identical findings. The
        panel looks busy while saying one thing, and the genuinely new finding
        is pushed off the bottom by copies of the old one.

        A short-lived Redis key claimed with NX is the whole mechanism: whoever
        sets it writes the finding, everyone else skips. The TTL rather than a
        permanent marker means a subject that is STILL offending resurfaces
        later, instead of being silently suppressed forever after one report.

        Fails OPEN: if Redis is unreachable we would rather show a duplicate
        than drop a finding an operator needs to see.
        """
        try:
            return bool(
                await self.redis.set(
                    f"analytics:finding:seen:{kind}:{subject}",
                    "1",
                    ex=_FINDING_DEDUP_TTL_S,
                    nx=True,
                )
            )
        except redis.RedisError:
            return True

    async def run_detection_cycle(self):
        """Run a complete detection cycle and store results in Redis."""
        try:
            if not self.redis:
                await self.connect()

            # Phase 236: Update heartbeat at start of every cycle
            await update_heartbeat(self.redis, poll_interval_seconds=60)

            # Get detection results
            detection_results = await self.get_detection_results()

            # Store results in Redis
            if self.redis:
                # Store campaigns as findings
                for campaign in detection_results["campaigns"]:
                    key = f"analytics:campaign:{campaign['subnet']}"
                    await self.redis.set(
                        key, json.dumps(campaign), ex=3600
                    )  # 1 hour TTL

                    # Phase 236: Write as structured finding
                    if not await self._claim_finding("campaign", campaign.get("subnet", "")):
                        continue
                    await write_finding(
                        self.redis,
                        confidence=0.95,
                        type="campaign",
                        # phase-827: the detectors emit no "description" key, so
                        # this always fell through to the generic string and the
                        # operator saw "Coordinated campaign detected" with no
                        # evidence — nothing to judge, and nothing to
                        # distinguish two findings from each other. Build the
                        # sentence from the measurements that triggered it.
                        description=campaign.get("description") or (
                            f"{campaign.get('unique_ips', 0)} IPs active across "
                            f"{campaign.get('subnet', 'a subnet')} "
                            f"({campaign.get('density', 0):.0%} of it), "
                            f"{campaign.get('block_rate', 0):.0%} of their "
                            "connections blocked"
                        ),
                        evidence_count=campaign.get(
                            "unique_ips", campaign.get("ip_count", 0)
                        ),
                        model_version="analytics-1.0",
                        model_trained_at="2026-01-01T00:00:00Z",
                        fp_rate_estimate=0.05,
                        suggested_action="investigate",
                        subject_ip=campaign.get("subnet", ""),
                    )

                # Store slow scans as findings
                for slow_scan in detection_results["slow_scans"]:
                    key = f"analytics:slowscan:{slow_scan['subnet']}"
                    await self.redis.set(
                        key, json.dumps(slow_scan), ex=1800
                    )  # 30 min TTL

                    if not await self._claim_finding("slowscan", slow_scan.get("subnet", "")):
                        continue
                    await write_finding(
                        self.redis,
                        confidence=0.85,
                        type="slowscan",
                        description=slow_scan.get("description") or (
                            f"{slow_scan.get('unique_ips', 0)} IPs in "
                            f"{slow_scan.get('subnet', 'a subnet')} made "
                            f"{slow_scan.get('total_requests', 0)} connections "
                            f"({slow_scan.get('avg_requests_per_ip', 0):.1f} each) "
                            "— low volume per host, spread wide"
                        ),
                        evidence_count=slow_scan.get(
                            "total_requests", slow_scan.get("connection_count", 0)
                        ),
                        model_version="analytics-1.0",
                        model_trained_at="2026-01-01T00:00:00Z",
                        fp_rate_estimate=0.10,
                        suggested_action="monitor",
                        subject_ip=slow_scan.get("subnet", ""),
                    )

                # Store JA4 candidates (sorted set by block rate)
                if detection_results["ja4_candidates"]:
                    ja4_members = {}
                    for candidate in detection_results["ja4_candidates"]:
                        ja4_members[candidate["ja4"]] = candidate["block_rate"]

                    await self.redis.zadd("analytics:ja4:candidates", ja4_members)
                    await self.redis.expire(
                        "analytics:ja4:candidates", 86400
                    )  # 24 hour TTL

                    # phase-826: also surface these as findings. Campaigns and
                    # slow scans were written through to analytics:finding:*,
                    # but JA4 candidates only ever landed in the sorted set
                    # above — which nothing in the console reads. The
                    # Intelligence panel was therefore structurally unable to
                    # show the one detector that does not require many unique
                    # source IPs, and so had no chance of reporting anything on
                    # a single-source deployment.
                    for candidate in detection_results["ja4_candidates"]:
                        if not await self._claim_finding("ja4", candidate["ja4"]):
                            continue

                        only_blocks = candidate.get("only_in_blocks", False)
                        # Confidence tracks the evidence: a fingerprint seen
                        # ONLY in blocked connections is a stronger signal than
                        # one that is merely mostly-blocked, which could be a
                        # shared stack (a library used by both a bot and a real
                        # client). Kept under 0.95 — the campaign detector's
                        # value — because a single JA4 is weaker evidence than
                        # coordinated multi-IP activity.
                        confidence = 0.90 if only_blocks else 0.75
                        await write_finding(
                            self.redis,
                            confidence=confidence,
                            type="ja4_intelligence",
                            description=(
                                f"JA4 {candidate['ja4']} blocked on "
                                f"{candidate['blocked_seen']}/{candidate['total_seen']} "
                                f"connections ({candidate['block_rate']:.0%})"
                                + (
                                    " and never allowed"
                                    if only_blocks
                                    else ""
                                )
                                + f", from {candidate.get('source_count', 0)} source IP(s)"
                            ),
                            evidence_count=candidate["total_seen"],
                            model_version="analytics-1.0",
                            model_trained_at="2026-01-01T00:00:00Z",
                            # A fingerprint seen only in blocks is unlikely to
                            # be a real browser; one that is also sometimes
                            # allowed may be shared, so the FP estimate is
                            # deliberately higher there.
                            fp_rate_estimate=0.02 if only_blocks else 0.15,
                            # Never "block" outright: acting on a fingerprint
                            # affects every client that shares it, and the
                            # asymmetry in CLAUDE.md makes a false positive far
                            # more expensive than a missed bot. The operator
                            # confirms from the evidence shown in the panel.
                            suggested_action="investigate",
                            subject_ja4=candidate["ja4"],
                        )

                # phase-827: one fingerprint across many separate networks.
                # Reported even when nothing was blocked — the value is
                # catching a distributed client that is currently getting
                # through untouched, which is exactly when it is invisible.
                for dist in detection_results.get("distributed", []):
                    if not await self._claim_finding("distributed", dist["ja4"]):
                        continue
                    geo = ""
                    if dist.get("country_count"):
                        geo = f", {dist['country_count']} countr" + (
                            "y" if dist["country_count"] == 1 else "ies"
                        )
                    if dist.get("asn_count"):
                        geo += f", {dist['asn_count']} ASN(s)"
                    await write_finding(
                        self.redis,
                        # Below the campaign detector's 0.95: wide spread is
                        # strong evidence of coordination, but a widely used
                        # library would look the same, so this stays reviewable
                        # rather than actionable-on-sight.
                        confidence=0.88,
                        type="distributed_client",
                        description=(
                            f"JA4 {dist['ja4']} seen from "
                            f"{dist['subnet_count']} separate networks "
                            f"({dist['unique_ips']} IPs{geo}) — "
                            f"{dist['blocked_seen']}/{dist['total_seen']} blocked. "
                            "Subnet-based detection cannot see this pattern."
                        ),
                        evidence_count=dist["total_seen"],
                        model_version="analytics-1.0",
                        model_trained_at="2026-01-01T00:00:00Z",
                        fp_rate_estimate=0.12,
                        suggested_action="investigate",
                        subject_ja4=dist["ja4"],
                    )

            return detection_results
        except Exception as e:
            print(f"Error running detection cycle: {e}")
            return {"error": str(e)}

    async def close(self):
        """Close the Redis connection."""
        if self.redis:
            await self.redis.close()

    # Phase 12c: Monitoring methods
    async def get_monitoring_status(self) -> Dict[str, Any]:
        """Get current monitoring status."""
        if not self.monitoring_enabled or not self.monitoring_system:
            return {"enabled": False, "message": "Monitoring system disabled"}

        return await self.monitoring_system.get_monitoring_status()

    async def get_alerts(self) -> Dict[str, Any]:
        """Get all active monitoring alerts."""
        if not self.monitoring_enabled or not self.monitoring_system:
            return {"enabled": False, "alerts": {}}

        return await self.monitoring_system.get_alerts()

    async def clear_all_alerts(self):
        """Clear all monitoring alerts."""
        if self.monitoring_enabled and self.monitoring_system:
            await self.monitoring_system.clear_all_alerts()
            return {"success": True}

        return {"success": False, "message": "Monitoring system disabled"}

    async def get_drift_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get score drift detection history."""
        if not self.monitoring_enabled or not self.monitoring_system:
            return []

        return await self.monitoring_system.get_drift_history(hours)

    async def get_shift_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get distribution shift detection history."""
        if not self.monitoring_enabled or not self.monitoring_system:
            return []

        return await self.monitoring_system.get_shift_history(hours)

    async def get_calibration_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get calibration check history."""
        if not self.monitoring_enabled or not self.monitoring_system:
            return []

        return await self.monitoring_system.get_calibration_history(hours)


class InvalidEventError(Exception):
    """Raised when an event fails validation."""

    pass
