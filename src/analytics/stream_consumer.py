# Redis Stream Consumer for Analytics Node
# Phase 12a: Foundation

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional

import aioredis
import redis
from jsonschema import ValidationError, validate
from prometheus_client import Gauge

from .aggregation import AggregationManager, HyperLogLogManager
from .authentication import HMACAuthenticator
from .detection import CampaignDetector, JA4FingerprintIntelligence, SlowScanDetector
from .event_schemas import EVENT_SCHEMA
from .validation import validate_event_comprehensive

# Stream lag: seconds between the most recent event's Redis timestamp and now.
# Exposed on the /metrics endpoint alongside the monitoring.py registry.
_STREAM_LAG = Gauge(
    "ja4proxy_analytics_stream_lag_seconds",
    "Seconds between the latest processed stream event and now",
)


class StreamConsumer:
    """Redis Stream consumer for analytics events."""

    def __init__(self, redis_url: str, stream_key: str = "ja4proxy:events",
                 consumer_group: str = "analytics", consumer_name: str = "analytics-1",
                 hmac_secret: Optional[str] = None, hmac_required: bool = True,
                 aggregation_window: int = 300,
                 campaign_detection: bool = True, slow_scan_detection: bool = True,
                 ja4_intelligence: bool = True, monitoring_enabled: bool = True,
                 monitoring_config: Optional[Dict[str, Any]] = None):
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
        self.campaign_detector = CampaignDetector() if campaign_detection else None
        self.slow_scan_detector = SlowScanDetector() if slow_scan_detection else None
        self.ja4_intelligence = JA4FingerprintIntelligence() if ja4_intelligence else None

        # Initialize monitoring system (Phase 12c)
        self.monitoring_enabled = monitoring_enabled
        self.monitoring_system = None
        self.monitoring_config = monitoring_config or {}

    async def connect(self):
        """Establish connection to Redis."""
        self.redis = await aioredis.from_url(self.redis_url)

        # Create consumer group if it doesn't exist
        try:
            await self.redis.xgroup_create(
                self.stream_key,
                self.consumer_group,
                id="$",  # Start from the end
                mkstream=True
            )
        except aioredis.ResponseError as e:
            # Group already exists, which is fine
            if "BUSYGROUP" not in str(e):
                raise

        # Initialize monitoring system (Phase 12c)
        if self.monitoring_enabled:
            from .monitoring import MonitoringSystem
            self.monitoring_system = MonitoringSystem(self.redis, self.monitoring_config)

    async def validate_event(self, event_data: Dict[str, Any]) -> bool:
        """Validate event against schema and business rules."""
        try:
            # 1. HMAC verification
            if not self.hmac_auth.verify(event_data):
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

            # Update monitoring system (Phase 12c)
            if self.monitoring_enabled and self.monitoring_system:
                await self.monitoring_system.update_with_event(event_data)

            # Store results in Redis (will be implemented in Phase 12b)
            # For Phase 12a, we just log the aggregation periodically
            results = self.aggregation_manager.get_aggregation_results()
            total_events = sum(r["total_events"] for r in results.values())
            if total_events % 100 == 0:  # Log every 100 events
                print(f"Aggregation results: {len(results)} subnets tracked, {total_events} total events")

            return True
        except Exception as e:
            print(f"Error processing event {event_id}: {e}")
            return False

    async def consume_events(self, batch_size: int = 100, timeout_ms: int = 5000,
                           detection_interval: int = 60, monitoring_interval: int = 60):
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
                if (current_time - last_detection_time >= detection_interval and
                    (self.campaign_detector or self.slow_scan_detector or self.ja4_intelligence)):
                    await self.run_detection_cycle()
                    last_detection_time = current_time

                # Run monitoring cycle periodically (Phase 12c)
                if (self.monitoring_enabled and self.monitoring_system and
                    current_time - last_monitoring_time >= monitoring_interval):
                    await self.monitoring_system.run_monitoring_cycle()
                    last_monitoring_time = current_time

                # Read events from the stream
                events = await self.redis.xreadgroup(
                    self.consumer_group,
                    self.consumer_name,
                    {self.stream_key: ">"},  # Read new events
                    count=batch_size,
                    block=timeout_ms
                )

                if not events:
                    continue

                stream, messages = events[0]

                for event_id, event_data in messages:
                    try:
                        # Parse event data
                        data = {k.decode(): v.decode() if isinstance(v, bytes) else v
                               for k, v in event_data.items()}

                        # Update stream lag from the Redis Stream message ID.
                        # Message IDs have the form "<ms_timestamp>-<seq>"; the
                        # ms part is the wall-clock time when the event was XADD'd.
                        try:
                            msg_id_str = event_id.decode() if isinstance(event_id, bytes) else event_id
                            msg_ms = int(msg_id_str.split("-")[0])
                            lag = max(0.0, time.time() - msg_ms / 1000.0)
                            _STREAM_LAG.set(lag)
                            if lag > 300:
                                logging.getLogger(__name__).warning(
                                    "analytics | event=stream_lag_high | lag_seconds=%.1f", lag
                                )
                        except (ValueError, AttributeError):
                            pass

                        # Validate event
                        await self.validate_event(data)

                        # Process event
                        success = await self.process_event(event_id.decode(), data)

                        if success:
                            # Acknowledge successful processing
                            await self.redis.xack(stream, self.consumer_group, event_id)

                    except InvalidEventError as e:
                        # Log invalid event but don't crash
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
            results['campaigns'] = campaigns
            results['campaign_count'] = len(campaigns)
        else:
            results['campaigns'] = []
            results['campaign_count'] = 0

        # Slow scan detection results
        if self.slow_scan_detector:
            slow_scans = self.slow_scan_detector.detect_slow_scans()
            results['slow_scans'] = slow_scans
            results['slow_scan_count'] = len(slow_scans)
        else:
            results['slow_scans'] = []
            results['slow_scan_count'] = 0

        # JA4 intelligence results
        if self.ja4_intelligence:
            ja4_candidates = self.ja4_intelligence.identify_candidates()
            results['ja4_candidates'] = ja4_candidates
            results['ja4_candidate_count'] = len(ja4_candidates)
        else:
            results['ja4_candidates'] = []
            results['ja4_candidate_count'] = 0

        return results

    async def run_detection_cycle(self):
        """Run a complete detection cycle and store results in Redis."""
        try:
            if not self.redis:
                await self.connect()

            # Get detection results
            detection_results = await self.get_detection_results()

            # Store results in Redis
            if self.redis:
                # Store campaigns
                for campaign in detection_results['campaigns']:
                    key = f"analytics:campaign:{campaign['subnet']}"
                    await self.redis.set(key, json.dumps(campaign), ex=3600)  # 1 hour TTL

                # Store slow scans
                for slow_scan in detection_results['slow_scans']:
                    key = f"analytics:slowscan:{slow_scan['subnet']}"
                    await self.redis.set(key, json.dumps(slow_scan), ex=1800)  # 30 min TTL

                # Store JA4 candidates (sorted set by block rate)
                if detection_results['ja4_candidates']:
                    ja4_members = {}
                    for candidate in detection_results['ja4_candidates']:
                        ja4_members[candidate['ja4']] = candidate['block_rate']

                    await self.redis.zadd("analytics:ja4:candidates", ja4_members)
                    await self.redis.expire("analytics:ja4:candidates", 86400)  # 24 hour TTL

            return detection_results
        except Exception as e:
            print(f"Error running detection cycle: {e}")
            return {'error': str(e)}

    async def close(self):
        """Close the Redis connection."""
        if self.redis:
            await self.redis.close()

    # Phase 12c: Monitoring methods
    async def get_monitoring_status(self) -> Dict[str, Any]:
        """Get current monitoring status."""
        if not self.monitoring_enabled or not self.monitoring_system:
            return {'enabled': False, 'message': 'Monitoring system disabled'}

        return await self.monitoring_system.get_monitoring_status()

    async def get_alerts(self) -> Dict[str, Any]:
        """Get all active monitoring alerts."""
        if not self.monitoring_enabled or not self.monitoring_system:
            return {'enabled': False, 'alerts': {}}

        return await self.monitoring_system.get_alerts()

    async def clear_all_alerts(self):
        """Clear all monitoring alerts."""
        if self.monitoring_enabled and self.monitoring_system:
            await self.monitoring_system.clear_all_alerts()
            return {'success': True}

        return {'success': False, 'message': 'Monitoring system disabled'}

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