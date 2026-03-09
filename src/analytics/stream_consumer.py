# Redis Stream Consumer for Analytics Node
# Phase 12a: Foundation

import asyncio
import json
import time
from typing import Dict, Any, Optional

import aioredis
from jsonschema import validate, ValidationError

from .event_schemas import EVENT_SCHEMA
from .validation import validate_event_comprehensive
from .authentication import HMACAuthenticator
from .aggregation import AggregationManager, HyperLogLogManager


class StreamConsumer:
    """Redis Stream consumer for analytics events."""
    
    def __init__(self, redis_url: str, stream_key: str = "ja4proxy:events", 
                 consumer_group: str = "analytics", consumer_name: str = "analytics-1",
                 hmac_secret: Optional[str] = None, hmac_required: bool = True,
                 aggregation_window: int = 300):
        self.redis_url = redis_url
        self.stream_key = stream_key
        self.consumer_group = consumer_group
        self.consumer_name = consumer_name
        self.redis = None
        self.logger = None
        self.hmac_auth = HMACAuthenticator(hmac_secret or "", hmac_required)
        self.aggregation_manager = AggregationManager(aggregation_window)
        self.hll_manager = HyperLogLogManager()
    
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
            
            # Update HyperLogLog
            subnet = self.aggregation_manager.get_subnet(event_data["src_ip"])
            self.hll_manager.add_ip(subnet, event_data["src_ip"])
            
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
    
    async def consume_events(self, batch_size: int = 100, timeout_ms: int = 5000):
        """Consume events from the stream in batches."""
        if not self.redis:
            await self.connect()
        
        while True:
            try:
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
    
    async def close(self):
        """Close the Redis connection."""
        if self.redis:
            await self.redis.close()


class InvalidEventError(Exception):
    """Raised when an event fails validation."""
    pass