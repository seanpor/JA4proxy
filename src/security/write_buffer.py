"""Deferred write batching for Redis operations (Phase 26e).

This module implements a WriteBuffer that accumulates Redis write operations
and flushes them in batches to reduce I/O overhead on the hot path.

Security Features:
- Bounded queue size to prevent memory exhaustion
- Graceful degradation on overflow (oldest writes dropped)
- Fail-open semantics (write failures don't block connections)
- Prometheus metrics for monitoring

GDPR Compliance:
- All writes still respect original TTLs
- No additional data retention beyond original design
"""

import asyncio
import logging
import time
from collections import deque
from typing import Deque, Optional, Tuple

from prometheus_client import Counter, Gauge

# Metrics
_WRITE_BUFFER_FLUSHES = Counter(
    "ja4proxy_write_buffer_flush_total",
    "Write buffer flush operations",
    ["result"],  # ok, overflow, error
)

_WRITE_BUFFER_QUEUE_DEPTH = Gauge(
    "ja4proxy_write_buffer_queue_depth",
    "Current number of operations queued in write buffer",
)

_WRITE_BUFFER_OPERATIONS = Counter(
    "ja4proxy_write_buffer_operations_total",
    "Write operations processed by buffer",
    ["type"],  # hset, zadd, expire, etc.
)

_WRITE_BUFFER_DROPPED = Counter(
    "ja4proxy_write_buffer_dropped_total",
    "Total number of dropped operations due to overflow"
)

_WRITE_BUFFER_FLUSH_DURATION = Gauge(
    "ja4proxy_write_buffer_flush_duration_seconds",
    "Time taken to flush the last batch to Redis"
)


class WriteBuffer:
    """
    Batch Redis writes to reduce I/O overhead on the hot path.

    Accumulates write operations and flushes them periodically in batches.
    Designed for post-decision writes that don't affect connection processing.

    Thread-safe: Yes (uses asyncio.Lock)
    Fail-open: Yes (errors are logged but don't block)
    """

    def __init__(
        self,
        redis_client: object,
        flush_interval_ms: int = 50,
        max_batch_size: int = 2000,
        max_queue_size: int = 10000
    ):
        """
        Initialize WriteBuffer.

        Args:
            redis_client: Redis client (sync or async)
            flush_interval_ms: Maximum time between flushes (milliseconds)
            max_batch_size: Maximum operations per flush batch
            max_queue_size: Maximum operations to queue (prevents memory exhaustion)

        Security:
            - max_queue_size prevents DoS via memory exhaustion
            - flush_interval_ms bounds stale-write window
        """
        self.redis_client = redis_client
        self.flush_interval_ms = flush_interval_ms / 1000.0  # Convert to seconds
        self.max_batch_size = max_batch_size
        self.max_queue_size = max_queue_size

        self.queue: Deque[Tuple[str, Tuple, dict]] = deque()
        self.lock = asyncio.Lock()
        self._flush_task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

        self.logger = logging.getLogger(__name__)

        # Check if Redis client is async
        self._is_async = self._check_async_redis()

    def _check_async_redis(self) -> bool:
        """Check if Redis client is async (redis.asyncio.Redis)."""
        try:
            import redis.asyncio

            return isinstance(self.redis_client, redis.asyncio.Redis)
        except ImportError:
            return False

    async def start(self) -> None:
        """Start the background flush loop."""
        if self._flush_task is not None:
            return

        self._stop_event.clear()
        self._flush_task = asyncio.create_task(self._flush_loop())
        self.logger.info(
            "WriteBuffer started with flush_interval=%.1fms, max_batch=%d",
            self.flush_interval_ms * 1000,
            self.max_batch_size,
        )

    async def stop(self) -> None:
        """Stop the background flush loop and flush remaining operations."""
        if self._flush_task is None:
            return

        self._stop_event.set()

        try:
            await self._flush_task
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.error("Error stopping WriteBuffer: %s", e)

        # Final flush
        await self._flush_now()

        self._flush_task = None
        self.logger.info("WriteBuffer stopped")

    async def enqueue(self, operation: str, *args, priority: bool = False, **kwargs) -> bool:
        """
        Enqueue a Redis write operation.

        Args:
            operation: Redis operation name (e.g., 'hset', 'zadd', 'expire')
            *args: Positional arguments for the operation
            priority: If True, this write is critical and should rarely be dropped.
            **kwargs: Keyword arguments for the operation

        Returns:
            True if operation was queued, False if queue is full

        Security:
            - Phase 30a: Load shedding. Drop non-priority writes when > 90% full.
            - Returns False if queue is full (prevents memory exhaustion)
            - Non-blocking (fail-open on full queue)
        """
        async with self.lock:
            queue_len = len(self.queue)
            
            # Load shedding for non-priority writes
            if not priority and queue_len > (self.max_queue_size * 0.9):
                _WRITE_BUFFER_DROPPED.inc()
                return False

            if queue_len >= self.max_queue_size:
                # Queue full - drop oldest operation to make room
                self.queue.popleft()
                _WRITE_BUFFER_FLUSHES.labels(result="overflow").inc()
                _WRITE_BUFFER_DROPPED.inc()
                self.logger.warning(
                    "WriteBuffer overflow: queue size %d >= max %d, dropping oldest operation",
                    len(self.queue),
                    self.max_queue_size,
                )

            # Add new operation
            self.queue.append((operation, args, kwargs))
            _WRITE_BUFFER_OPERATIONS.labels(type=operation).inc()
            _WRITE_BUFFER_QUEUE_DEPTH.set(len(self.queue))

            return True

    async def _flush_loop(self) -> None:
        """
        Background task that periodically flushes the write buffer.

        Phase 30a: Adaptive flush intervals.
        """
        try:
            while not self._stop_event.is_set():
                async with self.lock:
                    queue_len = len(self.queue)
                
                # Adaptive timing:
                # - > 90% full: flush immediately (sleep 0.0001)
                # - > 70% full: flush extremely fast
                # - > 50% full: flush 2x faster
                # - < 50% full: use default interval
                if queue_len > (self.max_queue_size * 0.9):
                    sleep_time = 0.0001
                elif queue_len > (self.max_queue_size * 0.7):
                    sleep_time = 0.001
                elif queue_len > (self.max_queue_size * 0.5):
                    sleep_time = self.flush_interval_ms / 2.0
                else:
                    sleep_time = self.flush_interval_ms

                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(),
                        timeout=sleep_time,
                    )
                except asyncio.TimeoutError:
                    pass  # Time to flush


                if self._stop_event.is_set():
                    break

                await self._flush_now()

        except asyncio.CancelledError:
            pass  # Normal shutdown
        except Exception as e:
            self.logger.error("WriteBuffer flush loop error: %s", e)

    async def _flush_now(self) -> None:
        """Flush queued operations to Redis."""
        async with self.lock:
            if not self.queue:
                return

            # Determine batch size (up to max_batch_size)
            batch_size = min(len(self.queue), self.max_batch_size)
            batch = []

            # Extract batch from queue
            for _ in range(batch_size):
                batch.append(self.queue.popleft())

            # Update queue depth metric
            _WRITE_BUFFER_QUEUE_DEPTH.set(len(self.queue))

        # Execute batch
        await self._execute_batch(batch)

    async def _execute_batch(self, batch: list) -> None:
        """Execute a batch of Redis operations."""
        if not batch:
            return

        start_time = time.time()
        try:
            if self._is_async:
                # Async Redis client
                async with self.redis_client.pipeline(transaction=False) as pipe:  # type: ignore[attr-defined]
                    for operation, args, kwargs in batch:
                        method = getattr(pipe, operation)
                        result = method(*args, **kwargs)
                        # Phase 30b: Safety check for mocks that might return coroutines
                        if asyncio.iscoroutine(result):
                            await result
                    
                    await pipe.execute()
            else:
                # Sync Redis client
                with self.redis_client.pipeline(transaction=False) as pipe:  # type: ignore[attr-defined]
                    for operation, args, kwargs in batch:
                        method = getattr(pipe, operation)
                        method(*args, **kwargs)

                    pipe.execute()

            _WRITE_BUFFER_FLUSHES.labels(result="ok").inc()

        except Exception as e:
            _WRITE_BUFFER_FLUSHES.labels(result="error").inc()
            self.logger.error("WriteBuffer batch execution failed: %s", e)
            # Fail-open: write failures don't affect connection processing
        finally:
            _WRITE_BUFFER_FLUSH_DURATION.set(time.time() - start_time)

    def __del__(self):
        """Cleanup on object destruction."""
        try:
            if hasattr(self, "_flush_task") and self._flush_task:
                self._flush_task.cancel()
        except Exception:
            pass  # Ignore cleanup errors
