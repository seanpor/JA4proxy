#!/usr/bin/env python3
"""
Multi-strategy rate tracker using Redis for distributed tracking.

This module implements connection rate tracking across multiple strategies
using Redis sorted sets for atomic sliding window calculations.

Security Features:
- Atomic Redis operations using Lua scripts (no race conditions)
- Input validation to prevent Redis key injection
- GDPR-compliant TTLs for automatic data expiration
- Fail-closed on Redis errors (block rather than allow)
- Resource limits to prevent DoS on Redis

GDPR Compliance:
- All data has TTLs (no permanent storage)
- Minimal data retention (60 seconds default)
- Pseudonymization in logs
- Data minimization by strategy selection
"""

import asyncio
import inspect
import logging
import time
from typing import Dict, List, Optional

import redis

from .rate_strategy import (
    RateLimitStrategy,
    RateMetrics,
    StrategyConfig,
)


class RateTrackerError(Exception):
    """Base exception for rate tracker errors."""
    pass


class RedisConnectionError(RateTrackerError):
    """Redis connection/operation failed."""
    pass


class MultiStrategyRateTracker:
    """
    Track connection rates using multiple configurable strategies.

    Uses Redis sorted sets with timestamps for atomic sliding window
    rate calculation without race conditions.

    Thread-safe: Yes (Redis operations are atomic)
    Distributed: Yes (works across multiple proxy instances)
    """

    # Security: Lua script for atomic rate tracking
    # This prevents race conditions between reading count and setting TTL
    RATE_TRACKING_SCRIPT = """
    local key = KEYS[1]
    local counter_key = KEYS[2]
    local now = tonumber(ARGV[1])
    local window = tonumber(ARGV[2])
    local ttl = tonumber(ARGV[3])

    -- Generate unique ID for this connection (timestamp + counter)
    local counter = redis.call('INCR', counter_key)
    local unique_id = now .. ':' .. counter

    -- Add current connection to sorted set (score = timestamp)
    redis.call('ZADD', key, now, unique_id)

    -- Remove connections outside the window (older than now - window)
    redis.call('ZREMRANGEBYSCORE', key, 0, now - window)

    -- Count remaining connections in window
    local count = redis.call('ZCARD', key)

    -- Set TTL for GDPR compliance (both keys)
    redis.call('EXPIRE', key, ttl)
    redis.call('EXPIRE', counter_key, ttl)

    return count
    """

    # Security constants
    MAX_CONNECTIONS_PER_WINDOW = 10000  # Prevent DoS on Redis
    MAX_STRATEGIES = 10  # Reasonable limit
    MIN_WINDOW_SECONDS = 0.1  # Minimum window size
    MAX_WINDOW_SECONDS = 3600  # Maximum window size (1 hour)
    DEFAULT_TTL_SECONDS = 60  # GDPR: minimal retention

    def __init__(self, redis_client: redis.Redis, config: dict):
        """
        Initialize multi-strategy rate tracker.

        Args:
            redis_client: Connected Redis client
            config: Configuration dictionary

        Raises:
            ValueError: If configuration is invalid
            RedisConnectionError: If Redis is unavailable
        """
        self.redis = redis_client
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Validate Redis connection
        self._validate_redis_connection()

        # Load and validate strategies
        self.enabled_strategies = self._load_enabled_strategies()

        if not self.enabled_strategies:
            self.logger.warning(
                "No rate limiting strategies enabled - rate limiting disabled"
            )

        # Load window configuration with validation
        self.windows = self._load_window_config()

        # Register Lua script
        try:
            self.rate_script = self.redis.register_script(self.RATE_TRACKING_SCRIPT)
        except redis.RedisError as e:
            raise RedisConnectionError(f"Failed to register Lua script: {e}")

        self.logger.info(
            "Rate tracker initialized with strategies: %s",
            [s.value for s in self.enabled_strategies]
        )

    @staticmethod
    def _is_async_redis(client: object) -> bool:
        """Return True if client is an async Redis client (redis.asyncio.Redis)."""
        try:
            return isinstance(client, redis.asyncio.Redis)
        except AttributeError:
            return False

    def _validate_redis_connection(self) -> None:
        """
        Validate Redis connection is working.

        Security: Fail early if Redis is unavailable (fail-closed).
        For async Redis clients ping() returns a coroutine and cannot be called
        synchronously from __init__; the caller already validated the connection
        at startup via await redis.ping(), so we skip the check here.
        """
        if self._is_async_redis(self.redis):
            return
        try:
            self.redis.ping()
        except redis.ConnectionError as e:
            raise RedisConnectionError(f"Redis connection failed: {e}")
        except redis.TimeoutError as e:
            raise RedisConnectionError(f"Redis connection timeout: {e}")

    def _load_enabled_strategies(self) -> List[RateLimitStrategy]:
        """
        Load enabled strategies from configuration with validation.

        Security: Validates configuration to prevent injection.

        Returns:
            List of enabled strategies

        Raises:
            ValueError: If configuration is invalid
        """
        strategies = []
        strategy_config = self.config.get('security', {}).get(
            'rate_limit_strategies', {}
        )

        if not isinstance(strategy_config, dict):
            raise ValueError("rate_limit_strategies must be a dictionary")

        # Check number of strategies
        if len(strategy_config) > self.MAX_STRATEGIES:
            raise ValueError(
                f"Too many strategies configured (max {self.MAX_STRATEGIES})"
            )

        # Load each strategy
        for strategy_name, settings in strategy_config.items():
            if not isinstance(settings, dict):
                self.logger.warning(
                    "Invalid settings for strategy %s, skipping", strategy_name
                )
                continue

            if settings.get('enabled', False):
                # Convert name to enum
                strategy = RateLimitStrategy.from_string(strategy_name)
                if strategy:
                    strategies.append(strategy)
                    self.logger.info("Enabled strategy: %s", strategy.value)
                else:
                    self.logger.warning(
                        "Unknown strategy '%s', skipping", strategy_name
                    )

        return strategies

    def _load_window_config(self) -> dict:
        """
        Load and validate window configuration.

        Security: Validates window sizes to prevent resource exhaustion.

        Returns:
            Dictionary of window configurations
        """
        windows_config = self.config.get('security', {}).get(
            'rate_windows', {}
        )

        # Default windows
        windows = {
            'short': 1.0,   # 1 second - real-time
            'medium': 10.0,  # 10 seconds - burst
            'long': 60.0,    # 60 seconds - sustained
        }

        # Validate and override with config
        for name, value in windows_config.items():
            try:
                value = float(value)
                if self.MIN_WINDOW_SECONDS <= value <= self.MAX_WINDOW_SECONDS:
                    windows[name] = value
                else:
                    self.logger.warning(
                        "Window '%s' value %s out of range [%s, %s], using default",
                        name, value, self.MIN_WINDOW_SECONDS, self.MAX_WINDOW_SECONDS
                    )
            except (TypeError, ValueError):
                self.logger.warning(
                    "Invalid window '%s' value: %s, using default",
                    name, value
                )

        return windows

    async def track_connection(
        self,
        ja4: str,
        ip: str,
        window: str = 'short'
    ) -> Dict[RateLimitStrategy, RateMetrics]:
        """
        Track a connection using all enabled strategies with pipelined batching.

        This method is the main entry point for rate tracking. It tracks
        the connection across all enabled strategies and returns metrics.
        Uses Redis pipeline batching to reduce round trips from 3 per strategy
        to 1 total batch operation.

        Security:
        - Validates inputs to prevent injection
        - Uses atomic Lua script to prevent race conditions
        - Fails closed on Redis errors (returns high rate to trigger block)
        - Maintains same security semantics as sequential implementation

        Args:
            ja4: JA4 fingerprint (validated by caller)
            ip: IP address (validated by caller)
            window: Window name ('short', 'medium', 'long')

        Returns:
            Dictionary mapping strategy to rate metrics

        Raises:
            ValueError: If inputs are invalid
            RateTrackerError: On tracking errors (fails closed)
        """
        # Input validation
        if not ja4 or not isinstance(ja4, str):
            raise ValueError("JA4 must be non-empty string")
        if not ip or not isinstance(ip, str):
            raise ValueError("IP must be non-empty string")
        if len(ja4) > 256:  # Reasonable limit
            raise ValueError("JA4 too long")
        if len(ip) > 45:  # Max IPv6 length
            raise ValueError("IP too long")

        # Get window size
        window_seconds = self.windows.get(window, 1.0)
        now = time.time()
        ttl = max(self.DEFAULT_TTL_SECONDS, int(window_seconds * 2))

        results = {}

        # Use pipeline batching for all strategies
        try:
            await self._track_with_pipeline_batching(
                ja4, ip, window_seconds, now, ttl, results
            )
        except RateTrackerError as e:
            # If pipeline batching fails, fall back to individual tracking
            self.logger.warning(
                "Pipeline batching failed, falling back to individual tracking: %s", e
            )
            
            # Track for each enabled strategy individually (fallback)
            for strategy in self.enabled_strategies:
                try:
                    metrics = await self._track_single_strategy(
                        ja4, ip, strategy, window_seconds
                    )
                    results[strategy] = metrics
                except RateTrackerError as e:
                    # Log error but continue with other strategies
                    self.logger.error(
                        "Error tracking strategy %s: %s", strategy.value, e
                    )
                    # Fail closed: return high rate to trigger block
                    results[strategy] = RateMetrics(
                        connections_per_second=self.MAX_CONNECTIONS_PER_WINDOW,
                        strategy=strategy,
                        entity_id=f"ERROR:{strategy.value}",
                        timestamp=now,
                        window_seconds=window_seconds,
                    )

        return results

    async def _track_with_pipeline_batching(
        self,
        ja4: str,
        ip: str,
        window_seconds: float,
        now: float,
        ttl: int,
        results: Dict[RateLimitStrategy, RateMetrics]
    ) -> None:
        """
        Track connection for all strategies using Redis pipeline batching.

        This reduces Redis round trips from 3 per strategy to 1 total batch.
        Maintains same security semantics as individual tracking.

        Args:
            ja4: JA4 fingerprint
            ip: IP address
            window_seconds: Window size in seconds
            now: Current timestamp
            ttl: TTL for Redis keys
            results: Dictionary to populate with results

        Raises:
            RateTrackerError: On Redis errors
        """
        if not self.enabled_strategies:
            return

        try:
            # Prepare pipeline
            if self._is_async_redis(self.redis):
                async with self.redis.pipeline(transaction=False) as pipe:
                    # Execute all Lua scripts in pipeline
                    for strategy in self.enabled_strategies:
                        entity_id = strategy.get_entity_id(ja4, ip)
                        key_prefix = strategy.get_redis_key_prefix()
                        key = f"{key_prefix}:{entity_id}:{window_seconds}s"
                        counter_key = f"{key}:counter"

                        # Queue the Lua script execution
                        self.rate_script(
                            keys=[key, counter_key],
                            args=[now, window_seconds, ttl],
                            client=pipe,
                        )

                    # Execute all queued commands
                    script_results = await pipe.execute()
                    
                    # Process results
                    for i, strategy in enumerate(self.enabled_strategies):
                        count = script_results[i]
                        
                        # Validate count (security: prevent DoS)
                        if count > self.MAX_CONNECTIONS_PER_WINDOW:
                            self.logger.warning(
                                "Strategy %s exceeded max connections: %s",
                                strategy.value, count
                            )
                            count = self.MAX_CONNECTIONS_PER_WINDOW

                        entity_id = strategy.get_entity_id(ja4, ip)
                        results[strategy] = RateMetrics(
                            connections_per_second=int(count),
                            strategy=strategy,
                            entity_id=entity_id,
                            timestamp=now,
                            window_seconds=window_seconds,
                        )

            else:
                # Sync Redis client - use transaction
                with self.redis.pipeline(transaction=False) as pipe:
                    # Execute all Lua scripts in pipeline
                    for strategy in self.enabled_strategies:
                        entity_id = strategy.get_entity_id(ja4, ip)
                        key_prefix = strategy.get_redis_key_prefix()
                        key = f"{key_prefix}:{entity_id}:{window_seconds}s"
                        counter_key = f"{key}:counter"

                        # Queue the Lua script execution
                        self.rate_script(
                            keys=[key, counter_key],
                            args=[now, window_seconds, ttl],
                            client=pipe,
                        )

                    # Execute all queued commands
                    script_results = pipe.execute()
                    
                    # Process results
                    for i, strategy in enumerate(self.enabled_strategies):
                        count = script_results[i]
                        
                        # Validate count (security: prevent DoS)
                        if count > self.MAX_CONNECTIONS_PER_WINDOW:
                            self.logger.warning(
                                "Strategy %s exceeded max connections: %s",
                                strategy.value, count
                            )
                            count = self.MAX_CONNECTIONS_PER_WINDOW

                        entity_id = strategy.get_entity_id(ja4, ip)
                        results[strategy] = RateMetrics(
                            connections_per_second=int(count),
                            strategy=strategy,
                            entity_id=entity_id,
                            timestamp=now,
                            window_seconds=window_seconds,
                        )

        except redis.ConnectionError as e:
            raise RateTrackerError(f"Redis connection error: {e}")
        except redis.TimeoutError as e:
            raise RateTrackerError(f"Redis timeout: {e}")
        except redis.RedisError as e:
            raise RateTrackerError(f"Redis error: {e}")
        except Exception as e:
            raise RateTrackerError(f"Unexpected error: {e}")

    async def _track_single_strategy(
        self,
        ja4: str,
        ip: str,
        strategy: RateLimitStrategy,
        window_seconds: float
    ) -> RateMetrics:
        """
        Track connection for a single strategy using atomic Lua script.

        Security:
        - Atomic operation prevents race conditions
        - TTL set in same operation (GDPR compliance)
        - Resource limits prevent Redis DoS

        Args:
            ja4: JA4 fingerprint
            ip: IP address
            strategy: Rate limiting strategy
            window_seconds: Window size in seconds

        Returns:
            Rate metrics for this strategy

        Raises:
            RateTrackerError: On Redis errors or limits exceeded
        """
        try:
            # Get entity ID based on strategy (validated in get_entity_id)
            entity_id = strategy.get_entity_id(ja4, ip)

            # Generate Redis keys
            key_prefix = strategy.get_redis_key_prefix()
            key = f"{key_prefix}:{entity_id}:{window_seconds}s"
            counter_key = f"{key}:counter"

            # Get current time with high precision
            now = time.time()

            # Calculate TTL (GDPR: minimal retention)
            # Keep data for 60 seconds or 2x window, whichever is larger
            ttl = max(self.DEFAULT_TTL_SECONDS, int(window_seconds * 2))

            # Execute atomic Lua script (supports both sync and async Redis clients)
            result = self.rate_script(
                keys=[key, counter_key],
                args=[now, window_seconds, ttl],
                client=self.redis,
            )
            count = await result if inspect.isawaitable(result) else result

            # Validate count (security: prevent DoS)
            if count > self.MAX_CONNECTIONS_PER_WINDOW:
                self.logger.warning(
                    "Strategy %s exceeded max connections: %s",
                    strategy.value, count
                )
                count = self.MAX_CONNECTIONS_PER_WINDOW

            # Create and return metrics
            return RateMetrics(
                connections_per_second=int(count),
                strategy=strategy,
                entity_id=entity_id,
                timestamp=now,
                window_seconds=window_seconds,
            )

        except redis.ConnectionError as e:
            raise RateTrackerError(f"Redis connection error: {e}")
        except redis.TimeoutError as e:
            raise RateTrackerError(f"Redis timeout: {e}")
        except redis.RedisError as e:
            raise RateTrackerError(f"Redis error: {e}")
        except Exception as e:
            raise RateTrackerError(f"Unexpected error: {e}")

    def get_strategy_config(self, strategy: RateLimitStrategy) -> StrategyConfig:
        """
        Get configuration for a specific strategy.

        Args:
            strategy: Rate limiting strategy

        Returns:
            Strategy configuration

        Raises:
            ValueError: If strategy not configured
        """
        strategy_configs = self.config.get('security', {}).get(
            'rate_limit_strategies', {}
        )

        config_dict = strategy_configs.get(strategy.value, {})
        if not config_dict:
            raise ValueError(f"Strategy {strategy.value} not configured")

        return StrategyConfig.from_config_dict(config_dict)

    def health_check(self) -> bool:
        """
        Check if rate tracker is healthy.

        Returns:
            True if healthy, False otherwise
        """
        if self._is_async_redis(self.redis):
            return True  # Async client — cannot ping synchronously; assume healthy.
        try:
            self.redis.ping()
            return True
        except redis.RedisError:
            return False
