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
            f"Rate tracker initialized with strategies: "
            f"{[s.value for s in self.enabled_strategies]}"
        )
    
    def _validate_redis_connection(self) -> None:
        """
        Validate Redis connection is working.
        
        Security: Fail early if Redis is unavailable (fail-closed).
        """
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
                    f"Invalid settings for strategy {strategy_name}, skipping"
                )
                continue
            
            if settings.get('enabled', False):
                # Convert name to enum
                strategy = RateLimitStrategy.from_string(strategy_name)
                if strategy:
                    strategies.append(strategy)
                    self.logger.info(f"Enabled strategy: {strategy.value}")
                else:
                    self.logger.warning(
                        f"Unknown strategy '{strategy_name}', skipping"
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
                        f"Window '{name}' value {value} out of range "
                        f"[{self.MIN_WINDOW_SECONDS}, {self.MAX_WINDOW_SECONDS}], "
                        f"using default"
                    )
            except (TypeError, ValueError):
                self.logger.warning(
                    f"Invalid window '{name}' value: {value}, using default"
                )
        
        return windows
    
    def track_connection(
        self,
        ja4: str,
        ip: str,
        window: str = 'short'
    ) -> Dict[RateLimitStrategy, RateMetrics]:
        """
        Track a connection using all enabled strategies.
        
        This method is the main entry point for rate tracking. It tracks
        the connection across all enabled strategies and returns metrics.
        
        Security:
        - Validates inputs to prevent injection
        - Uses atomic Lua script to prevent race conditions
        - Fails closed on Redis errors (returns high rate to trigger block)
        
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
        
        results = {}
        
        # Track for each enabled strategy
        for strategy in self.enabled_strategies:
            try:
                metrics = self._track_single_strategy(
                    ja4, ip, strategy, window_seconds
                )
                results[strategy] = metrics
            except RateTrackerError as e:
                # Log error but continue with other strategies
                self.logger.error(
                    f"Error tracking strategy {strategy.value}: {e}"
                )
                # Fail closed: return high rate to trigger block
                results[strategy] = RateMetrics(
                    connections_per_second=self.MAX_CONNECTIONS_PER_WINDOW,
                    strategy=strategy,
                    entity_id=f"ERROR:{strategy.value}",
                    timestamp=time.time(),
                    window_seconds=window_seconds,
                )
        
        return results
    
    def _track_single_strategy(
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
            
            # Execute atomic Lua script
            count = self.rate_script(
                keys=[key, counter_key],
                args=[now, window_seconds, ttl],
                client=self.redis
            )
            
            # Validate count (security: prevent DoS)
            if count > self.MAX_CONNECTIONS_PER_WINDOW:
                self.logger.warning(
                    f"Strategy {strategy.value} exceeded max connections: {count}"
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
        try:
            self.redis.ping()
            return True
        except redis.RedisError:
            return False
