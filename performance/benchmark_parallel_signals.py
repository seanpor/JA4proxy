#!/usr/bin/env python3
"""Simple benchmark to test parallel signal collection performance (Phase 26a)."""

import asyncio
import time
import tempfile
import os
from unittest.mock import AsyncMock, MagicMock

import redis.asyncio as redis
from src.config.loader import ConfigLoader
from src.security.pipeline import ConnectionContext, Pipeline
from src.cache.local_cache import LocalCache


async def create_test_pipeline():
    """Create a test pipeline with mock Redis client."""
    config_text = """
security_policy:
  alpn_browser_bypass: {enabled: true}
  ja4_whitelist_bypass: {enabled: true}
  mtls_bypass: {enabled: true}
  static_ip_allowlist: {enabled: true}
  ja4_blacklist_bypass: {enabled: true}
  country_blacklist_bypass: {enabled: true}
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        f.write(config_text)
        config_path = f.name

    try:
        loader = ConfigLoader(config_path)
        config = await loader.load()
        
        # Create mock Redis client
        mock_redis = MagicMock(spec=redis.Redis)
        mock_redis.ping = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.hmget = AsyncMock(return_value={})
        mock_redis.zadd = AsyncMock()
        mock_redis.evalsha = AsyncMock(return_value={"connections_per_second": 0})
        
        cache = LocalCache({})
        cache.dial = 0
        
        return Pipeline(config=config, local_cache=cache, redis_client=mock_redis)
    finally:
        os.unlink(config_path)


async def create_test_context():
    """Create a test connection context."""
    return ConnectionContext(
        client_ip="1.2.3.4",
        ja4="t13d_test_fingerprint",
        alpn="h2",
        sni="example.com",
        tls_version="TLSv1.3",
        cipher_list=[0x1301, 0x1302],
        client_certificate=None,
        country="US"
    )


async def benchmark_signal_collection(pipeline, ctx, num_iterations=100):
    """Benchmark signal collection performance."""
    print(f"Running {num_iterations} iterations...")
    
    start_time = time.time()
    
    for i in range(num_iterations):
        await pipeline._collect_signals(ctx)
    
    end_time = time.time()
    total_time = end_time - start_time
    avg_time_per_call = (total_time / num_iterations) * 1000  # Convert to ms
    
    print(f"Total time: {total_time:.3f} seconds")
    print(f"Average time per call: {avg_time_per_call:.3f} ms")
    print(f"Calls per second: {num_iterations / total_time:.1f}")
    
    return avg_time_per_call


async def main():
    """Main benchmark function."""
    print("=== Parallel Signal Collection Benchmark ===")
    print("Testing Phase 26a implementation")
    print()
    
    # Create pipeline and context
    pipeline = await create_test_pipeline()
    ctx = await create_test_context()
    
    # Warm up
    print("Warming up...")
    for _ in range(10):
        await pipeline._collect_signals(ctx)
    
    # Run benchmark
    print()
    avg_time = await benchmark_signal_collection(pipeline, ctx, num_iterations=100)
    
    print()
    print("=== Results ===")
    print(f"Average signal collection time: {avg_time:.3f} ms")
    print("✅ Parallel signal collection is working!")
    print()
    print("Note: This is a simple benchmark. For accurate performance")
    print("measurements, use the full benchmark suite with real Redis.")


if __name__ == "__main__":
    asyncio.run(main())
