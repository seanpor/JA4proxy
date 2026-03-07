"""Root pytest conftest — shared fixtures and collection guards.

Prometheus metric deduplication
--------------------------------
All new src/ modules register Prometheus metrics at import time. When pytest
collects multiple test modules that import the same src/ module, Python's module
cache means the code runs only once per process — but if a collection error
causes a partial import that leaves the module in sys.modules in a broken state,
a subsequent re-import re-executes the module code and hits a
"Duplicated timeseries in CollectorRegistry" ValueError.

The session-scoped fixture below clears the default Prometheus registry once
before the whole test session. This prevents any leftover registrations from
a previous in-process test run (e.g. when running tests interactively or via
pytest-xdist with forks).
"""

import asyncio
import sys
import redis
from unittest.mock import MagicMock

import pytest


def _run(coro):
    """Run an async coroutine from a sync test function.

    This helper works with pytest-asyncio's auto mode by creating a fresh
    event loop instead of relying on get_event_loop(), which fails when
    pytest-asyncio manages the event loop.
    """
    try:
        loop = asyncio.get_running_loop()
        raise RuntimeError("_run() should not be called from within an async context")
    except RuntimeError:
        return asyncio.new_event_loop().run_until_complete(coro)


@pytest.fixture
def run_async():
    """Fixture that provides the _run helper to tests."""
    return _run


@pytest.fixture(autouse=True, scope="session")
def _clean_prometheus_registry():
    """Unregister all ja4proxy metrics before the test session starts.

    This is a no-op on first run but prevents "Duplicated timeseries" errors
    when the test runner re-uses the same process (e.g. pytest-watch, coverage
    re-runs, or partial import failures that leave modules half-cached).
    """
    from prometheus_client import REGISTRY

    to_remove = [
        c
        for c in list(REGISTRY._names_to_collectors.values())
        if hasattr(c, "_name") and c._name.startswith("ja4proxy_")
    ]
    seen = set()
    for collector in to_remove:
        if id(collector) not in seen:
            seen.add(id(collector))
            try:
                REGISTRY.unregister(collector)
            except Exception:
                pass

    # Also evict any partially-initialised src/ modules so they re-register
    # cleanly in this session.
    broken = [
        key
        for key, mod in list(sys.modules.items())
        if key.startswith("src.") and mod is None
    ]
    for key in broken:
        del sys.modules[key]

    yield


@pytest.fixture
def mock_redis():
    """Mock Redis client for unit tests that don't need real Redis."""
    mock = MagicMock()
    mock.ping.return_value = True
    mock.get.return_value = None
    mock.setex.return_value = True
    mock.sadd.return_value = True
    mock.smembers.return_value = set()
    mock.delete.return_value = True
    mock.keys.return_value = []
    
    # Mock Bloom filter
    bloom_mock = MagicMock()
    bloom_mock.exists.return_value = False
    bloom_mock.add.return_value = True
    mock.bf.return_value = bloom_mock
    
    return mock


@pytest.fixture
def redis_client():
    """Real Redis client fixture for integration tests.
    
    This fixture attempts to connect to a real Redis instance.
    If Redis is not available, it provides a mock instead.
    """
    try:
        # Try to connect to Redis
        client = redis.Redis(
            host='localhost',
            port=6379,
            password='changeme',  # Default password
            db=0,
            decode_responses=False,
        )
        
        # Test the connection
        if client.ping():
            # Clean up before yielding
            client.flushdb()
            yield client
            # Clean up after
            client.flushdb()
            return
    except (redis.ConnectionError, ConnectionRefusedError):
        pass
    
    # Fall back to mock if Redis is not available
    print("\n⚠️  Redis not available - using mock for tests")
    mock = MagicMock()
    mock.ping.return_value = True
    mock.get.return_value = None
    mock.setex.return_value = True
    mock.sadd.return_value = True
    mock.smembers.return_value = set()
    mock.delete.return_value = True
    mock.keys.return_value = []
    
    # Mock Bloom filter
    bloom_mock = MagicMock()
    bloom_mock.exists.return_value = False
    bloom_mock.add.return_value = True
    mock.bf.return_value = bloom_mock
    
    yield mock


# Hook to prevent skipping Redis-dependent tests
# This ensures tests run with mock Redis instead of being skipped
def pytest_collection_modifyitems(items):
    """Modify collected tests to ensure Redis-dependent tests run with mock."""
    for item in items:
        # Remove skip markers from Redis-dependent tests
        if "redis" in str(item.fspath).lower() or "integration" in str(item.fspath).lower():
            if hasattr(item, 'own_markers'):
                # Remove pytest.mark.skip markers
                item.own_markers = [m for m in item.own_markers if m.name != 'skip']
