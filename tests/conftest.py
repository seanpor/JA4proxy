"""Root pytest conftest — shared fixtures, collection guards, and reporting.

Prometheus metric deduplication
--------------------------------
All src/ modules register Prometheus metrics at import time. When pytest
collects multiple test modules that import the same src/ module, a partial
import failure can leave the module in sys.modules in a broken state; on
re-import the registration code runs again and raises
"Duplicated timeseries in CollectorRegistry".

The _clean_prometheus_registry session fixture clears all ja4proxy metrics
before the session starts, preventing this on repeated or parallel runs.

Network isolation
-----------------
ASNClassifier._refresh_tor_list makes a real HTTP request to torproject.org
on first use. With a MagicMock Redis the classifier always believes it is the
download leader, adding ~4 s per test. The _no_real_network session fixture
patches this to a no-op for the entire session, keeping the suite under 2
minutes even on a slow machine.

Tests that need real Tor exit IPs populate _tor_exit_ips directly.

Empty-test guard
----------------
Any test whose body is nothing but `pass` (or only a docstring) is detected
at collection time and causes an immediate failure. Every test must contain
real assertions or test logic.

Docker vs local
---------------
pytest_sessionfinish uses os._exit() only inside Docker containers (where
normal asyncio teardown can hang the process indefinitely). On a local
development machine pytest exits normally, which lets asyncio clean up
pending tasks cleanly and produces no spurious warnings.
"""

import ast
import asyncio
import inspect
import sys
import textwrap
import time
import redis
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_SESSION_START: list[float] = []  # populated by pytest_sessionstart


# ── Helpers ───────────────────────────────────────────────────────────────────

def _run(coro):
    """Run an async coroutine from a sync context."""
    return asyncio.run(coro)


def pytest_sessionstart(session) -> None:  # noqa: ARG001
    """Record monotonic start time for our custom terminal summary."""
    _SESSION_START.append(time.monotonic())


# ── Empty-test guard ──────────────────────────────────────────────────────────

def _test_body_is_empty(func) -> bool:
    """Return True if the test function body is only ``pass`` or a docstring.

    Uses AST analysis. Returns False (not empty) if the source cannot be
    parsed — we err on the side of allowing the test to run.
    """
    try:
        raw = inspect.getsource(func)
        tree = ast.parse(textwrap.dedent(raw))
    except Exception:
        return False  # Can't parse — assume OK

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = node.body
        # Strip a leading docstring
        if (body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            body = body[1:]
        # Empty or pass-only
        if not body or all(isinstance(s, ast.Pass) for s in body):
            return True
        return False  # Has real content
    return False


def pytest_collection_finish(session) -> None:
    """Abort if any collected test has an empty body (pass / docstring only)."""
    empty = [
        item.nodeid
        for item in session.items
        if hasattr(item, "function") and _test_body_is_empty(item.function)
    ]
    if empty:
        lines = "\n".join(f"  {t}" for t in empty)
        pytest.exit(
            f"\n\nERROR: {len(empty)} empty test(s) detected "
            f"(body is only 'pass' or a docstring):\n{lines}\n\n"
            "All tests must contain real assertions or test logic.\n",
            returncode=3,
        )


# ── Session fixtures ───────────────────────────────────────────────────────────

@pytest.fixture
def run_async():
    """Provide the _run() helper to sync tests that exercise async code."""
    return _run


@pytest.fixture(autouse=True, scope="session")
def _clean_prometheus_registry():
    """Unregister all ja4proxy Prometheus metrics before the session starts.

    No-op on the first run; prevents "Duplicated timeseries" errors on
    subsequent runs (pytest-watch, parallel workers, partial import failures).
    """
    from prometheus_client import REGISTRY

    to_remove = [
        c
        for c in list(REGISTRY._names_to_collectors.values())
        if hasattr(c, "_name") and c._name.startswith("ja4proxy_")
    ]
    seen: set = set()
    for collector in to_remove:
        if id(collector) not in seen:
            seen.add(id(collector))
            try:
                REGISTRY.unregister(collector)
            except Exception:
                pass

    # Evict partially-initialised src/ modules so they re-register cleanly.
    broken = [k for k, v in list(sys.modules.items())
              if k.startswith("src.") and v is None]
    for key in broken:
        del sys.modules[key]

    yield


@pytest.fixture(autouse=True, scope="session")
def _no_real_network():
    """Prevent real HTTP calls to torproject.org during the test session.

    ASNClassifier._refresh_tor_list downloads the Tor exit node list on first
    use. Patching it to an async no-op keeps the suite fast and deterministic.
    Chaos tests that need to exercise real refresh logic use patch.object on
    the specific instance.
    """
    async def _noop(*args, **kwargs):
        pass

    with patch(
        "src.security.asn_classifier.ASNClassifier._refresh_tor_list",
        new=_noop,
    ):
        yield


# ── Redis fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture
def mock_redis():
    """Minimal MagicMock Redis for unit tests that don't need real Redis."""
    mock = MagicMock()
    mock.ping.return_value = True
    mock.get.return_value = None
    mock.setex.return_value = True
    mock.sadd.return_value = True
    mock.smembers.return_value = set()
    mock.delete.return_value = True
    mock.keys.return_value = []

    bloom_mock = MagicMock()
    bloom_mock.exists.return_value = False
    bloom_mock.add.return_value = True
    mock.bf.return_value = bloom_mock

    return mock


@pytest.fixture
def redis_client():
    """Real Redis client for integration tests; falls back to a mock.

    Falls back silently — integration tests are written to work with either.
    """
    try:
        client = redis.Redis(
            host="localhost", port=6379, password="changeme", db=0,
            decode_responses=False,
        )
        if client.ping():
            client.flushdb()
            yield client
            client.flushdb()
            return
    except (redis.ConnectionError, ConnectionRefusedError):
        pass

    # ── Mock fallback ──────────────────────────────────────────────────────────
    from collections import defaultdict

    mock = MagicMock()
    mock.ping.return_value = True
    mock.get.return_value = None
    mock.setex.return_value = True

    redis_sets: dict = {}
    redis_counters: dict = defaultdict(int)
    redis_keys_with_ttl: set = set()

    def _sadd(key, *values):
        k = key.decode() if isinstance(key, bytes) else str(key)
        redis_sets.setdefault(k, set())
        for v in values:
            redis_sets[k].add(v if isinstance(v, bytes) else str(v).encode())
        return len(redis_sets[k])

    def _smembers(key):
        k = key.decode() if isinstance(key, bytes) else str(key)
        return redis_sets.get(k, set())

    def _delete(*keys):
        for key in keys:
            k = key.decode() if isinstance(key, bytes) else str(key)
            redis_sets.pop(k, None)
        return 1

    def _script(keys=None, args=None, client=None):
        if keys:
            k = keys[0].decode() if isinstance(keys[0], bytes) else str(keys[0])
            redis_counters[k] += 1
            redis_keys_with_ttl.add(k)
            return redis_counters[k]
        return 1

    def _keys(pattern):
        prefix = pattern.rstrip("*")
        return [k.encode() for k in redis_keys_with_ttl if k.startswith(prefix)]

    script_mock = MagicMock()
    script_mock.side_effect = _script
    mock.register_script.return_value = script_mock
    mock.sadd.side_effect = _sadd
    mock.smembers.side_effect = _smembers
    mock.delete.side_effect = _delete
    mock.keys.side_effect = _keys
    mock.ttl.return_value = 30

    bloom_mock = MagicMock()
    bloom_mock.exists.return_value = False
    bloom_mock.add.return_value = True
    mock.bf.return_value = bloom_mock

    yield mock

    redis_counters.clear()
    redis_keys_with_ttl.clear()
    redis_sets.clear()


# ── Collection helpers ────────────────────────────────────────────────────────

def pytest_collection_modifyitems(items) -> None:
    """Remove any stray skip markers from integration/redis tests.

    These tests are designed to fall back to mocks, not to be skipped.
    """
    for item in items:
        fspath = str(getattr(item, "fspath", ""))
        if "redis" in fspath.lower() or "integration" in fspath.lower():
            if hasattr(item, "own_markers"):
                item.own_markers = [m for m in item.own_markers if m.name != "skip"]


# ── Shutdown ──────────────────────────────────────────────────────────────────


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus) -> None:  # noqa: ARG001
    """Use os._exit() only inside Docker to prevent container hangs.

    On a local development machine, let pytest exit normally so that asyncio
    can cancel pending tasks cleanly — this avoids the spurious
    "Cancelled N pending asyncio tasks" messages that os._exit() causes.
    """
    import os
    if os.path.exists("/.dockerenv"):
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(int(exitstatus))
    # Local: normal exit — asyncio teardown runs cleanly


# ── Terminal summary ──────────────────────────────────────────────────────────

def pytest_terminal_summary(terminalreporter, exitstatus, config) -> None:
    """Print a clean results block at the very end of the run."""
    tr = terminalreporter
    stats = tr.stats

    passed   = len(stats.get("passed",   []))
    failed   = len(stats.get("failed",   []))
    errored  = len(stats.get("error",    []))
    skipped  = len(stats.get("skipped",  []))
    warnings = len(stats.get("warnings", []))

    elapsed = time.monotonic() - (_SESSION_START[0] if _SESSION_START else time.monotonic())

    tr.write_sep("━", "SUMMARY")
    tr.write_line(f"  Passed:   {passed}")
    if failed:
        tr.write_line(f"  Failed:   {failed}  ◀ FAILURES")
    if errored:
        tr.write_line(f"  Errors:   {errored}  ◀ ERRORS")
    if skipped:
        tr.write_line(f"  Skipped:  {skipped}  ◀ UNEXPECTED")
    if warnings:
        tr.write_line(f"  Warnings: {warnings}")
    tr.write_line(f"  Duration: {elapsed:.1f}s  ({elapsed/60:.1f} min)")

    results = Path("test-results")
    if results.exists():
        for name, sym in [("Log", "latest.log"), ("JUnit", "latest-junit.xml")]:
            p = results / sym
            if p.exists():
                tr.write_line(f"  {name+':':8s} {p}")

    tr.write_sep("━", "")
