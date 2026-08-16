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

Docker vs local (phase-823)
---------------------------
There used to be a pytest_sessionfinish hook that called os._exit() inside
Docker to stop asyncio teardown hanging the container. It also terminated the
process before pytest's terminal reporter had written the FAILURES section, so
a failing test printed "F" and nothing else — no traceback, no assertion
message. Since every Python test in this project runs in a container, that was
every failure. The exit code stayed correct, so CI still went red, just
uninformatively, which is why it survived so long.

Phase 823 re-measured the hang it guarded against and could not reproduce it on
the current pytest / pytest-asyncio / base image, in either xdist or serial
mode, across tests/unit/ and management/tests/. The hook is therefore gone
rather than reordered — the simplest fix was no code. See PHASE_823.md.
"""

import os

# Force dev environment and info logging level for pytest runs.
# This prevents settings from the production .env file (e.g. ENVIRONMENT=production, LOG_LEVEL=WARNING)
# from causing test failures or refusing to start.
os.environ["ENVIRONMENT"] = "dev"
os.environ["LOG_LEVEL"] = "INFO"
os.environ.setdefault("MANAGEMENT_TEST_MODE", "1")
os.environ.setdefault("MANAGEMENT_DISABLE_CSRF", "1")

import ast
import asyncio
import inspect
import sys
import textwrap
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import redis

# Configure hypothesis to use an in-memory database when the default location
# (.hypothesis/examples) is not writable — avoids a HypothesisWarning in the
# tools container where /src is mounted read-owned by a different UID.
try:
    from hypothesis import settings
    from hypothesis.database import InMemoryExampleDatabase

    _hyp_dir = Path(".hypothesis/examples")
    if not (_hyp_dir.exists() and os.access(_hyp_dir, os.W_OK)):
        settings.register_profile("_no_disk_db", database=InMemoryExampleDatabase())
        settings.load_profile("_no_disk_db")
except Exception:  # noqa: BLE001  # hypothesis is optional for non-hypothesis tests
    pass

_SESSION_START: list[float] = []  # populated by pytest_sessionstart

# ── Approved skip registry ────────────────────────────────────────────────────
# Tests that are expected to be skipped in a local dev environment are listed
# here.  Any skip ABOVE this count is flagged as "◀ UNEXPECTED" in the summary.
#
# Current approved skips (13 total) — assumes `make test` or `make cli-build`
# has run so bin/ja4p is present.  Adding to this list requires sign-off.
#   3  Go chaos tests      — tests/chaos/test_go_proxy_chaos.py
#                            (require bin/ja4pd and live proxy; run make start)
#   3  Real Redis tests    — tests/integration/test_analytics_acl.py
#                            (no live Redis with ACL config; set INTEGRATION_REDIS_URL)
#   2  Docker enforcement  — tests/integration/test_multi_process_enforcement.py
#                            (requires Docker Compose multi-process env; set CI_DOCKER=1)
#   4  Performance tests   — tests/performance/test_bench_go_proxy.py
#                            (require live proxy; run make start then make test-perf)
#   1  Schema parity test  — tests/unit/test_schema_parity.py
#                            (requires analytics + management packages importable)
_APPROVED_SKIP_COUNT = 13


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
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
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
    broken = [
        k for k, v in list(sys.modules.items()) if k.startswith("src.") and v is None
    ]
    for key in broken:
        del sys.modules[key]

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
            host="localhost",
            port=6379,
            password="changeme",
            db=0,
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
        if client is not None:
            # Pipelined call — queue only, do not execute immediately.
            # In real Redis, pipelined Lua scripts execute on pipe.execute().
            # The pipeline mock can't return proper results, so the pipeline
            # batching path will fall back to individual tracking (which calls
            # _script without client). Do NOT increment here to avoid double-counting.
            return None
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


# phase-823: the pytest_sessionfinish hook that lived here called os._exit()
# inside Docker. os._exit() terminates immediately — before pytest's terminal
# reporter writes the FAILURES section and short summary — so a failing test
# printed "F" and nothing else. Every Python test here runs in a container, so
# that was every failure, and the exit code stayed correct so CI went red
# uninformatively rather than silently.
#
# The hook was not gratuitous: it guarded against asyncio teardown hanging the
# container. Phase 823 re-measured that hang and could not reproduce it on the
# current pytest / pytest-asyncio / base image — 1864 unit tests (xdist AND
# serial) and 751 management tests all exited cleanly in seconds with the hook
# removed. So it is deleted rather than reordered.
#
# Note `trylast=True` was tried first and does NOT fix the truncation: the
# terminal reporter's own sessionfinish runs in the same phase, and ordering
# alone does not guarantee it wins. Verified empirically — do not "restore" the
# hook with trylast on the assumption that it is safe.
#
# tests/unit/test_pytest_reporting.py fails if any conftest reintroduces
# os._exit() in a sessionfinish hook.


# ── Terminal summary ──────────────────────────────────────────────────────────


def pytest_terminal_summary(terminalreporter, exitstatus, config) -> None:
    """Print a clean results block at the very end of the run."""
    tr = terminalreporter
    stats = tr.stats

    passed = len(stats.get("passed", []))
    failed = len(stats.get("failed", []))
    errored = len(stats.get("error", []))
    skipped = len(stats.get("skipped", []))
    warnings = len(stats.get("warnings", []))

    elapsed = time.monotonic() - (
        _SESSION_START[0] if _SESSION_START else time.monotonic()
    )

    tr.write_sep("━", "SUMMARY")
    tr.write_line(f"  Passed:   {passed}")
    if failed:
        tr.write_line(f"  Failed:   {failed}  ◀ FAILURES")
    if errored:
        tr.write_line(f"  Errors:   {errored}  ◀ ERRORS")
    if skipped:
        unexpected = max(0, skipped - _APPROVED_SKIP_COUNT)
        if unexpected:
            tr.write_line(
                f"  Skipped:  {skipped} ({unexpected} unexpected)  ◀ UNEXPECTED"
            )
        else:
            tr.write_line(f"  Skipped:  {skipped} (all approved)")
    if warnings:
        tr.write_line(f"  Warnings: {warnings}")
    tr.write_line(f"  Duration: {elapsed:.1f}s  ({elapsed / 60:.1f} min)")

    results = Path("test-results")
    if results.exists():
        for name, sym in [("Log", "latest.log"), ("JUnit", "latest-junit.xml")]:
            p = results / sym
            if p.exists():
                tr.write_line(f"  {name + ':':8s} {p}")

    tr.write_sep("━", "")
