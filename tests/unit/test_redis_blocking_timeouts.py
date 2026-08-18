"""A blocking Redis read must never out-live its socket deadline.

WHY THIS EXISTS
---------------
Found 2026-08-17 while asking why the console's Intelligence panel was always
empty. The analytics stream consumer had been logging

    Stream consumer error: Timeout reading from redis:6379

on a 1-second retry loop, continuously, and nobody noticed because the loop
caught the exception, printed it, and carried on.

The cause was a coincidence of two 5-second numbers:

  * `consume_events()` called `xreadgroup(..., block=5000)` — asking the SERVER
    to hold the request open for 5s waiting for events.
  * `redis.asyncio.from_url()` in redis-py 8.x defaults `socket_timeout` to 5s —
    the CLIENT's read deadline.

Identical, so the client deadline fired at the same instant the server was due
to reply. The client always lost. Every poll raised TimeoutError; not one event
was ever ingested. No events -> no detection cycle output -> no findings written
-> the Intelligence panel truthfully reported "No high-confidence findings
active" for a pipeline that had never once run.

This is a nasty failure mode because every individual piece looks healthy: the
container is up, /health returns 200, PING works, XGROUP CREATE works, and the
panel renders without error. Only the blocking read fails.

Three call sites shared the defect (analytics consumer, ti_feeds runner,
management's live event feed), so these tests are structural rather than a
one-off assertion: relying on the library's default socket_timeout is the bug,
and any new blocking read inherits it.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

# Every module that constructs a Redis client used for blocking reads.
CLIENT_MODULES = [
    REPO / "src" / "analytics" / "stream_consumer.py",
    REPO / "src" / "analytics" / "main.py",
    REPO / "management" / "api" / "redis_client.py",
]

# Every module that issues a blocking read.
BLOCKING_CALL_MODULES = [
    REPO / "src" / "analytics" / "stream_consumer.py",
    REPO / "src" / "analytics" / "ti_feeds" / "runner.py",
    REPO / "management" / "api" / "routes" / "events.py",
]

_BLOCKING_METHODS = {"xread", "xreadgroup", "blpop", "brpop", "bzpopmin", "bzpopmax"}
_CONSTRUCTORS = {"from_url", "Redis", "ConnectionPool"}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _call_name(node: ast.Call) -> str:
    f = node.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return ""


def _kwarg(node: ast.Call, name: str) -> ast.expr | None:
    for kw in node.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _client_constructions(path: Path) -> list[ast.Call]:
    """Redis constructions in `path` that OWN their connection settings.

    `Redis(connection_pool=pool)` is skipped deliberately: it is a thin wrapper
    that inherits socket_timeout from the pool, so the pool is the only place
    the setting can meaningfully live. Flagging the wrapper too would demand a
    redundant kwarg that redis-py ignores.
    """
    out = []
    for node in ast.walk(_tree(path)):
        if not isinstance(node, ast.Call) or _call_name(node) not in _CONSTRUCTORS:
            continue
        # Only Redis ones: the callee chain must mention redis/aioredis/pool.
        src = ast.unparse(node.func).lower()
        if "redis" not in src and "connectionpool" not in src:
            continue
        if _kwarg(node, "connection_pool") is not None:
            continue
        out.append(node)
    return out


@pytest.mark.parametrize("path", CLIENT_MODULES, ids=lambda p: p.name)
def test_every_redis_client_sets_socket_timeout_explicitly(path: Path):
    """Never inherit the library default — that default IS the bug.

    redis-py's default has changed across major versions (8.x introduced the 5s
    that collided with block=5000). Pinning it explicitly means a library bump
    cannot silently re-break the consumer.
    """
    missing = [
        f"{path.name}:{node.lineno} {ast.unparse(node.func)}(...)"
        for node in _client_constructions(path)
        if _kwarg(node, "socket_timeout") is None
    ]
    assert not missing, (
        "Redis client(s) constructed without an explicit socket_timeout:\n  "
        + "\n  ".join(missing)
        + "\n\nredis-py 8.x defaults socket_timeout to 5s. Any blocking read with "
        "block >= 5000ms will then raise TimeoutError on EVERY call, silently, "
        "forever. Pass socket_timeout explicitly and keep it above the block."
    )


def test_stream_consumer_block_is_clamped_below_its_socket_timeout():
    """The clamp is what survives a hot reload of stream.timeout_ms.

    `timeout_ms` is reloadable at runtime (main.py handles SIGHUP), so a value
    set once at connect() time is not enough — someone can raise the block
    window past the socket deadline while the process is running.
    """
    from src.analytics.stream_consumer import (
        _BLOCK_MARGIN_S,
        _SOCKET_TIMEOUT_S,
        MAX_BLOCK_MS,
    )

    assert MAX_BLOCK_MS < _SOCKET_TIMEOUT_S * 1000, (
        f"max block {MAX_BLOCK_MS}ms must be strictly under the "
        f"{_SOCKET_TIMEOUT_S}s socket deadline"
    )
    assert _BLOCK_MARGIN_S >= 1.0, "margin too small to absorb scheduling jitter"


def test_stream_consumer_actually_applies_the_clamp():
    """Guard the clamp itself, not just the constants.

    Without `block=min(timeout_ms, MAX_BLOCK_MS)` the constants above are
    decorative.
    """
    src = (REPO / "src" / "analytics" / "stream_consumer.py").read_text()
    tree = ast.parse(src)
    blocks = [
        _kwarg(n, "block")
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and _call_name(n) in _BLOCKING_METHODS
    ]
    blocks = [b for b in blocks if b is not None]
    assert blocks, "no blocking read found in stream_consumer.py — did it move?"
    for b in blocks:
        rendered = ast.unparse(b)
        assert "MAX_BLOCK_MS" in rendered, (
            f"blocking read uses block={rendered!r}, which is not clamped to "
            "MAX_BLOCK_MS. A hot-reloaded timeout_ms could then exceed the "
            "socket deadline and re-create the silent-timeout bug."
        )


@pytest.mark.parametrize("path", BLOCKING_CALL_MODULES, ids=lambda p: p.name)
def test_literal_block_windows_stay_under_thirty_seconds(path: Path):
    """Any literal `block=` must fit inside the 30s socket budget we pin."""
    from management.api.redis_client import BLOCKING_SOCKET_TIMEOUT_S

    budget_ms = BLOCKING_SOCKET_TIMEOUT_S * 1000
    offenders = []
    for node in ast.walk(_tree(path)):
        if not isinstance(node, ast.Call) or _call_name(node) not in _BLOCKING_METHODS:
            continue
        b = _kwarg(node, "block")
        if isinstance(b, ast.Constant) and isinstance(b.value, (int, float)):
            if b.value >= budget_ms:
                offenders.append(f"{path.name}:{node.lineno} block={b.value}")
    assert not offenders, (
        f"blocking read(s) at or above the {BLOCKING_SOCKET_TIMEOUT_S}s socket "
        f"deadline:\n  " + "\n  ".join(offenders)
    )


def test_management_event_feed_block_is_under_its_pool_timeout():
    """The console's live event feed shares the management pool."""
    from management.api.redis_client import BLOCKING_SOCKET_TIMEOUT_S

    src = (REPO / "management" / "api" / "routes" / "events.py").read_text()
    m = re.search(r"^_BLOCK_MS\s*=\s*(\d+)", src, re.M)
    assert m, "_BLOCK_MS not found in routes/events.py"
    block_ms = int(m.group(1))
    assert block_ms < BLOCKING_SOCKET_TIMEOUT_S * 1000, (
        f"events.py blocks for {block_ms}ms on a pool whose socket deadline is "
        f"{BLOCKING_SOCKET_TIMEOUT_S * 1000:.0f}ms — the live event feed would "
        "time out on every poll."
    )
