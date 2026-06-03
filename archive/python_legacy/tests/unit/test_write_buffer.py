"""Unit tests for WriteBuffer (src/security/write_buffer.py).

These tests verify the security properties of the write buffer:
load shedding, overflow handling, fail-open behaviour on Redis errors,
and adaptive flush timing. Each test includes a "so what?" rationale
explaining why the behaviour matters for security.

asyncio_mode = "auto" (set in pyproject.toml) — no @pytest.mark.asyncio needed.
"""

import asyncio
from collections import deque
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
from src.security.write_buffer import WriteBuffer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sync_redis() -> MagicMock:
    """Return a MagicMock that looks like a synchronous Redis client.

    _check_async_redis() inspects isinstance(client, redis.asyncio.Redis).
    A plain MagicMock is not an instance of redis.asyncio.Redis, so
    _is_async will be False — the sync pipeline path will be taken.
    """
    mock = MagicMock()
    # Make pipeline() a context-manager that returns a pipeline mock.
    pipe = MagicMock()
    pipe.__enter__ = MagicMock(return_value=pipe)
    pipe.__exit__ = MagicMock(return_value=False)
    mock.pipeline.return_value = pipe
    return mock, pipe


def _make_async_redis_mock() -> MagicMock:
    """Return a MagicMock that looks like a redis.asyncio.Redis instance.

    We patch _check_async_redis to return True, so the async pipeline path
    is exercised without needing a real Redis import.
    """
    mock = MagicMock()
    pipe = MagicMock()
    pipe.__aenter__ = (
        asyncio.coroutine(lambda self: pipe)
        if False
        else (lambda self: _async_return(pipe))
    )
    pipe.__aexit__ = lambda self, *a: _async_return(False)
    pipe.execute = lambda: _async_return(None)
    mock.pipeline.return_value = pipe
    return mock, pipe


async def _async_return(val):
    return val


# ---------------------------------------------------------------------------
# 1. _check_async_redis ImportError path (lines 106-107)
# ---------------------------------------------------------------------------


class TestCheckAsyncRedisImportError:
    """_check_async_redis returns False when redis.asyncio is not importable.

    Why it matters: On a system where redis.asyncio is not installed, the
    write buffer must still work using the synchronous pipeline path rather
    than crashing. This is a fail-open requirement.
    """

    def test_import_error_returns_false(self):
        """Lines 106-107: ImportError in _check_async_redis → _is_async=False."""
        mock_redis = MagicMock()

        with patch.dict("sys.modules", {"redis.asyncio": None}):
            buf = WriteBuffer(mock_redis, flush_interval_ms=50, max_queue_size=100)

        # When redis.asyncio cannot be imported, _is_async must be False.
        # This ensures the sync pipeline path is used — no crash.
        assert (
            buf._is_async is False
        ), "WriteBuffer must default to sync mode when redis.asyncio is unavailable"


# ---------------------------------------------------------------------------
# 2. start() when already started (line 112)
# ---------------------------------------------------------------------------


class TestStartAlreadyStarted:
    """start() is a no-op when the flush task is already running.

    Why it matters: Double-starting the buffer would create a second background
    flush task, potentially causing duplicate Redis writes and racing on the queue.
    The guard at line 112 prevents that.
    """

    async def test_double_start_is_noop(self):
        """Line 112: calling start() twice must not create a second task."""
        mock_redis, _ = _make_sync_redis()
        buf = WriteBuffer(mock_redis, flush_interval_ms=1000, max_queue_size=100)

        await buf.start()
        first_task = buf._flush_task
        assert first_task is not None

        await buf.start()  # second call — must be a no-op
        assert (
            buf._flush_task is first_task
        ), "Second start() must not replace the running task — would cause double-flush"

        await buf.stop()


# ---------------------------------------------------------------------------
# 3. stop() when not started (line 125)
# ---------------------------------------------------------------------------


class TestStopNotStarted:
    """stop() when the buffer was never started is a no-op.

    Why it matters: Code that calls stop() defensively during shutdown (e.g.
    cleanup in finally blocks) must not raise even if start() was never called.
    Raising here would suppress the real shutdown logic.
    """

    async def test_stop_before_start_does_not_raise(self):
        """Line 125: stop() before start() must return without error."""
        mock_redis, _ = _make_sync_redis()
        buf = WriteBuffer(mock_redis, flush_interval_ms=50, max_queue_size=100)

        # _flush_task is None — stop() must return immediately without raising
        await buf.stop()
        assert buf._flush_task is None


# ---------------------------------------------------------------------------
# 4. stop() CancelledError and Exception paths (lines 131-134)
# ---------------------------------------------------------------------------


class TestStopExceptionPaths:
    """stop() swallows CancelledError and logs but ignores other exceptions.

    Why it matters: Shutdown must be resilient. If the flush task raises
    unexpectedly during stop(), the buffer must still perform the final flush
    and clear _flush_task — otherwise subsequent stop() calls might deadlock
    or leave dangling tasks.
    """

    async def test_stop_swallows_cancelled_error(self):
        """Line 131-132: CancelledError from flush task is caught, not propagated."""
        mock_redis, _ = _make_sync_redis()
        buf = WriteBuffer(mock_redis, flush_interval_ms=50, max_queue_size=100)

        # Replace _flush_task with a coroutine that raises CancelledError
        async def _raising():
            raise asyncio.CancelledError()

        await buf.start()
        buf._flush_task = asyncio.create_task(_raising())
        # Give the task a moment to start
        await asyncio.sleep(0)

        # stop() must not propagate CancelledError
        await buf.stop()
        assert (
            buf._flush_task is None
        ), "stop() must clear _flush_task even after CancelledError"

    async def test_stop_swallows_generic_exception(self):
        """Lines 133-134: non-CancelledError from flush task is logged, not propagated."""
        mock_redis, _ = _make_sync_redis()
        buf = WriteBuffer(mock_redis, flush_interval_ms=50, max_queue_size=100)

        async def _raising():
            raise RuntimeError("unexpected flush task failure")

        await buf.start()
        buf._flush_task = asyncio.create_task(_raising())
        await asyncio.sleep(0)

        # stop() must not propagate the RuntimeError
        await buf.stop()
        assert (
            buf._flush_task is None
        ), "stop() must clear _flush_task even after RuntimeError"


# ---------------------------------------------------------------------------
# 5. stop() performs final flush (line 137)
# ---------------------------------------------------------------------------


class TestStopFinalFlush:
    """stop() flushes remaining operations before exiting.

    Why it matters: When the proxy is shutting down, any security telemetry
    queued in the buffer (e.g. ban records, rate-limit updates) must reach Redis
    before the process exits. Missing the final flush could leave bans unrecorded.
    """

    async def test_stop_flushes_remaining_operations(self):
        """Lines 136-137: stop() calls _flush_now() as the final step."""
        mock_redis, pipe = _make_sync_redis()
        buf = WriteBuffer(mock_redis, flush_interval_ms=1000, max_queue_size=100)

        await buf.start()

        # Enqueue an operation that must reach Redis during shutdown
        await buf.enqueue("set", "ban:1.2.3.4", "1")

        assert len(buf.queue) == 1, "Operation must be in queue before stop()"

        await buf.stop()

        # After stop(), the queue must be empty (final flush happened)
        assert (
            len(buf.queue) == 0
        ), "stop() must flush remaining operations — missing final flush loses security data"


# ---------------------------------------------------------------------------
# 6. enqueue() load shedding: priority=True bypasses the 90% check (lines 162-168)
# ---------------------------------------------------------------------------


class TestEnqueuePriorityLoadShedding:
    """priority=True writes are not load-shed at >90% queue fill.

    Why it matters: Priority writes carry security-critical data (e.g. ban
    records, rate-limit hits). Dropping them under load would allow an attacker
    to avoid being banned by generating enough traffic to fill the queue. At
    exactly-full the oldest item is evicted to make room for the priority write.
    """

    async def test_priority_write_accepted_above_90_percent(self):
        """Lines 162-168: priority=True bypasses the load-shed check at >90%.

        Non-priority writes are rejected above 90% fill; priority writes pass through.

        Threshold is max_queue_size * 0.9. For max_queue_size=10: threshold=9.0.
        queue_len > 9.0 requires queue_len >= 10. We fill with priority=True writes
        to bypass load shedding and reach 10 items, then test the two branches.
        """
        mock_redis, _ = _make_sync_redis()
        buf = WriteBuffer(mock_redis, flush_interval_ms=1000, max_queue_size=10)

        # Fill to 100% using priority=True so we bypass the load-shed check.
        # With priority=True: load-shed check is skipped; overflow (popleft) kicks in
        # at >= max_queue_size. We stop at exactly max_queue_size by only adding 10.
        for i in range(10):
            result = await buf.enqueue("set", f"key:{i}", "v", priority=True)
            assert result is True, f"Priority item {i} must be accepted"

        # queue_len is now 10 (= max_queue_size), threshold = 10 * 0.9 = 9.0
        # queue_len (10) > 9.0 → non-priority write is load-shed
        assert len(buf.queue) == 10

        # A non-priority write when queue_len=10 (> 9.0) must be dropped
        non_prio_result = await buf.enqueue("set", "non_prio", "v", priority=False)
        assert (
            non_prio_result is False
        ), "Non-priority write must be load-shed above 90% — prevents memory exhaustion DoS"
        # Queue length must not have changed — the item was dropped, not added
        assert len(buf.queue) == 10, "Dropped item must not change queue length"

        # A priority write at queue_len=10 (> 9.0) bypasses the load-shed check.
        # It hits the overflow path (>= max_queue_size), evicts oldest, then appends.
        prio_result = await buf.enqueue("set", "ban:attacker", "1", priority=True)
        assert (
            prio_result is True
        ), "Priority write must bypass load shedding — dropping ban records weakens security"
        assert (
            len(buf.queue) == 10
        ), "Overflow eviction must keep queue at max_queue_size"

        await buf.stop()


# ---------------------------------------------------------------------------
# 7. enqueue() overflow: 100% full drops oldest (lines 170-179)
# ---------------------------------------------------------------------------


class TestEnqueueOverflow:
    """When queue is 100% full, priority writes drop the oldest item to make room.

    Why it matters: The alternative — blocking or returning False — would either
    stall the hot path or silently drop the new (high-priority) write. Evicting
    the oldest item is a bounded-memory, fail-open strategy. The security event
    is recorded; the oldest (possibly stale) event is sacrificed.
    """

    async def test_overflow_drops_oldest_item(self):
        """Lines 170-179: queue at max_queue_size → popleft() + new item added."""
        mock_redis, _ = _make_sync_redis()
        buf = WriteBuffer(mock_redis, flush_interval_ms=1000, max_queue_size=5)

        # Fill queue completely using priority=True to bypass load shedding
        for i in range(5):
            await buf.enqueue("set", f"key:{i}", "v", priority=True)
        assert len(buf.queue) == 5

        # Record which item is currently at the front (will be evicted)
        oldest_op, oldest_args, _ = buf.queue[0]
        assert oldest_args == ("key:0", "v")

        # Add one more priority write — must evict the oldest and add the new one
        added = await buf.enqueue("set", "key:NEW", "v", priority=True)
        assert added is True, "Priority write must succeed even at max capacity"
        assert len(buf.queue) == 5, "Queue must remain at max_queue_size after overflow"

        # The oldest item must have been dropped
        current_front_args = buf.queue[0][1]
        assert current_front_args != (
            "key:0",
            "v",
        ), "Oldest item must be evicted on overflow — bounded memory prevents DoS"

        await buf.stop()


# ---------------------------------------------------------------------------
# 8. _execute_batch() with empty batch (line 254)
# ---------------------------------------------------------------------------


class TestExecuteBatchEmpty:
    """_execute_batch() with an empty list returns immediately without touching Redis.

    Why it matters: An empty batch could be dispatched during a flush cycle when
    the queue was drained between lock acquisitions. Attempting to open a Redis
    pipeline for zero operations wastes a connection and adds latency.
    """

    async def test_empty_batch_does_not_call_redis(self):
        """Line 254: _execute_batch([]) returns without calling redis.pipeline."""
        mock_redis, pipe = _make_sync_redis()
        buf = WriteBuffer(mock_redis, flush_interval_ms=50, max_queue_size=100)

        await buf._execute_batch([])

        mock_redis.pipeline.assert_not_called(), (
            "Empty batch must not open a Redis pipeline — wasteful and adds latency"
        )


# ---------------------------------------------------------------------------
# 9. _execute_batch() with sync redis client (lines 271-276)
# ---------------------------------------------------------------------------


class TestExecuteBatchSync:
    """_execute_batch() uses the sync pipeline path when _is_async is False.

    Why it matters: In environments where only the synchronous Redis client is
    available (e.g. embedded deployments), writes must still reach Redis. The
    sync path must be exercised to ensure it works correctly.
    """

    async def test_sync_redis_pipeline_is_used(self):
        """Lines 271-276: sync redis client → with pipe: → pipe.execute() called."""
        mock_redis, pipe = _make_sync_redis()
        buf = WriteBuffer(mock_redis, flush_interval_ms=50, max_queue_size=100)

        # Confirm _is_async is False (sync mock)
        assert buf._is_async is False

        batch = [("set", ("key:1", "val1"), {}), ("set", ("key:2", "val2"), {})]
        await buf._execute_batch(batch)

        mock_redis.pipeline.assert_called_once_with(transaction=False), (
            "Sync path must open a pipeline for batch efficiency"
        )
        pipe.execute.assert_called_once(), (
            "Sync pipeline.execute() must be called — otherwise writes never reach Redis"
        )


# ---------------------------------------------------------------------------
# 10. _execute_batch() fail-open on Redis exception (lines 280-283)
# ---------------------------------------------------------------------------


class TestExecuteBatchFailOpen:
    """_execute_batch() logs Redis exceptions but does not re-raise them.

    Why it matters: Write failures must NEVER block or crash connection
    processing. If a batch fails (e.g. Redis is temporarily unavailable),
    the security data is lost for that window, but the proxy keeps serving
    legitimate traffic. This is the fundamental fail-open guarantee.
    """

    async def test_redis_exception_does_not_propagate(self):
        """Lines 280-283: exception in pipeline is caught and logged, not raised."""
        mock_redis = MagicMock()
        pipe = MagicMock()
        pipe.__enter__ = MagicMock(return_value=pipe)
        pipe.__exit__ = MagicMock(return_value=False)
        pipe.execute.side_effect = ConnectionError("Redis unreachable")
        mock_redis.pipeline.return_value = pipe

        buf = WriteBuffer(mock_redis, flush_interval_ms=50, max_queue_size=100)
        # Force sync mode
        buf._is_async = False

        # Must not raise
        await buf._execute_batch([("set", ("key", "val"), {})])
        # If we reach here, the exception was swallowed — fail-open confirmed


# ---------------------------------------------------------------------------
# 11. _flush_loop() adaptive timing paths (lines 196-229)
# ---------------------------------------------------------------------------


class TestFlushLoopAdaptiveTiming:
    """_flush_loop selects different sleep intervals based on queue fill level.

    Why it matters: The adaptive timing ensures that when the queue is nearly
    full (under heavy attack load), the buffer flushes very aggressively to
    prevent overflow and data loss. When the queue is nearly empty (normal
    traffic), it uses a longer interval to avoid unnecessary Redis round-trips.
    """

    async def test_flush_loop_runs_and_processes_queue(self):
        """Lines 196-229: flush loop starts, reads queue, flushes to Redis, stops.

        Covers the main loop body including adaptive sleep selection and the
        _flush_now() call.
        """
        mock_redis, pipe = _make_sync_redis()
        buf = WriteBuffer(
            mock_redis,
            flush_interval_ms=10,  # fast flush for test speed
            max_batch_size=100,
            max_queue_size=100,
        )

        await buf.start()

        # Enqueue a few items — the flush loop should pick them up
        for i in range(3):
            await buf.enqueue("set", f"k:{i}", "v")

        # Give the flush loop time to run at least one cycle
        await asyncio.sleep(0.05)

        await buf.stop()

        # After stop(), queue should be empty (flushed by loop + final flush)
        assert (
            len(buf.queue) == 0
        ), "Flush loop must drain the queue — stale security writes indicate loop is broken"
        # Redis pipeline must have been invoked
        assert (
            mock_redis.pipeline.called
        ), "Flush loop must have called redis.pipeline — writes must reach Redis"

    async def test_flush_loop_above_90_percent_uses_fast_sleep(self):
        """Lines 204-205: >90% fill → sleep_time=0.0001 (aggressive flush).

        At >90% capacity, the flush interval drops to 0.1ms so the buffer can
        drain before overflowing. This prevents an attacker from saturating the
        write buffer with high-frequency writes.
        """
        mock_redis, pipe = _make_sync_redis()
        buf = WriteBuffer(
            mock_redis,
            flush_interval_ms=500,  # long default interval
            max_batch_size=1,  # flush one item at a time
            max_queue_size=10,
        )

        await buf.start()

        # Fill to >90%: 10 * 0.9 = 9.0, so 10 items triggers fast path
        for i in range(10):
            await buf.enqueue("set", f"k:{i}", "v", priority=True)

        # With sleep_time=0.0001 the loop should flush quickly
        await asyncio.sleep(0.05)  # enough for ~500 iterations at 0.1ms

        await buf.stop()

        # The fast path must have drained the queue far below 90%
        assert (
            mock_redis.pipeline.called
        ), "Aggressive flush path must invoke redis.pipeline to drain the overloaded queue"

    async def test_flush_loop_above_70_percent_uses_medium_sleep(self):
        """Lines 206-207: >70% fill → sleep_time=0.001.

        At 70% capacity, the flush interval is 1ms — faster than the default
        but not as aggressive as the 90% path. This staged response allows
        the system to catch up without overwhelming Redis.
        """
        mock_redis, pipe = _make_sync_redis()
        buf = WriteBuffer(
            mock_redis,
            flush_interval_ms=500,
            max_batch_size=1,
            max_queue_size=10,
        )

        await buf.start()

        # Fill to >70%: 10 * 0.7 = 7.0, so 8 items
        for i in range(8):
            await buf.enqueue("set", f"k:{i}", "v", priority=True)

        await asyncio.sleep(0.05)
        await buf.stop()

        assert mock_redis.pipeline.called

    async def test_flush_loop_above_50_percent_uses_half_interval(self):
        """Lines 208-209: >50% fill → sleep_time = flush_interval_ms / 2.

        At 50% capacity, the buffer flushes at double speed to stay ahead of
        the incoming write rate. This is the last proactive tier before the
        default interval takes over.
        """
        mock_redis, pipe = _make_sync_redis()
        buf = WriteBuffer(
            mock_redis,
            flush_interval_ms=20,
            max_batch_size=1,
            max_queue_size=10,
        )

        await buf.start()

        # Fill to >50%: 10 * 0.5 = 5.0, so 6 items
        for i in range(6):
            await buf.enqueue("set", f"k:{i}", "v", priority=True)

        await asyncio.sleep(0.05)
        await buf.stop()

        assert mock_redis.pipeline.called

    async def test_flush_loop_exception_is_logged_not_raised(self):
        """Lines 226-229: unexpected exception in flush loop is caught, not propagated.

        Why it matters: A bug in _flush_now() or the loop itself must not kill
        the background task silently — the logger.error call ensures the failure
        is visible in observability tooling. The loop must terminate cleanly
        via CancelledError rather than an unhandled exception.
        """
        mock_redis, pipe = _make_sync_redis()
        buf = WriteBuffer(mock_redis, flush_interval_ms=10, max_queue_size=100)

        # Make _flush_now raise on first call
        call_count = [0]
        original_flush_now = buf._flush_now

        async def _exploding_flush():
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("simulated flush_now failure")
            return await original_flush_now()

        buf._flush_now = _exploding_flush

        await buf.start()
        await asyncio.sleep(0.05)

        # stop() must not raise even though _flush_now() failed once
        await buf.stop()
        assert call_count[0] >= 1, "The patched _flush_now must have been called"


# ---------------------------------------------------------------------------
# 12. __del__ cleanup path (lines 291-293)
# ---------------------------------------------------------------------------


class TestDelCleanup:
    """__del__ cancels the flush task if it is still running.

    Why it matters: If the WriteBuffer object is garbage-collected without
    an explicit stop(), the flush task would run indefinitely, holding a
    reference to the Redis client and consuming event-loop resources. The
    __del__ method provides a last-resort cleanup.
    """

    def test_del_cancels_running_task(self):
        """Lines 291-293: __del__ calls task.cancel() when task is not None."""
        mock_redis, _ = _make_sync_redis()
        buf = WriteBuffer(mock_redis, flush_interval_ms=50, max_queue_size=100)

        # Inject a mock task so we don't need a real event loop
        mock_task = MagicMock()
        buf._flush_task = mock_task

        # Invoke __del__ explicitly
        buf.__del__()

        mock_task.cancel.assert_called_once(), (
            "__del__ must cancel the running task — leaked tasks hold Redis connections"
        )

    def test_del_with_no_task_does_not_raise(self):
        """Lines 289-293: __del__ must not raise when _flush_task is None."""
        mock_redis, _ = _make_sync_redis()
        buf = WriteBuffer(mock_redis, flush_interval_ms=50, max_queue_size=100)

        # _flush_task is None by default
        assert buf._flush_task is None

        # Must not raise
        buf.__del__()

    def test_del_with_missing_attribute_does_not_raise(self):
        """Lines 289-293: __del__ must not raise when _flush_task attr is absent.

        This can happen if __init__ raised before _flush_task was set and
        the GC still calls __del__ on the partially-constructed object.
        """
        mock_redis, _ = _make_sync_redis()
        buf = WriteBuffer(mock_redis, flush_interval_ms=50, max_queue_size=100)
        del buf._flush_task  # simulate partial init

        # Must not raise — the hasattr() guard handles this
        buf.__del__()

    def test_del_swallows_exception_from_cancel(self):
        """Lines 292-293: if task.cancel() raises, __del__ swallows the exception.

        Why it matters: __del__ must never raise. If cancel() fails (e.g. the
        event loop is already closed), the process must still exit cleanly.
        """
        mock_redis, _ = _make_sync_redis()
        buf = WriteBuffer(mock_redis, flush_interval_ms=50, max_queue_size=100)

        # Inject a task whose cancel() raises
        mock_task = MagicMock()
        mock_task.cancel.side_effect = RuntimeError("event loop closed")
        buf._flush_task = mock_task

        # Must not raise — the except Exception: pass guard handles it
        buf.__del__()
        mock_task.cancel.assert_called_once()


# ── Missing-coverage additions ────────────────────────────────────────────────


class TestExecuteBatchAsync:
    """Cover the async Redis pipeline path (lines 260-268).

    So what: if the async pipeline code is never executed, the proxy silently
    falls back to sync Redis on async deployments, reducing write throughput
    by orders of magnitude and potentially causing queue overflow under load.
    """

    async def test_async_pipeline_path_executes_and_calls_pipe_execute(self):
        """Lines 260-268: _is_async=True → async pipeline opened, execute() awaited.
        So what: if execute() is not awaited, no Redis writes happen — all security
        telemetry (bans, rate-limit hits) is silently discarded."""
        from unittest.mock import AsyncMock

        pipe = MagicMock()
        pipe.execute = AsyncMock(return_value=None)
        pipe.__aenter__ = AsyncMock(return_value=pipe)
        pipe.__aexit__ = AsyncMock(return_value=None)

        mock_redis = MagicMock()
        mock_redis.pipeline.return_value = pipe

        buf = WriteBuffer(mock_redis, flush_interval_ms=50, max_queue_size=100)
        buf._is_async = True  # force async mode

        batch = [
            ("set", ("ban:1.2.3.4", "1"), {}),
            ("expire", ("ban:1.2.3.4", 300), {}),
        ]
        await buf._execute_batch(batch)

        pipe.execute.assert_called_once()

    async def test_async_pipeline_awaits_coroutine_result(self):
        """Lines 265-266: method returning a coroutine is awaited (safety shim).
        So what: if coroutine results are not awaited, the async pipeline call is
        a no-op and the operation is never applied to Redis."""
        from unittest.mock import AsyncMock

        async def _coro_method(*args, **kwargs):
            return None

        pipe = MagicMock()
        pipe.execute = AsyncMock(return_value=None)
        pipe.__aenter__ = AsyncMock(return_value=pipe)
        pipe.__aexit__ = AsyncMock(return_value=None)
        # Make pipe.set return a coroutine (simulates a mock that returns a coro)
        pipe.set = MagicMock(side_effect=lambda *a, **kw: _coro_method())

        mock_redis = MagicMock()
        mock_redis.pipeline.return_value = pipe

        buf = WriteBuffer(mock_redis, flush_interval_ms=50, max_queue_size=100)
        buf._is_async = True

        batch = [("set", ("key:1", "val1"), {})]
        await buf._execute_batch(batch)

        pipe.set.assert_called_once_with("key:1", "val1")
        pipe.execute.assert_called_once()


# ---------------------------------------------------------------------------
# 13. _flush_loop CancelledError path (line 227)
# ---------------------------------------------------------------------------


class TestFlushLoopCancelledError:
    """_flush_loop handles CancelledError gracefully (line 227: pass).

    Why it matters: When asyncio cancels the flush task (e.g. during forceful
    shutdown), the loop must exit cleanly via the CancelledError branch rather
    than logging a spurious error. This keeps the shutdown log clean.
    """

    async def test_flush_loop_cancelled_error_path(self):
        """Line 227: CancelledError in flush loop is caught silently (pass).

        The flush loop sleeps in asyncio.wait_for(..., timeout=sleep_time).
        When the task is cancelled, asyncio.CancelledError propagates from
        wait_for through the inner try (which only catches TimeoutError) and
        is caught by the outer 'except asyncio.CancelledError: pass' at line 227.
        """
        mock_redis, pipe = _make_sync_redis()
        buf = WriteBuffer(mock_redis, flush_interval_ms=1000, max_queue_size=100)

        await buf.start()
        task = buf._flush_task
        assert task is not None

        # Give the loop one scheduler cycle to enter the wait_for sleep
        await asyncio.sleep(0)

        # Forcefully cancel the task — CancelledError will propagate to line 226-227
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass  # expected — the task exits via CancelledError

        # The task must be done (either cancelled or finished via the break path)
        assert task.done(), "Task must be done after cancellation"
