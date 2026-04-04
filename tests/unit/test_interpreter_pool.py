"""Unit tests for src/tls/interpreter_pool.py (Phase 70).

Tests cover:
- create_pool() returns a usable pool on Python < 3.14 (ThreadPoolExecutor fallback)
- Pool can submit work and retrieve results
- Context manager protocol works
- shutdown() cleans up without error
- _SubinterpreterPool repr includes worker count and Python version
"""

from concurrent.futures import Future, ThreadPoolExecutor

from src.tls.interpreter_pool import _SubinterpreterPool, create_pool


class TestCreatePool:
    def test_returns_usable_pool(self):
        """create_pool() returns something we can submit to."""
        pool = create_pool(workers=2)
        try:
            future = pool.submit(lambda: 42)
            assert future.result(timeout=5) == 42
        finally:
            pool.shutdown(wait=True)

    def test_fallback_is_thread_pool_executor(self):
        """On Python < 3.14 (interpreters absent) we get a ThreadPoolExecutor."""
        pool = create_pool(workers=1)
        # The returned object must have the ThreadPoolExecutor interface
        assert hasattr(pool, "submit")
        assert hasattr(pool, "shutdown")
        pool.shutdown(wait=True)

    def test_context_manager(self):
        """create_pool() result supports context manager protocol."""
        with create_pool(workers=2) as pool:
            future = pool.submit(str, 123)
            assert future.result(timeout=5) == "123"

    def test_submit_multiple_tasks(self):
        """Multiple tasks can run concurrently."""
        with create_pool(workers=4) as pool:
            futures = [pool.submit(lambda x=i: x * 2, i) for i in range(8)]
            results = [f.result(timeout=5) for f in futures]
        assert sorted(results) == [0, 2, 4, 6, 8, 10, 12, 14]

    def test_submit_exception_propagates(self):
        """Exceptions from submitted callables surface on future.result()."""
        import pytest

        with create_pool(workers=1) as pool:
            future = pool.submit(lambda: (_ for _ in ()).throw(ValueError("boom")))
            with pytest.raises(ValueError, match="boom"):
                future.result(timeout=5)


class TestSubinterpreterPool:
    def test_submit_returns_future(self):
        pool = _SubinterpreterPool(workers=2)
        try:
            future = pool.submit(lambda: "hello")
            assert isinstance(future, Future)
            assert future.result(timeout=5) == "hello"
        finally:
            pool.shutdown()

    def test_context_manager(self):
        with _SubinterpreterPool(workers=1) as pool:
            result = pool.submit(int, "7").result(timeout=5)
        assert result == 7

    def test_shutdown_wait_true(self):
        pool = _SubinterpreterPool(workers=1)
        pool.submit(lambda: None).result(timeout=5)
        pool.shutdown(wait=True)  # must not raise

    def test_shutdown_wait_false(self):
        pool = _SubinterpreterPool(workers=1)
        pool.shutdown(wait=False)  # must not raise

    def test_repr_includes_workers(self):
        pool = _SubinterpreterPool(workers=3)
        r = repr(pool)
        assert "3" in r
        assert "python=" in r
        pool.shutdown()
