"""
Tests for pipeline-batched Redis dump in BackupWorker (P19-G3).
"""
from unittest.mock import MagicMock, call, patch

import pytest
import redis as redis_lib

from src.backup.worker import PIPELINE_BATCH_SIZE, BackupWorker


def _make_worker():
    return BackupWorker(
        redis_host="localhost",
        redis_port=6379,
        redis_db=0,
        max_keys_per_run=10000,
    )


def _make_mock_redis(key_values: dict):
    """Return a mock redis.Redis whose pipeline().execute() returns dump bytes."""
    mock_redis = MagicMock()

    def make_pipeline(**kw):
        pipe = MagicMock()
        recorded_keys = []

        def _dump(key):
            key_str = key.decode() if isinstance(key, bytes) else key
            recorded_keys.append(key_str)
            return pipe

        pipe.dump.side_effect = _dump

        def _execute(raise_on_error=True):
            return [key_values.get(k) for k in recorded_keys]

        pipe.execute.side_effect = _execute
        return pipe

    mock_redis.pipeline.side_effect = make_pipeline
    return mock_redis


class TestDumpKeysBatched:
    def test_1001_keys_uses_2_pipeline_calls(self):
        """1001 keys split into batches of 1000 → 2 pipeline() calls."""
        worker = _make_worker()
        keys = [f"key:{i}" for i in range(1001)]
        key_values = {k: b"data" for k in keys}
        mock_redis = _make_mock_redis(key_values)

        worker._dump_keys_batched(mock_redis, keys)

        assert mock_redis.pipeline.call_count == 2

    def test_exactly_1000_keys_uses_1_pipeline_call(self):
        worker = _make_worker()
        keys = [f"key:{i}" for i in range(1000)]
        key_values = {k: b"data" for k in keys}
        mock_redis = _make_mock_redis(key_values)

        worker._dump_keys_batched(mock_redis, keys)

        assert mock_redis.pipeline.call_count == 1

    def test_empty_key_list_makes_no_pipeline_calls(self):
        worker = _make_worker()
        mock_redis = _make_mock_redis({})

        result = worker._dump_keys_batched(mock_redis, [])

        assert mock_redis.pipeline.call_count == 0
        assert result == {}

    def test_expired_key_returns_none_not_exception(self):
        """A key that returns None (expired mid-backup) maps to None, not error."""
        worker = _make_worker()
        keys = ["alive", "expired"]
        key_values = {"alive": b"\x01\x02", "expired": None}
        mock_redis = _make_mock_redis(key_values)

        result = worker._dump_keys_batched(mock_redis, keys)

        assert result["alive"] == b"\x01\x02"
        assert result["expired"] is None

    def test_redis_exception_in_execute_maps_to_none(self):
        """A RedisError for one key in a batch returns None for that key."""
        worker = _make_worker()
        keys = ["good", "bad"]
        key_values = {"good": b"ok", "bad": redis_lib.RedisError("oops")}

        # Use the real mock structure but inject an exception value
        mock_redis = MagicMock()
        pipe = MagicMock()
        pipe.dump.return_value = pipe  # fluent
        pipe.execute.return_value = [b"ok", redis_lib.RedisError("oops")]
        mock_redis.pipeline.return_value = pipe

        result = worker._dump_keys_batched(mock_redis, keys)

        assert result["good"] == b"ok"
        assert result["bad"] is None

    def test_bytes_keys_decoded_to_str(self):
        """Keys supplied as bytes are decoded to str in the result dict."""
        worker = _make_worker()
        keys = [b"bytekey"]
        mock_redis = _make_mock_redis({"bytekey": b"data"})

        result = worker._dump_keys_batched(mock_redis, keys)

        assert "bytekey" in result
        assert result["bytekey"] == b"data"

    def test_pipeline_uses_transaction_false(self):
        """pipeline() must be called with transaction=False for best performance."""
        worker = _make_worker()
        mock_redis = _make_mock_redis({"k": b"v"})

        worker._dump_keys_batched(mock_redis, ["k"])

        mock_redis.pipeline.assert_called_with(transaction=False)

    def test_5000_keys_uses_5_pipeline_calls(self):
        worker = _make_worker()
        keys = [f"k:{i}" for i in range(5000)]
        key_values = {k: b"v" for k in keys}
        mock_redis = _make_mock_redis(key_values)

        worker._dump_keys_batched(mock_redis, keys)

        assert mock_redis.pipeline.call_count == 5

    def test_batch_size_constant_is_1000(self):
        assert PIPELINE_BATCH_SIZE == 1000

    def test_pipeline_execute_exception_maps_all_keys_to_none(self):
        """Lines 447-448: pipe.execute() raises → all keys in that batch map to None.
        So what: without this except, a transient Redis pipeline error propagates out of
        _dump_keys_batched, aborting the entire backup run — losing all subsequent keys
        even though only one batch encountered the network fault."""
        worker = _make_worker()
        keys = ["k1", "k2", "k3"]

        mock_redis = MagicMock()
        pipe = MagicMock()
        pipe.dump.return_value = pipe
        pipe.execute.side_effect = Exception("pipeline timeout")
        mock_redis.pipeline.return_value = pipe

        result = worker._dump_keys_batched(mock_redis, keys)

        assert result == {"k1": None, "k2": None, "k3": None}
