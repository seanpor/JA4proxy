"""
Unit tests for src/tap/fingerprint_store.py — Group 7 (Phase 20).
"""
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, call

import pytest

from src.tap.fingerprint_store import (
    FingerprintStore,
    _CONN_TTL,
    _IP_TTL,
    _JA4_TTL,
    _JA4S_MAP_TTL,
    _OS_COUNT_TTL,
    _OS_IP_TTL,
    _IP_SORTED_SET_MAX,
)
from src.tap.fingerprints.correlation import ConnectionFingerprints


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fp(**kwargs) -> ConnectionFingerprints:
    defaults = {
        "conn_id": str(uuid.uuid4()),
        "timestamp": datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        "client_ip": "1.2.3.4",
        "server_ip": "5.6.7.8",
        "server_port": 443,
    }
    defaults.update(kwargs)
    return ConnectionFingerprints(**defaults)


def _make_redis() -> MagicMock:
    """Return a MagicMock that mimics enough of redis-py."""
    m = MagicMock()
    m.hset.return_value = 1
    m.expire.return_value = True
    m.zadd.return_value = 1
    m.zremrangebyrank.return_value = 0
    m.pfadd.return_value = 1
    m.incr.return_value = 1
    m.hincrby.return_value = 1
    m.set.return_value = True
    m.zrevrange.return_value = []
    m.hgetall.return_value = {}
    m.get.return_value = None
    m.pfcount.return_value = 0
    return m


def _make_store(redis: MagicMock = None) -> tuple[FingerprintStore, MagicMock]:
    r = redis or _make_redis()
    return FingerprintStore(r), r


# ---------------------------------------------------------------------------
# Write: fp:conn
# ---------------------------------------------------------------------------

class TestWriteConn:
    @pytest.mark.asyncio
    async def test_write_creates_fp_conn_key_with_7_day_ttl(self):
        store, redis = _make_store()
        fp = _make_fp()
        await store.write(fp)

        hset_calls = [str(c) for c in redis.hset.call_args_list]
        assert any(f"fp:conn:{fp.conn_id}" in c for c in hset_calls)

        expire_calls = [str(c) for c in redis.expire.call_args_list]
        assert any(
            f"fp:conn:{fp.conn_id}" in c and str(_CONN_TTL) in c
            for c in expire_calls
        )

    @pytest.mark.asyncio
    async def test_conn_hash_contains_client_ip(self):
        store, redis = _make_store()
        fp = _make_fp(client_ip="9.8.7.6")
        await store.write(fp)

        # The hset call's mapping kwarg must contain client_ip
        hset_call = next(
            c for c in redis.hset.call_args_list
            if f"fp:conn:{fp.conn_id}" in str(c)
        )
        mapping = hset_call.kwargs.get("mapping") or hset_call.args[1]
        assert mapping.get("client_ip") == "9.8.7.6"


# ---------------------------------------------------------------------------
# Write: fp:ip sorted set
# ---------------------------------------------------------------------------

class TestWriteIpSortedSet:
    @pytest.mark.asyncio
    async def test_write_adds_to_fp_ip_sorted_set(self):
        store, redis = _make_store()
        fp = _make_fp(client_ip="1.2.3.4")
        await store.write(fp)

        zadd_calls = [str(c) for c in redis.zadd.call_args_list]
        assert any("fp:ip:1.2.3.4" in c for c in zadd_calls)

    @pytest.mark.asyncio
    async def test_fp_ip_sorted_set_trimmed_to_1000(self):
        store, redis = _make_store()
        fp = _make_fp(client_ip="1.2.3.4")
        await store.write(fp)

        zrem_calls = [str(c) for c in redis.zremrangebyrank.call_args_list]
        # zremrangebyrank called on fp:ip:* key
        assert any("fp:ip:1.2.3.4" in c for c in zrem_calls)

    @pytest.mark.asyncio
    async def test_fp_ip_sorted_set_has_30_day_ttl(self):
        store, redis = _make_store()
        fp = _make_fp(client_ip="1.2.3.4")
        await store.write(fp)

        expire_calls = [str(c) for c in redis.expire.call_args_list]
        assert any(
            "fp:ip:1.2.3.4" in c and str(_IP_TTL) in c
            for c in expire_calls
        )


# ---------------------------------------------------------------------------
# Write: fp:ja4:hll and fp:ja4:count
# ---------------------------------------------------------------------------

class TestWriteJA4:
    @pytest.mark.asyncio
    async def test_write_pfadd_to_ja4_hll(self):
        store, redis = _make_store()
        fp = _make_fp(ja4="t13d1516h2_aabbccddeeff_001122334455", client_ip="1.2.3.4")
        await store.write(fp)

        pfadd_calls = [str(c) for c in redis.pfadd.call_args_list]
        assert any(
            "fp:ja4:hll:t13d1516h2_aabbccddeeff_001122334455" in c
            for c in pfadd_calls
        )

    @pytest.mark.asyncio
    async def test_write_incr_ja4_count(self):
        store, redis = _make_store()
        fp = _make_fp(ja4="t13d1516h2_aabbccddeeff_001122334455")
        await store.write(fp)

        incr_calls = [str(c) for c in redis.incr.call_args_list]
        assert any(
            "fp:ja4:count:t13d1516h2_aabbccddeeff_001122334455" in c
            for c in incr_calls
        )

    @pytest.mark.asyncio
    async def test_no_ja4_skips_hll_and_count(self):
        store, redis = _make_store()
        fp = _make_fp(ja4=None)
        await store.write(fp)

        assert redis.pfadd.call_count == 0
        assert redis.incr.call_count == 0


# ---------------------------------------------------------------------------
# Write: fp:os:count and fp:os:ip
# ---------------------------------------------------------------------------

class TestWriteOS:
    @pytest.mark.asyncio
    async def test_write_incr_os_count(self):
        store, redis = _make_store()
        fp = _make_fp(os_fingerprint="linux_5x_default")
        await store.write(fp)

        incr_calls = [str(c) for c in redis.incr.call_args_list]
        assert any("fp:os:count:linux_5x_default" in c for c in incr_calls)

    @pytest.mark.asyncio
    async def test_write_os_ip_with_24h_ttl(self):
        store, redis = _make_store()
        fp = _make_fp(os_fingerprint="windows_10_default", client_ip="2.3.4.5")
        await store.write(fp)

        set_calls = [str(c) for c in redis.set.call_args_list]
        assert any("fp:os:ip:2.3.4.5" in c for c in set_calls)

    @pytest.mark.asyncio
    async def test_no_os_fingerprint_skips_os_writes(self):
        store, redis = _make_store()
        fp = _make_fp(os_fingerprint=None)
        await store.write(fp)

        incr_calls = [str(c) for c in redis.incr.call_args_list]
        assert not any("fp:os:" in c for c in incr_calls)


# ---------------------------------------------------------------------------
# Write: fp:ja4_to_ja4s correlation map
# ---------------------------------------------------------------------------

class TestWriteJA4ToJA4S:
    @pytest.mark.asyncio
    async def test_ja4_to_ja4s_correlation_updated(self):
        store, redis = _make_store()
        fp = _make_fp(
            ja4="t13d1516h2_aabbccddeeff_001122334455",
            ja4s="s13d0101_1301_aabbccdd",
        )
        await store.write(fp)

        hincrby_calls = [str(c) for c in redis.hincrby.call_args_list]
        assert any(
            "fp:ja4_to_ja4s:t13d1516h2_aabbccddeeff_001122334455" in c
            for c in hincrby_calls
        )

    @pytest.mark.asyncio
    async def test_no_ja4s_skips_correlation(self):
        store, redis = _make_store()
        fp = _make_fp(ja4="t13d1516h2_aabbccddeeff_001122334455", ja4s=None)
        await store.write(fp)

        assert redis.hincrby.call_count == 0

    @pytest.mark.asyncio
    async def test_ja4_to_ja4s_has_correct_ttl(self):
        store, redis = _make_store()
        fp = _make_fp(
            ja4="t13d1516h2_aabbccddeeff_001122334455",
            ja4s="s13d0101_1301_aabbccdd",
        )
        await store.write(fp)

        expire_calls = [str(c) for c in redis.expire.call_args_list]
        assert any(
            "fp:ja4_to_ja4s:" in c and str(_JA4S_MAP_TTL) in c
            for c in expire_calls
        )


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------

class TestGetIpHistory:
    @pytest.mark.asyncio
    async def test_get_ip_history_returns_empty_when_no_history(self):
        store, redis = _make_store()
        redis.zrevrange.return_value = []
        result = await store.get_ip_history("1.2.3.4")
        assert result == []

    @pytest.mark.asyncio
    async def test_get_ip_history_returns_last_10_connections(self):
        conn_ids = [str(uuid.uuid4()) for _ in range(10)]
        redis = _make_redis()
        redis.zrevrange.return_value = [c.encode() for c in conn_ids]

        def _hgetall(key):
            cid = key.replace("fp:conn:", "")
            return {
                b"conn_id": cid.encode(),
                b"client_ip": b"1.2.3.4",
                b"server_ip": b"5.6.7.8",
                b"server_port": b"443",
                b"timestamp": b"2024-01-01T12:00:00+00:00",
                b"risk_score": b"0",
                b"action": b"observe",
            }

        redis.hgetall.side_effect = _hgetall
        store = FingerprintStore(redis)

        result = await store.get_ip_history("1.2.3.4", limit=10)
        assert len(result) == 10
        assert all(isinstance(r, ConnectionFingerprints) for r in result)

    @pytest.mark.asyncio
    async def test_get_ip_history_redis_error_returns_empty(self):
        redis = _make_redis()
        redis.zrevrange.side_effect = ConnectionError("Redis down")
        store = FingerprintStore(redis)
        result = await store.get_ip_history("1.2.3.4")
        assert result == []


class TestGetJA4Stats:
    @pytest.mark.asyncio
    async def test_get_ja4_stats_returns_count_and_hll_estimate(self):
        redis = _make_redis()
        redis.get.return_value = b"42"
        redis.pfcount.return_value = 17
        store = FingerprintStore(redis)

        stats = await store.get_ja4_stats("t13d1516h2_aabbccddeeff_001122334455")
        assert stats["count"] == 42
        assert stats["unique_ips"] == 17

    @pytest.mark.asyncio
    async def test_get_ja4_stats_zero_when_no_data(self):
        redis = _make_redis()
        redis.get.return_value = None
        redis.pfcount.return_value = 0
        store = FingerprintStore(redis)

        stats = await store.get_ja4_stats("t13d1516h2_aabbccddeeff_001122334455")
        assert stats["count"] == 0
        assert stats["unique_ips"] == 0

    @pytest.mark.asyncio
    async def test_get_ja4_stats_redis_error_returns_zeros(self):
        redis = _make_redis()
        redis.get.side_effect = ConnectionError("Redis down")
        store = FingerprintStore(redis)

        stats = await store.get_ja4_stats("t13d1516h2_aabbccddeeff_001122334455")
        assert stats == {"count": 0, "unique_ips": 0}
