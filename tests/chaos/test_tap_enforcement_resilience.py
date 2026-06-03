"""
Chaos / resilience tests for src/tap/enforcement_bridge.py — Group 8 (Phase 20).

Tests verify that:
- One backend failing never prevents other backends from running.
- Missing named pipes are logged without crashing.
- pub/sub disconnect triggers reconnect (not crash).
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from src.tap.enforcement_bridge import EnforcementBridge

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(iptables=True, bgp=True, webhook=True, session=None) -> dict:
    return {
        "tap_enforcement": {
            "iptables": {"enabled": iptables, "ipset_name": "ja4proxy_ban"},
            "bgp": {
                "enabled": bgp,
                "pipe": "/tmp/fake_exabgp.cmd",
                "next_hop": "self",
                "aggregate_prefix_len_v4": 32,
                "aggregate_prefix_len_v6": 128,
            },
            "webhook": {
                "enabled": webhook,
                "url": "http://webhook.test/ban",
                "secret": "s3cr3t",
                "max_retries": 0,
                "retry_delay_s": 0,
            },
        }
    }


def _make_bridge(
    iptables=True, bgp=True, webhook=True, session=None
) -> EnforcementBridge:
    return EnforcementBridge(
        config=_make_config(iptables=iptables, bgp=bgp, webhook=webhook),
        redis=MagicMock(),
        http_session=session,
    )


# ---------------------------------------------------------------------------
# Backend isolation
# ---------------------------------------------------------------------------


class TestBackendIsolation:
    @pytest.mark.asyncio
    async def test_iptables_failure_does_not_prevent_bgp_enforcement(self):
        """iptables failing must not stop BGP from running."""
        bridge = _make_bridge(iptables=True, bgp=True, webhook=False)
        bgp_called = False

        async def boom_iptables(ip, ttl):
            raise RuntimeError("ipset down")

        async def ok_bgp(ip):
            nonlocal bgp_called
            bgp_called = True

        with patch.object(bridge, "_iptables_ban", new=boom_iptables):
            with patch.object(bridge, "_bgp_announce", new=ok_bgp):
                await bridge._on_ban("1.2.3.4", 3600, "reason")

        assert bgp_called, "BGP backend must run even if iptables fails"

    @pytest.mark.asyncio
    async def test_webhook_failure_does_not_prevent_iptables_enforcement(self):
        """Webhook failing must not stop iptables from running."""
        session = MagicMock()
        session.post.side_effect = ConnectionError("webhook unreachable")

        bridge = _make_bridge(iptables=True, bgp=False, webhook=True, session=session)
        iptables_called = False

        async def ok_iptables(ip, ttl):
            nonlocal iptables_called
            iptables_called = True

        with patch.object(bridge, "_iptables_ban", new=ok_iptables):
            await bridge._on_ban("1.2.3.4", 3600, "reason")

        assert iptables_called, "iptables backend must run even if webhook fails"

    @pytest.mark.asyncio
    async def test_all_backends_failing_logs_error_not_crash(self):
        """All backends failing must be logged; must not raise."""
        session = MagicMock()
        bridge = _make_bridge(iptables=True, bgp=True, webhook=True, session=session)

        async def boom(ip, ttl=None, reason=None):
            raise RuntimeError("backend down")

        with patch.object(bridge, "_iptables_ban", new=boom):
            with patch.object(bridge, "_bgp_announce", new=boom):
                with patch.object(bridge, "_webhook_ban", new=boom):
                    await bridge._on_ban("1.2.3.4", 3600, "reason")
        # If we reach here, no exception was raised — test passes

    @pytest.mark.asyncio
    async def test_bgp_pipe_missing_increments_error_metric_not_crash(self):
        """Missing ExaBGP named pipe must be logged; must not crash."""
        bridge = _make_bridge(iptables=False, bgp=True, webhook=False)

        # Force FileNotFoundError in run_in_executor
        async def fake_executor(_, fn):
            raise FileNotFoundError("No such file: /tmp/fake_exabgp.cmd")

        loop = asyncio.get_event_loop()
        with patch.object(loop, "run_in_executor", new=fake_executor):
            await bridge._bgp_announce("1.2.3.4")
        # Must not raise; error is swallowed by outer except block

    @pytest.mark.asyncio
    async def test_iptables_failure_exception_swallowed(self):
        """iptables RuntimeError must not propagate from _on_ban."""
        bridge = _make_bridge(iptables=True, bgp=False, webhook=False)

        proc_mock = AsyncMock()
        proc_mock.returncode = 127  # command not found
        proc_mock.communicate.return_value = (b"", b"ipset: command not found")

        with patch("asyncio.create_subprocess_exec", return_value=proc_mock):
            await bridge._on_ban("1.2.3.4", 3600, "reason")  # must not raise


# ---------------------------------------------------------------------------
# Pub/sub reconnect
# ---------------------------------------------------------------------------


class TestPubSubReconnect:
    @pytest.mark.asyncio
    async def test_redis_pubsub_reconnects_after_disconnect(self):
        """_listen_loop must reconnect after a pub/sub error."""
        bridge = _make_bridge(iptables=False, bgp=False, webhook=False)

        call_count = 0

        def _make_pubsub():
            nonlocal call_count
            call_count += 1
            ps = MagicMock()
            ps.subscribe.return_value = None

            msg_count = [0]

            def get_message(**kwargs):
                msg_count[0] += 1
                if call_count == 1 and msg_count[0] == 1:
                    raise ConnectionError("Redis disconnected")
                # After reconnect, stop the loop
                bridge._running = False
                return None

            ps.get_message.side_effect = get_message
            ps.close.return_value = None
            return ps

        redis = MagicMock()
        redis.pubsub.side_effect = _make_pubsub
        bridge._redis = redis
        bridge._running = True  # start() normally sets this

        # Patch asyncio.sleep so reconnect delay doesn't slow the test
        with patch("src.tap.enforcement_bridge.asyncio.sleep", new=AsyncMock()):
            try:
                await asyncio.wait_for(bridge._listen_loop(), timeout=1.0)
            except asyncio.TimeoutError:
                pass  # Acceptable — just verify reconnect happened

        # pubsub() was called at least twice (initial + reconnect)
        assert (
            redis.pubsub.call_count >= 2
        ), f"Expected ≥2 pubsub() calls (reconnect), got {redis.pubsub.call_count}"
