"""
Unit tests for src/tap/tap_sensor.py — TapSensor lifecycle (lines 32-46).
"""

import asyncio

import pytest
from src.tap.tap_sensor import TapSensor


class TestTapSensorLifecycle:
    """Cover __init__, run(), and shutdown()."""

    def test_init_creates_shutdown_event(self):
        """__init__ must set up the internal shutdown event (lines 32-34).
        So what: if the event isn't created, run() will crash before the sensor
        ever starts processing packets."""
        sensor = TapSensor(config={"mode": "tap"})
        assert sensor._shutdown_event is not None
        assert not sensor._shutdown_event.is_set()

    def test_init_stores_config_and_redis(self):
        """Config and redis_client are stored for use by sub-components."""
        redis = object()
        sensor = TapSensor(config={"foo": "bar"}, redis_client=redis)
        assert sensor._config == {"foo": "bar"}
        assert sensor._redis_client is redis

    @pytest.mark.asyncio
    async def test_run_blocks_until_shutdown_called(self):
        """run() blocks on the shutdown event; shutdown() unblocks it (lines 38-46).
        So what: if shutdown() doesn't set the event, the sensor never exits cleanly,
        leaving zombie tasks and open sockets."""
        sensor = TapSensor(config={})
        run_task = asyncio.create_task(sensor.run())
        # Give run() a moment to start waiting
        await asyncio.sleep(0)
        assert not run_task.done()

        await sensor.shutdown()
        await asyncio.wait_for(run_task, timeout=1.0)
        assert run_task.done()

    @pytest.mark.asyncio
    async def test_shutdown_sets_event(self):
        """shutdown() must set the internal event (line 46).
        So what: this is the only clean-exit signal — without it, graceful restarts
        are impossible and SIGTERM would hard-kill the process."""
        sensor = TapSensor(config={})
        assert not sensor._shutdown_event.is_set()
        await sensor.shutdown()
        assert sensor._shutdown_event.is_set()

    @pytest.mark.asyncio
    async def test_shutdown_idempotent(self):
        """Calling shutdown() twice must not raise."""
        sensor = TapSensor(config={})
        await sensor.shutdown()
        await sensor.shutdown()  # must not raise
