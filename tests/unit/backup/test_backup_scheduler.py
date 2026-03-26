"""
Tests for BackupScheduler (P19-G1 — backup schedule executor).
"""
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from src.backup.scheduler import BackupScheduler, _next_delay_s

# ---------------------------------------------------------------------------
# _next_delay_s unit tests
# ---------------------------------------------------------------------------

class TestNextDelayS:
    def test_plain_integer_string_returns_float(self):
        assert _next_delay_s("3600") == 3600.0

    def test_plain_integer_zero(self):
        assert _next_delay_s("0") == 0.0

    def test_croniter_returns_positive_delay(self):
        """Any valid cron expression should give a positive delay."""
        delay = _next_delay_s("0 2 * * *")
        assert delay > 0

    def test_invalid_cron_falls_back_to_default(self):
        """Bad cron expression should not raise; returns default interval."""
        delay = _next_delay_s("not_a_cron")
        assert delay > 0

    def test_croniter_5_field_expression_works(self):
        delay = _next_delay_s("*/5 * * * *")
        # Next run ≤ 5 minutes away
        assert 0 < delay <= 300 + 1  # +1 for sub-second timing


# ---------------------------------------------------------------------------
# BackupScheduler unit tests
# ---------------------------------------------------------------------------

def _make_worker(dest="/app/backups"):
    worker = MagicMock()
    worker.create_backup.return_value = Path(dest) / "backup_test.bin"
    return worker


def _make_config(enabled=True, schedule="1", destination="/app/backups",
                 schedule_enabled=True):
    return {
        "enabled": enabled,
        "schedule": schedule,
        "destination": destination,
        "schedule_enabled": schedule_enabled,
    }


class TestBackupSchedulerStart:
    @pytest.mark.asyncio
    async def test_scheduler_starts_when_enabled(self):
        worker = _make_worker()
        scheduler = BackupScheduler(worker, _make_config(enabled=True, schedule="1"))
        await scheduler.start()
        assert scheduler._task is not None
        await scheduler.stop()

    @pytest.mark.asyncio
    async def test_scheduler_does_not_start_when_backup_disabled(self):
        worker = _make_worker()
        scheduler = BackupScheduler(worker, _make_config(enabled=False))
        await scheduler.start()
        assert scheduler._task is None

    @pytest.mark.asyncio
    async def test_scheduler_does_not_start_when_no_schedule(self):
        worker = _make_worker()
        cfg = _make_config(enabled=True)
        cfg.pop("schedule")
        scheduler = BackupScheduler(worker, cfg)
        await scheduler.start()
        assert scheduler._task is None

    @pytest.mark.asyncio
    async def test_scheduler_does_not_start_when_schedule_enabled_false(self):
        worker = _make_worker()
        scheduler = BackupScheduler(
            worker, _make_config(enabled=True, schedule="60", schedule_enabled=False)
        )
        await scheduler.start()
        assert scheduler._task is None

    @pytest.mark.asyncio
    async def test_stop_scheduler_cancels_task_cleanly(self):
        worker = _make_worker()
        scheduler = BackupScheduler(worker, _make_config(schedule="3600"))
        await scheduler.start()
        assert scheduler._task is not None
        await scheduler.stop()
        assert scheduler._task is None

    @pytest.mark.asyncio
    async def test_stop_when_not_started_is_a_noop(self):
        worker = _make_worker()
        scheduler = BackupScheduler(worker, _make_config(enabled=False))
        await scheduler.start()
        await scheduler.stop()  # should not raise


class TestBackupSchedulerFires:
    @pytest.mark.asyncio
    async def test_scheduler_fires_backup_after_interval(self):
        """Using a 0-second interval the backup fires almost immediately."""
        worker = _make_worker()
        fired = asyncio.Event()

        async def mock_fire(self_):
            fired.set()

        scheduler = BackupScheduler(worker, _make_config(schedule="0"))
        with patch.object(BackupScheduler, "_fire", mock_fire):
            await scheduler.start()
            await asyncio.wait_for(fired.wait(), timeout=2.0)
            await scheduler.stop()

    @pytest.mark.asyncio
    async def test_scheduler_calls_worker_create_backup(self):
        worker = _make_worker()
        fired = asyncio.Event()
        # One-shot guard: the 0-second loop may fire multiple times before stop();
        # only execute the real _fire once to keep the assertion deterministic.
        _already_fired = False
        original_fire = BackupScheduler._fire

        async def patched_fire(self_):
            nonlocal _already_fired
            if _already_fired:
                return
            _already_fired = True
            await original_fire(self_)
            fired.set()

        scheduler = BackupScheduler(worker, _make_config(schedule="0"))
        with patch.object(BackupScheduler, "_fire", patched_fire):
            await scheduler.start()
            await asyncio.wait_for(fired.wait(), timeout=2.0)
            await scheduler.stop()

        worker.create_backup.assert_called_once()

    @pytest.mark.asyncio
    async def test_scheduler_logs_warn_on_backup_failure_not_raise(self):
        """A failing backup must not crash the scheduler loop."""
        worker = _make_worker()
        worker.create_backup.side_effect = RuntimeError("disk full")

        fired = asyncio.Event()
        original_fire = BackupScheduler._fire

        async def patched_fire(self_):
            await original_fire(self_)
            fired.set()

        scheduler = BackupScheduler(worker, _make_config(schedule="0"))
        with patch.object(BackupScheduler, "_fire", patched_fire):
            await scheduler.start()
            await asyncio.wait_for(fired.wait(), timeout=2.0)
            # Task must still be alive after the failure
            assert not scheduler._task.done()
            await scheduler.stop()
