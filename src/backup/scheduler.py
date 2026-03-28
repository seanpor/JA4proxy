"""
Backup scheduler module.

Wires the backup.schedule cron expression (or interval_s fallback) to an
asyncio periodic task that calls BackupWorker.create_backup() automatically.

Usage (from proxy.py):
    scheduler = BackupScheduler(worker, config["backup"], destination)
    await scheduler.start()
    # ... later ...
    await scheduler.stop()
"""

import asyncio
import contextlib
import logging
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_INTERVAL_S = 86400  # fallback: once per day


def _next_delay_s(schedule: str) -> float:
    """Return seconds until the next scheduled run for *schedule*.

    *schedule* is a cron expression (e.g. ``"0 2 * * *"``) or a plain
    integer string representing an interval in seconds (e.g. ``"3600"``).

    Requires ``croniter`` for cron expressions.  If croniter is unavailable
    and the expression is not a plain integer, falls back to
    ``_DEFAULT_INTERVAL_S`` and logs a warning.
    """

    # Plain integer → treat as interval in seconds
    try:
        return float(int(schedule))
    except (ValueError, TypeError):
        pass

    # Cron expression → compute seconds until next fire
    try:
        import datetime

        from croniter import croniter  # type: ignore[import]

        now = datetime.datetime.now()
        cron = croniter(schedule, now)
        next_run = cron.get_next(datetime.datetime)
        delay = (next_run - now).total_seconds()
        return max(delay, 1.0)
    except Exception as exc:  # croniter missing or invalid expression
        logger.warning(
            "backup | event=schedule_parse_failed | schedule=%r | error=%s"
            " | fallback_interval_s=%d",
            schedule,
            exc,
            _DEFAULT_INTERVAL_S,
        )
        return float(_DEFAULT_INTERVAL_S)


class BackupScheduler:
    """Asyncio-based backup scheduler.

    Fires ``BackupWorker.create_backup(destination)`` according to the cron
    expression (or interval_s) in the backup config.  The backup call is
    dispatched via ``asyncio.to_thread`` so the synchronous ``BackupWorker``
    never blocks the event loop.

    Config keys read from *backup_config*:
        enabled (bool)         — must be True for scheduler to run
        schedule (str)         — cron expression or integer seconds
        destination (str)      — backup directory passed to create_backup()
        schedule_enabled (bool)— optional explicit override; defaults to True
                                  when schedule key is present
    """

    def __init__(
        self, worker, backup_config: dict, destination: Optional[str] = None
    ) -> None:
        self._worker = worker
        self._config = backup_config
        self._destination = destination or backup_config.get(
            "destination", "/app/backups"
        )
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Start the scheduler task if backup is enabled and schedule is set."""
        if not self._config.get("enabled", False):
            logger.debug("backup | event=scheduler_skipped | reason=backup_not_enabled")
            return

        schedule = self._config.get("schedule")
        if not schedule:
            logger.debug(
                "backup | event=scheduler_skipped | reason=no_schedule_configured"
            )
            return

        schedule_enabled = self._config.get("schedule_enabled", True)
        if not schedule_enabled:
            logger.debug(
                "backup | event=scheduler_skipped | reason=schedule_enabled=false"
            )
            return

        self._task = asyncio.create_task(self._run_loop(str(schedule)))
        logger.info(
            "backup | event=scheduler_started | schedule=%r | destination=%s",
            schedule,
            self._destination,
        )

    async def stop(self) -> None:
        """Cancel the scheduler task and wait for it to exit cleanly."""
        if self._task is None:
            return
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None
        logger.info("backup | event=scheduler_stopped")

    async def _run_loop(self, schedule: str) -> None:
        """Main scheduler loop.  Computes delay, sleeps, fires backup, repeat."""
        while True:
            delay = _next_delay_s(schedule)
            logger.debug("backup | event=scheduler_next_run | delay_s=%.1f", delay)
            await asyncio.sleep(delay)
            await self._fire()

    async def _fire(self) -> None:
        """Run the backup worker in a thread; log result; never raise."""
        destination = self._destination
        logger.info(
            "backup | event=scheduled_backup_start | destination=%s", destination
        )
        try:
            path = await asyncio.to_thread(self._worker.create_backup, destination)
            logger.info("backup | event=scheduled_backup_success | artifact=%s", path)
        except Exception as exc:
            logger.warning("backup | event=scheduled_backup_failed | error=%s", exc)
