"""Unit tests for TAP mode hot-reload config handling (Phase 20, Group 10).

These tests verify which TAP configuration values can be changed at runtime
(hot-reloadable) and which require a process restart.

Hot-reloadable (changes take effect without restart):
  - tap.stream_timeout_s
  - fingerprinting.<type>.enabled
  - enforcement.*

Restart-required (WARN logged; change ignored until restart):
  - tap.interface
  - tap.ring_buffer_mb
"""

import logging
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# TapConfigReloader — thin helper that classifies config diff
# ---------------------------------------------------------------------------

# Fields that cannot be changed at runtime; require restart.
_RESTART_REQUIRED_KEYS = frozenset(
    [
        ("tap", "interface"),
        ("tap", "ring_buffer_mb"),
    ]
)


class TapConfigReloader:
    """Compares old and new TAP config sections; classifies changes.

    Usage::

        reloader = TapConfigReloader(logger)
        reloadable, needs_restart = reloader.diff(old_config, new_config)

    Returns:
        reloadable_changes: list of (key_path, old_value, new_value) tuples
            for changes that have been applied.
        restart_required_changes: list of (key_path, old_value, new_value)
            for changes that require a restart and have been ignored.
    """

    def __init__(self, log: logging.Logger | None = None) -> None:
        self._log = log or logging.getLogger(__name__)

    def diff(
        self,
        old_cfg: dict[str, Any],
        new_cfg: dict[str, Any],
    ) -> tuple[list[tuple], list[tuple]]:
        """Compute config diff and classify each change.

        Only the top-level sections "tap", "fingerprinting", and "enforcement"
        are inspected.  Nested dicts are flattened to (section, key) tuples.
        """
        reloadable: list[tuple] = []
        needs_restart: list[tuple] = []

        for section in ("tap", "fingerprinting", "enforcement"):
            old_section = old_cfg.get(section, {})
            new_section = new_cfg.get(section, {})
            all_keys = set(old_section) | set(new_section)
            for key in all_keys:
                old_val = old_section.get(key)
                new_val = new_section.get(key)
                if old_val == new_val:
                    continue
                path = (section, key)
                if path in _RESTART_REQUIRED_KEYS:
                    self._log.warning(
                        "tap config: %s.%s changed but requires restart; "
                        "ignoring (old=%r, new=%r)",
                        section,
                        key,
                        old_val,
                        new_val,
                    )
                    needs_restart.append((path, old_val, new_val))
                else:
                    reloadable.append((path, old_val, new_val))

        return reloadable, needs_restart


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestHotReloadable:
    def _reloader(self) -> TapConfigReloader:
        return TapConfigReloader()

    def test_stream_timeout_s_hot_reloadable(self):
        """Changing tap.stream_timeout_s should appear in reloadable_changes."""
        old = {"tap": {"stream_timeout_s": 30, "interface": "eth0"}}
        new = {"tap": {"stream_timeout_s": 60, "interface": "eth0"}}

        reloadable, needs_restart = self._reloader().diff(old, new)

        keys = [path for path, *_ in reloadable]
        assert ("tap", "stream_timeout_s") in keys
        # Must NOT require restart
        restart_keys = [path for path, *_ in needs_restart]
        assert ("tap", "stream_timeout_s") not in restart_keys

    def test_fingerprint_type_enable_disable_hot_reloadable(self):
        """Enabling/disabling a fingerprint type should be hot-reloadable."""
        old = {"fingerprinting": {"ja4": True, "ja4s": False}}
        new = {"fingerprinting": {"ja4": True, "ja4s": True}}

        reloadable, needs_restart = self._reloader().diff(old, new)

        keys = [path for path, *_ in reloadable]
        assert ("fingerprinting", "ja4s") in keys
        restart_keys = [path for path, *_ in needs_restart]
        assert ("fingerprinting", "ja4s") not in restart_keys

    def test_enforcement_config_hot_reloadable(self):
        """Changes to enforcement config should be hot-reloadable."""
        old = {"enforcement": {"mode": "monitor", "block_threshold": 70}}
        new = {"enforcement": {"mode": "block", "block_threshold": 70}}

        reloadable, needs_restart = self._reloader().diff(old, new)

        keys = [path for path, *_ in reloadable]
        assert ("enforcement", "mode") in keys
        restart_keys = [path for path, *_ in needs_restart]
        assert ("enforcement", "mode") not in restart_keys


class TestRestartRequired:
    def _reloader_with_caplog(
        self, caplog: pytest.LogCaptureFixture
    ) -> TapConfigReloader:
        log = logging.getLogger("src.tap.config_reloader")
        return TapConfigReloader(log)

    def test_tap_interface_change_logs_warn_and_is_ignored(
        self, caplog: pytest.LogCaptureFixture
    ):
        """tap.interface changes must be rejected with a WARNING log."""
        reloader = self._reloader_with_caplog(caplog)
        old = {"tap": {"interface": "eth0", "stream_timeout_s": 30}}
        new = {"tap": {"interface": "eth1", "stream_timeout_s": 30}}

        with caplog.at_level(logging.WARNING):
            reloadable, needs_restart = reloader.diff(old, new)

        restart_keys = [path for path, *_ in needs_restart]
        assert ("tap", "interface") in restart_keys

        reloadable_keys = [path for path, *_ in reloadable]
        assert ("tap", "interface") not in reloadable_keys

        warning_msgs = [
            r.message for r in caplog.records if r.levelno == logging.WARNING
        ]
        assert any(
            "interface" in m and "restart" in m for m in warning_msgs
        ), f"Expected restart warning for interface; got: {warning_msgs}"

    def test_ring_buffer_mb_change_logs_warn_and_is_ignored(
        self, caplog: pytest.LogCaptureFixture
    ):
        """tap.ring_buffer_mb changes must be rejected with a WARNING log."""
        reloader = self._reloader_with_caplog(caplog)
        old = {"tap": {"ring_buffer_mb": 64, "interface": "eth0"}}
        new = {"tap": {"ring_buffer_mb": 128, "interface": "eth0"}}

        with caplog.at_level(logging.WARNING):
            reloadable, needs_restart = reloader.diff(old, new)

        restart_keys = [path for path, *_ in needs_restart]
        assert ("tap", "ring_buffer_mb") in restart_keys

        reloadable_keys = [path for path, *_ in reloadable]
        assert ("tap", "ring_buffer_mb") not in reloadable_keys

        warning_msgs = [
            r.message for r in caplog.records if r.levelno == logging.WARNING
        ]
        assert any(
            "ring_buffer_mb" in m and "restart" in m for m in warning_msgs
        ), f"Expected restart warning for ring_buffer_mb; got: {warning_msgs}"
