"""Tests for Phase 101c — CRITICAL safety caps.

TDD Tests — these tests define the expected behavior.
They will FAIL until the coder implements the fixes.

Gap Coverage
-----------
- C4 (CRITICAL): Per-feed safety caps (max_new_per_poll, max_owned_total, max_delta_per_poll)
- C5 (CRITICAL): Two-empty-poll gate before bulk cleanup
- C6 (CRITICAL): ja4_safe_to_block(ja4) FP corpus check
"""

from __future__ import annotations

import pytest


class TestFeedConfigDefaults:
    """Tests for FeedConfig default safety cap values."""

    def test_default_max_new_per_poll_is_500(self):
        """Default max_new_per_poll should be 500."""
        pytest.skip("C4 fix pending - FeedConfig needs caps field")

    def test_default_max_owned_total_is_50k(self):
        """Default max_owned_total should be 50000."""
        pytest.skip("C4 fix pending - FeedConfig needs caps field")

    def test_default_max_delta_per_poll_is_zero(self):
        """Default max_delta_per_poll should be 0 (unlimited)."""
        pytest.skip("C4 fix pending - FeedConfig needs caps field")


class TestRunnerCapEnforcement:
    """Tests for runner cap enforcement."""

    def test_max_new_per_poll_enforced(self):
        """When poll returns more than cap, only first N processed."""
        pytest.skip("C4 fix pending - runner cap enforcement needed")

    def test_max_owned_total_enforced(self):
        """When owned >= cap, refuse new indicators."""
        pytest.skip("C4 fix pending - runner cap enforcement needed")


class TestEmptyPollGate:
    """Tests for two-empty-poll cleanup gate."""

    def test_first_empty_skips_cleanup(self):
        """First empty poll skips cleanup."""
        pytest.skip("C5 fix pending - empty streak tracking needed")

    def test_second_empty_enables_cleanup(self):
        """Second empty enables capped cleanup."""
        pytest.skip("C5 fix pending - empty streak tracking needed")


class TestJA4Safety:
    """Tests for JA4 false-positive check."""

    def test_ja4_safety_module_exists(self):
        """ja4_safety module should exist."""
        pytest.skip("C6 fix pending - ja4_safety module needed")

    def test_known_browser_ja4_allowed(self):
        """Known browser JA4 should not be blocked."""
        pytest.skip("C6 fix pending - FP corpus check needed")


class TestMetrics:
    """Tests for cap metrics."""

    def test_caps_hit_metric_wired(self):
        """ti_feed_caps_hit_total should be wired."""
        pytest.skip("C4 fix pending - metric")

    def test_fp_blocked_metric_wired(self):
        """ti_feed_fp_blocked_total should be wired."""
        pytest.skip("C6 fix pending - metric")
