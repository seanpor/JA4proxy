"""Phase 827 — the signing-secret misconfiguration must be loud at startup.

WHY THIS EXISTS
---------------
The proxy signs every connection event with ANALYTICS_HMAC_SECRET; this node
verifies it with the same value. When they differ, every event is discarded and
NOTHING reports a problem — both containers healthy, /health 200, the proxy
still writing, the Intelligence panel simply empty. It was found by eye.

The commonest cause is detectable before a single event is lost: the variable
was plumbed into docker-compose but never read into the config, leaving the
built-in placeholder in force. These tests pin that check.
"""

from __future__ import annotations

import logging

import pytest

from src.analytics.main import AnalyticsNode

PLACEHOLDER = "default-secret-change-me"


def node_with(security: dict) -> AnalyticsNode:
    """An AnalyticsNode with config injected, bypassing file loading."""
    node = AnalyticsNode.__new__(AnalyticsNode)
    node.config = {"security": security}
    return node


class TestPlaceholderSecret:
    @pytest.mark.parametrize("secret", [PLACEHOLDER, ""])
    def test_unconfigured_secret_logs_at_error(self, secret, caplog):
        caplog.set_level(logging.DEBUG)
        node_with({"hmac_secret": secret, "hmac_required": True})._warn_on_placeholder_hmac_secret()

        errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
        assert errors, (
            "an unconfigured signing secret discards 100% of events while the "
            "service reports healthy — it must not be logged below ERROR"
        )
        text = errors[0].getMessage()
        assert "ANALYTICS_HMAC_SECRET" in text, "the message must name the variable to set"
        assert "runbook" in text or "docs/runbooks" in text, "must point somewhere"

    def test_configured_secret_is_silent(self, caplog):
        caplog.set_level(logging.DEBUG)
        node_with(
            {"hmac_secret": "a-real-32-byte-secret-from-the-env", "hmac_required": True}
        )._warn_on_placeholder_hmac_secret()

        assert not [r for r in caplog.records if r.levelno >= logging.WARNING], (
            "a correctly configured node must start quietly, or the real "
            "warning gets tuned out"
        )

    def test_verification_disabled_is_warned_separately(self, caplog):
        """hmac_required=false is a different risk: any writer is trusted."""
        caplog.set_level(logging.DEBUG)
        node_with(
            {"hmac_secret": PLACEHOLDER, "hmac_required": False}
        )._warn_on_placeholder_hmac_secret()

        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert warnings, "disabled verification must still be announced"
        assert "hmac_disabled" in warnings[0].getMessage()

    def test_placeholder_matches_the_config_default(self):
        """If the default is renamed, this check silently stops working."""
        from src.analytics.config import load_config

        import tempfile, os, yaml

        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            yaml.safe_dump({"redis": {"host": "x"}}, f)
            path = f.name
        try:
            env_backup = os.environ.pop("ANALYTICS_HMAC_SECRET", None)
            default = load_config(path)["security"]["hmac_secret"]
        finally:
            os.unlink(path)
            if env_backup is not None:
                os.environ["ANALYTICS_HMAC_SECRET"] = env_backup

        assert default == PLACEHOLDER, (
            f"config default is {default!r} but the startup check looks for "
            f"{PLACEHOLDER!r} — the check would never fire"
        )
