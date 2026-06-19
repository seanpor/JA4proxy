"""Tests for management.api.pubsub_signing.

The Go proxy drops messages on critical pub/sub channels unless they carry a
valid ``{type, value, signature}`` envelope (JA4PROXY-2026-0019). These tests
pin the Python publisher to the *exact* scheme the Go ``verifyPubSubHMAC``
implements, so a UI config-reload actually reaches a proxy that has a pub/sub
HMAC secret configured.

Go reference (internal/redis/pubsub.go):
    msgType = env.Type or channel
    want    = hex( HMAC_SHA256(secret, msgType + ":" + env.Value) )
    accept iff hmac.Equal(computed, want)
"""

import hashlib
import hmac
import json

import pytest

from management.api import pubsub_signing


def _go_verify(secret: bytes, channel: str, payload: str) -> bool:
    """Faithful reimplementation of the Go verifyPubSubHMAC accept path."""
    env = json.loads(payload)
    if not env.get("signature"):
        return False
    msg_type = env.get("type") or channel
    want = bytes.fromhex(env["signature"])
    mac = hmac.new(secret, f"{msg_type}:{env['value']}".encode(), hashlib.sha256)
    return hmac.compare_digest(mac.digest(), want)


@pytest.fixture
def proxy_config(tmp_path, monkeypatch):
    """Point get_proxy_config at a temp proxy.yml and bust its 60s cache."""
    def _write(redis_section: str) -> None:
        cfg = tmp_path / "proxy.yml"
        cfg.write_text(f"redis:\n{redis_section}\n")
        monkeypatch.setenv("MANAGEMENT_PROXY_CONFIG_PATH", str(cfg))
        # The loader caches for 60s keyed on a module global; reset it.
        pubsub_signing.get_proxy_config.__globals__["_cache"] = None

    return _write


def test_unsigned_when_no_secret(proxy_config):
    proxy_config("  host: localhost")  # no pubsub_hmac_secret
    payload = pubsub_signing.build_envelope("config:reload", "2026-06-19T00:00:00Z")
    env = json.loads(payload)
    assert env["type"] == "config:reload"
    assert "signature" not in env
    assert pubsub_signing.pubsub_hmac_secret() is None


def test_signed_envelope_verifies_under_go_scheme(proxy_config):
    proxy_config('  pubsub_hmac_secret: "s3cr3t-value"')
    payload = pubsub_signing.build_envelope("config:reload", "2026-06-19T00:00:00Z")
    env = json.loads(payload)
    assert env["signature"]
    assert _go_verify(b"s3cr3t-value", "config:reload", payload)
    # A wrong secret must NOT verify.
    assert not _go_verify(b"wrong-secret", "config:reload", payload)


def test_env_var_expansion_matches_proxy(proxy_config, monkeypatch):
    # The proxy expands ${VAR} before parsing; the publisher must too, or the
    # secrets diverge and every signed message is rejected.
    monkeypatch.setenv("MY_PUBSUB_SECRET", "from-env")
    proxy_config("  pubsub_hmac_secret: ${MY_PUBSUB_SECRET}")
    assert pubsub_signing.pubsub_hmac_secret() == b"from-env"
    payload = pubsub_signing.build_envelope("config:reload", "v")
    assert _go_verify(b"from-env", "config:reload", payload)


def test_env_var_default_used_when_unset(proxy_config, monkeypatch):
    monkeypatch.delenv("UNSET_SECRET", raising=False)
    proxy_config("  pubsub_hmac_secret: ${UNSET_SECRET:-fallback}")
    assert pubsub_signing.pubsub_hmac_secret() == b"fallback"


def test_unresolved_placeholder_is_treated_as_no_secret(proxy_config, monkeypatch):
    monkeypatch.delenv("UNSET_SECRET", raising=False)
    proxy_config("  pubsub_hmac_secret: ${UNSET_SECRET}")  # no default, unset
    assert pubsub_signing.pubsub_hmac_secret() is None
