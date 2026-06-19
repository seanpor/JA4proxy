"""Build pub/sub payloads the Go proxy will accept on its control channels.

Phase 309 fix — the Go proxy subscribes to **colon-namespaced** channels
(``config:reload``, ``config:dial:change``, ``ja4:blacklist:add`` …, see
``internal/redis/pubsub.go``). When ``redis.pubsub_hmac_secret`` is configured it
treats those channels as *critical* and **drops any message that is not
HMAC-signed** (JA4PROXY-2026-0019). This module produces the exact
``{type, value, signature}`` envelope ``verifyPubSubHMAC`` expects, signing it
with the same secret the proxy loads from ``config/proxy.yml``.

The signature scheme mirrors the Go verifier byte-for-byte:

    signature = hex( HMAC_SHA256( secret, f"{type}:{value}" ) )

where ``type`` is the channel name (the proxy falls back to the channel name when
the envelope ``type`` is empty). When no secret is configured the proxy performs
no verification, so the (still well-formed) envelope is published unsigned.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re

from .proxy_config import get_proxy_config

logger = logging.getLogger(__name__)

# Mirrors envVarPattern in internal/config/loader.go: ${VAR} and ${VAR:-default}.
_ENV_VAR_RE = re.compile(r"\$\{([^}:]+)(?::-([^}]*))?\}")


def _expand_env_vars(s: str) -> str:
    """Expand ``${VAR}`` / ``${VAR:-default}`` exactly as the Go loader does.

    The proxy expands the whole YAML before parsing, but the management API reads
    the raw YAML, so the secret value reaches us un-expanded. We must apply the
    identical rule (use the env value when set *and* non-empty, else the default)
    so the secret we sign with matches the one the proxy verifies with.
    """

    def repl(m: re.Match[str]) -> str:
        var = m.group(1)
        default = m.group(2) or ""
        val = os.environ.get(var)
        if val:  # set and non-empty
            return val
        return default

    return _ENV_VAR_RE.sub(repl, s)


def pubsub_hmac_secret() -> bytes | None:
    """Return the proxy's pub/sub HMAC secret, or ``None`` if not configured.

    Reads ``redis.pubsub_hmac_secret`` from ``config/proxy.yml`` and applies the
    same env-var expansion the proxy uses. An unresolved ``${VAR}`` (no value, no
    default) yields ``None`` — we never sign with a literal placeholder.
    """
    cfg = get_proxy_config() or {}
    raw = ((cfg.get("redis") or {}).get("pubsub_hmac_secret") or "")
    if not isinstance(raw, str):
        return None
    secret = _expand_env_vars(raw).strip()
    if not secret:
        return None
    return secret.encode()


def build_envelope(channel: str, value: str) -> str:
    """Return the JSON payload to ``PUBLISH`` on *channel*.

    Always a ``{type, value}`` envelope; a ``signature`` field is added when a
    pub/sub HMAC secret is configured so the proxy accepts it on a critical
    channel. The ``value`` is informational for reload channels (the proxy
    re-reads config regardless) but is part of the signed material.
    """
    env: dict[str, str] = {"type": channel, "value": value}
    secret = pubsub_hmac_secret()
    if secret is not None:
        sig = hmac.new(secret, f"{channel}:{value}".encode(), hashlib.sha256).hexdigest()
        env["signature"] = sig
    return json.dumps(env)
