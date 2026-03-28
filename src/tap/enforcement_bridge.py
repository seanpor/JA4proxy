"""
Enforcement Bridge — dispatches TAP-mode bans to enforcement backends (Phase 20, Group 8).

Subscribes to the Redis ``ja4proxy:bans`` channel.  For each ban event, dispatches
concurrently to all enabled backends:

- **iptables/ipset**: ``ipset add ja4proxy_ban {ip} timeout {ttl}``
  via ``asyncio.create_subprocess_exec`` (never shell=True).
- **BGP (ExaBGP)**: writes ``announce route`` command to the ExaBGP named pipe.
  Prefix length guard: rejects IPv4 prefixes broader than /24, IPv6 broader than /48.
- **Webhook**: HTTP POST with HMAC-SHA256 ``X-JA4Proxy-Signature`` header.
  Retries up to ``max_retries`` on 5xx responses.

Backend failures are logged individually and never propagate — one failed backend
never prevents the others from executing.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Redis channel where TapPipeline publishes ban events
BAN_CHANNEL = "ja4proxy:bans"

# BGP prefix length guards
_BGP_MIN_PREFIX_V4 = 24  # /24 = 256 hosts; reject anything broader (e.g. /16)
_BGP_MIN_PREFIX_V6 = 48  # /48; reject /32 or broader


class EnforcementBridge:
    """Subscribes to Redis ban events and dispatches to enforcement backends.

    All backends run concurrently via ``asyncio.gather(return_exceptions=True)``.
    Individual backend failures are logged and swallowed.

    Config path: ``tap_enforcement`` section of proxy.yml.

    Args:
        config: Full proxy config dict.  Reads ``tap_enforcement`` section.
        redis: Synchronous redis-py instance (used for pub/sub).
        http_session: Optional ``aiohttp.ClientSession`` for webhook calls.
                      If None, webhook backend is disabled.
    """

    def __init__(
        self,
        config: dict,
        redis: Any,
        http_session: Any = None,
    ) -> None:
        self._redis = redis
        self._session = http_session
        cfg = config.get("tap_enforcement", {})

        # iptables/ipset backend
        self._iptables_enabled: bool = cfg.get("iptables", {}).get("enabled", False)
        self._ipset_name: str = cfg.get("iptables", {}).get(
            "ipset_name", "ja4proxy_ban"
        )

        # BGP backend
        bgp_cfg = cfg.get("bgp", {})
        self._bgp_enabled: bool = bgp_cfg.get("enabled", False)
        self._bgp_pipe: str = bgp_cfg.get("pipe", "/run/exabgp.cmd")
        self._bgp_next_hop: str = bgp_cfg.get("next_hop", "self")
        self._bgp_agg_v4: int = int(bgp_cfg.get("aggregate_prefix_len_v4", 32))
        self._bgp_agg_v6: int = int(bgp_cfg.get("aggregate_prefix_len_v6", 128))

        # Webhook backend
        webhook_cfg = cfg.get("webhook", {})
        self._webhook_enabled: bool = webhook_cfg.get("enabled", False)
        self._webhook_url: str = webhook_cfg.get("url", "")
        self._webhook_secret: bytes = webhook_cfg.get("secret", "").encode()
        self._webhook_max_retries: int = int(webhook_cfg.get("max_retries", 3))
        self._webhook_retry_delay: float = float(webhook_cfg.get("retry_delay_s", 1.0))

        self._pubsub: Any = None
        self._task: Optional[asyncio.Task] = None
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Subscribe to ``ja4proxy:bans`` and start the dispatch loop."""
        self._running = True
        self._task = asyncio.create_task(self._listen_loop(), name="enforcement_bridge")

    async def close(self) -> None:
        """Cancel the dispatch loop and unsubscribe."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        if self._pubsub is not None:
            try:
                await asyncio.get_event_loop().run_in_executor(None, self._pubsub.close)
            except Exception:
                pass

    async def _listen_loop(self) -> None:
        """Subscribe to Redis pub/sub and dispatch bans.  Reconnects on error."""
        while self._running:
            try:
                pubsub = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: self._redis.pubsub()
                )
                self._pubsub = pubsub
                await asyncio.get_event_loop().run_in_executor(
                    None, lambda: pubsub.subscribe(BAN_CHANNEL)
                )
                logger.info(
                    "enforcement_bridge | event=subscribed | channel=%s", BAN_CHANNEL
                )

                while self._running:
                    msg = await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: pubsub.get_message(
                            ignore_subscribe_messages=True, timeout=1.0
                        ),
                    )
                    if msg and msg.get("type") == "message":
                        await self._handle_message(msg)
            except asyncio.CancelledError:
                return
            except Exception:
                logger.exception(
                    "enforcement_bridge | event=pubsub_error | reconnect_in=5s"
                )
                await asyncio.sleep(5)

    async def _handle_message(self, msg: dict) -> None:
        try:
            data = json.loads(msg["data"])
            ip = data["ip"]
            ttl = int(data.get("ttl", 3600))
            reason = data.get("reason", "")
            await self._on_ban(ip, ttl, reason)
        except Exception:
            logger.exception(
                "enforcement_bridge | event=message_parse_error | msg=%s", msg
            )

    # ------------------------------------------------------------------
    # Fan-out
    # ------------------------------------------------------------------

    async def _on_ban(self, ip: str, ttl: int, reason: str) -> None:
        """Dispatch ban to all enabled backends concurrently.

        Individual backend failures are logged and swallowed via
        ``asyncio.gather(return_exceptions=True)``.
        """
        backends = []
        if self._iptables_enabled:
            backends.append(self._iptables_ban(ip, ttl))
        if self._bgp_enabled:
            backends.append(self._bgp_announce(ip))
        if self._webhook_enabled and self._session is not None:
            backends.append(self._webhook_ban(ip, ttl, reason))

        if not backends:
            return

        results = await asyncio.gather(*backends, return_exceptions=True)
        for i, result in enumerate(results):
            if isinstance(result, BaseException):
                logger.error(
                    "enforcement_bridge | event=backend_error | backend=%d | err=%s",
                    i,
                    result,
                )

    # ------------------------------------------------------------------
    # Backends
    # ------------------------------------------------------------------

    async def _iptables_ban(self, ip: str, ttl: int) -> None:
        """Add IP to ipset with TTL via ``ipset add`` (never shell=True)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ipset",
                "add",
                self._ipset_name,
                ip,
                "timeout",
                str(ttl),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode != 0:
                err = stderr.decode().strip() if stderr else ""
                # "already in set" is not an error
                if "already added" not in err and "already in set" not in err:
                    logger.warning(
                        "enforcement_bridge | event=ipset_error | ip=%s | err=%s",
                        ip,
                        err,
                    )
        except FileNotFoundError:
            logger.warning(
                "enforcement_bridge | event=ipset_not_found | "
                "help=install ipset and create set ja4proxy_ban"
            )
        except Exception:
            logger.exception("enforcement_bridge | event=iptables_error | ip=%s", ip)

    async def _bgp_announce(self, ip: str) -> None:
        """Write an ExaBGP ``announce route`` command to the named pipe.

        Prefix length guard: rejects IPv4 prefixes broader than /%d,
        IPv6 broader than /%d.
        """ % (
            _BGP_MIN_PREFIX_V4,
            _BGP_MIN_PREFIX_V6,
        )
        try:
            addr = ipaddress.ip_address(ip)
            if addr.version == 4:
                agg_len = self._bgp_agg_v4
                if agg_len < _BGP_MIN_PREFIX_V4:
                    logger.warning(
                        "enforcement_bridge | event=bgp_prefix_rejected | "
                        "ip=%s | prefix_len=%d | min=%d",
                        ip,
                        agg_len,
                        _BGP_MIN_PREFIX_V4,
                    )
                    return
            else:
                agg_len = self._bgp_agg_v6
                if agg_len < _BGP_MIN_PREFIX_V6:
                    logger.warning(
                        "enforcement_bridge | event=bgp_prefix_rejected | "
                        "ip=%s | prefix_len=%d | min=%d",
                        ip,
                        agg_len,
                        _BGP_MIN_PREFIX_V6,
                    )
                    return

            network = ipaddress.ip_network(f"{ip}/{agg_len}", strict=False)
            cmd = f"announce route {network} next-hop {self._bgp_next_hop}\n"

            def _write_pipe():
                with open(self._bgp_pipe, "w") as pipe:
                    pipe.write(cmd)

            try:
                await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(None, _write_pipe),
                    timeout=5.0,
                )
            except asyncio.TimeoutError:
                logger.error(
                    "enforcement_bridge | event=bgp_pipe_timeout | pipe=%s",
                    self._bgp_pipe,
                )
            except FileNotFoundError:
                logger.error(
                    "enforcement_bridge | event=bgp_pipe_missing | pipe=%s",
                    self._bgp_pipe,
                )
        except Exception:
            logger.exception("enforcement_bridge | event=bgp_error | ip=%s", ip)

    async def _webhook_ban(self, ip: str, ttl: int, reason: str) -> None:
        """POST ban to webhook URL with HMAC-SHA256 signature.  Retries on 5xx."""
        payload = json.dumps(
            {"ip": ip, "ttl": ttl, "reason": reason}, separators=(",", ":")
        )
        sig = hmac.new(
            self._webhook_secret, payload.encode(), hashlib.sha256
        ).hexdigest()
        headers = {
            "Content-Type": "application/json",
            "X-JA4Proxy-Signature": f"sha256={sig}",
        }

        for attempt in range(self._webhook_max_retries + 1):
            try:
                async with self._session.post(
                    self._webhook_url,
                    data=payload,
                    headers=headers,
                    timeout=10,
                ) as resp:
                    if resp.status < 500:
                        return
                    # 5xx — retry
                    logger.warning(
                        "enforcement_bridge | event=webhook_5xx | "
                        "status=%d | attempt=%d",
                        resp.status,
                        attempt + 1,
                    )
            except Exception:
                logger.exception(
                    "enforcement_bridge | event=webhook_error | attempt=%d", attempt + 1
                )

            if attempt < self._webhook_max_retries:
                await asyncio.sleep(self._webhook_retry_delay)

        logger.error(
            "enforcement_bridge | event=webhook_max_retries | ip=%s | retries=%d",
            ip,
            self._webhook_max_retries,
        )
