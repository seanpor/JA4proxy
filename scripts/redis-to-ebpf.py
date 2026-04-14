#!/usr/bin/env python3
"""redis-to-ebpf.py — Sync Redis blacklist/ban entries into a BPF hash map.

This sidecar process polls Redis every 5 seconds and calls ``bpftool map
update`` for each blocked IPv4 address.  It is designed to run alongside
the JA4proxy eBPF/XDP program (``src/ebpf/ja4block.o``).

Usage
-----
  python3 scripts/redis-to-ebpf.py --map-id <BPF_MAP_ID> [options]

Options
-------
  --map-id INT       BPF map file descriptor / kernel map ID (required)
  --redis-url STR    Redis URL (default: redis://localhost:6379/0)
  --interval INT     Poll interval in seconds (default: 5)
  --metrics-port INT Prometheus metrics port (default: 9099, 0 to disable)

Graceful fallback
-----------------
If ``bpftool`` is not installed or the map update fails, a WARNING is
logged and the error is swallowed — the proxy continues running without
eBPF enforcement.

Prometheus metrics
------------------
  ja4proxy_ebpf_drops_total{reason="blacklist|ban"}
    Read from the BPF per-CPU array map via ``bpftool map dump``.
  ja4proxy_ebpf_sync_errors_total
    Incremented on each failed bpftool call.
"""

import argparse
import asyncio
import json
import logging
import socket
import struct
import subprocess
import sys
from typing import Dict, Optional, Set

import redis.asyncio as aioredis
from prometheus_client import Counter, start_http_server

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("redis-to-ebpf")

# Configure root logger only when running as a standalone script.
# Importing this module for testing must not reconfigure the caller's logging.
if not logger.handlers and not logging.root.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

# ---------------------------------------------------------------------------
# Prometheus
# ---------------------------------------------------------------------------

EBPF_DROPS = Counter(
    "ja4proxy_ebpf_drops_total",
    "Packets dropped by the XDP program",
    ["reason"],
)
EBPF_SYNC_ERRORS = Counter(
    "ja4proxy_ebpf_sync_errors_total",
    "Errors encountered while syncing IPs to the BPF map",
)

# Pre-initialise label combinations so they appear at zero on first scrape.
for _reason in ("blacklist", "ban"):
    EBPF_DROPS.labels(reason=_reason)

# ---------------------------------------------------------------------------
# BPF helpers
# ---------------------------------------------------------------------------

# Reason index in the drop_counters per-CPU array (matches ja4block.c)
_REASON_BLACKLIST = 0
_REASON_BAN = 1

_REASON_NAMES = {_REASON_BLACKLIST: "blacklist", _REASON_BAN: "ban"}


def _ip_to_hex(ip: str) -> Optional[str]:
    """Convert a dotted-decimal IPv4 address to a 4-byte hex string.

    Returns ``None`` for non-IPv4 addresses (IPv6, CIDR ranges, etc.).
    """
    try:
        packed = socket.inet_pton(socket.AF_INET, ip.strip())
        return " ".join(f"{b:02x}" for b in packed)
    except OSError:
        return None


def _bpftool_update(map_id: int, ip_hex: str) -> bool:
    """Call ``bpftool map update`` to insert an entry into the BPF map.

    Returns True on success, False on any error (fallback: log + skip).
    """
    cmd = [
        "bpftool",
        "map",
        "update",
        "id",
        str(map_id),
        "key",
        "hex",
        ip_hex,
        "value",
        "hex",
        "01",
    ]
    try:
        subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            timeout=5,
        )
        return True
    except FileNotFoundError:
        logger.warning(
            "ebpf | event=bpftool_not_found | "
            "effect=eBPF sync disabled (bpftool not installed)"
        )
        return False
    except PermissionError:
        logger.warning(
            "ebpf | event=bpftool_permission_denied | "
            "effect=eBPF sync disabled (missing CAP_BPF)"
        )
        return False
    except subprocess.CalledProcessError as exc:
        logger.warning(
            "ebpf | event=bpftool_error | cmd=%s | stderr=%s",
            " ".join(cmd),
            exc.stderr.decode(errors="replace").strip(),
        )
        EBPF_SYNC_ERRORS.inc()
        return False
    except subprocess.TimeoutExpired:
        logger.warning(
            "ebpf | event=bpftool_timeout | cmd=%s", " ".join(cmd)
        )
        EBPF_SYNC_ERRORS.inc()
        return False


def _bpftool_delete(map_id: int, ip_hex: str) -> bool:
    """Remove an entry from the BPF map."""
    cmd = [
        "bpftool",
        "map",
        "delete",
        "id",
        str(map_id),
        "key",
        "hex",
        ip_hex,
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=5)
        return True
    except (FileNotFoundError, PermissionError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def _read_drop_counters(map_id: int) -> Dict[str, int]:
    """Read drop counters from the BPF per-CPU array map.

    Returns a dict ``{reason_name: count}`` summed across all CPUs.
    Returns an empty dict on any error (fail-open).
    """
    cmd = ["bpftool", "map", "dump", "id", str(map_id), "--json"]
    try:
        result = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            timeout=5,
        )
        entries = json.loads(result.stdout)
    except FileNotFoundError:
        return {}
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return {}

    counters: Dict[str, int] = {}
    for entry in entries:
        try:
            key_raw = entry.get("key", [])
            if not key_raw:
                continue
            idx = int(key_raw[0], 16) if isinstance(key_raw[0], str) else key_raw[0]
            reason = _REASON_NAMES.get(idx)
            if reason is None:
                continue
            # value is a list of per-CPU values (hex strings or ints)
            values = entry.get("value", [])
            total = sum(
                int(v, 16) if isinstance(v, str) else int(v) for v in values
            )
            counters[reason] = total
        except (KeyError, ValueError, TypeError):
            continue
    return counters


# ---------------------------------------------------------------------------
# Redis helpers
# ---------------------------------------------------------------------------


async def _collect_blocked_ips(redis_client: aioredis.Redis) -> Dict[str, str]:
    """Return a dict of ``{ip: reason}`` from Redis blacklist and ban:* keys.

    Errors are logged and an empty dict is returned (fail-open).
    """
    result: Dict[str, str] = {}
    try:
        # ja4:blacklist holds JA4 fingerprints, not IPs — not used here.
        # IP-level blocking sources:
        #   ban:{ip}      — TTL-bound per-IP bans (Phase 0+, see REDIS_SCHEMA.md)
        #   ip:blacklist  — static operator-managed IP SET (Phase 35, see REDIS_SCHEMA.md)
        #
        # ban:{ip} keys — TTL-bound per-IP bans
        async for key in redis_client.scan_iter("ban:*"):
            ip = key.decode("utf-8", errors="ignore").removeprefix("ban:")
            if ip:
                result[ip] = "ban"

        # ip:blacklist — static blocklist SET (if present)
        members = await redis_client.smembers("ip:blacklist")
        for m in members:
            ip = m.decode("utf-8", errors="ignore")
            if ip and ip not in result:
                result[ip] = "blacklist"

    except Exception as exc:
        logger.error(
            "ebpf | event=redis_collect_error | error=%s", exc
        )
    return result


# ---------------------------------------------------------------------------
# Main sync loop
# ---------------------------------------------------------------------------


async def _sync_loop(
    map_id: int,
    redis_url: str,
    interval: int,
    drop_counters_map_id: Optional[int],
) -> None:
    """Continuously sync Redis block lists into the BPF map."""
    redis_client = aioredis.from_url(redis_url, decode_responses=False)
    synced: Set[str] = set()      # IPs already in the BPF map
    prev_drop_counts: Dict[str, int] = {}

    logger.info(
        "ebpf | event=sync_started | map_id=%d | interval=%d | redis=%s",
        map_id,
        interval,
        redis_url,
    )

    try:
        while True:
            try:
                # ── Collect current blocked IPs ──────────────────────────────
                blocked = await _collect_blocked_ips(redis_client)

                # ── Add new entries ──────────────────────────────────────────
                for ip, reason in blocked.items():
                    if ip in synced:
                        continue
                    ip_hex = _ip_to_hex(ip)
                    if ip_hex is None:
                        logger.debug(
                            "ebpf | event=ipv6_skip | ip=%s | "
                            "effect=XDP map only supports IPv4",
                            ip,
                        )
                        continue  # skip IPv6 / invalid
                    ok = _bpftool_update(map_id, ip_hex)
                    if ok:
                        synced.add(ip)
                        logger.debug(
                            "ebpf | event=ip_added | ip=%s | reason=%s", ip, reason
                        )

                # ── Remove stale entries ─────────────────────────────────────
                for ip in list(synced):
                    if ip not in blocked:
                        ip_hex = _ip_to_hex(ip)
                        if ip_hex:
                            _bpftool_delete(map_id, ip_hex)
                        synced.discard(ip)
                        logger.debug(
                            "ebpf | event=ip_removed | ip=%s", ip
                        )

                # ── Update Prometheus counters from BPF map ──────────────────
                if drop_counters_map_id is not None:
                    current = _read_drop_counters(drop_counters_map_id)
                    for reason, total in current.items():
                        prev = prev_drop_counts.get(reason, 0)
                        delta = max(0, total - prev)
                        if delta > 0:
                            EBPF_DROPS.labels(reason=reason).inc(delta)
                        prev_drop_counts[reason] = total

            except asyncio.CancelledError:
                logger.info("ebpf | event=sync_stopped")
                raise  # propagate so asyncio.Task cleanup works correctly
            except Exception as exc:
                logger.error(
                    "ebpf | event=sync_error | error=%s", exc
                )
                EBPF_SYNC_ERRORS.inc()

            await asyncio.sleep(interval)
    finally:
        await redis_client.aclose()
        logger.debug("ebpf | event=redis_client_closed")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="redis-to-ebpf",
        description="Sync Redis block lists into a BPF map for XDP enforcement.",
    )
    p.add_argument(
        "--map-id",
        type=int,
        required=True,
        metavar="ID",
        help="BPF map kernel ID of the blocked_ips hash map.",
    )
    p.add_argument(
        "--counters-map-id",
        type=int,
        default=None,
        metavar="ID",
        help="BPF map kernel ID of the drop_counters per-CPU array (optional).",
    )
    p.add_argument(
        "--redis-url",
        default="redis://localhost:6379/0",
        metavar="URL",
        help="Redis URL (default: redis://localhost:6379/0).",
    )
    p.add_argument(
        "--interval",
        type=int,
        default=5,
        metavar="SECS",
        help="Poll interval in seconds (default: 5).",
    )
    p.add_argument(
        "--metrics-port",
        type=int,
        default=9099,
        metavar="PORT",
        help="Prometheus metrics port (default: 9099; 0 to disable).",
    )
    return p


async def _async_main(args: argparse.Namespace) -> None:
    if args.metrics_port:
        try:
            start_http_server(args.metrics_port)
            logger.info(
                "ebpf | event=metrics_started | port=%d", args.metrics_port
            )
        except OSError as exc:
            logger.warning(
                "ebpf | event=metrics_port_error | port=%d | error=%s",
                args.metrics_port,
                exc,
            )

    await _sync_loop(
        map_id=args.map_id,
        redis_url=args.redis_url,
        interval=args.interval,
        drop_counters_map_id=args.counters_map_id,
    )


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    try:
        asyncio.run(_async_main(args))
    except KeyboardInterrupt:
        logger.info("ebpf | event=interrupted")


if __name__ == "__main__":
    main()
