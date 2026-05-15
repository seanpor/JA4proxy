#!/usr/bin/env python3
"""
reconcile_ipset.py — iptables/ipset drift reconciliation for TAP enforcement.

Compares the live iptables ipset (ja4proxy_ban) against the Redis ban keys
and reconciles any drift:
  - IPs in Redis but missing from ipset → re-added
  - IPs in ipset but not in Redis → removed (ban expired)

Usage:
    sudo python3 scripts/reconcile_ipset.py [--dry-run] [--verbose]
    sudo python3 scripts/reconcile_ipset.py --ipset-name ja4proxy_ban --redis-url redis://localhost:6379

This script must be run as root (or with CAP_NET_ADMIN) to manage ipset.

Designed to run on a schedule (e.g. every 5 minutes via cron) as a safeguard
against temporary enforcement failures.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import subprocess
import sys
from typing import Optional

logger = logging.getLogger("reconcile_ipset")


# ─────────────────────────────────────────────────────────────────────────────
# ipset helpers
# ─────────────────────────────────────────────────────────────────────────────


def _ipset_list(ipset_name: str) -> set[str]:
    """Return the set of IPs currently in the named ipset."""
    try:
        result = subprocess.run(
            ["ipset", "list", ipset_name, "-output", "plain"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            logger.warning("ipset list failed: %s", result.stderr.strip())
            return set()
        lines = result.stdout.splitlines()
        # Lines after "Members:" are the IPs
        in_members = False
        ips: set[str] = set()
        for line in lines:
            if line.strip() == "Members:":
                in_members = True
                continue
            if in_members and line.strip():
                # May include timeout: "1.2.3.4 timeout 3600"
                ip = line.strip().split()[0]
                ips.add(ip)
        return ips
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.error("ipset not available: %s", exc)
        return set()


def _ipset_add(ipset_name: str, ip: str, ttl: int, dry_run: bool) -> None:
    """Add an IP to the ipset with a timeout."""
    cmd = ["ipset", "add", ipset_name, ip, "timeout", str(ttl)]
    if dry_run:
        logger.info("DRY-RUN: %s", " ".join(cmd))
        return
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    if result.returncode != 0 and "already added" not in result.stderr:
        logger.warning("ipset add failed for %s: %s", ip, result.stderr.strip())


def _ipset_del(ipset_name: str, ip: str, dry_run: bool) -> None:
    """Remove an IP from the ipset."""
    cmd = ["ipset", "del", ipset_name, ip]
    if dry_run:
        logger.info("DRY-RUN: %s", " ".join(cmd))
        return
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    if result.returncode != 0 and "Element not found" not in result.stderr:
        logger.warning("ipset del failed for %s: %s", ip, result.stderr.strip())


# ─────────────────────────────────────────────────────────────────────────────
# Redis helpers
# ─────────────────────────────────────────────────────────────────────────────


def _redis_get_bans(redis_url: str) -> dict[str, int]:
    """Return dict of {ip: remaining_ttl_s} for all ban:{ip} keys in Redis."""
    try:
        import redis as redis_mod
    except ImportError:
        logger.error("redis-py not installed: pip install redis")
        return {}

    client = redis_mod.from_url(redis_url, decode_responses=True, socket_timeout=5)
    result: dict[str, int] = {}
    try:
        cursor = 0
        while True:
            cursor, keys = client.scan(cursor, match="ban:*", count=500)
            for key in keys:
                ip = key[4:]  # strip "ban:"
                ttl = client.ttl(key)
                if ttl > 0:
                    result[ip] = ttl
                elif ttl == -1:
                    result[ip] = 3600  # no-TTL bans treated as 1h default
            if cursor == 0:
                break
    except Exception as exc:
        logger.error("Redis scan failed: %s", exc)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Reconciliation logic
# ─────────────────────────────────────────────────────────────────────────────


def reconcile(
    ipset_name: str,
    redis_url: str,
    dry_run: bool,
    verbose: bool,
) -> tuple[int, int, int]:
    """Compare Redis bans against ipset and reconcile drift.

    Returns:
        (n_added, n_removed, n_ok) — counts of reconciliation actions.
    """
    redis_bans = _redis_get_bans(redis_url)
    ipset_ips = _ipset_list(ipset_name)

    redis_set = set(redis_bans.keys())

    missing_from_ipset = redis_set - ipset_ips  # in Redis, missing from ipset
    stale_in_ipset = ipset_ips - redis_set  # in ipset, not in Redis (expired)
    already_ok = redis_set & ipset_ips

    n_added = 0
    n_removed = 0

    if verbose or missing_from_ipset:
        logger.info("IPs in Redis but missing from ipset: %d", len(missing_from_ipset))
    for ip in sorted(missing_from_ipset):
        ttl = redis_bans.get(ip, 3600)
        if verbose:
            logger.info("  ADD %s (ttl=%ds)", ip, ttl)
        _ipset_add(ipset_name, ip, ttl, dry_run)
        n_added += 1

    if verbose or stale_in_ipset:
        logger.info("IPs in ipset but not in Redis (stale): %d", len(stale_in_ipset))
    for ip in sorted(stale_in_ipset):
        if verbose:
            logger.info("  DEL %s (ban expired)", ip)
        _ipset_del(ipset_name, ip, dry_run)
        n_removed += 1

    n_ok = len(already_ok)
    logger.info(
        "Reconciliation complete: added=%d removed=%d unchanged=%d%s",
        n_added,
        n_removed,
        n_ok,
        " [DRY-RUN]" if dry_run else "",
    )

    return n_added, n_removed, n_ok


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reconcile iptables ipset with Redis ban keys"
    )
    parser.add_argument(
        "--ipset-name",
        default="ja4proxy_ban",
        help="ipset name (default: ja4proxy_ban)",
    )
    parser.add_argument(
        "--redis-url",
        default=os.environ.get("REDIS_URL", "redis://localhost:6379"),
        help="Redis URL (default: $REDIS_URL or redis://localhost:6379)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print actions without executing them",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Log each IP add/remove",
    )
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)-5s %(name)s | %(message)s",
    )

    n_added, n_removed, n_ok = reconcile(
        ipset_name=args.ipset_name,
        redis_url=args.redis_url,
        dry_run=args.dry_run,
        verbose=args.verbose,
    )

    # Exit non-zero if any drift was found (useful for monitoring)
    if n_added > 0 or n_removed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
