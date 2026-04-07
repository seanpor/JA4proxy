#!/usr/bin/env python3
"""
GDPR Subject Erasure (Right to be Forgotten) — Live Redis Purge

Deletes all per-IP personal data held in Redis for a given IP address.
Covers every key pattern documented in docs/REDIS_SCHEMA.md that is
keyed by IP address.

Usage:
    make gdpr-delete IP=1.2.3.4
    python3 scripts/gdpr_delete.py --ip 1.2.3.4
    python3 scripts/gdpr_delete.py --ip 1.2.3.4 --dry-run
    python3 scripts/gdpr_delete.py --ip 1.2.3.4 --report

Limitations:
    - HyperLogLog keys (hll:cidr48:*) cannot be individually erased.
      They are skipped and reported. They expire naturally via TTL.
    - Backup archive redaction is a separate concern: src/backup/redactor.py
      See Phase 40 documentation.
"""

import argparse
import ipaddress
import json
import os
import sys
from datetime import datetime, timezone

# Allow running from repo root without installing the package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _redis_client():
    import redis

    host = os.environ.get("REDIS_HOST", "127.0.0.1")
    port = int(os.environ.get("REDIS_PORT", "6379"))
    password = os.environ.get("REDIS_PASSWORD") or None
    return redis.Redis(host=host, port=port, password=password, decode_responses=True)


# All key patterns from REDIS_SCHEMA.md that are keyed by IP address.
# Each entry is a string template with {ip} as the placeholder.
_IP_KEY_PATTERNS = [
    "ban:{ip}",
    "session:ip:{ip}:ja4:*",  # wildcard — scan required
    "lifespan:{ip}",
    "concurrent:{ip}",
    "visitor:{ip}",
    "rdap:ip:{ip}",
    "abuseipdb:{ip}",
    "greynoise:data:{ip}",
    "alienvault:data:{ip}",
    "misp:data:{ip}",
    "threatfox:data:{ip}",
    "virustotal:data:{ip}",
    "beacon:{ip}:*",          # wildcard — scan required
]

# HyperLogLog keys: individual contributors CANNOT be removed from a sketch.
# These are NOT deleted. The limitation is reported to the caller.
# hll:cidr48:* keys carry a 24h TTL and expire naturally.
_HLL_PATTERNS = [
    "hll:cidr48:*",
]

# Sorted sets where the IP appears as a member value (key is not the IP).
# Requires ZREM rather than DEL.  Format: (key_glob, member_prefix_template)
_ZSET_MEMBER_PATTERNS = [
    ("behavioral:burst:*", "{ip}:"),  # member format: {ip}:{ts_ms}
]

# Patterns that need a SCAN (contain wildcard)
_SCAN_PATTERNS = [p for p in _IP_KEY_PATTERNS if "*" in p]
_EXACT_PATTERNS = [p for p in _IP_KEY_PATTERNS if "*" not in p]


def _write_audit_log(r, ip: str, dry_run: bool, keys_deleted: int,
                     hll_skipped: int, zset_removed: int,
                     invoked_by: str = "gdpr_delete.py") -> None:
    """Write an erasure audit entry to management:gdpr_erasure_log (last 1000)."""
    entry = json.dumps({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip": ip,
        "dry_run": dry_run,
        "keys_deleted": keys_deleted,
        "keys_skipped_hll": hll_skipped,
        "zset_members_removed": zset_removed,
        "invoked_by": invoked_by,
    })
    r.lpush("management:gdpr_erasure_log", entry)
    r.ltrim("management:gdpr_erasure_log", 0, 999)


def purge_ip(ip: str, dry_run: bool = False, r=None) -> dict:
    """Delete all Redis data associated with *ip*.

    Returns a dict with keys:
      keys_deleted, zset_members_removed, hll_skipped

    Args:
        ip: IP address string to erase (any valid form; normalised internally).
        dry_run: If True, report what would be deleted without deleting.
        r: Optional Redis client. If None, one is created via _redis_client().
    """
    # Normalise to canonical form before any key operations
    ip = ipaddress.ip_address(ip.strip()).compressed
    if r is None:
        r = _redis_client()
    keys_to_delete = []
    zset_removed = 0
    hll_skipped = 0

    # --- Exact-match keys ---
    for pattern in _EXACT_PATTERNS:
        key = pattern.replace("{ip}", ip)
        if r.exists(key):
            keys_to_delete.append(key)

    # --- Wildcard key patterns — SCAN with IP embedded ---
    for pattern in _SCAN_PATTERNS:
        scan_glob = pattern.replace("{ip}", ip)
        cursor = 0
        while True:
            cursor, matches = r.scan(cursor, match=scan_glob, count=100)
            keys_to_delete.extend(matches)
            if cursor == 0:
                break

    # --- Sorted set member removal ---
    for key_glob, member_prefix_tpl in _ZSET_MEMBER_PATTERNS:
        member_prefix = member_prefix_tpl.replace("{ip}", ip)
        cursor = 0
        while True:
            cursor, keys = r.scan(cursor, match=key_glob, count=100)
            for key in keys:
                members = [m for m in r.zrange(key, 0, -1)
                           if m.startswith(member_prefix)]
                if members:
                    if dry_run:
                        print(f"  [dry-run] would ZREM {len(members)} member(s) from: {key}")
                    else:
                        r.zrem(key, *members)
                        print(f"  ZREM {len(members)} member(s) from: {key}")
                    zset_removed += len(members)
            if cursor == 0:
                break

    # --- HyperLogLog: cannot erase individual contributors ---
    for pattern in _HLL_PATTERNS:
        cursor = 0
        while True:
            cursor, keys = r.scan(cursor, match=pattern, count=100)
            if keys:
                hll_skipped += len(keys)
                for key in keys:
                    print(f"  [skipped HLL — cannot remove individual IP] {key}")
            if cursor == 0:
                break

    keys_deleted = 0
    if keys_to_delete:
        for key in sorted(keys_to_delete):
            if dry_run:
                print(f"  [dry-run] would delete: {key}")
            else:
                r.delete(key)
                print(f"  deleted: {key}")
                keys_deleted += 1
    elif zset_removed == 0 and hll_skipped == 0:
        print(f"No Redis data found for IP {ip}.")

    result = {
        "keys_deleted": len(keys_to_delete) if dry_run else keys_deleted,
        "zset_members_removed": zset_removed,
        "hll_skipped": hll_skipped,
    }
    _write_audit_log(r, ip, dry_run,
                     result["keys_deleted"], hll_skipped, zset_removed)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Delete all JA4proxy Redis data for a given IP address (GDPR erasure)."
    )
    parser.add_argument("--ip", required=True, help="IP address to erase")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print keys that would be deleted without deleting them",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Print a JSON summary of the erasure operation to stdout",
    )
    args = parser.parse_args()

    raw_ip = args.ip.strip()
    try:
        ip = ipaddress.ip_address(raw_ip).compressed  # canonical form
    except ValueError:
        print(f"ERROR: '{raw_ip}' is not a valid IP address.", file=sys.stderr)
        return 1

    action = "DRY RUN —" if args.dry_run else "Deleting"
    print(f"GDPR erasure: {action} all Redis data for IP {ip}")

    try:
        result = purge_ip(ip, dry_run=args.dry_run)
    except Exception as exc:
        print(f"ERROR: could not connect to Redis: {exc}", file=sys.stderr)
        print("Set REDIS_HOST / REDIS_PORT / REDIS_PASSWORD as needed.", file=sys.stderr)
        return 1

    if args.report:
        print(json.dumps({
            "ip": ip,
            "dry_run": args.dry_run,
            **result,
        }, indent=2))

    prefix = "Dry run complete." if args.dry_run else "Erasure complete."
    print(f"\n{prefix}")
    print(f"  Keys deleted:          {result['keys_deleted']}")
    print(f"  ZSET members removed:  {result['zset_members_removed']}")
    if result["hll_skipped"]:
        print(f"  HLL keys skipped:      {result['hll_skipped']} "
              f"(probabilistic sketch — cannot erase; expire via TTL)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
