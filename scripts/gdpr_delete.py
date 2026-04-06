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

For backup archive redaction (separate concern), see src/backup/redactor.py.
"""

import argparse
import os
import sys

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
    "hll:cidr48:*",           # per-CIDR HyperLogLog — not per-IP; skip
]

# Patterns that need a SCAN (contain wildcard)
_SCAN_PATTERNS = [p for p in _IP_KEY_PATTERNS if "*" in p]
_EXACT_PATTERNS = [p for p in _IP_KEY_PATTERNS if "*" not in p]


def purge_ip(ip: str, dry_run: bool = False) -> int:
    """Delete all Redis keys associated with *ip*. Returns count of deleted keys."""
    r = _redis_client()
    deleted = 0
    keys_to_delete = []

    # Exact-match keys
    for pattern in _EXACT_PATTERNS:
        key = pattern.replace("{ip}", ip)
        if r.exists(key):
            keys_to_delete.append(key)

    # Wildcard patterns — use SCAN with the IP embedded
    for pattern in _SCAN_PATTERNS:
        scan_glob = pattern.replace("{ip}", ip)
        cursor = 0
        while True:
            cursor, matches = r.scan(cursor, match=scan_glob, count=100)
            keys_to_delete.extend(matches)
            if cursor == 0:
                break

    if not keys_to_delete:
        print(f"No Redis keys found for IP {ip}.")
        return 0

    for key in sorted(keys_to_delete):
        if dry_run:
            print(f"  [dry-run] would delete: {key}")
        else:
            r.delete(key)
            print(f"  deleted: {key}")
            deleted += 1

    return len(keys_to_delete) if dry_run else deleted


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
    args = parser.parse_args()

    ip = args.ip.strip()
    try:
        import ipaddress
        ipaddress.ip_address(ip)
    except ValueError:
        print(f"ERROR: '{ip}' is not a valid IP address.", file=sys.stderr)
        return 1

    action = "DRY RUN —" if args.dry_run else "Deleting"
    print(f"GDPR erasure: {action} all Redis data for IP {ip}")

    try:
        count = purge_ip(ip, dry_run=args.dry_run)
    except Exception as exc:
        print(f"ERROR: could not connect to Redis: {exc}", file=sys.stderr)
        print("Set REDIS_HOST / REDIS_PORT / REDIS_PASSWORD as needed.", file=sys.stderr)
        return 1

    if args.dry_run:
        print(f"\nDry run complete. {count} key(s) would be deleted.")
    else:
        print(f"\nErasure complete. {count} key(s) deleted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
