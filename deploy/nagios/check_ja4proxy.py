#!/usr/bin/env python3
# deploy/nagios/check_ja4proxy.py
#
# Nagios-compatible check plugin for JA4proxy health monitoring.
# Phase 86f — returns standard Nagios exit codes and perfdata.
#
# Usage:
#   check_ja4proxy.py --url https://ja4proxy-mgmt --token $TOKEN \
#                      --check health|dial|redis|cert [--expected-dial N]
#
# Returns:
#   0 = OK, 1 = WARNING, 2 = CRITICAL, 3 = UNKNOWN
#
# Perfdata format:
#   'metric_name'=value;warn;crit;min;max
#
# Install:
#   cp check_ja4proxy.py /usr/lib64/nagios/plugins/check_ja4proxy
#   chmod 755 /usr/lib64/nagios/plugins/check_ja4proxy

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

# ── Exit codes ────────────────────────────────────────────────────────────────
OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3

# ── Thresholds ────────────────────────────────────────────────────────────────
REDIS_LATENCY_WARN_MS = 20.0
REDIS_LATENCY_CRIT_MS = 50.0
CERT_DAYS_WARN = 30
CERT_DAYS_CRIT = 7


def _build_tls_context(url: str) -> "ssl.SSLContext | None":
    """Build a TLS context for HTTPS requests to the Management API.

    JA4PROXY-2026-0055 — the previous call to ``urlopen`` passed no
    ``context`` argument, which on older CPython releases skipped
    verification entirely. A passive network attacker between Nagios
    and the Management API could then feed the plugin a forged health
    doc, hiding a real outage. We now always build a verifying context for
    HTTPS URLs; operators may opt into ``JA4PROXY_CA_BUNDLE`` to pin a
    custom CA, or ``JA4PROXY_TLS_INSECURE=1`` as a last-resort escape
    hatch (printed to stderr on every invocation so it's visible in the
    Nagios log).
    """
    if not url.lower().startswith("https://"):
        return None
    if os.environ.get("JA4PROXY_TLS_INSECURE", "") == "1":
        print(
            "WARNING: JA4PROXY_TLS_INSECURE=1 — TLS verification disabled; "
            "Nagios results are vulnerable to an active MITM.",
            file=sys.stderr,
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    ca_bundle = os.environ.get("JA4PROXY_CA_BUNDLE", "")
    if ca_bundle:
        return ssl.create_default_context(cafile=ca_bundle)
    return ssl.create_default_context()


def _fetch(url: str, token: str) -> dict:
    """GET /api/v1/health/deep and return parsed JSON."""
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    ctx = _build_tls_context(url)
    try:
        with urllib.request.urlopen(
            req, timeout=10, context=ctx
        ) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        print(f"UNKNOWN - HTTP {exc.code} from {url} | ", file=sys.stdout)
        sys.exit(UNKNOWN)
    except (urllib.error.URLError, OSError) as exc:
        print(f"UNKNOWN - cannot reach {url}: {exc} | ", file=sys.stdout)
        sys.exit(UNKNOWN)


def _perfdata(metrics: dict) -> str:
    """Format key metrics as Nagios perfdata."""
    parts = []
    for key, label, warn, crit, vmin, vmax in [
        (
            "redis_latency_ms",
            "redis_latency",
            REDIS_LATENCY_WARN_MS,
            REDIS_LATENCY_CRIT_MS,
            0,
            1000,
        ),
        ("active_connections", "active_connections", None, None, 0, None),
        ("dial", "dial_setting", None, None, 0, 100),
        (
            "cert_days_remaining",
            "cert_days_remaining",
            CERT_DAYS_WARN,
            CERT_DAYS_CRIT,
            0,
            None,
        ),
        ("block_rate_pct", "block_rate", None, None, 0, 100),
    ]:
        val = metrics.get(key)
        if val is None:
            continue
        w = f";{warn}" if warn is not None else ""
        c = f";{crit}" if crit is not None else ""
        mn = f";{vmin}" if vmin is not None else ""
        mx = f";{vmax}" if vmax is not None else ""
        parts.append(f"{label}={val}{w}{c}{mn}{mx}")
    return " ".join(parts)


def check_health(data: dict, _args: argparse.Namespace) -> int:
    """Check overall health status."""
    status = data.get("status", "unknown")
    redis_ms = data.get("redis_latency_ms", 0)
    active = data.get("active_connections", 0)
    pd = _perfdata(data)

    if status == "ok":
        print(f"OK - All nodes healthy | {pd}")
        return OK
    if status == "degraded":
        print(
            f"WARNING - Degraded (redis_latency={redis_ms}ms, "
            f"active_connections={active}) | {pd}"
        )
        return WARNING
    print(f"CRITICAL - Status: {status} | {pd}")
    return CRITICAL


def check_dial(data: dict, args: argparse.Namespace) -> int:
    """Check dial setting matches expected value."""
    dial = data.get("dial", 0)
    pd = _perfdata(data)

    if args.expected_dial is not None and dial != args.expected_dial:
        print(f"WARNING - dial={dial}, expected {args.expected_dial} | {pd}")
        return WARNING
    print(f"OK - dial={dial} | {pd}")
    return OK


def check_redis(data: dict, _args: argparse.Namespace) -> int:
    """Check Redis latency and connectivity."""
    redis_ms = data.get("redis_latency_ms", -1)
    redis_connected = data.get("redis_connected", False)
    pd = _perfdata(data)

    if not redis_connected:
        print(f"CRITICAL - Redis not connected | {pd}")
        return CRITICAL
    if redis_ms > REDIS_LATENCY_CRIT_MS:
        print(
            f"CRITICAL - Redis latency {redis_ms}ms > {REDIS_LATENCY_CRIT_MS}ms | {pd}"
        )
        return CRITICAL
    if redis_ms > REDIS_LATENCY_WARN_MS:
        print(
            f"WARNING - Redis latency {redis_ms}ms > {REDIS_LATENCY_WARN_MS}ms | {pd}"
        )
        return WARNING
    print(f"OK - Redis latency {redis_ms}ms | {pd}")
    return OK


def check_cert(data: dict, _args: argparse.Namespace) -> int:
    """Check TLS certificate days remaining."""
    days = data.get("cert_days_remaining")
    pd = _perfdata(data)

    if days is None:
        print(f"UNKNOWN - Certificate expiry unknown | {pd}")
        return UNKNOWN
    if days < 0:
        print(f"CRITICAL - Certificate expired {abs(days):.0f} days ago | {pd}")
        return CRITICAL
    if days <= CERT_DAYS_CRIT:
        print(f"CRITICAL - Certificate expires in {days:.0f} days | {pd}")
        return CRITICAL
    if days <= CERT_DAYS_WARN:
        print(f"WARNING - Certificate expires in {days:.0f} days | {pd}")
        return WARNING
    print(f"OK - Certificate valid for {days:.0f} days | {pd}")
    return OK


CHECKS = {
    "health": check_health,
    "dial": check_dial,
    "redis": check_redis,
    "cert": check_cert,
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Nagios check plugin for JA4proxy health monitoring.",
    )
    parser.add_argument(
        "--url",
        required=True,
        help="Management API base URL (e.g. https://ja4proxy-mgmt)",
    )
    parser.add_argument("--token", default="", help="API authentication token")
    parser.add_argument(
        "--check",
        required=True,
        choices=list(CHECKS.keys()),
        help="Check type: health, dial, redis, cert",
    )
    parser.add_argument(
        "--expected-dial",
        type=int,
        default=None,
        help="Expected dial value (for --check dial)",
    )
    args = parser.parse_args()

    url = f"{args.url.rstrip('/')}/api/v1/health/deep"
    data = _fetch(url, args.token)

    handler = CHECKS[args.check]
    rc = handler(data, args)
    sys.exit(rc)


if __name__ == "__main__":
    main()
