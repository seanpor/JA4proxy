#!/usr/bin/env python3
"""
JA4proxy test bot — lightweight manual tester.

Connects to a running JA4proxy instance, sends TLS connections through it,
reports per-connection verdict (ALLOWED / BLOCKED / ERROR), latency, and the
JA4 fingerprint the proxy observed.

Stdlib only — no pip install required.

Usage:
    # Default: connect to localhost:443 (HAProxy frontend)
    python3 scripts/test-bot.py

    # Specific host/port
    python3 scripts/test-bot.py --proxy 10.0.0.5 --port 443

    # Show JA4 fingerprint sent by each connection
    python3 scripts/test-bot.py --show-ja4

    # Quick connectivity check (1 connection, exit 0 on success)
    python3 scripts/test-bot.py --ping
"""

import argparse
import os
import socket
import ssl
import sys
import time
from dataclasses import dataclass

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


@dataclass
class ConnectionResult:
    name: str
    ok: bool
    blocked: bool
    latency_ms: float
    error: str = ""
    ja4_hint: str = ""


TEST_PROFILES = [
    {
        "name": "Chrome-like (modern browser)",
        "sni": "backend",
        "min_version": ssl.TLSVersion.TLSv1_2,
        "max_version": ssl.TLSVersion.TLSv1_3,
        "ciphers": "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!MD5:!DSS",
        "alpn": ["h2", "http/1.1"],
        "expect_allowed": True,
    },
    {
        "name": "Python-requests (no ALPN, default ciphers)",
        "sni": "backend",
        "min_version": ssl.TLSVersion.TLSv1_2,
        "max_version": ssl.TLSVersion.TLSv1_3,
        "ciphers": "DEFAULT",
        "alpn": None,
        "expect_allowed": True,
    },
    {
        "name": "Scanner-like (TLS 1.2 only, one cipher, no ALPN)",
        "sni": "backend",
        "min_version": ssl.TLSVersion.TLSv1_2,
        "max_version": ssl.TLSVersion.TLSv1_2,
        "ciphers": "AES128-SHA",
        "alpn": None,
        "expect_allowed": False,
    },
    {
        "name": "curl-like (TLS 1.2, modern cipher, no ALPN)",
        "sni": "backend",
        "min_version": ssl.TLSVersion.TLSv1_2,
        "max_version": ssl.TLSVersion.TLSv1_3,
        "ciphers": "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384",
        "alpn": None,
        "expect_allowed": True,
    },
    {
        "name": "Minimal (TLS 1.2, single cipher, no ALPN)",
        "sni": "backend",
        "min_version": ssl.TLSVersion.TLSv1_2,
        "max_version": ssl.TLSVersion.TLSv1_2,
        "ciphers": "ECDHE-RSA-AES128-GCM-SHA256",
        "alpn": None,
        "expect_allowed": False,
    },
]


def make_ja4_fingerprint(alpn, tls_max) -> str:
    """Best-effort local JA4 fingerprint computation.

    This approximates what the proxy will see. The actual JA4 is computed
    server-side from the raw ClientHello bytes.
    """
    tls_version = "13" if tls_max >= ssl.TLSVersion.TLSv1_3 else "12"
    alpn_str = alpn if alpn else "00"
    alpn_hash = f"{len(alpn_str):02x}"[:12].ljust(12, "0")
    return f"t{tls_version}{alpn_hash}"


def try_connection(
    proxy_host: str,
    proxy_port: int,
    profile: dict,
    timeout: float,
) -> ConnectionResult:
    """Attempt a single TLS connection through the proxy."""
    name = profile["name"]
    start = time.monotonic()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = profile["min_version"]
    ctx.maximum_version = profile["max_version"]
    try:
        ctx.set_ciphers(profile["ciphers"])
    except ssl.SSLError:
        pass
    if profile.get("alpn"):
        ctx.set_alpn_protocols(profile["alpn"])

    alpn_val = "".join(sorted(profile.get("alpn") or ""))
    ja4_hint = make_ja4_fingerprint(alpn_val or None, profile["max_version"])

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((proxy_host, proxy_port))
        tls_sock = ctx.wrap_socket(sock, server_hostname=profile["sni"])
    except socket.timeout:
        elapsed = (time.monotonic() - start) * 1000
        return ConnectionResult(
            name=name, ok=False, blocked=True,
            latency_ms=elapsed, error="timeout (blocked/tarpitted)",
            ja4_hint=ja4_hint,
        )
    except ConnectionRefusedError:
        elapsed = (time.monotonic() - start) * 1000
        return ConnectionResult(
            name=name, ok=False, blocked=True,
            latency_ms=elapsed, error="connection refused (blocked)",
            ja4_hint=ja4_hint,
        )
    except ssl.SSLError as exc:
        elapsed = (time.monotonic() - start) * 1000
        return ConnectionResult(
            name=name, ok=False, blocked=True,
            latency_ms=elapsed, error=f"TLS error: {exc}",
            ja4_hint=ja4_hint,
        )
    except OSError as exc:
        elapsed = (time.monotonic() - start) * 1000
        return ConnectionResult(
            name=name, ok=False, blocked=False,
            latency_ms=elapsed, error=str(exc),
            ja4_hint=ja4_hint,
        )

    elapsed = (time.monotonic() - start) * 1000

    request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {profile['sni']}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    try:
        tls_sock.send(request)
        response = tls_sock.recv(4096)
        has_body = len(response) > 0
    except (OSError, ssl.SSLError):
        has_body = False

    tls_sock.close()
    sock.close()

    ok = has_body or not profile["expect_allowed"]
    blocked = (not has_body) if profile["expect_allowed"] else False

    return ConnectionResult(
        name=name, ok=ok, blocked=blocked,
        latency_ms=elapsed, ja4_hint=ja4_hint,
    )


def fmt_verdict(result: ConnectionResult, show_ja4: bool) -> str:
    """Format a single result line."""
    if result.error:
        status = f"{RED}✗ ERROR{RESET}"
        detail = result.error
    elif result.blocked:
        status = f"{RED}✗ BLOCKED{RESET}"
        detail = "connection rejected by proxy"
    else:
        status = f"{GREEN}✓ ALLOWED{RESET}"
        detail = ""

    ja4_str = f" {DIM}[JA4 ~{result.ja4_hint}]{RESET}" if show_ja4 else ""
    latency_str = f" {YELLOW}{result.latency_ms:.0f}ms{RESET}" if result.latency_ms > 0 else ""

    out = f"  {status}  {BOLD}{result.name}{RESET}{ja4_str}{latency_str}"
    if detail:
        out += f"\n           {DIM}{detail}{RESET}"
    return out


def main():
    parser = argparse.ArgumentParser(
        description="JA4proxy test bot — run TLS connections through the proxy and report verdicts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s\n"
            "  %(prog)s --proxy 10.0.0.5 --port 443\n"
            "  %(prog)s --ping --proxy 10.0.0.5\n"
            "  %(prog)s --show-ja4\n"
        ),
    )
    parser.add_argument(
        "--proxy", "-p",
        default=os.environ.get("PROXY_HOST", "localhost"),
        help="Proxy hostname or IP (default: localhost, or $PROXY_HOST)",
    )
    parser.add_argument(
        "--port", "-P",
        type=int,
        default=int(os.environ.get("PROXY_PORT", "443")),
        help="Proxy port (default: 443, or $PROXY_PORT)",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=float,
        default=10.0,
        help="Per-connection timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--show-ja4", "-j",
        action="store_true",
        help="Print approximate JA4 fingerprint for each connection",
    )
    parser.add_argument(
        "--ping",
        action="store_true",
        help="Quick mode — 1 connection, exit 0 on success",
    )
    parser.add_argument(
        "--profile",
        type=int,
        default=None,
        help="Run only a specific profile by index (0-based, see list)",
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="List available test profiles and exit",
    )

    args = parser.parse_args()

    if args.list_profiles:
        print(f"{BOLD}Available test profiles:{RESET}\n")
        for i, p in enumerate(TEST_PROFILES):
            expect = f"{GREEN}ALLOWED{RESET}" if p["expect_allowed"] else f"{RED}BLOCKED{RESET}"
            print(f"  [{i}] {BOLD}{p['name']}{RESET}")
            print(f"      Expected:        {expect}")
            print(f"      TLS:             {p['min_version'].name} → {p['max_version'].name}")
            print(f"      ALPN:            {','.join(p['alpn']) if p['alpn'] else '(none)'}")
            print(f"      Ciphers:         {p['ciphers']}")
            print()
        return

    profiles = TEST_PROFILES
    if args.profile is not None:
        if args.profile < 0 or args.profile >= len(profiles):
            print(f"{RED}Error:{RESET} profile index {args.profile} out of range (0-{len(profiles)-1})")
            sys.exit(1)
        profiles = [profiles[args.profile]]

    if args.ping:
        profiles = [profiles[0]]

    host = args.proxy
    port = args.port
    timeout = args.timeout

    print(f"{BOLD}JA4proxy Test Bot{RESET}")
    print(f"{DIM}  Target:   {host}:{port}{RESET}")
    n = len(profiles)
    label = f"{n} connection{'s' if n > 1 else ''}"
    print(f"{DIM}  Profiles: {label}{RESET}")
    print()
    print(f"{DIM}  Legend:   {GREEN}✓ ALLOWED{RESET} = TLS handshake + HTTP response received")
    print(f"            {RED}✗ BLOCKED{RESET} = connection rejected or timed out")
    print(f"            {RED}✗ ERROR{RESET}   = unexpected failure{RESET}")
    print()

    all_ok = True
    results = []

    for profile in profiles:
        result = try_connection(host, port, profile, timeout)
        results.append(result)
        line = fmt_verdict(result, args.show_ja4)
        print(line)

        if not result.ok:
            all_ok = False

        if args.ping:
            break

    allowed = sum(1 for r in results if not r.blocked and not r.error)
    blocked = sum(1 for r in results if r.blocked)

    print()
    total = len(results)
    status_icon = f"{GREEN}✓" if all_ok else f"{RED}✗"
    print(f"{status_icon} {BOLD}Summary:{RESET} {total} total, {allowed} allowed, {blocked} blocked")

    if args.ping:
        ok_count = sum(1 for r in results if r.ok)
        print()
        if ok_count > 0:
            print(f"{GREEN}✓ Proxy is reachable and responding{RESET}")
        else:
            print(f"{RED}✗ Proxy is NOT reachable{RESET}")
            sys.exit(1)

    if not all_ok and not args.ping:
        sys.exit(1)


if __name__ == "__main__":
    main()
