#!/usr/bin/env python3
"""Pre-flight guard for JA4PROXY-2026-0045 (Phase 226).

A static test cannot see the value an operator assigns to ``AGENT_BIND_IP`` at
deploy time, so this guard runs in the start path and refuses to bring up the
monitoring/management stack on a *public* interface.

Policy (decided 2026-06-05): the management/monitoring bind must be **loopback**
(the SSH-tunnel default) or a **private** (RFC1918 / RFC4193) address — never
``0.0.0.0`` / ``::`` / a public address. The proxy itself is unaffected; it is
supposed to be public.

Resolution order for the bind address:
  1. ``AGENT_BIND_IP`` in the environment
  2. ``AGENT_BIND_IP=`` in ./.env
  3. unset → ``127.0.0.1`` (the compose default; safe)

Dependency-free (stdlib only) so it runs anywhere, like the rest of the
pre-flight tooling. Exit 0 = safe, exit 1 = refuse to start.
"""
from __future__ import annotations

import ipaddress
import os
import sys
from pathlib import Path

DEFAULT_BIND = "127.0.0.1"


def resolve_bind_address(env_path: str = ".env") -> str:
    val = os.environ.get("AGENT_BIND_IP")
    if val:
        return val.strip()
    p = Path(env_path)
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("AGENT_BIND_IP=") and not line.startswith("#"):
                return line.split("=", 1)[1].strip().strip("\"'")
    return DEFAULT_BIND


def is_loopback_or_private(host_ip: str) -> bool:
    if host_ip == "localhost":
        return True
    try:
        addr = ipaddress.ip_address(host_ip)
    except ValueError:
        return False  # unparseable → refuse (fail closed)
    if addr.is_unspecified:  # 0.0.0.0 / ::
        return False
    return addr.is_loopback or addr.is_private


def main() -> int:
    bind = resolve_bind_address()
    if is_loopback_or_private(bind):
        print(f"✓ AGENT_BIND_IP={bind} is loopback-or-private (monitoring/management not public)")
        return 0
    print(
        f"✗ REFUSING TO START: AGENT_BIND_IP={bind!r} would publish the "
        f"monitoring/management stack on a public interface (JA4PROXY-2026-0045).\n"
        f"  Use a loopback address (default 127.0.0.1, reach via SSH tunnel) or a "
        f"private/VPN address. The proxy itself stays public regardless.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
