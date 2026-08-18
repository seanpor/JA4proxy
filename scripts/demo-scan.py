#!/usr/bin/env python3
"""Generate distributed-scan traffic from many real source IPs.

WHY THIS EXISTS
---------------
The campaign and slow-scan detectors key on the number of DISTINCT source IPs
in a /24, not on volume:

    slow scan  >= 20 unique IPs, averaging <= 3 requests each
    campaign   density >= 0.15 of the /24 (39+ IPs) and >= 70% blocked

tls-traffic-generator.py runs in one container, so every connection it makes
carries one source IP. No amount of traffic from it can satisfy either
detector — which is why they had never fired, and why the console's
Intelligence panel had nothing from them to show.

This script adds secondary addresses to the container's interface and binds
each connection to a different one. The source IPs are REAL: the proxy sees
them at the TCP layer and records them without any PROXY-protocol trust or
IP-spoofing feature being enabled. The traffic genuinely has the shape the
detector is looking for, so a detection here means the detector works — not
that a threshold was lowered until something appeared.

Requires NET_ADMIN (to add addresses). Aliases live only for the life of the
container, so there is nothing to clean up.
"""

from __future__ import annotations

import argparse
import socket
import ssl
import subprocess
import sys
import time

# Tool-shaped TLS: no ALPN and a short cipher list, so the fingerprint decodes
# as "not browser-shaped". Matches the CobaltStrike/Credential_Stuffer profile
# in tls-traffic-generator.py, which keeps the demo's fingerprints consistent.
TOOL_CIPHERS = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"


def add_alias(addr: str, prefix: int, dev: str) -> bool:
    r = subprocess.run(
        ["ip", "addr", "add", f"{addr}/{prefix}", "dev", dev],
        capture_output=True,
        text=True,
    )
    # "File exists" just means a previous run in this container already added it.
    return r.returncode == 0 or "File exists" in r.stderr


def connect_from(src: str, host: str, port: int, timeout: float) -> str:
    """One TLS connection bound to `src`. Returns a short outcome label."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers(TOOL_CIPHERS)
    except ssl.SSLError:
        pass  # Older/newer OpenSSL may reject the exact list; shape still differs.

    # Reject the unspecified address explicitly. This script exists to make each
    # simulated scanner appear from its OWN source IP; binding 0.0.0.0 would
    # silently defeat that (every connection would leave from the default route)
    # AND listen on every interface. CodeQL flags the bind for the second
    # reason; the first is why it would ruin the demo.
    if src in ("", "0.0.0.0", "::"):  # nosec B104 — rejected, not bound
        raise ValueError(
            f"refusing to bind the unspecified address {src!r}: "
            "each simulated source needs a specific IP"
        )

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.bind((src, 0))
        s.connect((host, port))
        t = ctx.wrap_socket(s, server_hostname="scan.local")
        try:
            t.send(b"GET / HTTP/1.1\r\nHost: scan.local\r\nConnection: close\r\n\r\n")
            t.recv(256)
            return "allowed"
        finally:
            t.close()
        # A blocked connection is a successful demo of enforcement, so RST and
        # handshake failure are both counted as "blocked", not as errors.
    except (ConnectionResetError, BrokenPipeError, ssl.SSLError):
        return "blocked"
    except socket.timeout:
        return "timeout"
    except OSError as exc:
        return f"error:{exc.errno}"
    finally:
        try:
            s.close()
        except OSError:
            pass


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--target-host", default="proxy")
    p.add_argument("--target-port", type=int, default=8080)
    p.add_argument("--base", default="172.25.200",
                   help="/24 prefix to source from; must be inside the docker network")
    p.add_argument("--ips", type=int, default=25,
                   help="distinct source IPs (slow scan needs >=20; campaign >=39)")
    p.add_argument("--requests-per-ip", type=int, default=2,
                   help="slow scan requires the AVERAGE to be <= 3")
    p.add_argument("--prefix", type=int, default=16, help="netmask for the aliases")
    p.add_argument("--dev", default="eth0")
    p.add_argument("--timeout", type=float, default=5.0)
    args = p.parse_args()

    if args.ips > 250:
        print("demo-scan: --ips above 250 will not fit in a single /24", file=sys.stderr)
        return 2

    # .1 is conventionally a gateway; start at .10 to stay clear of anything the
    # docker IPAM may have handed out low in the range.
    addrs = [f"{args.base}.{i}" for i in range(10, 10 + args.ips)]

    print(f"Adding {len(addrs)} source addresses on {args.dev} ({args.base}.0/24)...")
    added = [a for a in addrs if add_alias(a, args.prefix, args.dev)]
    if len(added) < len(addrs):
        print(f"  warning: only {len(added)}/{len(addrs)} added — need NET_ADMIN", file=sys.stderr)
    if not added:
        print("demo-scan: no addresses could be added; is NET_ADMIN granted?", file=sys.stderr)
        return 1

    total = len(added) * args.requests_per_ip
    print(f"Making {total} connections ({args.requests_per_ip} per IP) "
          f"to {args.target_host}:{args.target_port}...")

    outcomes: dict[str, int] = {}
    start = time.time()
    for _ in range(args.requests_per_ip):
        for a in added:
            r = connect_from(a, args.target_host, args.target_port, args.timeout)
            outcomes[r] = outcomes.get(r, 0) + 1
    elapsed = time.time() - start

    blocked = outcomes.get("blocked", 0)
    rate = blocked / total if total else 0.0
    print(f"\nDone in {elapsed:.1f}s")
    print(f"  unique source IPs : {len(added)}")
    print(f"  avg requests / IP : {args.requests_per_ip}")
    print(f"  outcomes          : {outcomes}")
    print(f"  block rate        : {rate:.0%}")
    print()
    print("Detector expectations for this run:")
    print(f"  slow scan  (>=20 IPs, avg <=3 req):  "
          f"{'MET' if len(added) >= 20 and args.requests_per_ip <= 3 else 'not met'}")
    density = len(added) / 256
    print(f"  campaign   (density >=0.15, >=70% blocked): "
          f"density {density:.2f}, blocked {rate:.0%} -> "
          f"{'MET' if density >= 0.15 and rate >= 0.70 else 'not met'}")
    print()
    print("Detection runs on a timer; give the analytics node a cycle, then check")
    print("the Intelligence panel or: make demo-check")
    return 0


if __name__ == "__main__":
    sys.exit(main())
