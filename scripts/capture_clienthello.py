#!/usr/bin/env python3
"""
Capture TLS ClientHello bytes from connections for JA4 parity testing.
Usage: python3 scripts/capture_clienthello.py <name> [port]
Then connect: curl --tlsv1.3 https://127.0.0.1:<port>/
Saves to tests/fixtures/clienthello/<name>.bin
"""

import pathlib
import socket
import sys

FIXTURES = pathlib.Path("tests/fixtures/clienthello")
FIXTURES.mkdir(parents=True, exist_ok=True)


def capture(name: str, port: int = 9443):
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(1)
    print(f"Listening on :{port} — connect to capture '{name}'")
    conn, addr = sock.accept()
    data = conn.recv(8192)
    out = FIXTURES / f"{name}.bin"
    out.write_bytes(data)
    print(f"Saved {len(data)} bytes to {out}")
    conn.close()
    sock.close()


if __name__ == "__main__":
    name = sys.argv[1] if len(sys.argv) > 1 else "capture"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9443
    capture(name, port)
