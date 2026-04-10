#!/usr/bin/env python3
"""
Persistent TLS ClientHello capture server.

Listens on one or more TCP ports. For each incoming connection:
  1. Reads up to 8192 bytes (the TLS ClientHello record)
  2. Saves to tests/fixtures/clienthello/<name>.bin
  3. Closes the connection

Usage:
  python3 scripts/capture_server.py                     # interactive: ports 9443,9444,9445,9446
  python3 scripts/capture_server.py --names chrome_tls13,firefox_tls13,curl_tls13,curl_tls12

Ports: 9443=first name, 9444=second, 9445=third, etc.
"""
import argparse
import pathlib
import socket
import sys
import threading
import time

FIXTURES_DIR = pathlib.Path("tests/fixtures/clienthello")
BASE_PORT = 9443


def serve_capture(port: int, name: str, done_event: threading.Event):
    """Listen on port, capture one ClientHello per connection until done_event set."""
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    # nosemgrep: python.lang.security.audit.network.bind.avoid-bind-to-all-interfaces
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(1.0)
    sock.bind(("0.0.0.0", port))
    sock.listen(5)
    seq = 0
    print(f"[{name}] listening on port {port}", flush=True)
    while not done_event.is_set():
        try:
            conn, addr = sock.accept()
        except socket.timeout:
            continue
        try:
            data = conn.recv(8192)
            if data:
                # First capture = <name>.bin, subsequent = <name>_2.bin etc
                suffix = "" if seq == 0 else f"_{seq + 1}"
                out = FIXTURES_DIR / f"{name}{suffix}.bin"
                out.write_bytes(data)
                print(
                    f"[{name}] saved {len(data)} bytes from {addr[0]} -> {out}",
                    flush=True,
                )
                seq += 1
        except Exception as e:
            print(f"[{name}] error: {e}", flush=True)
        finally:
            conn.close()
    sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--names",
        default="chrome_tls13,firefox_tls13,curl_tls13,curl_tls12",
        help="Comma-separated fixture names (one per port starting at base-port)",
    )
    parser.add_argument("--base-port", type=int, default=BASE_PORT)
    parser.add_argument(
        "--timeout",
        type=int,
        default=0,
        help="Auto-exit after N seconds (0=run forever)",
    )
    args = parser.parse_args()

    names = [n.strip() for n in args.names.split(",")]
    done = threading.Event()
    threads = []
    for i, name in enumerate(names):
        port = args.base_port + i
        t = threading.Thread(target=serve_capture, args=(port, name, done), daemon=True)
        t.start()
        threads.append(t)

    print(
        f"Capture server ready. Connect to ports "
        f"{args.base_port}-{args.base_port + len(names) - 1}.",
        flush=True,
    )
    print("Press Ctrl-C to stop.", flush=True)
    try:
        if args.timeout > 0:
            time.sleep(args.timeout)
            done.set()
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        done.set()
    for t in threads:
        t.join(timeout=2)
    print("Done.", flush=True)


if __name__ == "__main__":
    main()
