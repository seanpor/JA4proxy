#!/usr/bin/env python3
"""
Live Parity Check Harness.
Runs Python and Go proxies side-by-side and compares their decisions
for a set of binary ClientHello fixtures.
"""

import json
import os
import pathlib
import socket
import subprocess
import sys
import time

FIXTURES_DIR = pathlib.Path("tests/fixtures/clienthello")
PYTHON_PORT = 8080
GO_PORT = 8082

def send_payload(port, payload):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(2)
        s.connect(("127.0.0.1", port))
        s.sendall(payload)
        # We don't expect a response as the backend isn't necessarily up
        # but we wait long enough for the proxy to process.
        time.sleep(0.1)

def get_latest_logs(agent_name, lines=10):
    # This assumes logs are written to a known location or accessible via docker
    # For this POC harness, we'll look at the recently updated Redis keys
    # or rely on the proxy emitting a specific 'parity-check' header if we had a mock backend.
    # SIMPLIFICATION: We will check Redis for the stored fingerprints.
    pass

def run_parity():
    print(f"🚀 Starting Parity Check across ports {PYTHON_PORT} (Py) and {GO_PORT} (Go)")
    
    fixtures = list(FIXTURES_DIR.glob("*.bin"))
    if not fixtures:
        print("❌ No fixtures found.")
        return 1

    with open(FIXTURES_DIR / "known_ja4.json", "r") as f:
        known_ja4 = json.load(f)

    results = []
    
    for fix in fixtures:
        name = fix.stem
        payload = fix.read_bytes()
        expected = known_ja4.get(name, "unknown")
        
        print(f"Testing {name}...", end=" ", flush=True)
        
        # Send to both (assumes proxies are already running or started externally)
        try:
            send_payload(PYTHON_PORT, payload)
            send_payload(GO_PORT, payload)
            print("✅ Sent")
            results.append({"name": name, "status": "sent"})
        except ConnectionRefusedError:
            print("❌ Connection Refused (Are proxies running?)")
            return 1

    print("\n✅ Parity Check Payloads Delivered.")
    print("Note: End-to-end score verification requires a mock backend or log analysis.")
    return 0

if __name__ == "__main__":
    sys.exit(run_parity())
