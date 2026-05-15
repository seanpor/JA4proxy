#!/usr/bin/env python3
"""
Generate TLS ClientHello fixtures from real browsers using Playwright.

Usage (inside Docker):
  python3 scripts/generate_fixtures_browser.py --recorder-host recorder

Prerequisites: playwright install --with-deps chromium firefox
"""

import argparse
import pathlib
import sys
import time

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print(
        "playwright not installed: "
        "pip install playwright && playwright install --with-deps chromium firefox"
    )
    sys.exit(1)

FIXTURES_DIR = pathlib.Path("tests/fixtures/clienthello")
BASE_PORT = 9443

BROWSERS = [
    ("chromium", "chrome_tls13", 9443),
    ("firefox", "firefox_tls13", 9444),
]


def capture_browser(playwright, browser_name: str, fixture_name: str, url: str):
    print(f"Launching {browser_name}...", flush=True)
    try:
        browser = getattr(playwright, browser_name).launch(headless=True)
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        try:
            page.goto(url, timeout=5000)
        except Exception:
            pass  # Expected: recorder closes connection abruptly
        browser.close()
        print(f"  {fixture_name}: connection made to {url}", flush=True)
    except Exception as e:
        print(f"  {browser_name} failed: {e}", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--recorder-host", default="localhost")
    parser.add_argument("--base-port", type=int, default=BASE_PORT)
    args = parser.parse_args()

    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        for browser_name, fixture_name, port_offset in BROWSERS:
            url = (
                f"https://{args.recorder_host}:"
                f"{args.base_port + (port_offset - BASE_PORT)}/"
            )
            capture_browser(p, browser_name, fixture_name, url)
            time.sleep(0.5)

    print("Done generating browser fixtures.", flush=True)


if __name__ == "__main__":
    main()
