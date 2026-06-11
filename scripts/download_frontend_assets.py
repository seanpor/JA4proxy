#!/usr/bin/env python3
"""
download_frontend_assets.py — Pulls down and saves pinned frontend dependencies locally.
"""

import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = REPO_ROOT / "management" / "static"

# Single source of truth for frontend assets
FRONTEND_ASSETS = {
    "alpine.min.js": {
        "version": "3.14.0",
        "url": "https://unpkg.com/alpinejs@3.14.0/dist/cdn.min.js"
    },
    "htmx.min.js": {
        "version": "1.9.12",
        "url": "https://unpkg.com/htmx.org@1.9.12/dist/htmx.min.js"
    },
    "sse.js": {
        "version": "2.2.1",
        "url": "https://unpkg.com/htmx-ext-sse@2.2.1/sse.js"
    },
    "chart.umd.min.js": {
        "version": "4.4.2",
        "url": "https://cdn.jsdelivr.net/npm/chart.js@4.4.2/dist/chart.umd.min.js"
    },
    "tailwind.min.js": {
        "version": "3.x",
        "url": "https://cdn.tailwindcss.com"
    }
}

def download_assets():
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    print("=== Downloading Frontend Assets ===")
    for filename, info in FRONTEND_ASSETS.items():
        dest = STATIC_DIR / filename
        print(f"  Downloading {filename} (v{info['version']}) ...")
        try:
            req = urllib.request.Request(
                info["url"],
                headers={"User-Agent": "ja4proxy-asset-downloader/1.0"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                dest.write_bytes(resp.read())
            print(f"    ✓ Saved to {dest.relative_to(REPO_ROOT)}")
        except (urllib.error.HTTPError, urllib.error.URLError) as e:
            print(f"    ✗ Failed to download {filename}: {e}")
            raise SystemExit(1)
    print("=== Download Complete ===")

if __name__ == "__main__":
    download_assets()
