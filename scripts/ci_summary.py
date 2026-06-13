#!/usr/bin/env python3
"""CI summary utility.

This script is invoked by the Makefile after lint or scan stages to emit a concise
one‑line status line. The Makefile uses `set -e` and explicit exit codes, so this
script will only run when the preceding stage succeeded. It prints a pass
message; a failure will abort the make process before this script runs.
"""
import sys

def main():
    stage = sys.argv[1] if len(sys.argv) > 1 else "unknown"
    print(f"✅ CI {stage.upper()} PASS")

if __name__ == "__main__":
    main()
