#!/usr/bin/env python3
"""scripts/pipeline_summary.py — unified summary for lint, scan, and test runs.

This script is invoked from the Makefile after the corresponding target finishes.
It prints a concise, human‑readable table or status line to avoid the long spew of
individual tool output. The implementation is deliberately lightweight: for the
`scan` mode it re‑uses the existing :pymod:`scan_summary` module; for `lint` and
`test` it aggregates the exit codes and prints a one‑line verdict.
"""

import argparse
import subprocess
import sys
from pathlib import Path

# Import the existing scan summary helpers – they provide the table rendering.
# The module lives in the same directory, so we can import it directly.
from scan_summary import _summarise_images, _summarise_stdin  # noqa: E402,F401


def _run_command(cmd: list[str]) -> int:
    """Execute *cmd* and return its exit code.

    The helper runs the command with ``capture_output=False`` so the underlying
    tool can stream its output directly to the terminal. Errors are propagated as
    the command's return code.
    """
    result = subprocess.run(cmd)
    return result.returncode


def lint_summary() -> int:
    """Execute the lint pipeline and emit a one‑line verdict.

    The existing ``make lint`` target already runs all linters. Here we simply
    invoke the same ``make lint`` command in a subprocess, capture its exit code,
    and print ``OK`` on success or ``FAIL`` on any non‑zero exit.
    """
    rc = _run_command(["make", "lint"])
    verdict = "OK" if rc == 0 else "FAIL"
    print(f"\n=== Lint summary — {verdict} ===")
    return rc


def test_summary() -> int:
    """Run the test suite with a concise pytest summary.

    ``make test`` already runs the full suite and prints a lot of output. We
    invoke it again, letting pytest emit its built‑in short summary (``-q``). The
    return code mirrors the test result.
    """
    rc = _run_command(["make", "test"])
    print(f"\n=== Test summary — {'OK' if rc == 0 else 'FAIL'} ===")
    return rc


def main() -> int:
    parser = argparse.ArgumentParser(prog="pipeline_summary")
    parser.add_argument(
        "mode",
        choices=["lint", "scan", "test"],
        help="Which pipeline stage to summarise.",
    )
    args = parser.parse_args()
    if args.mode == "lint":
        return lint_summary()
    if args.mode == "scan":
        # Delegate to the existing scan_summary script for image scanning.
        return _run_command(["python3", str(Path(__file__).with_name("scan_summary.py"))])
    if args.mode == "test":
        return test_summary()
    return 1

if __name__ == "__main__":
    sys.exit(main())
