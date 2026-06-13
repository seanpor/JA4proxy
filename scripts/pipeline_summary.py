#!/usr/bin/env python3
"""scripts/pipeline_summary.py — unified one-line verdict for lint, scan, and test.

This script is invoked from the Makefile *after* the corresponding target has
already done its work (e.g. the ``test`` recipe runs the suite and then calls
``pipeline_summary.py test``). Its only job is to print a concise, human-readable
verdict so the long per-tool output is capped with a clear pass line.

It must therefore **never re-invoke** ``make``: the Makefile recipes use ``set -e``
and sequential ``@``-prefixed lines, so a failure aborts make *before* this
summary is reached. Reaching here means the stage passed. (An earlier version
called ``make <stage>`` here, which recursed infinitely:
``make test`` -> ``pipeline_summary test`` -> ``make test`` -> ...)

The detailed per-image / per-scanner tables are the job of
:pymod:`scan_summary` (``make scan-summary``); this script is intentionally just
the verdict line.
"""

import argparse
import sys


def _verdict(stage: str) -> int:
    """Print the pass verdict for *stage* and return 0.

    Only reached when the stage succeeded (make aborts on failure before this
    runs), so the verdict is unconditionally OK.
    """
    print(f"\n=== {stage.capitalize()} summary — OK ===")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="pipeline_summary")
    parser.add_argument(
        "mode",
        choices=["lint", "scan", "test"],
        help="Which pipeline stage to summarise.",
    )
    args = parser.parse_args()
    return _verdict(args.mode)


if __name__ == "__main__":
    sys.exit(main())
