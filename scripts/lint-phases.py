#!/usr/bin/env python3
"""
lint-phases.py — Validate phase documentation consistency.

Checks:
  1. Every phase in manifest.yaml with an action_plan has an existing file.
  2. Every phase doc's H1 heading does not contain a stale phase number
     (i.e. a number that doesn't match the filename).
  3. Every status value in manifest.yaml is from the allowed set.

Exit 0 = clean. Exit 1 = violations found (details printed).
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent
MANIFEST = ROOT / "docs" / "phases" / "manifest.yaml"
ALLOWED_STATUSES = {"COMPLETE", "IN_PROGRESS", "PROPOSED", "DEFERRED", "CLOSED"}

errors: list[str] = []


def load_manifest() -> dict:
    with MANIFEST.open() as f:
        return yaml.safe_load(f)


def check_action_plans(phases: dict) -> None:
    """Rule 1: action_plan files must exist."""
    for phase_id, data in phases.items():
        plan = data.get("action_plan")
        if not plan:
            continue
        full_path = ROOT / plan
        if not full_path.exists():
            errors.append(
                f"Phase {phase_id}: action_plan '{plan}' does not exist on disk."
            )


def check_heading_numbers(phases: dict) -> None:
    """Rule 2: H1 heading in each phase doc must not contain a stale phase number.

    A 'stale number' is a digit sequence in the heading that doesn't match
    the phase ID from the manifest.  We extract the number from the filename
    (e.g. PHASE_51.md → 51) and compare against any number found in the H1.
    """
    for phase_id, data in phases.items():
        plan = data.get("action_plan")
        if not plan:
            continue
        full_path = ROOT / plan
        if not full_path.exists():
            continue  # already reported above

        # Extract numeric component from filename (e.g. PHASE_51.md → "51")
        filename = Path(plan).stem  # e.g. "PHASE_51_ADVERSARIAL_TESTS"
        file_num_match = re.search(r"PHASE_(\d+)", filename, re.IGNORECASE)
        if not file_num_match:
            continue
        file_num = file_num_match.group(1).lstrip("0") or "0"  # "051" → "51"

        # Read first H1 heading
        content = full_path.read_text(encoding="utf-8")
        h1_match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
        if not h1_match:
            continue
        heading = h1_match.group(1)

        # Only check the number that directly follows the leading "Phase" keyword,
        # e.g. "Phase 44: ..." → "44".  Numbers appearing mid-heading as
        # sub-series identifiers ("- Phase 2: Redis Optimization") are intentional
        # and must not be flagged.
        lead_match = re.match(r"^(?:PHASE|Phase)\s+(\d+)\b", heading, re.IGNORECASE)
        if not lead_match:
            continue
        heading_lead = lead_match.group(1).lstrip("0") or "0"
        if heading_lead != file_num and heading_lead != str(phase_id):
            errors.append(
                f"Phase {phase_id} ({Path(plan).name}): "
                f"H1 heading starts with 'Phase {lead_match.group(1)}' but "
                f"filename number is '{file_num}' and phase ID is '{phase_id}'. "
                f'Heading: "{heading}"'
            )


def check_statuses(phases: dict) -> None:
    """Rule 3: status values must be from the allowed set."""
    for phase_id, data in phases.items():
        status = data.get("status")
        if status and status not in ALLOWED_STATUSES:
            errors.append(
                f"Phase {phase_id}: status '{status}' is not in allowed set "
                f"{sorted(ALLOWED_STATUSES)}."
            )


def main() -> int:
    if not MANIFEST.exists():
        print(f"ERROR: manifest not found at {MANIFEST}", file=sys.stderr)
        return 1

    manifest = load_manifest()
    phases = manifest.get("phases", {})

    check_action_plans(phases)
    check_heading_numbers(phases)
    check_statuses(phases)

    if errors:
        print(f"lint-phases: {len(errors)} violation(s) found:\n")
        for e in errors:
            print(f"  ✗  {e}")
        print()
        return 1

    print(f"lint-phases: OK — {len(phases)} phases checked, 0 violations.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
