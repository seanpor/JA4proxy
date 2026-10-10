#!/usr/bin/env python3
"""
sweep_retrospective_findings.py — Execute Phase 814c Retrospective Closure Sweep.

Scans all CRITICAL and HIGH findings in `docs/security/findings.yaml`, verifies
their two-state proof using `scripts/verify_revert.sh`, and promotes validated
findings to status: VERIFIED.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
FINDINGS_YAML = REPO_ROOT / "docs" / "security" / "findings.yaml"
VERIFY_SCRIPT = REPO_ROOT / "scripts" / "verify_revert.sh"


def main() -> int:
    if not FINDINGS_YAML.exists():
        print(f"Error: {FINDINGS_YAML} not found")
        return 1

    content = FINDINGS_YAML.read_text()
    data = yaml.safe_load(content)
    findings = data.get("findings", [])

    verified_count = 0
    failed_count = 0
    skipped_count = 0

    print("=================================================================")
    print(" Executing Phase 814c Retrospective Closure Sweep")
    print("=================================================================")

    for f in findings:
        fid = f.get("id")
        sev = f.get("severity")
        st = f.get("status")
        reg_test = f.get("regression_test")
        closed_commit = f.get("closed_commit")

        if sev not in ("CRITICAL", "HIGH"):
            continue

        if not reg_test or not closed_commit:
            print(f"▶ Skipping {fid} ({sev}): missing regression_test or closed_commit")
            skipped_count += 1
            continue

        print(f"\n▶ Sweeping {fid} ({sev}) — commit: {closed_commit[:8]}...")
        cmd = [str(VERIFY_SCRIPT), fid, "--fix-commit", closed_commit]
        proc = subprocess.run(cmd, capture_output=True, text=True)

        if proc.returncode == 0:
            print(f"  ✓ TWO-STATE PROOF HOLDS for {fid}")
            f["status"] = "VERIFIED"
            f["verified_by"] = "@seanpor"
            f["verified_on"] = "2026-10-10"
            verified_count += 1
        else:
            print(f"  ✗ Two-state proof FAILED for {fid}:")
            for line in proc.stdout.splitlines()[-5:]:
                print(f"    {line}")
            failed_count += 1

    # Save updated findings.yaml
    with open(FINDINGS_YAML, "w") as out:
        yaml.dump(data, out, sort_keys=False, default_flow_style=False)

    print("\n=================================================================")
    print(f" Sweep Summary: {verified_count} VERIFIED, {failed_count} FAILED, {skipped_count} SKIPPED")
    print("=================================================================")

    return 0 if failed_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
