#!/usr/bin/env python3
"""
Signal Score Consistency Linter.
Audits Python and Go sources to ensure hardcoded signal scores match
the authoritative config/signal_scores.yml.
"""

import os
import pathlib
import re
import sys

import yaml


def check_scores():
    registry_path = pathlib.Path("config/signal_scores.yml")
    if not registry_path.exists():
        print(f"ERROR: Registry not found at {registry_path}")
        return 1

    with open(registry_path, "r") as f:
        registry = yaml.safe_load(f)["signals"]

    errors = 0

    # Check Python sources (src/security/)
    py_dir = pathlib.Path("src/security")
    for py_file in py_dir.glob("*.py"):
        content = py_file.read_text()
        for signal, data in registry.items():
            score = data.get("score") or data.get("score_cap")
            # Look for: Name: "signal_name", Score: score
            # Or similar patterns in Python RiskSignal instantiation
            pattern = rf'name=["\']{signal}["\'],\s*score=(-?\d+)'
            matches = re.findall(pattern, content)
            for match in matches:
                if int(match) != score:
                    print(
                        f"DRIFT [Python]: {py_file.name} - {signal} has score {match}, registry says {score}"
                    )
                    errors += 1

    # Check Go sources (internal/security/)
    go_dir = pathlib.Path("internal/security")
    for go_file in go_dir.glob("*.go"):
        content = go_file.read_text()
        for signal, data in registry.items():
            score = data.get("score") or data.get("score_cap")
            # Look for: Name: "{signal}", Score: {score}
            pattern = rf'Name:\s*["\']{signal}["\'],\s*Score:\s*(-?\d+)'
            matches = re.findall(pattern, content)
            for match in matches:
                if int(match) != score:
                    print(
                        f"DRIFT [Go]: {go_file.name} - {signal} has score {match}, registry says {score}"
                    )
                    errors += 1

    if errors == 0:
        print("✅ All signal scores consistent with registry.")
        return 0
    else:
        print(f"❌ Found {errors} score inconsistencies.")
        return 1


if __name__ == "__main__":
    sys.exit(check_scores())
