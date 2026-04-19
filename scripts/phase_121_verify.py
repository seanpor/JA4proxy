#!/usr/bin/env python3
"""Phase 121 close-out gate.

Verifies that the program-discipline deliverables from sub-phases 121a–j are
all landed and internally consistent. Exits 0 when every required artifact
exists and the canonical findings register validates; exits 1 with a
human-readable report otherwise.

Not a substitute for `make verify-findings` or the regression-test gate — it
composes them.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent

REQUIRED_DOCS = [
    "docs/security/findings.yaml",
    "docs/security/FINDINGS_REGISTER.md",
    "docs/security/SEVERITY_RUBRIC.md",
    "docs/security/REMEDIATION_WAVES.md",
    "docs/security/CLOSURE_VERIFICATION.md",
    "docs/security/INTAKE_RUNBOOK.md",
    "docs/security/OWNERSHIP.md",
    "docs/decisions/ADR-121a-cvss-version.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
    "scripts/findings_register.py",
]

MIN_FINDINGS = 40


def _fail(errors: list[str]) -> int:
    print("phase-121-verify: FAIL")
    for e in errors:
        print(f"  - {e}")
    return 1


def check_required_docs() -> list[str]:
    return [f"missing {p}" for p in REQUIRED_DOCS if not (REPO / p).is_file()]


def check_register() -> list[str]:
    errors: list[str] = []
    result = subprocess.run(
        [sys.executable, "scripts/findings_register.py", "validate"],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        errors.append(
            f"findings_register.py validate failed: {result.stdout.strip()} {result.stderr.strip()}"
        )
        return errors

    data = yaml.safe_load((REPO / "docs/security/findings.yaml").read_text())
    findings = data.get("findings", []) if isinstance(data, dict) else data
    if len(findings) < MIN_FINDINGS:
        errors.append(
            f"register has {len(findings)} findings; Phase 121k requires >= {MIN_FINDINGS}"
        )
    return errors


def check_manifest() -> list[str]:
    errors: list[str] = []
    manifest = yaml.safe_load((REPO / "docs/phases/manifest.yaml").read_text())
    phases = manifest.get("phases", {})

    p121 = phases.get(121)
    if not p121:
        errors.append("manifest: phase 121 missing")
    elif p121.get("status") not in {"PROPOSED", "IN_PROGRESS", "COMPLETE"}:
        errors.append(f"manifest: phase 121 has unexpected status={p121.get('status')}")

    p120 = phases.get(120)
    if not p120:
        errors.append("manifest: phase 120 missing")
    else:
        if p120.get("status") not in {"DEFERRED", "RETIRED"}:
            errors.append(
                f"manifest: phase 120 must be DEFERRED/RETIRED (got {p120.get('status')})"
            )
        if p120.get("superseded_by") != 119:
            errors.append(
                f"manifest: phase 120 must have superseded_by: 119 (got {p120.get('superseded_by')})"
            )

    p117 = phases.get(117)
    if not p117:
        errors.append("manifest: phase 117 missing")
    elif p117.get("superseded_by") != 118:
        errors.append(
            f"manifest: phase 117 must have superseded_by: 118 (got {p117.get('superseded_by')})"
        )

    return errors


def main() -> int:
    errors: list[str] = []
    errors += check_required_docs()
    errors += check_register()
    errors += check_manifest()

    if errors:
        return _fail(errors)

    print("phase-121-verify: OK")
    print(f"  - all {len(REQUIRED_DOCS)} required docs present")
    print("  - findings_register.py validate passes")
    print(f"  - >= {MIN_FINDINGS} canonical findings")
    print("  - manifest: 121 registered, 120 DEFERRED/superseded_by 119, 117 superseded_by 118")
    return 0


if __name__ == "__main__":
    sys.exit(main())
