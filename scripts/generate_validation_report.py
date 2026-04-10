#!/usr/bin/env python3
"""Phase 62 — pre-enterprise validation report generator.

Emits a markdown summary of the Go-side test surface for the JA4proxy
production proxy. Counts unit tests, fuzz targets, benchmarks, and
property/chaos tests, and lists recent Phase 200-203 remediation commits.

Usage:

    python3 scripts/generate_validation_report.py
    python3 scripts/generate_validation_report.py --output PATH

The default output path is docs/security/PRE_ENTERPRISE_VALIDATION_REPORT.md.
The script never fails on missing optional sections — it labels them as
"unavailable" so the report still generates in any environment.
"""

from __future__ import annotations

import argparse
import datetime
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO_ROOT / "docs" / "security" / "PRE_ENTERPRISE_VALIDATION_REPORT.md"

GO_TEST_DIRS = [
    "cmd/proxy",
    "cmd/ja4check",
    "cmd/ja4proxy-cli",
    "internal/tls",
    "internal/security",
    "internal/proxy",
    "internal/redis",
    "internal/config",
    "internal/metrics",
    "internal/logging",
    "internal/webhook",
]


def run(cmd: list[str], cwd: Path | None = None, timeout: int = 60) -> tuple[int, str]:
    """Run a subprocess and return (exit_code, combined_output). Never raises."""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd or REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.returncode, (result.stdout or "") + (result.stderr or "")
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return 127, f"<command failed: {exc}>"


def count_pattern_in_files(root: Path, pattern: re.Pattern[str], suffix: str) -> int:
    total = 0
    if not root.exists():
        return 0
    for path in root.rglob(f"*{suffix}"):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        total += len(pattern.findall(text))
    return total


def count_go_tests() -> dict[str, int]:
    """Count Go tests, fuzz targets, benchmarks, and property tests."""
    test_re = re.compile(r"^func\s+(Test[A-Z]\w*)\s*\(", re.MULTILINE)
    fuzz_re = re.compile(r"^func\s+(Fuzz[A-Z]\w*)\s*\(", re.MULTILINE)
    bench_re = re.compile(r"^func\s+(Benchmark[A-Z]\w*)\s*\(", re.MULTILINE)
    property_re = re.compile(r"^func\s+(TestProperty\w*)\s*\(", re.MULTILINE)
    chaos_re = re.compile(r"^func\s+(TestPipeline_(?:RedisOutage|PartialOutage|DialFlip)\w*)\s*\(", re.MULTILINE)

    counts = {"tests": 0, "fuzz": 0, "bench": 0, "property": 0, "chaos": 0}
    for d in GO_TEST_DIRS:
        root = REPO_ROOT / d
        counts["tests"] += count_pattern_in_files(root, test_re, "_test.go")
        counts["fuzz"] += count_pattern_in_files(root, fuzz_re, "_test.go")
        counts["bench"] += count_pattern_in_files(root, bench_re, "_test.go")
        counts["property"] += count_pattern_in_files(root, property_re, "_test.go")
        counts["chaos"] += count_pattern_in_files(root, chaos_re, "_test.go")
    return counts


def go_security_findings_commits() -> str:
    """Surface Phase 200/201/202/203 remediation commits."""
    code, out = run(
        ["git", "log", "--oneline", "--all", "-n", "30", "--grep=phase-20[0-3]"],
    )
    if code != 0 or not out.strip():
        return "_No Phase 200-203 commits found in this checkout._"
    return "```\n" + out.strip() + "\n```"


def govulncheck_section() -> str:
    if shutil.which("govulncheck") is None:
        return "_govulncheck not installed — skipped._"
    code, out = run(["govulncheck", "./..."], timeout=300)
    summary = "PASS" if code == 0 else f"FAIL (exit {code})"
    return f"Status: **{summary}**\n\n```\n{out.strip()[:2000]}\n```"


def pip_audit_section() -> str:
    if shutil.which("pip-audit") is None:
        return "_pip-audit not installed — skipped._"
    code, out = run(["pip-audit", "--strict", "--progress-spinner=off"], timeout=300)
    summary = "PASS" if code == 0 else f"FAIL (exit {code})"
    return f"Status: **{summary}**\n\n```\n{out.strip()[:2000]}\n```"


def fuzz_smoke_section() -> str:
    """Run a tiny fuzz smoke (1s per target) to confirm zero new crashes."""
    goroot = "/snap/go/current"
    env = os.environ.copy()
    if Path(goroot).exists():
        env["GOROOT"] = goroot
    targets = ["FuzzClientHello", "FuzzReadProxyProtocol", "FuzzReadProxyProtocolV2"]
    lines = []
    for tgt in targets:
        try:
            result = subprocess.run(
                [
                    "go",
                    "test",
                    "-run=^$",
                    f"-fuzz=^{tgt}$",
                    "-fuzztime=1s",
                    "./cmd/proxy/",
                ],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                timeout=60,
                env=env,
                check=False,
            )
            status = "PASS" if result.returncode == 0 else f"FAIL ({result.returncode})"
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            status = f"SKIP ({exc})"
        lines.append(f"- `{tgt}`: **{status}**")
    return "\n".join(lines)


def _section_deployment() -> str:
    """Phase 64i — Deployment Validation Evidence section.

    Collects smoke test results, MTTR baseline, and DR exercise history.
    Gracefully degrades if any input is missing (never raises).
    """
    lines = ["## Deployment Validation Evidence", ""]

    smoke_dir = Path("test-results/smoke")
    lines.append("### Smoke Tests")
    if smoke_dir.exists():
        for result_file in sorted(smoke_dir.glob("*.result")):
            status = result_file.read_text().strip()
            lines.append(f"- {result_file.stem}: **{status}**")
    else:
        lines.append("- No smoke test results found. Run `make smoke-docker` first.")
    lines.append("")

    mttr_file = Path("MTTR_BASELINE.md")
    lines.append("### MTTR Baseline")
    if mttr_file.exists():
        lines.extend(mttr_file.read_text().splitlines())
    else:
        lines.append("- `MTTR_BASELINE.md` not found. Run `make measure-mttr` first.")
    lines.append("")

    dr_runbook = Path("docs/runbooks/disaster_recovery.md")
    gameday_file = Path("docs/runbooks/gameday_scenarios.md")
    lines.append("### DR Runbook Exercise History")
    if dr_runbook.exists() and "Runbook Exercise History" in dr_runbook.read_text():
        content = dr_runbook.read_text()
        section = content.split("Runbook Exercise History", 1)[1].split("\n## ", 1)[0]
        lines.extend(section.strip().splitlines())
    elif gameday_file.exists() and "Runbook Exercise History" in gameday_file.read_text():
        content = gameday_file.read_text()
        section = content.split("Runbook Exercise History", 1)[1].split("\n## ", 1)[0]
        lines.extend(section.strip().splitlines())
    else:
        lines.append("- No exercise history recorded yet. Run a GameDay first.")
    lines.append("")

    return "\n".join(lines)


def build_report(extra_section: str | None = None) -> str:
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    counts = count_go_tests()
    parts = [
        "# JA4proxy — Pre-Enterprise Validation Report",
        "",
        f"_Generated: {now}_",
        "",
        "This report summarises the Go production proxy's defensive test",
        "surface as enumerated by Phase 62. The Python proxy is experimental",
        "and intentionally excluded.",
        "",
        "## Go test surface",
        "",
        f"- Unit tests:        **{counts['tests']}**",
        f"- Fuzz targets:      **{counts['fuzz']}**",
        f"- Benchmarks:        **{counts['bench']}**",
        f"- Property tests:    **{counts['property']}**",
        f"- Chaos tests:       **{counts['chaos']}**",
        "",
        "## Go security findings (Phase 200-203 commits)",
        "",
        go_security_findings_commits(),
        "",
        "## govulncheck",
        "",
        govulncheck_section(),
        "",
        "## pip-audit (production Python services)",
        "",
        pip_audit_section(),
        "",
        "## Fuzz smoke (1s per target — new-crash check only)",
        "",
        fuzz_smoke_section(),
        "",
    ]

    # Append deployment section if requested (Phase 64i)
    if extra_section == "deployment":
        parts.append(_section_deployment())

    return "\n".join(parts) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", default=str(DEFAULT_OUTPUT), help="output markdown path")
    ap.add_argument("--stdout", action="store_true", help="also print to stdout")
    ap.add_argument(
        "--section",
        choices=["deployment"],
        default=None,
        help="append a specific evidence section (e.g. --section deployment)",
    )
    args = ap.parse_args()

    report = build_report(extra_section=args.section)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")
    if args.stdout:
        sys.stdout.write(report)
    print(f"wrote {out_path} ({len(report)} bytes)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
