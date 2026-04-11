#!/usr/bin/env python3
"""Phase 86h - Rewrite dead runbook_url annotations in Alertmanager rule files.

Rewrites every `runbook_url:` line in `monitoring/alertmanager/rules/*.yml`
to the canonical format:

    https://github.com/seanpor/JA4proxy/blob/main/docs/runbooks/<file>.md

The target filename for each alert is looked up in a YAML mapping file
(docs/phases/PHASE_86h_runbook_mapping.yml by default), keyed by alert name.

Behaviour notes:
    - Preserves surrounding YAML structure (line-based rewrite, not YAML
      round-tripping) but does NOT preserve trailing comments on the
      `runbook_url:` line itself. No in-tree rule file uses that pattern.
    - Two-pass: the fixer first plans every rewrite and collects every
      error (unmapped alerts, mapping targets that do not exist under
      `--runbooks-dir`). If ANY error is found across the whole run, NO
      file is written — the operator sees all errors at once and the
      working tree is left untouched. This prevents half-rewritten files.

Usage:
    python3 scripts/fix_runbook_urls.py \\
        --rules-dir monitoring/alertmanager/rules/ \\
        --mapping docs/phases/PHASE_86h_runbook_mapping.yml \\
        --runbooks-dir docs/runbooks/
    python3 scripts/fix_runbook_urls.py \\
        --rules-dir monitoring/alertmanager/rules/ \\
        --mapping docs/phases/PHASE_86h_runbook_mapping.yml \\
        --check

Exit codes:
    0  - apply mode: all files updated successfully (or already clean)
         check mode: all files already clean
    1  - check mode: at least one file needs updating, or an error occurred
         (e.g. an alert has no entry in the mapping file, or a mapping target
         does not exist under --runbooks-dir)
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

CANONICAL_PREFIX = "https://github.com/seanpor/JA4proxy/blob/main/docs/runbooks/"

# Match `- alert: <Name>` lines preserving whatever indent / quoting.
_ALERT_RE = re.compile(r"^\s*-\s*alert:\s*['\"]?([A-Za-z0-9_]+)['\"]?\s*$")
# Match `runbook_url:` lines. Captures indent so we can rewrite with the
# original indent. NOTE: trailing comments on the runbook_url line are NOT
# preserved — the whole value is replaced with a double-quoted URL.
_RUNBOOK_RE = re.compile(r"^(?P<indent>\s*)runbook_url:\s*(?P<value>.*)$")


def load_mapping(path: Path) -> dict[str, str]:
    data = yaml.safe_load(path.read_text()) or {}
    if not isinstance(data, dict):
        raise SystemExit(
            f"error: mapping file {path} must be a YAML dict, got {type(data).__name__}"
        )
    return {str(k): str(v) for k, v in data.items()}


def validate_mapping_targets(
    mapping: dict[str, str], runbooks_dir: Path
) -> list[str]:
    """Return a list of error strings for mapping entries whose target file
    does not resolve under `runbooks_dir`. Empty list means all targets valid.
    """
    errors: list[str] = []
    try:
        runbooks_root = runbooks_dir.resolve(strict=True)
    except (OSError, FileNotFoundError):
        return [f"runbooks dir {runbooks_dir} is not a directory"]

    for alert, target_name in mapping.items():
        if not target_name:
            errors.append(f"mapping entry for alert {alert!r} is empty")
            continue
        candidate = (runbooks_root / target_name).resolve()
        # Ensure the resolved path stays under runbooks_root (no traversal)
        # and points to an existing file.
        try:
            candidate.relative_to(runbooks_root)
        except ValueError:
            errors.append(
                f"mapping entry {alert!r} -> {target_name!r} escapes --runbooks-dir"
            )
            continue
        if not candidate.is_file():
            errors.append(
                f"mapping entry {alert!r} -> {target_name!r} does not exist "
                f"under {runbooks_dir}"
            )
    return errors


def plan_file_rewrite(
    text: str, mapping: dict[str, str], filepath: Path
) -> tuple[str, bool, list[str]]:
    """Return (new_text, changed, errors).

    Walks the text line-by-line. When a `runbook_url:` is encountered, uses the
    most recently seen `alert:` name to look up the canonical URL in `mapping`
    and rewrites the line. Line-based instead of structured-YAML so comments
    and formatting are preserved (except trailing comments on the
    runbook_url: line itself — see module docstring).
    """
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    current_alert: str | None = None
    errors: list[str] = []
    changed = False

    for line in lines:
        stripped = line.rstrip("\r\n")
        alert_match = _ALERT_RE.match(stripped)
        if alert_match:
            current_alert = alert_match.group(1)
            out.append(line)
            continue

        runbook_match = _RUNBOOK_RE.match(stripped)
        if runbook_match:
            if current_alert is None:
                errors.append(
                    f"{filepath}: runbook_url line encountered before any alert: {stripped!r}"
                )
                out.append(line)
                continue
            target = mapping.get(current_alert)
            if target is None:
                errors.append(
                    f"{filepath}: alert {current_alert!r} has no entry in mapping file"
                )
                out.append(line)
                continue
            canonical = f'{CANONICAL_PREFIX}{target}'
            indent = runbook_match.group("indent")
            newline_suffix = line[len(stripped):]  # preserve original \n or \r\n
            new_line = f'{indent}runbook_url: "{canonical}"{newline_suffix}'
            if new_line != line:
                changed = True
            out.append(new_line)
            continue

        out.append(line)

    return "".join(out), changed, errors


# Backward-compatible alias for any external callers of the prior name.
rewrite_file_text = plan_file_rewrite


def process(
    rules_dir: Path,
    mapping: dict[str, str],
    runbooks_dir: Path,
    check: bool,
) -> int:
    rule_files = sorted(rules_dir.glob("*.yml"))
    if not rule_files:
        print(f"error: no *.yml rule files in {rules_dir}", file=sys.stderr)
        return 1

    # Validate mapping targets FIRST — before touching any rule file. A bad
    # mapping is a global precondition failure, not a per-file issue.
    mapping_errors = validate_mapping_targets(mapping, runbooks_dir)
    if mapping_errors:
        for err in mapping_errors:
            print(f"error: {err}", file=sys.stderr)
        return 1

    # First pass: plan every rewrite, collect every error. Do NOT write.
    planned: list[tuple[Path, str, bool]] = []  # (file, new_text, changed)
    all_errors: list[str] = []
    for rf in rule_files:
        original = rf.read_text()
        new_text, changed, errors = plan_file_rewrite(original, mapping, rf)
        planned.append((rf, new_text, changed))
        all_errors.extend(errors)

    if all_errors:
        for err in all_errors:
            print(f"error: {err}", file=sys.stderr)
        print(
            f"aborting: {len(all_errors)} error(s) — no files written",
            file=sys.stderr,
        )
        return 1

    # Second pass: apply the plan.
    dirty: list[Path] = []
    for rf, new_text, changed in planned:
        if not changed:
            continue
        dirty.append(rf)
        if check:
            print(
                f"would rewrite: {rf} (runbook_url values not canonical)",
                file=sys.stderr,
            )
        else:
            rf.write_text(new_text)
            print(f"rewrote: {rf}")

    if check:
        if dirty:
            print(
                f"{len(dirty)} file(s) need fixing. Run without --check to apply.",
                file=sys.stderr,
            )
            return 1
        return 0

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rewrite runbook_url annotations in Alertmanager rule files."
    )
    parser.add_argument(
        "--rules-dir",
        required=True,
        type=Path,
        help="Directory containing Alertmanager *.yml rule files",
    )
    parser.add_argument(
        "--mapping",
        required=True,
        type=Path,
        help="YAML mapping file: <AlertName>: <runbook_filename.md>",
    )
    parser.add_argument(
        "--runbooks-dir",
        type=Path,
        default=Path("docs/runbooks"),
        help="Directory where mapping targets must resolve (default: docs/runbooks/)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Dry run; exit non-zero if any file would be rewritten",
    )
    args = parser.parse_args()

    if not args.rules_dir.is_dir():
        print(f"error: --rules-dir {args.rules_dir} is not a directory", file=sys.stderr)
        sys.exit(1)
    if not args.mapping.is_file():
        print(f"error: --mapping {args.mapping} is not a file", file=sys.stderr)
        sys.exit(1)
    if not args.runbooks_dir.is_dir():
        print(
            f"error: --runbooks-dir {args.runbooks_dir} is not a directory",
            file=sys.stderr,
        )
        sys.exit(1)

    mapping = load_mapping(args.mapping)
    sys.exit(
        process(
            args.rules_dir,
            mapping,
            runbooks_dir=args.runbooks_dir,
            check=args.check,
        )
    )


if __name__ == "__main__":
    main()
