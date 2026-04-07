#!/usr/bin/env python3
"""JA4proxy policy-as-code CLI.

Stopgap Python script implementing ``validate``, ``apply``, and ``diff``
commands.  Phase 83 replaces this with a compiled Go binary (``ja4proxy-cli
policy …``) using the same interface — existing CI/CD templates require no
changes.

Usage
-----
validate --file <path>
    Validate a policy YAML file offline (no API calls required).
    Exit 0 = valid.
    Exit 1 = validation error (message printed to stderr).

apply --file <path> --url <api-url> --token <token> [--dry-run]
    Apply the policy to the Management API.
    Exit 0 = success   ("N added, M removed, P unchanged" on stdout).
    Exit 1 = error.
    Exit 2 = pending approval ("PENDING APPROVAL: {decision_id}" on stdout).

diff --file <path> --url <api-url> --token <token>
    Compare policy file against live API state.
    Exit 0 = no drift.
    Exit 1 = drift detected (report on stdout).

Token precedence:  ``--token`` flag > ``JA4PROXY_TOKEN`` env var.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

# ---------------------------------------------------------------------------
# Guard: ensure src/ is importable when run from the repo root.
# ---------------------------------------------------------------------------
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)


# ---------------------------------------------------------------------------
# Sub-command implementations
# ---------------------------------------------------------------------------


def cmd_validate(args: argparse.Namespace) -> int:
    """Run offline validation and return an exit code.

    Args:
        args: Parsed CLI arguments (``args.file``, ``args.current_dial``).

    Returns:
        0 on success, 1 on any validation failure.
    """
    from src.governance.policy_validator import (
        PolicyDuplicateError,
        PolicySchemaError,
        PolicySyntaxError,
        PolicyTTLError,
        PolicyValidationError,
        validate_policy,
    )

    try:
        with open(args.file, encoding="utf-8") as fh:
            yaml_text = fh.read()
    except OSError as exc:
        print(f"ERROR: cannot read file {args.file!r}: {exc}", file=sys.stderr)
        return 1

    current_dial: int = getattr(args, "current_dial", 0) or 0

    try:
        validate_policy(yaml_text, current_dial=current_dial)
    except (
        PolicySyntaxError,
        PolicySchemaError,
        PolicyTTLError,
        PolicyDuplicateError,
        PolicyValidationError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print("Policy is valid.")
    return 0


async def _async_apply(args: argparse.Namespace) -> int:
    """Async implementation of the ``apply`` command.

    Args:
        args: Parsed CLI arguments.

    Returns:
        0 on success, 1 on error, 2 on pending approval.
    """
    from src.governance.policy_applier import PendingApprovalError, apply_policy
    from src.governance.policy_validator import validate_policy

    try:
        with open(args.file, encoding="utf-8") as fh:
            yaml_text = fh.read()
    except OSError as exc:
        print(f"ERROR: cannot read file {args.file!r}: {exc}", file=sys.stderr)
        return 1

    try:
        policy_dict = validate_policy(yaml_text)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: validation failed: {exc}", file=sys.stderr)
        return 1

    token = _resolve_token(args)
    if not token:
        print(
            "ERROR: no token provided — use --token or set JA4PROXY_TOKEN",
            file=sys.stderr,
        )
        return 1

    if getattr(args, "dry_run", False):
        print("Dry run — no API calls made.")
        return 0

    try:
        result = await apply_policy(policy_dict, args.url, token)
    except PendingApprovalError as exc:
        print(f"PENDING APPROVAL: {exc.decision_id}")
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: apply failed: {exc}", file=sys.stderr)
        return 1

    print(
        f"{result.added} added, {result.removed} removed, "
        f"{result.unchanged} unchanged"
    )
    if result.pending_approvals:
        for decision_id in result.pending_approvals:
            print(f"PENDING APPROVAL: {decision_id}")
        return 2
    return 0


async def _async_diff(args: argparse.Namespace) -> int:
    """Async implementation of the ``diff`` command.

    Args:
        args: Parsed CLI arguments.

    Returns:
        0 if no drift, 1 if drift detected or error.
    """
    from src.governance.policy_applier import diff_policy
    from src.governance.policy_validator import validate_policy

    try:
        with open(args.file, encoding="utf-8") as fh:
            yaml_text = fh.read()
    except OSError as exc:
        print(f"ERROR: cannot read file {args.file!r}: {exc}", file=sys.stderr)
        return 1

    try:
        policy_dict = validate_policy(yaml_text)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: validation failed: {exc}", file=sys.stderr)
        return 1

    token = _resolve_token(args)
    if not token:
        print(
            "ERROR: no token provided — use --token or set JA4PROXY_TOKEN",
            file=sys.stderr,
        )
        return 1

    try:
        drift_entries = await diff_policy(policy_dict, args.url, token)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: diff failed: {exc}", file=sys.stderr)
        return 1

    if not drift_entries:
        print("No drift detected.")
        return 0

    print(f"Drift detected: {len(drift_entries)} unexpected entries")
    for entry in drift_entries:
        line = (
            f"  [{entry.resource_type}] {entry.identifier}"
            f"  managed_by={entry.managed_by}"
        )
        if entry.note:
            line += f"  note={entry.note}"
        print(line)
    return 1


def cmd_apply(args: argparse.Namespace) -> int:
    """Run the apply command synchronously.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Exit code.
    """
    return asyncio.run(_async_apply(args))


def cmd_diff(args: argparse.Namespace) -> int:
    """Run the diff command synchronously.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Exit code.
    """
    return asyncio.run(_async_diff(args))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_token(args: argparse.Namespace) -> str:
    """Return the API token from CLI flag or environment variable.

    Flag takes precedence over env var.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Token string (may be empty if neither source provides one).
    """
    flag_token: str = getattr(args, "token", "") or ""
    if flag_token:
        return flag_token
    return os.environ.get("JA4PROXY_TOKEN", "")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser.

    Returns:
        Configured ``argparse.ArgumentParser``.
    """
    parser = argparse.ArgumentParser(
        prog="ja4proxy-policy.py",
        description="JA4proxy policy-as-code CLI (Phase 82 stopgap).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── validate ─────────────────────────────────────────────────────────────
    p_validate = sub.add_parser(
        "validate",
        help="Validate a policy YAML file offline (no API calls).",
    )
    p_validate.add_argument("--file", required=True, help="Path to policy YAML file.")
    p_validate.add_argument(
        "--current-dial",
        type=int,
        default=0,
        dest="current_dial",
        help="Current dial setting for increase-validation (default: 0).",
    )

    # ── apply ─────────────────────────────────────────────────────────────────
    p_apply = sub.add_parser(
        "apply",
        help="Apply policy to the Management API.",
    )
    p_apply.add_argument("--file", required=True, help="Path to policy YAML file.")
    p_apply.add_argument(
        "--url", required=True, help="Management API base URL."
    )
    p_apply.add_argument(
        "--token",
        default="",
        help="API bearer token (or set JA4PROXY_TOKEN env var).",
    )
    p_apply.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="Validate and report without making API calls.",
    )

    # ── diff ──────────────────────────────────────────────────────────────────
    p_diff = sub.add_parser(
        "diff",
        help="Compare policy file against live API state.",
    )
    p_diff.add_argument("--file", required=True, help="Path to policy YAML file.")
    p_diff.add_argument(
        "--url", required=True, help="Management API base URL."
    )
    p_diff.add_argument(
        "--token",
        default="",
        help="API bearer token (or set JA4PROXY_TOKEN env var).",
    )

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Parse arguments and dispatch to the appropriate sub-command."""
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "validate": cmd_validate,
        "apply": cmd_apply,
        "diff": cmd_diff,
    }

    handler = dispatch[args.command]
    exit_code = handler(args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
