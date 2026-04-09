"""Phase 61 — verify GitHub Actions workflows are SHA-pinned and permission-scoped.

Every `uses:` line in `.github/workflows/*.yml` must reference a 40-character
hex commit SHA (not a tag like ``@v4``), with the one documented exception of
reusable workflows loaded via ``uses: owner/repo/.github/workflows/foo.yml@vTAG``
(GitHub only accepts a ref, not a SHA, for those — ``release-cli.yml`` already
uses this form for ``slsa-framework/slsa-github-generator``).

Every workflow must also declare a top-level ``permissions:`` block so the
default ``GITHUB_TOKEN`` scope is explicitly narrowed.
"""
from __future__ import annotations

import glob
import os
import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"

SHA_PIN_RE = re.compile(r"^[^/\s]+/[^@\s]+@[a-f0-9]{40}(\s|$)")
REUSABLE_WORKFLOW_RE = re.compile(r"^[^/\s]+/[^@\s]+/\.github/workflows/[^@\s]+@")


def _workflow_files() -> list[Path]:
    files = sorted(Path(p) for p in glob.glob(str(WORKFLOW_DIR / "*.yml")))
    assert files, f"No workflow files found under {WORKFLOW_DIR}"
    return files


def _iter_uses(node):
    """Yield every ``uses:`` string value in a parsed workflow."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "uses" and isinstance(v, str):
                yield v
            else:
                yield from _iter_uses(v)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_uses(item)


def test_every_workflow_parses_as_yaml():
    for f in _workflow_files():
        with f.open() as fh:
            yaml.safe_load(fh)


def test_every_uses_line_is_sha_pinned():
    failures: list[str] = []
    for f in _workflow_files():
        with f.open() as fh:
            doc = yaml.safe_load(fh)
        for use in _iter_uses(doc):
            if REUSABLE_WORKFLOW_RE.match(use):
                # reusable workflows cannot be pinned to a SHA by GitHub rules
                continue
            if not SHA_PIN_RE.match(use + " "):
                failures.append(f"{f.name}: {use}")
    assert not failures, (
        "Unpinned uses: entries found (must be 40-char SHA):\n  "
        + "\n  ".join(failures)
    )


def test_every_workflow_has_top_level_permissions():
    failures: list[str] = []
    for f in _workflow_files():
        with f.open() as fh:
            doc = yaml.safe_load(fh)
        if not isinstance(doc, dict) or "permissions" not in doc:
            failures.append(f.name)
    assert not failures, (
        "Workflows missing top-level permissions block:\n  "
        + "\n  ".join(failures)
    )


def test_branch_protection_script_executable():
    script = REPO_ROOT / "scripts" / "branch_protection.sh"
    assert script.exists(), f"{script} missing"
    assert os.access(script, os.X_OK), f"{script} not executable"


def test_dependabot_config_present_and_valid():
    cfg = REPO_ROOT / ".github" / "dependabot.yml"
    assert cfg.exists(), f"{cfg} missing"
    with cfg.open() as fh:
        doc = yaml.safe_load(fh)
    assert doc.get("version") == 2
    ecosystems = {u["package-ecosystem"] for u in doc["updates"]}
    assert {"github-actions", "pip", "gomod"} <= ecosystems, ecosystems


if __name__ == "__main__":
    import sys

    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    rc = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except AssertionError as e:
            rc = 1
            print(f"FAIL {t.__name__}: {e}")
    sys.exit(rc)
