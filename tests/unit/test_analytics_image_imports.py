"""Regression test for JA4PROXY-2026-0097 (Phase 817).

The analytics container crash-looped on every startup with
``ModuleNotFoundError: No module named 'src.utils'``: ``src/analytics/main.py``
imports ``src.utils.logging_config``, but the Dockerfile copied only
``src/analytics`` into the image. ``src/utils`` — which exists in the repo —
was never present at runtime.

Nothing caught it because no test exercised the analytics image's import
closure. This is that test.

It is deliberately **static** (parse imports, parse the Dockerfile's ``COPY``
lines) rather than a container build:

* it runs in milliseconds on the unit path with no Docker;
* it catches the whole *class* — any ``src.*`` import that ships without its
  subtree — not just the one instance that was found;
* the end-to-end "does the container actually start" check is the range
  bring-up (`make pentest-range`), verified during Phase 817. This guards the
  invariant that made the crash possible.

Two-state proof (PROGRAMME.md §10.3): with the pre-fix Dockerfile (no
``COPY src/utils``) this test FAILS; with the fix it PASSES.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ANALYTICS_DIR = ROOT / "src" / "analytics"
DOCKERFILE = ANALYTICS_DIR / "Dockerfile"


def _src_imports(package_dir: Path) -> set[str]:
    """Return every top-level ``src`` subpackage the package imports.

    e.g. ``from src.utils.logging_config import x`` -> ``"utils"``.
    """
    needed: set[str] = set()
    for py in package_dir.rglob("*.py"):
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for node in ast.walk(tree):
            module: str | None = None
            if isinstance(node, ast.ImportFrom) and node.level == 0:
                module = node.module
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("src."):
                        needed.add(alias.name.split(".")[1])
            if module and module.startswith("src."):
                needed.add(module.split(".")[1])
    return needed


def _copied_src_subtrees(dockerfile: Path) -> set[str]:
    """Return every ``src/<subtree>`` the Dockerfile COPYs into the image."""
    copied: set[str] = set()
    for line in dockerfile.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped.upper().startswith("COPY "):
            continue
        for match in re.finditer(r"\bsrc/([A-Za-z0-9_]+)", stripped):
            copied.add(match.group(1))
    return copied


def test_every_src_import_is_copied_into_the_analytics_image() -> None:
    """The exact invariant whose violation crash-looped the analytics node.

    Every ``src.<sub>`` the analytics package imports must have its ``src/<sub>``
    subtree copied into the image, or the container dies at import time.
    """
    imported = _src_imports(ANALYTICS_DIR)
    copied = _copied_src_subtrees(DOCKERFILE)
    missing = imported - copied
    assert not missing, (
        "analytics image is missing src subtree(s) it imports: "
        f"{sorted(missing)}. Add `COPY src/<name> /app/src/<name>` to "
        f"{DOCKERFILE.relative_to(ROOT)} — this is exactly the JA4PROXY-2026-0097 "
        "crash-loop (ModuleNotFoundError at startup)."
    )


def test_analytics_imports_src_utils() -> None:
    """Pin the specific regression: analytics genuinely needs src.utils.

    Guards against a future refactor removing the import and the COPY together
    in a way that would make the class-check above vacuously pass while quietly
    dropping the coverage this finding is about.
    """
    assert "utils" in _src_imports(ANALYTICS_DIR), (
        "expected src/analytics to import src.utils — if that changed, update "
        "this test and JA4PROXY-2026-0097's regression note deliberately"
    )
