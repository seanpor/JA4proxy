"""Every ``{% block %}`` a child template defines must exist in its parent.

WHY THIS EXISTS
---------------
Jinja2 silently discards a ``{% block foo %}`` in a child template when the
parent does not declare ``{% block foo %}``. There is no warning, no error, and
no marker in the output — the content simply is not there.

``fingerprint.html`` and ``ip_detail.html`` both wrapped their Alpine component
definitions in ``{% block scripts %}``. ``base.html`` declares
``{% block extra_scripts %}``. So ``fingerprintPage()`` and ``ipPage()`` were
never emitted, ``x-data="fingerprintPage()"`` threw a ReferenceError in the
browser, no profile fetch was ever made, and the pages rendered with every
counter empty. The API endpoint they were blamed on was working the whole time
and returned real data when called directly.

The failure is invisible to every other kind of test: the route returns 200,
the HTML is well-formed, the template renders without raising, and a unit test
of the endpoint passes. Only comparing block names across the inheritance edge
catches it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "templates"

_EXTENDS = re.compile(r"""\{%-?\s*extends\s+["']([^"']+)["']""")
_BLOCK = re.compile(r"""\{%-?\s*block\s+([A-Za-z_][A-Za-z0-9_]*)""")


def _templates() -> list[Path]:
    return sorted(TEMPLATE_DIR.rglob("*.html"))


def _blocks(path: Path) -> set[str]:
    return set(_BLOCK.findall(path.read_text(encoding="utf-8")))


def _parent_of(path: Path) -> Path | None:
    m = _EXTENDS.search(path.read_text(encoding="utf-8"))
    if not m:
        return None
    return TEMPLATE_DIR / m.group(1)


def _inherited_blocks(path: Path) -> set[str]:
    """Blocks available to ``path`` from its ancestors, following the chain.

    A grandparent's blocks count: Jinja resolves the whole chain, so a block
    declared two levels up is a legitimate override target.
    """
    available: set[str] = set()
    seen: set[Path] = set()
    parent = _parent_of(path)
    while parent is not None and parent not in seen:
        seen.add(parent)
        if not parent.exists():
            break
        available |= _blocks(parent)
        parent = _parent_of(parent)
    return available


@pytest.mark.parametrize(
    "template", [p for p in _templates() if _EXTENDS.search(p.read_text(encoding="utf-8"))],
    ids=lambda p: str(p.relative_to(TEMPLATE_DIR)),
)
def test_child_blocks_exist_in_parent(template: Path) -> None:
    """A block name the parent chain never declares is dead content."""
    parent = _parent_of(template)
    assert parent is not None and parent.exists(), (
        f"{template.name} extends a template that does not exist: {parent}"
    )

    available = _inherited_blocks(template)
    orphans = sorted(_blocks(template) - available)

    assert not orphans, (
        f"{template.relative_to(TEMPLATE_DIR)} defines block(s) {orphans} that no "
        f"ancestor declares. Jinja drops these silently — the content will never "
        f"render. Parent chain offers: {sorted(available)}"
    )


def test_the_guard_can_actually_fail(tmp_path: Path) -> None:
    """Vacuity check: prove the comparison detects a genuine orphan block.

    Without this, a bug in the regexes (matching nothing, so every set is
    empty) would make the test above pass on a codebase that is entirely
    broken.
    """
    parent = tmp_path / "parent.html"
    parent.write_text("{% block content %}{% endblock %}", encoding="utf-8")
    child = tmp_path / "child.html"
    child.write_text(
        '{% extends "parent.html" %}\n'
        "{% block content %}hi{% endblock %}\n"
        "{% block typo_name %}dropped{% endblock %}\n",
        encoding="utf-8",
    )

    child_blocks = _blocks(child)
    parent_blocks = _blocks(parent)
    assert "typo_name" in child_blocks
    assert "typo_name" not in parent_blocks
    assert child_blocks - parent_blocks == {"typo_name"}


def test_alpine_components_are_defined_in_a_rendered_block() -> None:
    """Every ``x-data="fn()"`` must have ``function fn()`` in live content.

    The block-name check above is structural; this one is about the specific
    breakage it caused. A template that calls an Alpine factory it never
    defines produces a page whose bindings are all inert.
    """
    x_data = re.compile(r"""x-data=["']([A-Za-z_][A-Za-z0-9_]*)\(\)["']""")
    failures: list[str] = []

    for path in _templates():
        text = path.read_text(encoding="utf-8")
        for fn in x_data.findall(text):
            if not re.search(rf"function\s+{re.escape(fn)}\s*\(", text):
                failures.append(f"{path.relative_to(TEMPLATE_DIR)}: x-data={fn}()")
                continue
            # Defined — but is the definition inside a block the parent keeps?
            orphans = _blocks(path) - _inherited_blocks(path)
            if orphans and _EXTENDS.search(text):
                failures.append(
                    f"{path.relative_to(TEMPLATE_DIR)}: {fn}() may sit in "
                    f"dropped block(s) {sorted(orphans)}"
                )

    assert not failures, "Alpine components that will not initialise: " + "; ".join(failures)
