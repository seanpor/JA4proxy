"""No styled control may end up with its text the same colour as its background.

WHY THIS EXISTS
---------------
``custom.css`` styles ``.glass-input`` for the dark scheme, then re-declares
background and colour inside ``@media (prefers-color-scheme: light)``. The
light block overrode ``.glass-input`` fully but overrode ``.glass-input:focus``
only for ``border-color``.

The base ``:focus`` rule sets ``background: rgba(11, 15, 25, 0.95)`` — a
near-black — with ``!important``. Nothing in the light block reset it. So on a
light-scheme OS, focusing an input turned its background black while the light
block's ``color: #0f172a`` kept the text black. Black on black: the operator
could not read what they were typing.

It reached production because it needs three conditions at once — light colour
scheme, the ``:focus`` state, and a rule split across a media query — and no
test looked at rendered colour at all. It affected every ``.glass-input`` in the
app, including the username and password fields on the login form.

These tests resolve the cascade the way a browser does (later rule of equal
specificity wins; ``!important`` beats non-important) and assert the resulting
foreground and background differ by enough luminance to read.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

CSS = Path(__file__).resolve().parents[1] / "static" / "custom.css"

# WCAG 1.4.3 asks 4.5:1 for body text. This is a regression guard, not an
# accessibility audit: the bug it exists for produced a ratio of 1.0 (identical
# colours). 3.0 catches that class of failure without failing the whole suite on
# a designer's borderline grey.
MIN_CONTRAST = 3.0


def _srgb_to_linear(c: float) -> float:
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def _luminance(rgb: tuple[float, float, float]) -> float:
    r, g, b = (_srgb_to_linear(v / 255.0) for v in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _contrast(fg: tuple[float, float, float], bg: tuple[float, float, float]) -> float:
    lf, lb = _luminance(fg), _luminance(bg)
    lighter, darker = max(lf, lb), min(lf, lb)
    return (lighter + 0.05) / (darker + 0.05)


def _parse_colour(value: str) -> tuple[float, float, float] | None:
    """Parse ``#rgb``/``#rrggbb``/``rgb()``/``rgba()``. Alpha is composited
    against white, matching how a light-scheme page actually renders."""
    # NOT rstrip("!important") -- rstrip takes a character SET, so it eats any
    # trailing !,i,m,p,o,r,t,a,n and turned "#0f172a" into "#0f172".
    value = re.sub(r"\s*!\s*important\s*$", "", value.strip(), flags=re.I).strip()

    m = re.fullmatch(r"#([0-9a-fA-F]{3})", value)
    if m:
        return tuple(int(ch * 2, 16) for ch in m.group(1))  # type: ignore[return-value]

    m = re.fullmatch(r"#([0-9a-fA-F]{6})", value)
    if m:
        h = m.group(1)
        return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))

    m = re.fullmatch(r"rgba?\(([^)]+)\)", value)
    if m:
        parts = [p.strip() for p in m.group(1).replace("/", ",").split(",")]
        if len(parts) < 3:
            return None
        try:
            r, g, b = (float(p) for p in parts[:3])
        except ValueError:
            return None
        alpha = float(parts[3]) if len(parts) > 3 else 1.0
        # Composite over white: the light scheme's page background.
        return tuple(v * alpha + 255.0 * (1.0 - alpha) for v in (r, g, b))  # type: ignore[return-value]

    return None


def _blocks(css: str) -> list[tuple[str, str, bool]]:
    """Return (selector, body, inside_light_media) in source order.

    A flat scan is enough here: this stylesheet nests at most one level
    (rules inside ``@media``), which the brace depth counter tracks.
    """
    out: list[tuple[str, str, bool]] = []
    depth = 0
    in_light = False
    i = 0
    while i < len(css):
        brace = css.find("{", i)
        if brace == -1:
            break
        prelude = css[i:brace].strip()
        # Strip comments from the prelude so selectors are clean.
        prelude = re.sub(r"/\*.*?\*/", "", prelude, flags=re.S).strip()

        if prelude.startswith("@media"):
            in_light = "prefers-color-scheme" in prelude and "light" in prelude
            depth += 1
            i = brace + 1
            continue

        close = css.find("}", brace)
        if close == -1:
            break
        body = css[brace + 1 : close]
        if prelude:
            out.append((prelude, body, in_light))
        i = close + 1
        # A '}' that closes the media block resets the flag.
        nxt = css.find("{", i)
        seg = css[i:nxt] if nxt != -1 else css[i:]
        if depth > 0 and "}" in seg:
            in_light = False
            depth -= 1
    return out


def _resolve(selector: str, light: bool) -> dict[str, str]:
    """Resolve `background`/`color` for `selector` as a browser would.

    Walks matching rules in source order, applying the dark (non-media) rules
    first and then the light-media ones when ``light`` is set — which is the
    document order in this stylesheet, and therefore the cascade order for
    rules of equal specificity.
    """
    css = CSS.read_text(encoding="utf-8")
    resolved: dict[str, str] = {}
    for sel, body, in_light in _blocks(css):
        if in_light and not light:
            continue
        selectors = {s.strip() for s in sel.split(",")}
        if selector not in selectors:
            continue
        for decl in body.split(";"):
            if ":" not in decl:
                continue
            prop, _, val = decl.partition(":")
            prop = prop.strip().lower()
            if prop in ("background", "background-color", "color"):
                resolved["background" if prop.startswith("background") else "color"] = val
    return resolved


# Controls a user types into, in both states and both schemes. `.glass-input`
# is the app's only text-input class -- it styles the dial, the ban forms, the
# list forms and the login form.
CASES = [
    (".glass-input", False, "dark, resting"),
    (".glass-input:focus", False, "dark, focused"),
    (".glass-input", True, "light, resting"),
    (".glass-input:focus", True, "light, focused"),
]


@pytest.mark.parametrize("selector,light,label", CASES, ids=[c[2] for c in CASES])
def test_input_text_is_readable(selector: str, light: bool, label: str) -> None:
    """Resolved foreground and background must be distinguishable."""
    resolved = _resolve(selector, light)

    # A :focus rule may legitimately inherit colour from the base rule.
    if "color" not in resolved or "background" not in resolved:
        base = _resolve(selector.replace(":focus", ""), light)
        resolved = {**base, **resolved}

    assert "color" in resolved and "background" in resolved, (
        f"{label}: could not resolve both colour and background for {selector} "
        f"(got {sorted(resolved)})"
    )

    fg = _parse_colour(resolved["color"])
    bg = _parse_colour(resolved["background"])
    assert fg is not None, f"{label}: unparsable colour {resolved['color']!r}"
    assert bg is not None, f"{label}: unparsable background {resolved['background']!r}"

    ratio = _contrast(fg, bg)
    assert ratio >= MIN_CONTRAST, (
        f"{label}: {selector} renders text at contrast {ratio:.2f}:1 "
        f"(colour {resolved['color'].strip()} on background "
        f"{resolved['background'].strip()}). Below {MIN_CONTRAST}:1 the operator "
        f"cannot read what they are typing. If a media query overrides one of "
        f"background/color for a state, it must override both."
    )


def test_the_contrast_check_can_actually_fail() -> None:
    """Vacuity guard: prove the maths reports the original bug.

    Without this, a parser that silently returned None for every colour would
    make the tests above pass on a stylesheet that is entirely unreadable.
    """
    black = _parse_colour("#0f172a")
    near_black = _parse_colour("rgba(11, 15, 25, 0.95)")
    assert black is not None and near_black is not None
    assert _contrast(black, near_black) < MIN_CONTRAST, (
        "the exact colour pair from the reported bug must be judged unreadable"
    )
    white = _parse_colour("#ffffff")
    assert white is not None
    assert _contrast(black, white) >= MIN_CONTRAST
