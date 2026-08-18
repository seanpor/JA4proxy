"""
The dial presets must actually be reachable.

The API caps a single dial change at ±10 — a deliberate safety rail against
jumping straight to full enforcement. The widget mirrored that check
client-side and, when the delta exceeded 10, refused to send anything and told
the operator to "use the presets to step gradually".

But every preset (Monitor 0, Low 25, Mid 50, High 75) is more than 10 apart, so
from a standing start of dial=0 the slider AND all four presets silently did
nothing. The request never left the browser — server logs showed no dial write
at all. The error message pointed at buttons that could not work either.

Fixed by walking to the target in ≤10 steps with a single confirmation.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
WIDGET = REPO / "management" / "templates" / "partials" / "dial_widget.html"


def test_widget_does_not_refuse_large_changes_outright():
    """The early return that made every preset a no-op must not come back."""
    src = WIDGET.read_text(encoding="utf-8")
    blocking = re.search(
        r"if\s*\(\s*delta\s*>\s*10\s*\)\s*\{[^}]*return;", src, re.S
    )
    assert not blocking, (
        "dial_widget refuses deltas > 10 client-side again. Every preset is "
        ">10 from dial=0, so this makes all of them silently do nothing — the "
        "request never reaches the server."
    )


def test_widget_steps_toward_the_target():
    """It must walk in increments rather than sending one oversized request."""
    src = WIDGET.read_text(encoding="utf-8")
    assert "steps.push" in src and "Math.min(10" in src, (
        "dial_widget no longer builds ≤10 increments; a single large PUT will "
        "be rejected by the server's ±10 cap"
    )


def test_presets_are_still_more_than_ten_apart():
    """Pins WHY stepping is required — if presets change, revisit this.

    If someone re-spaces the presets ≤10 apart, the stepping logic becomes
    unnecessary and this test should be revisited deliberately rather than
    the logic being removed on a hunch.
    """
    src = WIDGET.read_text(encoding="utf-8")
    values = [int(v) for v in re.findall(r'\("(?:Monitor|Low|Mid|High)[^"]*",\s*(\d+)\)', src)]
    assert values, "could not find the preset values in the widget"
    assert max(values) - min(values) > 10, (
        f"presets {values} now span ≤10 — stepping may no longer be needed"
    )


def test_routine_presets_do_not_use_the_emergency_endpoint():
    """Emergency is for genuine overrides and is audited differently.

    /api/v1/dial/emergency logs event=emergency_override and carries
    auto-revert semantics. Routing routine preset clicks through it would
    misrepresent operator intent in the audit trail.
    """
    src = WIDGET.read_text(encoding="utf-8")
    apply_fn = src[src.index("async applyDial()"):]
    apply_fn = apply_fn[: apply_fn.index("\n    },")]
    assert "/api/v1/dial/emergency" not in apply_fn, (
        "applyDial uses the emergency override endpoint for routine changes"
    )
