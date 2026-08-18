"""Phase 827 — an interactive control must actually be wired to something.

WHY THIS EXISTS
---------------
Every interactive control in this console has, at some point, been silently
broken: the dial refused changes over ±10, the dial presets did nothing, the
dial's POST omitted the CSRF header, and the dashboard's time-window buttons
(5m/15m/1h/24h) updated localStorage and then changed nothing on screen.

Each one looked fine to the existing tests, which assert that routes resolve
and that panels are not rendering an error. A control that fires an event with
no listener returns 200 from every endpoint and renders perfectly — it just
does not work. The active pill even moved, so the UI looked responsive while
the data underneath never changed.

The specific defect for the time window: the container declared
`hx-trigger="every 30s"` while the click handler called
`htmx.trigger(container, 'refresh')`. htmx only acts on events named in
hx-trigger, so 'refresh' went nowhere.

This test reads the templates and checks that every custom event fired by
JavaScript is one the target element actually listens for. It is static, so it
runs in milliseconds and cannot be defeated by a panel that happens to be empty
in the test fixture.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

TEMPLATES = Path(__file__).resolve().parents[1] / "templates"

# htmx.trigger(target, 'event')  — target is '#id' or a JS variable.
_TRIGGER = re.compile(r"""htmx\.trigger\(\s*(?P<target>'[^']+'|"[^"]+"|[A-Za-z_$][\w$]*)\s*,\s*['"](?P<event>[^'"]+)['"]""")
# Elements carrying hx-trigger, captured with their id when present.
_HX_TRIGGER = re.compile(r"""hx-trigger\s*=\s*["']([^"']+)["']""")


def _templates() -> list[Path]:
    return sorted(TEMPLATES.rglob("*.html"))


def _strip_comments(text: str) -> str:
    """Drop Jinja and HTML comments so prose about a bug is not read as code."""
    text = re.sub(r"\{#.*?#\}", "", text, flags=re.S)
    return re.sub(r"<!--.*?-->", "", text, flags=re.S)


def _trigger_calls() -> list[tuple[Path, str, str]]:
    out = []
    for tpl in _templates():
        body = _strip_comments(tpl.read_text())
        for m in _TRIGGER.finditer(body):
            out.append((tpl, m.group("target").strip("'\""), m.group("event")))
    return out


def test_there_are_trigger_calls_to_check():
    """Guard the guard — a broken regex would pass everything vacuously."""
    calls = _trigger_calls()
    assert len(calls) >= 5, f"only found {calls}; the htmx.trigger regex is likely broken"


@pytest.mark.parametrize(
    "tpl,target,event",
    [(t, tg, ev) for t, tg, ev in _trigger_calls()],
    ids=lambda v: v.name if isinstance(v, Path) else str(v),
)
def test_triggered_event_has_a_listener(tpl: Path, target: str, event: str):
    """Every htmx.trigger(el, 'evt') needs 'evt' in that element's hx-trigger.

    Searched across all templates because the target element is frequently
    defined in a different partial from the script that triggers it.
    """
    # htmx's own built-ins are always available and need no declaration.
    if event in {"load", "click", "submit", "change", "revealed", "intersect"}:
        pytest.skip(f"{event} is a native htmx trigger")

    corpus = "\n".join(_strip_comments(t.read_text()) for t in _templates())

    listeners = []
    for m in _HX_TRIGGER.finditer(corpus):
        events = {e.strip().split(" ")[0] for e in m.group(1).split(",")}
        listeners.extend(events)

    assert event in listeners, (
        f"{tpl.name} fires htmx.trigger({target!r}, {event!r}) but no element "
        f"declares {event!r} in hx-trigger — the control updates state and then "
        "does nothing visible. Add it: hx-trigger=\"every 30s, "
        f"{event}\". Declared events: {sorted(set(listeners))}"
    )


def test_window_selector_targets_an_element_that_listens():
    """Specific regression: the 5m/15m/1h/24h buttons on the dashboard."""
    tp = _strip_comments((TEMPLATES / "partials" / "threat_posture.html").read_text())
    assert "htmx.trigger(container, 'refresh')" in tp, "handler moved — update this test"
    m = re.search(r'id="threat-posture".*?hx-trigger\s*=\s*["\']([^"\']+)["\']', tp, re.S)
    assert m, "threat-posture container has no hx-trigger"
    assert "refresh" in m.group(1), (
        f"threat-posture listens for {m.group(1)!r}, so the window buttons fire "
        "into the void and the panel only updates on its 30s poll"
    )
