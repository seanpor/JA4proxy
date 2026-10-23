"""Phase 824c — Template route-target gate (static, no live HTTP).

Every hx-* target in the templates must resolve to a registered route with
the matching HTTP method. The reverse direction is enforced for partials:
a registered ``GET /api/v1/partials/*`` route may only exist if either some
template references it, or it is explicitly allowed as an alias (and that
allowance is justified by a test).

This gate is static by design. It intentionally does **not** send mutating
requests (``hx-post``/``hx-delete``) — the full list of mutating targets is
documented in ``docs/phases/PHASE_824.md``. It also does not scan
server-generated attributes (``management/api/routes/events.py`` emits
``hx-post`` from f-strings) — those duplicate template targets and the
normaliser invariant below covers the known JS-assembled case.

Known blind spots (written down, not swept under the carpet):
- ``management/templates/partials/threat_posture.html`` builds its ``hx-get``
  in JavaScript via ``setThreatWindow()``; the same path appears as a static
  literal (``hx-get="/api/v1/partials/threat-posture?window={{ window }}"``)
  so the *path* is covered. The invariant test below asserts that.
- Server-generated attributes in Python are out of scope for a templates-only
  scan.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from .hx_targets import hx_targets

MANAGEMENT = Path(__file__).resolve().parents[1]
ROUTES_DIR = MANAGEMENT / "api" / "routes"
TEMPLATES_DIR = MANAGEMENT / "templates"
JOURNEY = MANAGEMENT.parent / "tests" / "integration" / "journeys" / "check_console_journey.sh"

# A route may be registered under /api/v1/partials/ with no template hx-get
# reference ONLY if justified here. The justify test asserts the allowance is
# not abused (referenced by zero templates and by an HTML comment only).
ALLOWED_UNREFERENCED_PARTIALS = {"/api/v1/partials/attack-table"}

DECORATOR = re.compile(
    r'@router\.(get|post|put|patch|delete)\(\s*f?[\'"]([^\'"]+)[\'"]',
    re.IGNORECASE,
)


def _scan_routes() -> list[tuple[str, str, str]]:
    """(method, route_path, source) for every router decorator in the route modules."""
    routes: list[tuple[str, str, str]] = []
    for py in sorted(ROUTES_DIR.rglob("*.py")):
        text = py.read_text(encoding="utf-8")
        for m in DECORATOR.finditer(text):
            method = m.group(1).upper()
            route_path = m.group(2)
            routes.append((method, route_path, str(py.relative_to(MANAGEMENT))))
    return routes


def _journey_partials() -> set[str]:
    """The partial names the live-stack journey probes, from its `PARTIALS=(...)`."""
    block = JOURNEY.read_text(encoding="utf-8").split("PARTIALS=(", 1)[1].split(")", 1)[0]
    return {line.strip() for line in block.splitlines() if line.strip()}


_PARAM_SEGMENT = re.compile(r"^\{([^{}:]+)(?::([a-z]+))?\}$")


def _route_prefix_matches(declared: str, path: str) -> bool:
    """Does a concrete request `path` match the route `declared`?

    Segment-wise, mirroring the rules FastAPI/Starlette apply:

    * a literal segment must be equal;
    * ``{name}`` matches exactly **one** segment;
    * ``{name:path}`` consumes the rest of the path (one or more segments);
    * the segment counts must otherwise be equal.

    Two earlier rules were wrong, and both made the forward half of this gate
    assert **nothing** (Phase 824c close-out, found by renaming a partial route
    and watching the forward check stay green):

    1. A naive prefix match let the root route ``GET /`` match every path.
    2. ``GET /api/v1/{list_name}`` — a *one-segment* parameterised route from
       ``canonical_lists.py`` — matched every path under ``/api/v1/`` including
       ``/api/v1/partials/attack-top``, so any ``/api/v1`` target "resolved".

    Counting segments fixes both, and still matches the parameterised routes the
    old rule existed for (``/api/v1/bans/{ip:path}`` → ``/api/v1/bans/1.2.3.4``).
    This is deliberately stricter than `test_pages.py`'s prefix rule: a gate that
    accepts a catch-all as proof of a specific route cannot fail, which is worse
    than a gate that occasionally needs a route declaration tightened.
    """
    declared_segments = [s for s in declared.split("/") if s]
    path_segments = [s for s in path.split("/") if s]

    for index, segment in enumerate(declared_segments):
        param = _PARAM_SEGMENT.match(segment)
        if param is None:
            if index >= len(path_segments) or path_segments[index] != segment:
                return False
            continue
        if (param.group(2) or "") == "path":
            return index < len(path_segments)  # consumes every remaining segment
        if index >= len(path_segments):
            return False
    return len(path_segments) == len(declared_segments)


class TestTemplateRouteTargets:
    def test_extractor_is_not_vacuous(self):
        targets = hx_targets()
        assert len(targets) >= 20
        assert sum(1 for m, _, _ in targets if m in {"POST", "DELETE"}) >= 6

    def test_root_route_does_not_match_every_path(self):
        """`GET /` is a catch-all; a catch-all must not satisfy a specific target.

        Before this was pinned, `_route_prefix_matches("/", anything)` returned
        True (the prefix "/" ends with "/"), so every GET target in the forward
        check resolved to the root page and the check could never fail. Verified
        by renaming a partial route: the reverse and journey checks failed, the
        forward check did not.
        """
        assert _route_prefix_matches("/", "/")
        assert not _route_prefix_matches("/", "/api/v1/partials/attack-top")
        assert not _route_prefix_matches("/", "/api/v1/status")

    @pytest.mark.parametrize("method,request_url,path", hx_targets())
    def test_hx_target_resolves_to_a_registered_route(
        self, method: str, request_url: str, path: str
    ):
        routes = _scan_routes()
        matched = [
            (rm, rp, src)
            for rm, rp, src in routes
            if _route_prefix_matches(rp, path) and rm == method
        ]
        assert matched, (
            f"{method} {request_url!r} (path {path!r}) is referenced by a template "
            f"but no registered route matches {method} with that path prefix. "
            f"Check management/api/routes/."
        )

    def test_partials_reverse_direction(self):
        """Every registered GET partial route must be referenced by a template
        or explicitly allowed."""
        routes = _scan_routes()
        partials = {
            path for method, path, _ in routes if method == "GET" and path.startswith("/api/v1/partials/")
        }
        referenced = {path for _, _, path in hx_targets() if path.startswith("/api/v1/partials/")}
        allowed = ALLOWED_UNREFERENCED_PARTIALS
        unreferenced = partials - referenced
        assert unreferenced == allowed, (
            f"Unreferenced partial routes (add a template hx-get or justify): "
            f"{sorted(unreferenced - allowed)}"
        )

    def test_attack_table_alias_is_justified(self):
        """attack-table has a second decorator and exists only as an HTML comment
        reference — it must not be pulled into templates as an hx-get."""
        routes = _scan_routes()
        partials = {
            path for method, path, _ in routes if method == "GET" and path.startswith("/api/v1/partials/")
        }
        assert "/api/v1/partials/attack-table" in partials
        referenced = {path for method, _, path in hx_targets() if method == "GET"}
        assert "/api/v1/partials/attack-table" not in referenced

        # It must be mentioned only as a comment (or not as an hx-get)
        comment_only = False
        for tpl in TEMPLATES_DIR.rglob("*.html"):
            for m in re.finditer(r"""hx-get=["']([^"']*)["']""", tpl.read_text(encoding="utf-8")):
                if "/api/v1/partials/attack-table" in m.group(1):
                    pytest.fail(f"attack-table referenced as hx-get in {tpl}")
            if "/api/v1/partials/attack-table" in tpl.read_text(encoding="utf-8"):
                comment_only = True
        assert comment_only

    def test_threat_posture_js_path_is_covered_by_static_target(self):
        """The JS-assembled hx-get must share its path with a static literal."""
        targets = hx_targets()
        threat_paths = [p for _, _, p in targets if p == "/api/v1/partials/threat-posture"]
        assert threat_paths, "threat-posture must appear as a static hx-get target"

    def test_journey_partial_list_matches_registered_routes(self):
        """The live-stack journey must probe exactly the registered partials.

        `tests/integration/journeys/check_console_journey.sh` cannot import the
        route table — it is a shell script asserting real 401 behaviour against
        a running stack — so its `PARTIALS=(...)` list is a hand-maintained copy
        of the routes, and hand-maintained copies rot. The first draft of this
        phase's refresh dropped a real route (`attack-mode-indicator`) while
        claiming the list was complete, which is precisely the failure class
        this phase exists to kill: the journey would have kept reporting a green
        401 sweep while one partial went unprobed.

        Aliases are excluded: the journey is a route sweep, and an alias that no
        template fetches adds nothing to it.
        """
        routes = _scan_routes()
        registered = {
            path.rsplit("/", 1)[-1]
            for method, path, _ in routes
            if method == "GET" and path.startswith("/api/v1/partials/")
        } - {path.rsplit("/", 1)[-1] for path in ALLOWED_UNREFERENCED_PARTIALS}

        journey = _journey_partials()

        assert journey, "could not parse PARTIALS=(...) from the journey script"
        assert journey == registered, (
            "the journey's partial list has drifted from the registered routes — "
            f"missing from the journey: {sorted(registered - journey)}; "
            f"not a registered route: {sorted(journey - registered)}"
        )
