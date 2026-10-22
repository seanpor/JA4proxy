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


def _route_prefix_matches(declared: str, path: str) -> bool:
    """Prefix match by stripping the declared route at its first '{'.

    Mirrors management/tests/test_pages.py:375 — parameterised routes like
    /api/v1/bans/{ip:path} must match a concrete /api/v1/bans/1.2.3.4.
    """
    prefix = declared.split("{", 1)[0]
    if prefix.endswith("/"):
        return path.startswith(prefix)
    return path == prefix or path.startswith(prefix + "/")


class TestTemplateRouteTargets:
    def test_extractor_is_not_vacuous(self):
        targets = hx_targets()
        assert len(targets) >= 20
        assert sum(1 for m, _, _ in targets if m in {"POST", "DELETE"}) >= 6

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
