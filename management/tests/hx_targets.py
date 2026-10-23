"""Shared hx-* target extractor for the console UI.

Phase 824c: templates reference hx-get/hx-post/hx-delete, but the old regex
in test_ui_regression._hx_urls() dropped any URL containing ``{`` or ``}`` —
so ``attack-top{% if ... %}...{% endif %}`` and
``attack-fingerprint-table{% if ... %}...{% endif %}`` were invisible to
Tier 1. The normaliser here strips Jinja tags/expressions so the registration
gate and Tier 1 see the same, complete set.
"""

from __future__ import annotations

import re
from pathlib import Path

TEMPLATES = Path(__file__).resolve().parents[1] / "templates"

ATTR = re.compile(r"""hx-(get|post|put|patch|delete)=["']([^"']*)["']""", re.IGNORECASE)
JINJA_TAG = re.compile(r"\{%.*?%\}", re.S)
JINJA_EXPR = re.compile(r"\{\{.*?\}\}", re.S)


def hx_targets() -> list[tuple[str, str, str]]:
    """(method, request_url, path) for every hx-* target in the templates.

    - Jinja tags ``{% ... %}`` are stripped (keeping their bodies when present).
    - Jinja expressions ``{{ ... }}`` are replaced with ``sample``.
    - ``request_url`` keeps the query string; ``path`` drops it (first ``?``).
    - Only URLs starting with ``/`` are returned.
    """
    out: list[tuple[str, str, str]] = []
    for tpl in sorted(TEMPLATES.rglob("*.html")):
        text = tpl.read_text(encoding="utf-8")
        for m in ATTR.finditer(text):
            method = m.group(1).upper()
            raw = m.group(2).strip()
            url = JINJA_TAG.sub("", raw)
            url = JINJA_EXPR.sub("sample", url)
            if "{" in url or "}" in url:
                raise RuntimeError(
                    f"hx target in {tpl} still contains braces after normalisation: {url!r}"
                )
            if not url.startswith("/"):
                continue
            path = url.split("?", 1)[0]
            out.append((method, url, path))
    return out
