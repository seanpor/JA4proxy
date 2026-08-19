"""Phase 828b, outcome O5 — the feed row must not throw away the decision.

Each connection event carries roughly twenty fields. The live feed rendered
five: time, IP, JA4, action, score.

The costliest omission was ``ja4proxy.bypass_reason``. A connection blocked by
an explicit list entry and one blocked by its risk score both rendered as
"block / 100" — identical rows, despite calling for opposite responses. If a
list entry did it, the interesting question is who added that entry and when. If
a score did it, the question is which signals fired. An operator could not tell
which question to ask.

Country and ASN organisation were likewise resolved on every connection and
discarded before display, so the feed could not tell Vodafone Ireland from a
host on the other side of the world — the exact question an operator asks first.
"""

from __future__ import annotations

import json

from management.api.routes.events import _build_row


def _event(**over) -> dict:
    base = {
        "@timestamp": "2026-08-19T09:15:00.123456789Z",
        "source.ip": "213.233.128.1",
        "ja4proxy.fingerprint.ja4": "t13d1516h2_8daaf6152771_02713d6af862",
        "event.action": "block",
        "event.risk_score": 100,
        "ja4proxy.bypass_reason": "",
        "client.geo.country_iso": "IE",
        "client.as.organization.name": "Vodafone Ireland Limited",
    }
    base.update(over)
    return base


def test_row_shows_country_and_asn_org() -> None:
    row = _build_row(_event(), "1787000000000-0")
    assert "IE" in row
    assert "Vodafone Ireland Limited" in row


def test_row_shows_bypass_reason() -> None:
    row = _build_row(_event(**{"ja4proxy.bypass_reason": "ja4_blacklist"}), "1-0")
    assert "ja4_blacklist" in row


def test_blocked_by_list_differs_from_blocked_by_score() -> None:
    """The finding, restated as an assertion.

    Both rows say "block". Only one of them was a decision the scorer made. If
    these render identically the operator has no way to know which question to
    ask, which is the state this phase exists to end.
    """
    by_list = _build_row(_event(**{"ja4proxy.bypass_reason": "ja4_blacklist"}), "1-0")
    by_score = _build_row(_event(**{"ja4proxy.bypass_reason": ""}), "1-0")

    assert by_list != by_score
    assert "ja4_blacklist" in by_list
    assert "ja4_blacklist" not in by_score


def test_missing_origin_does_not_render_the_word_none() -> None:
    """An event with no geo must degrade to a dash, not to Python's None."""
    row = _build_row(
        _event(**{"client.geo.country_iso": "", "client.as.organization.name": ""}),
        "1-0",
    )
    assert "None" not in row


def test_row_escapes_hostile_field_values() -> None:
    """Event fields originate from the network. They are not markup.

    ASN organisation strings come from a MaxMind database and SNI-adjacent
    values ultimately from the client, so a row builder that interpolates them
    raw is an XSS sink aimed straight at the operator console.
    """
    row = _build_row(
        _event(**{"client.as.organization.name": '<script>alert("x")</script>'}),
        "1-0",
    )
    assert "<script>" not in row
    assert "&lt;script&gt;" in row


def test_row_still_has_its_original_columns() -> None:
    """Adding columns must not cost the ones that already worked."""
    row = _build_row(_event(), "1-0")
    for want in ("213.233.128.1", "t13d1516h2_8daaf6152771_02713d6af862", "block", "100"):
        assert want in row, f"row lost {want!r}"


def test_column_count_matches_the_header() -> None:
    """A row with more cells than the header silently corrupts the table.

    Counted here rather than eyeballed: the header lives in a Jinja template and
    the row in Python, so nothing else connects the two.
    """
    from pathlib import Path

    tpl = (
        Path(__file__).resolve().parents[1] / "templates" / "partials" / "live_feed.html"
    ).read_text(encoding="utf-8")
    header_cells = tpl.count("<th ") + tpl.count("<th>")

    row = _build_row(_event(), "1-0")
    row_cells = row.count("<td")

    assert row_cells == header_cells, (
        f"row renders {row_cells} cells, header declares {header_cells}"
    )


def test_json_round_trip_of_a_real_event() -> None:
    """Guard the exact ECS key names the Go proxy emits.

    A rename on either side would silently blank a column rather than fail.
    """
    raw = json.dumps(_event(**{"ja4proxy.bypass_reason": "blocklist"}))
    row = _build_row(json.loads(raw), "1-0")
    assert "blocklist" in row and "IE" in row
