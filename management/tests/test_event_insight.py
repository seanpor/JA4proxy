"""Phase 828b/c/d — outcomes O2, O5, O6, O7, O8, O9, O10.

The console had every fact tested here sitting in the event stream and displayed
none of them. These tests pin the interpretation layer that surfaces them, and
in particular the two places where getting it wrong would manufacture false
positives:

* a CGNAT address must never read as a single automated client (O7), and
* nothing here may ever recommend banning a shared egress (O10).

`CLAUDE.md`'s core asymmetry — a blocked real user costs far more than a missed
bot — makes those two the load-bearing assertions in this file.
"""

from __future__ import annotations

import pytest

from management.api.event_insight import (
    GEO_LOOKUP_FAILED,
    GEO_NOT_ROUTABLE,
    GEO_RESOLVED,
    GEO_UNALLOCATED,
    SHAPE_MIXED,
    SHAPE_SHARED_EGRESS,
    SHAPE_SINGLE_CLIENT,
    crosstab,
    extract_explanation,
    geo_status,
    is_provisional,
    shape_verdict,
    suggest_action,
)


# ── O2: the explanation reaches the API verbatim ──────────────────────────────


def test_signals_round_trip_with_their_reasons() -> None:
    """The reason string is the whole point; names and scores alone explain nothing."""
    ev = {
        "ja4proxy.signals": [
            {"name": "ja4_tls_mismatch", "score": 35, "weight": 1.0,
             "reason": 'JA4 prefix "t13" claims TLS 0x0304; negotiated 0x0303'},
            {"name": "asn_datacenter", "score": 25, "weight": 0.8,
             "reason": "AS16509 is a hosting provider"},
        ],
        "ja4proxy.counterfactuals": {"25": "allow", "100": "rate_limit"},
    }

    out = extract_explanation(ev)

    assert out is not None
    assert out["signals"][0]["reason"] == (
        'JA4 prefix "t13" claims TLS 0x0304; negotiated 0x0303'
    )
    assert out["counterfactuals"]["100"] == "rate_limit"


def test_signals_ordered_by_absolute_contribution() -> None:
    """A -40 signal outranks a +5 one.

    Something actively vouching for a connection is as interesting to an
    operator as something arguing against it. Ordering by raw score would push
    every negative signal to the bottom of the panel — hiding the evidence for
    allowing while showing the evidence against.
    """
    ev = {"ja4proxy.signals": [
        {"name": "small", "score": 5, "reason": "a"},
        {"name": "vouching", "score": -40, "reason": "b"},
        {"name": "medium", "score": 20, "reason": "c"},
    ]}

    names = [s["name"] for s in extract_explanation(ev)["signals"]]

    assert names == ["vouching", "medium", "small"]


def test_missing_signals_degrades_to_none_not_empty() -> None:
    """An event from a pre-828a proxy has no explanation to give.

    None must mean "not available", which the UI renders as such. Returning an
    empty signal list instead would render as "no signals fired" — a claim about
    the traffic that nobody made.
    """
    assert extract_explanation({"event.risk_score": 35}) is None


# ── O5: provisional entries are not counted ───────────────────────────────────


@pytest.mark.parametrize(
    "phase,expected",
    [("provisional", True), ("final", False), ("", False), (None, False)],
)
def test_is_provisional(phase, expected) -> None:
    ev = {} if phase is None else {"ja4proxy.event_phase": phase}
    assert is_provisional(ev) is expected


def test_absent_phase_is_not_provisional() -> None:
    """Version skew must not silently discard the entire stream.

    An older proxy emits no phase at all. If that were treated as provisional,
    a management API newer than its proxy would show an empty console with
    nothing failing — a failure mode this project has already shipped three
    times in one phase (826).
    """
    assert is_provisional({"event.risk_score": 90, "event.action": "block"}) is False


# ── O6/O7/O8: the (ip, ja4) cross-tab and the shape it implies ────────────────


def test_crosstab_counts_pairs() -> None:
    events = (
        [{"ja4proxy.fingerprint.ja4": "aaa", "event.action": "allow",
          "@timestamp": "2026-08-19T09:00:00Z"}] * 3
        + [{"ja4proxy.fingerprint.ja4": "bbb", "event.action": "block",
            "@timestamp": "2026-08-19T10:00:00Z"}] * 7
    )

    out = crosstab(events)

    assert out["aaa"]["count"] == 3
    assert out["bbb"]["count"] == 7
    assert out["bbb"]["actions"] == {"block": 7}


def test_cgnat_pattern_is_shared_egress() -> None:
    """25 fingerprints x 3 events on one address — the Irish mobile CGNAT case.

    This is the single most important assertion in the file. Reading this
    address as one automated client is how a console talks an operator into
    banning several hundred real subscribers with one click.
    """
    counts = {f"ja4-{i}": 3 for i in range(25)}

    verdict = shape_verdict(counts)

    assert verdict["shape"] == SHAPE_SHARED_EGRESS
    assert verdict["distinct_fingerprints"] == 25


def test_scanner_pattern_is_single_client() -> None:
    """1 fingerprint x 400 events — an automated client, and it should say so.

    The counterpart to the CGNAT test: a classifier that called everything
    shared-egress would pass that one and be useless.
    """
    verdict = shape_verdict({"ja4-scan": 400})

    assert verdict["shape"] == SHAPE_SINGLE_CLIENT
    assert verdict["top_share"] == 1.0


def test_ambiguous_pattern_is_mixed() -> None:
    """Neither shape must be claimed on thin evidence."""
    assert shape_verdict({"a": 10, "b": 8, "c": 6})["shape"] == SHAPE_MIXED


def test_empty_address_does_not_crash() -> None:
    assert shape_verdict({})["shape"] == SHAPE_MIXED


def test_shape_verdict_carries_no_action() -> None:
    """A description of a distribution, never a recommendation.

    If a shape verdict ever grows an `action` field it becomes a block button
    with statistics attached, and the CGNAT case turns into an outage.
    """
    for counts in ({"a": 400}, {f"j{i}": 3 for i in range(25)}, {"a": 5, "b": 4}):
        verdict = shape_verdict(counts)
        assert "action" not in verdict
        assert "recommendation" not in verdict


# ── O9: "Unknown" is three different situations ───────────────────────────────


def test_rfc1918_is_not_routable() -> None:
    """A private address has no owner. That is an answer, not a failure."""
    assert geo_status("192.168.1.10")["status"] == GEO_NOT_ROUTABLE


def test_cgnat_range_is_not_routable() -> None:
    """100.64.0.0/10 is carrier-internal — the address Irish mobile users sit behind."""
    assert geo_status("100.64.3.9")["status"] == GEO_NOT_ROUTABLE


def test_missing_database_is_lookup_failed() -> None:
    """A public address with nothing resolved anywhere means we failed to look."""
    out = geo_status("8.8.8.8", db_appears_present=False)
    assert out["status"] == GEO_LOOKUP_FAILED
    assert "runbook" in out["explanation"] or "geoip" in out["explanation"].lower()


def test_public_ip_with_working_db_is_unallocated() -> None:
    """A genuinely routable address that resolved to nothing.

    Note 203.0.113.0/24 is NOT suitable here: it is TEST-NET-3 documentation
    space, which `ipaddress.is_global` correctly reports as non-routable. That
    is the right answer for it — reserved ranges have no owner either — so this
    needs an address that really is on the internet.
    """
    assert geo_status("1.2.3.4", db_appears_present=True)["status"] == GEO_UNALLOCATED


def test_resolved_geo_is_resolved() -> None:
    out = geo_status("213.233.128.1", country="IE", asn=15502,
                     asn_org="Vodafone Ireland Limited")
    assert out["status"] == GEO_RESOLVED
    assert out["asn_org"] == "Vodafone Ireland Limited"


def test_the_four_statuses_are_all_distinct() -> None:
    """Vacuity guard.

    Every test above asserts one status. If a refactor collapsed them back to a
    single "unknown" string, most of those assertions could still be made to
    pass one at a time — which is exactly the bug being fixed, reintroduced.
    """
    statuses = {
        geo_status("192.168.1.1")["status"],
        geo_status("8.8.8.8", db_appears_present=False)["status"],
        geo_status("1.2.3.4", db_appears_present=True)["status"],
        geo_status("1.1.1.1", country="AU")["status"],
    }
    assert len(statuses) == 4, f"statuses collapsed: {statuses}"


# ── O10: suggestions, and what being wrong would cost ─────────────────────────


def test_no_ban_suggestion_for_a_shared_egress() -> None:
    """The core asymmetry, as an assertion.

    A CGNAT address whose traffic is overwhelmingly blocked is still a CGNAT
    address. Every signal here points at "ban", and the answer must still be no.
    """
    shape = shape_verdict({f"ja4-{i}": 3 for i in range(25)})

    out = suggest_action(shape=shape, action_counts={"block": 74, "allow": 1})

    assert out["suggestion"] == "do-not-ban"
    assert "shared egress" in out["rationale"]


def test_ban_suggestion_states_blast_radius() -> None:
    shape = shape_verdict({"ja4-scan": 400})

    out = suggest_action(shape=shape, action_counts={"block": 400})

    assert out["suggestion"] == "consider-ban"
    assert "1 distinct" in out["blast_radius"]


def test_every_suggestion_states_blast_radius() -> None:
    """No suggestion may be offered without the cost of acting on it."""
    cases = [
        (shape_verdict({"a": 400}), {"block": 400}),
        (shape_verdict({f"j{i}": 3 for i in range(25)}), {"block": 74}),
        (shape_verdict({"a": 5, "b": 4}), {"allow": 9}),
        (shape_verdict({}), {}),
    ]
    for shape, actions in cases:
        out = suggest_action(shape=shape, action_counts=actions)
        assert out["blast_radius"], f"no blast radius for {shape['shape']}"
        assert out["rationale"]


def test_low_block_rate_single_client_is_only_watched() -> None:
    """One fingerprint is not on its own a reason to ban anything."""
    shape = shape_verdict({"ja4-one": 400})
    out = suggest_action(shape=shape, action_counts={"allow": 390, "block": 10})
    assert out["suggestion"] == "watch"


def test_already_banned_suggests_nothing() -> None:
    shape = shape_verdict({"ja4-scan": 400})
    out = suggest_action(shape=shape, action_counts={"block": 400}, is_banned=True)
    assert out["suggestion"] == "none"


def test_bypassed_connection_explains_itself_via_the_rule() -> None:
    """A blacklisted fingerprint is the most likely thing an operator clicks.

    It has no signals because the scorer never ran, and returning None for it
    sent the page down its "no explanation recorded — the events predate the
    proxy version that records one" path. That is wrong twice over: the events
    are current, and the reason was in them the whole time.
    """
    out = extract_explanation(
        {"ja4proxy.bypass_reason": "ja4_blacklist", "event.action": "block"}
    )

    assert out is not None, "a bypass reason IS an explanation"
    assert out["bypass_reason"] == "ja4_blacklist"
    assert out["signals"] == [], "no signals ran, and that is the honest answer"


def test_no_bypass_and_no_signals_is_still_unavailable() -> None:
    """The genuinely-empty case must stay distinguishable from a bypass."""
    assert extract_explanation({"event.risk_score": 35, "ja4proxy.bypass_reason": ""}) is None
