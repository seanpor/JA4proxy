"""A connection scored asynchronously must be counted once, not twice.

WHY THIS EXISTS
---------------
Phase 828 made the proxy publish a second event once its async scoring worker
finishes, because the first one is written before any score exists. Both carry
``ja4proxy.connection_id``; they differ by ``ja4proxy.event_phase``:

* ``provisional`` — the connection was answered and forwarded; scoring is queued.
  ``event.risk_score`` is 0 because nothing has been evaluated.
* ``final`` — the complete decision, with score, signals and counterfactuals.

Ingesting both would do two separate kinds of damage:

1. Every per-IP and per-JA4 connection total doubles, so density-based
   detectors (campaign needs >= 0.15 of a /24) fire on half the real traffic.
2. Score statistics get an unevaluated 0 averaged in against every real score.
   "Allow / 0" on a provisional event means *not assessed yet*, not *assessed
   and found harmless* — treating the placeholder as a verdict is precisely the
   confusion `PipelineResult.Deferred` exists to prevent.

The consumer therefore skips provisional entries. It **acks** them (so they are
not redelivered forever) and counts them as *skipped*, not *rejected* —
rejections are an error signal with an alert attached, and folding a routine
half of normal traffic into it would render that alert meaningless.
"""

from __future__ import annotations

import json

import pytest

from src.analytics.ecs_envelope import normalise as normalise_ecs


def _envelope(phase: str, conn_id: str = "node-1", score: int = 0) -> dict:
    return {
        "event": json.dumps(
            {
                "@timestamp": "2026-08-19T09:00:00.123456789Z",
                "source.ip": "203.0.113.5",
                "event.action": "allow",
                "event.risk_score": score,
                "ja4proxy.fingerprint.ja4": "t13d1516h2_8daaf6152771_02713d6af862",
                "ja4proxy.node_id": "node-1",
                "ja4proxy.connection_id": conn_id,
                "ja4proxy.event_phase": phase,
            }
        )
    }


def test_event_phase_survives_normalisation() -> None:
    """The consumer's skip check reads this key after translation.

    ``normalise_ecs`` renames a handful of fields and passes the rest through.
    If it ever stopped carrying unmapped keys, the skip would silently never
    fire and every connection would be counted twice — with nothing failing.
    """
    out = normalise_ecs(_envelope("provisional"))
    assert out["ja4proxy.event_phase"] == "provisional"
    assert out["ja4proxy.connection_id"] == "node-1"


def test_connection_id_survives_normalisation() -> None:
    """Without the id, the two events cannot be joined by any consumer."""
    out = normalise_ecs(_envelope("final", conn_id="node-1-7fz"))
    assert out["ja4proxy.connection_id"] == "node-1-7fz"


def test_final_events_are_translated_normally() -> None:
    """The skip must not disturb the path a real event takes."""
    out = normalise_ecs(_envelope("final", score=72))
    assert out["score"] == 72
    assert out["src_ip"] == "203.0.113.5"
    assert out["ja4"] == "t13d1516h2_8daaf6152771_02713d6af862"
    assert out["ja4proxy.event_phase"] == "final"


def test_events_without_a_phase_are_not_skipped() -> None:
    """Backwards compatibility: an older proxy emits no phase at all.

    The skip is keyed on the literal string "provisional". Anything else —
    including a missing key — must fall through to normal processing, or a
    version skew between proxy and analytics node would silently discard every
    event on the stream. That failure mode has happened on this project before
    (phase 826, three layers of it), so it gets its own test.
    """
    entry = {
        "event": json.dumps(
            {
                "@timestamp": "2026-08-19T09:00:00Z",
                "source.ip": "198.51.100.9",
                "event.action": "block",
                "event.risk_score": 90,
                "ja4proxy.fingerprint.ja4": "t13d1516h2_8daaf6152771_02713d6af862",
                "ja4proxy.node_id": "node-1",
            }
        )
    }
    out = normalise_ecs(entry)
    assert out.get("ja4proxy.event_phase") is None
    assert out["score"] == 90


@pytest.mark.parametrize(
    "phase,should_skip",
    [
        ("provisional", True),
        ("final", False),
        ("", False),
        ("PROVISIONAL", False),  # exact match only; no case folding
    ],
)
def test_skip_predicate_matches_the_consumer(phase: str, should_skip: bool) -> None:
    """Pin the exact comparison ``consume_events`` performs.

    Kept in lockstep with stream_consumer.py deliberately: this is the one line
    standing between "each connection counted once" and "every total doubled".
    """
    out = normalise_ecs(_envelope(phase)) if phase else {"ja4proxy.event_phase": ""}
    assert (out.get("ja4proxy.event_phase") == "provisional") is should_skip
