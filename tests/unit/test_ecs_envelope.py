"""Phase 826 — the proxy's ECS envelope must survive the trip to the analytics node.

WHY THIS EXISTS
---------------
The Go proxy and the Python analytics node were written against each other and
never actually connected. A blocking-read bug meant the consumer had never read
a single event, so two further mismatches sat undetected behind it:

  * the proxy writes ONE field containing an ECS JSON document, while the
    consumer expected flat `timestamp`/`src_ip`/`score`/`ja4`/`proxy_id`;
  * the consumer required an HMAC the proxy never applied — 7,749 consecutive
    events rejected once the read was fixed.

The signature covers the RAW envelope bytes rather than a re-encoded object,
specifically so verification does not depend on Go's and Python's JSON encoders
agreeing on key order, float formatting and unicode escaping. The golden-vector
test below is the load-bearing one: it pins the exact digest a Go
`hmac.New(sha256.New, secret); m.Write(event)` produces, so a future "tidy-up"
that reintroduces canonicalisation on either side fails here rather than in
production as a silent 100% rejection rate.
"""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from src.analytics.ecs_envelope import (
    VALID_ACTIONS,
    is_ecs_envelope,
    normalise,
    verify_envelope_signature,
)

# A real entry read from events:connection on 2026-08-17, verbatim.
REAL_ENVELOPE = (
    '{"@timestamp":"2026-08-17T17:45:25.298824415Z","destination.ip":"backend",'
    '"destination.port":443,"event.action":"allow","event.risk_score":35,'
    '"ja4proxy.dial_setting":75,'
    '"ja4proxy.fingerprint.ja4":"t13d1212h2_eac1b15b5477_8e6e362c5eac",'
    '"ja4proxy.node_id":"ja4proxy-lane23-proxy-1","ja4proxy.sni":"backend",'
    '"network.protocol":"tls","network.transport":"tcp",'
    '"service.name":"ja4proxy","source.ip":"172.25.0.4","source.port":55558}'
)
SECRET = "phase-826-test-secret"


def signed(raw: str = REAL_ENVELOPE, secret: str = SECRET) -> dict:
    return {
        "event": raw,
        "hmac": hmac.new(secret.encode(), raw.encode(), hashlib.sha256).hexdigest(),
    }


class TestSignature:
    def test_golden_vector_matches_the_go_construction(self):
        """Pin the digest. Go writes HMAC-SHA256 over the event bytes, hex-encoded.

        If this ever fails, the two languages have stopped computing the same
        thing and EVERY event will be rejected in production.
        """
        expected = hmac.new(
            SECRET.encode(), REAL_ENVELOPE.encode(), hashlib.sha256
        ).hexdigest()
        assert len(expected) == 64, "hex sha256 digest"
        assert verify_envelope_signature(
            {"event": REAL_ENVELOPE, "hmac": expected}, SECRET
        )

    def test_signature_covers_raw_bytes_not_a_reencoded_object(self):
        """Re-serialising the parsed object must NOT produce a valid signature.

        This is the whole reason the scheme signs wire bytes. Python's
        json.dumps reorders and respaces relative to Go's encoder; if that
        round-trip happened to verify, the test above would be passing for the
        wrong reason.
        """
        reencoded = json.dumps(json.loads(REAL_ENVELOPE))
        assert reencoded != REAL_ENVELOPE, "fixture no longer exercises the risk"
        bad = hmac.new(SECRET.encode(), reencoded.encode(), hashlib.sha256).hexdigest()
        assert not verify_envelope_signature({"event": REAL_ENVELOPE, "hmac": bad}, SECRET)

    def test_wrong_secret_rejected(self):
        assert not verify_envelope_signature(signed(), "not-the-secret")

    def test_tampered_payload_rejected(self):
        entry = signed()
        entry["event"] = entry["event"].replace('"allow"', '"block"')
        assert not verify_envelope_signature(entry, SECRET)

    def test_missing_signature_rejected(self):
        assert not verify_envelope_signature({"event": REAL_ENVELOPE}, SECRET)

    def test_empty_signature_rejected(self):
        assert not verify_envelope_signature({"event": REAL_ENVELOPE, "hmac": ""}, SECRET)


class TestDetection:
    def test_ecs_envelope_detected(self):
        assert is_ecs_envelope(signed())

    def test_flat_legacy_event_not_treated_as_envelope(self):
        """The legacy flat schema must keep its original code path."""
        assert not is_ecs_envelope(
            {"timestamp": 1, "src_ip": "1.2.3.4", "action": "allow"}
        )


class TestNormalisation:
    @pytest.fixture
    def out(self):
        return normalise(signed())

    def test_maps_every_field_the_consumer_schema_requires(self, out):
        # These six are EVENT_SCHEMA's `required` list. Missing any one of them
        # rejects the event.
        for field in ("timestamp", "src_ip", "ja4", "action", "score", "proxy_id"):
            assert field in out, f"{field} not mapped from ECS"

    def test_timestamp_becomes_epoch_seconds(self, out):
        # Go emits RFC3339Nano — 9 fractional digits, which datetime.fromisoformat
        # rejects outright.
        assert isinstance(out["timestamp"], float)
        assert 1_700_000_000 < out["timestamp"] < 2_000_000_000

    def test_proxy_id_prefers_node_id_over_service_name(self, out):
        """service.name is the constant "ja4proxy" — it cannot distinguish nodes."""
        assert out["proxy_id"] == "ja4proxy-lane23-proxy-1"

    def test_falls_back_to_service_name_when_node_id_absent(self):
        raw = json.dumps({"service.name": "ja4proxy", "source.ip": "1.2.3.4"})
        assert normalise({"event": raw})["proxy_id"] == "ja4proxy"

    def test_original_ecs_keys_are_retained(self, out):
        """Detectors may read fields this mapping does not rename."""
        assert out["ja4proxy.sni"] == "backend"
        assert out["network.transport"] == "tcp"

    def test_signature_carried_through(self, out):
        assert out["hmac"] == signed()["hmac"]

    @pytest.mark.parametrize("bad", ["not json", "", "[1,2,3]", "null"])
    def test_unparseable_envelope_raises_valueerror(self, bad):
        """Must raise, not crash the consumer loop — caller treats it as invalid."""
        with pytest.raises(ValueError):
            normalise({"event": bad})

    def test_timestamp_without_fractional_seconds(self):
        raw = json.dumps({"@timestamp": "2026-08-17T17:45:25Z"})
        assert normalise({"event": raw})["timestamp"] == pytest.approx(1786988725.0)


class TestActionSet:
    @pytest.mark.parametrize("action", ["flag", "rate_limit", "ban"])
    def test_proxy_only_actions_are_accepted(self, action):
        """These three were missing, so the proxy's real actions were rejected.

        rate_limit especially: it is the only non-allow action a monitor-mode
        deployment produces in volume, so the events most worth analysing were
        exactly the ones discarded.
        """
        assert action in VALID_ACTIONS

    def test_schema_and_validator_agree_on_the_action_set(self):
        """Two copies of this list exist; drift silently rejects valid events."""
        from src.analytics.event_schemas import EVENT_SCHEMA

        assert set(EVENT_SCHEMA["properties"]["action"]["enum"]) == set(VALID_ACTIONS)
