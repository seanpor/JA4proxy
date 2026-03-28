"""
Unit tests for src/tap/fingerprints/correlation.py (Phase 20 Group 5-L).
"""
import uuid
from datetime import datetime, timezone

import pytest

from src.tap.fingerprints.correlation import ConnectionFingerprints
from src.tap.fingerprints.tls_ext_values import JA4TLSExtValues


def _make_fp(**kwargs) -> ConnectionFingerprints:
    defaults = {
        "conn_id": str(uuid.uuid4()),
        "timestamp": datetime.now(tz=timezone.utc),
        "client_ip": "1.2.3.4",
        "server_ip": "5.6.7.8",
        "server_port": 443,
    }
    defaults.update(kwargs)
    return ConnectionFingerprints(**defaults)


class TestConnectionFingerprints:
    def test_to_redis_dict_serialises_all_fields(self):
        fp = _make_fp(
            ja4="t13d1516h2_aabbccddeeff_001122334455",
            ja4t="65535_1460_MSTNW_7",
            risk_score=42,
            action="flag",
        )
        d = fp.to_redis_dict()
        assert d["conn_id"] == fp.conn_id
        assert d["client_ip"] == "1.2.3.4"
        assert d["server_port"] == "443"
        assert d["ja4"] == fp.ja4
        assert d["ja4t"] == fp.ja4t
        assert d["risk_score"] == "42"
        assert d["action"] == "flag"

    def test_from_redis_dict_round_trips_correctly(self):
        fp = _make_fp(
            ja4="t13d1516h2_aabbccddeeff_001122334455",
            risk_score=75,
            action="signal_block",
            signals=[{"name": "scanner_tool", "score": 20}],
        )
        d = fp.to_redis_dict()
        fp2 = ConnectionFingerprints.from_redis_dict(d)
        assert fp2.conn_id == fp.conn_id
        assert fp2.ja4 == fp.ja4
        assert fp2.risk_score == 75
        assert fp2.action == "signal_block"
        assert len(fp2.signals) == 1
        assert fp2.signals[0]["name"] == "scanner_tool"

    def test_none_fields_omitted_from_redis_dict(self):
        fp = _make_fp(ja4=None, ja4s=None)
        d = fp.to_redis_dict()
        assert "ja4" not in d
        assert "ja4s" not in d

    def test_conn_id_is_uuid_format(self):
        fp = _make_fp()
        # UUID4 format: 8-4-4-4-12 hex chars
        try:
            parsed = uuid.UUID(fp.conn_id)
            assert str(parsed) == fp.conn_id
        except ValueError:
            pytest.fail(f"conn_id is not a valid UUID: {fp.conn_id}")

    def test_tls_ext_values_round_trips(self):
        ext = JA4TLSExtValues(
            supported_groups=[0x1D, 0x17],
            key_share_groups=[0x1D],
            sig_algs=[0x0403, 0x0804],
            psk_modes=[1],
            grease_values=[0x0A0A],
            has_compress_cert=True,
            has_alps=True,
            padding_len=16,
            session_ticket_len=0,
        )
        fp = _make_fp(tls_ext_values=ext)
        d = fp.to_redis_dict()
        assert "tls_ext_values" in d
        fp2 = ConnectionFingerprints.from_redis_dict(d)
        assert fp2.tls_ext_values is not None
        assert fp2.tls_ext_values.has_compress_cert is True
        assert fp2.tls_ext_values.supported_groups == [0x1D, 0x17]

    def test_timestamp_preserved_across_round_trip(self):
        ts = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        fp = _make_fp(timestamp=ts)
        d = fp.to_redis_dict()
        fp2 = ConnectionFingerprints.from_redis_dict(d)
        assert fp2.timestamp == ts

    def test_server_port_preserved(self):
        fp = _make_fp(server_port=8443)
        d = fp.to_redis_dict()
        fp2 = ConnectionFingerprints.from_redis_dict(d)
        assert fp2.server_port == 8443
