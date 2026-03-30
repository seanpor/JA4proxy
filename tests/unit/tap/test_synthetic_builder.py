"""
Unit tests for SyntheticPacketBuilder (Phase 20, Group 13).
"""
import pytest

from src.tap.capture import ParsedPacket
from src.tap.fingerprints.ja4 import extract_ja4
from tests.tap.conftest import SyntheticPacketBuilder


class TestSyntheticBuilder:
    def test_syn_synack_ack_sequence_valid(self):
        pkts = (
            SyntheticPacketBuilder()
            .syn("1.2.3.4", 54321, "5.6.7.8", 443)
            .synack()
            .ack()
            .build()
        )
        assert len(pkts) == 3
        # SYN
        assert pkts[0].flags & 0x002  # SYN set
        assert not (pkts[0].flags & 0x010)  # ACK not set
        assert pkts[0].src_ip == "1.2.3.4"
        assert pkts[0].dst_port == 443
        # SYN-ACK
        assert pkts[1].flags & 0x002  # SYN
        assert pkts[1].flags & 0x010  # ACK
        assert pkts[1].src_ip == "5.6.7.8"  # reversed
        # ACK
        assert pkts[2].flags == 0x010  # only ACK

    def test_tls_client_hello_parseable_by_extractor(self):
        pkts = (
            SyntheticPacketBuilder()
            .syn("1.2.3.4", 54321, "5.6.7.8", 443)
            .synack()
            .ack()
            .tls_client_hello(
                ciphers=[0x1301, 0x1302, 0x1303],
                extensions=[0, 11, 10, 16, 22, 23, 13, 43, 45, 51, 21],
                sni="example.com",
                grease=True,
            )
            .build()
        )
        # Find the data packet
        data_pkts = [p for p in pkts if p.data]
        assert len(data_pkts) == 1

        # Extract JA4 from the data
        result = extract_ja4(data_pkts[0].data)
        assert result is not None, "JA4 extractor must parse the synthetic ClientHello"
        assert result.fingerprint.startswith("t")
        # GREASE should be filtered from the fingerprint
        assert "0a0a" not in result.fingerprint.lower()

    def test_rst_produces_rst_flag_set(self):
        pkts = (
            SyntheticPacketBuilder()
            .syn("1.2.3.4", 12345, "5.6.7.8", 80)
            .synack()
            .ack()
            .rst()
            .build()
        )
        rst_pkts = [p for p in pkts if p.flags & 0x004]
        assert len(rst_pkts) == 1
        assert rst_pkts[0].flags & 0x004  # RST set

    def test_fin_produces_fin_flag_set(self):
        pkts = (
            SyntheticPacketBuilder()
            .syn("1.2.3.4", 12345, "5.6.7.8", 443)
            .synack()
            .ack()
            .tls_client_hello()
            .fin()
            .build()
        )
        fin_pkts = [p for p in pkts if p.flags & 0x001]
        assert len(fin_pkts) == 1

    def test_http_request_data_in_packet(self):
        pkts = (
            SyntheticPacketBuilder()
            .syn("1.2.3.4", 12345, "5.6.7.8", 80)
            .synack()
            .ack()
            .http_request("GET", "/", headers={"Host": "example.com"})
            .build()
        )
        data_pkts = [p for p in pkts if p.data]
        assert len(data_pkts) == 1
        assert b"GET / HTTP/1.1" in data_pkts[0].data
        assert b"Host: example.com" in data_pkts[0].data

    def test_syn_tcp_options_present(self):
        pkts = (
            SyntheticPacketBuilder()
            .syn("1.2.3.4", 12345, "5.6.7.8", 443, mss=1400, wscale=6)
            .build()
        )
        syn = pkts[0]
        assert len(syn.tcp_options_raw) > 0
        # MSS option (kind=2) should be present
        assert b"\x02\x04" in syn.tcp_options_raw

    def test_server_hello_data_parseable(self):
        pkts = (
            SyntheticPacketBuilder()
            .syn("1.2.3.4", 54321, "5.6.7.8", 443)
            .synack()
            .ack()
            .tls_client_hello()
            .tls_server_hello(cipher=0x1301, extensions=[43, 51])
            .build()
        )
        server_pkts = [p for p in pkts if p.src_ip == "5.6.7.8" and p.data]
        assert len(server_pkts) >= 1
        server_data = server_pkts[0].data
        # Should start with TLS record header
        assert server_data[0] == 0x16  # ContentType.handshake

    def test_no_grease_in_fingerprint_when_disabled(self):
        pkts = (
            SyntheticPacketBuilder()
            .syn("1.2.3.4", 54321, "5.6.7.8", 443)
            .synack()
            .ack()
            .tls_client_hello(grease=False)
            .build()
        )
        data_pkts = [p for p in pkts if p.data]
        result = extract_ja4(data_pkts[0].data)
        assert result is not None
        assert len(result.grease_values) == 0
