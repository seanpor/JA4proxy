"""
TAP pipeline — fingerprint extraction + risk scoring integration (Phase 20, Group 6).

Classes:
    FingerprintExtractor  — coordinates all extractors; called by StreamReassembler
    TapPipeline           — converts fingerprints to RiskSignals, scores, signals Redis
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any, Optional

from src.tap.fingerprint_store import FingerprintStore
from src.tap.fingerprints.correlation import ConnectionFingerprints
from src.tap.fingerprints.h2_fingerprint import H2Signature, extract_h2_fingerprint
from src.tap.fingerprints.ja4 import extract_ja4
from src.tap.fingerprints.ja4h import extract_ja4h
from src.tap.fingerprints.ja4l import extract_ja4l
from src.tap.fingerprints.ja4s import extract_ja4s
from src.tap.fingerprints.ja4ssh import extract_ja4ssh
from src.tap.fingerprints.ja4t import extract_ja4t_from_syn
from src.tap.fingerprints.ja4x import extract_ja4x
from src.tap.fingerprints.os_fingerprint import OSSignature, match_os
from src.tap.fingerprints.tls_ext_values import extract_tls_ext_values

if TYPE_CHECKING:
    from src.tap.reassembler import TCPStream

logger = logging.getLogger(__name__)

# TAP-mode score → action mapping (PHASE_20.md §9.1)
_SCORE_ACTIONS = [
    (85, "signal_ban"),
    (70, "signal_block"),
    (55, "signal_slow"),
    (35, "flag"),
    (20, "flag"),
    (0, "observe"),
]

# Known scanner JA4 prefixes (fingerprint starts with these)
_SCANNER_JA4_PREFIXES = frozenset(
    [
        "t00",  # non-TLS scanner / raw TCP probe
        "t10",  # TLS 1.0 scanner
        "t11",  # TLS 1.1 scanner
    ]
)

# Known attack-tool SSH kexinit patterns (substring match on sorted kex string)
_ATTACK_TOOL_KEX = frozenset(
    [
        "diffie-hellman-group1-sha1",  # very old / attack tools
        "ecdh-sha2-1.3.132.0.10",  # unusual curve — attack tool indicator
    ]
)

# 7-day TTL for connection records (seconds)
_FP_CONN_TTL = 7 * 86400
# 30-day TTL for per-IP and JA4 records
_FP_IP_TTL = 30 * 86400


class FingerprintExtractor:
    """Coordinates all TAP-mode fingerprint extractors.

    Called by ``StreamReassembler`` via:
    - ``on_stream_data(stream)`` — called incrementally as data arrives
    - ``on_stream_close(stream)`` — called at stream end; returns final record
    """

    def __init__(
        self,
        config: dict,
        os_database: Optional[list[OSSignature]] = None,
        h2_database: Optional[list[H2Signature]] = None,
    ) -> None:
        tap_cfg = config.get("tap", {})
        self._tls_ports: set[int] = set(
            tap_cfg.get("tls_ports", [443, 8443, 465, 587, 993, 995, 8080, 8888])
        )
        self._ssh_ports: set[int] = set(tap_cfg.get("ssh_ports", [22, 2222]))
        self._http_ports: set[int] = set(
            tap_cfg.get("http_ports", [80, 8080, 8000, 8888])
        )
        self._os_db = os_database or []
        self._h2_db = h2_database or []

    def on_stream_data(self, stream: "TCPStream") -> None:
        """Attempt incremental fingerprint extraction as data arrives.

        Called by StreamReassembler each time new data is appended.
        Results are stored in ``stream.fingerprints``.
        """
        fp = stream.fingerprints
        if fp is None:
            stream.fingerprints = {}
            fp = stream.fingerprints

        client_data = bytes(stream.client_data)
        server_data = bytes(stream.server_data)
        port = stream.server_port

        # JA4 — from client TLS ClientHello
        if "ja4" not in fp and port in self._tls_ports and client_data:
            result = extract_ja4(client_data)
            if result is not None:
                fp["ja4"] = result.fingerprint
                fp["_ja4_result"] = result

        # JA4S — from server TLS ServerHello
        if "ja4s" not in fp and port in self._tls_ports and server_data:
            ja4s_r = extract_ja4s(server_data)
            if ja4s_r is not None:
                fp["ja4s"] = ja4s_r.fingerprint

        # JA4H — from HTTP/1.1 request
        if "ja4h" not in fp and port in self._http_ports and client_data:
            ja4h_r = extract_ja4h(client_data)
            if ja4h_r is not None:
                fp["ja4h"] = ja4h_r.fingerprint

        # JA4SSH — from SSH KEXINIT
        if "ja4ssh" not in fp and port in self._ssh_ports and client_data:
            # Look for SSH_MSG_KEXINIT (0x14) after the banner
            offset = _find_ssh_kexinit(client_data)
            if offset is not None:
                ja4ssh_r = extract_ja4ssh(client_data[offset:], direction="client")
                if ja4ssh_r is not None:
                    fp["ja4ssh"] = ja4ssh_r.fingerprint

        # H2 fingerprint — from HTTP/2 stream
        if "h2_fingerprint" not in fp and client_data:
            h2_r = extract_h2_fingerprint(client_data, self._h2_db)
            if h2_r is not None:
                fp["h2_fingerprint"] = h2_r.fingerprint
                if h2_r.matched_client:
                    fp["_h2_matched_client"] = h2_r.matched_client

        # QUIC — from UDP payload (would need to be set externally; placeholder)
        # QUIC extraction happens at the capture layer, not the reassembler

    def on_stream_close(self, stream: "TCPStream") -> ConnectionFingerprints:
        """Called when stream closes. Extract final fingerprints and return record."""
        self.on_stream_data(stream)  # One last extraction pass

        fp = stream.fingerprints or {}
        server_data = bytes(stream.server_data)
        port = stream.server_port

        # JA4T — from SYN TCP options (set during SYN_RCVD handling)
        ja4t_fp: Optional[str] = None
        if stream.syn_tcp_opts:
            ja4t_result = extract_ja4t_from_syn(
                stream.syn_tcp_opts,
                window_size=65535,  # stored window size not available here
            )
            ja4t_fp = ja4t_result.fingerprint

        # JA4X — from TLS Certificate message in server data
        ja4x_fp: Optional[str] = None
        cert_is_expired = False
        cert_is_self_signed = False
        if port in self._tls_ports and server_data:
            ja4x_result = extract_ja4x(server_data)
            if ja4x_result is not None:
                ja4x_fp = ja4x_result.fingerprint
                cert_is_self_signed = ja4x_result.self_signed
                if ja4x_result.not_after is not None:
                    from datetime import datetime
                    from datetime import timezone as _tz

                    cert_is_expired = ja4x_result.not_after < datetime.now(tz=_tz.utc)

        # JA4L — from handshake timestamps
        ja4l_fp: Optional[str] = None
        if (
            stream.syn_ts is not None
            and stream.synack_ts is not None
            and stream.ack_ts is not None
        ):
            ja4l_result = extract_ja4l(stream.syn_ts, stream.synack_ts, stream.ack_ts)
            ja4l_fp = ja4l_result.fingerprint

        # OS fingerprint — from JA4T data
        os_fp: Optional[str] = None
        if stream.syn_tcp_opts and self._os_db:
            os_result = match_os(
                stream.syn_tcp_opts,
                window_size=65535,
                ttl=64,
                df=True,
                database=self._os_db,
            )
            if os_result.confidence > 0.3:
                os_fp = os_result.fingerprint_id

        # TLS extension values
        ja4_result = fp.get("_ja4_result")
        tls_ext = None
        if ja4_result is not None:
            tls_ext = extract_tls_ext_values(ja4_result)

        from datetime import datetime, timezone

        return ConnectionFingerprints(
            conn_id=stream.conn_id,
            timestamp=datetime.now(tz=timezone.utc),
            client_ip=stream.client_ip,
            server_ip=stream.server_ip,
            server_port=stream.server_port,
            ja4=fp.get("ja4"),
            ja4s=fp.get("ja4s"),
            ja4t=ja4t_fp,
            ja4h=fp.get("ja4h"),
            ja4l=ja4l_fp,
            ja4x=ja4x_fp,
            ja4ssh=fp.get("ja4ssh"),
            h2_fingerprint=fp.get("h2_fingerprint"),
            os_fingerprint=os_fp,
            tls_ext_values=tls_ext,
            cert_is_expired=cert_is_expired,
            cert_is_self_signed=cert_is_self_signed,
            h2_matched_client=fp.get("_h2_matched_client"),
        )


class TapPipeline:
    """Integrates fingerprints with RiskScorer and ActionDecider.

    After ``FingerprintExtractor.on_stream_close()`` returns a
    ``ConnectionFingerprints`` record, ``TapPipeline.process()`` converts it
    to RiskSignals, scores them, and writes the result to Redis.
    """

    def __init__(
        self,
        config: dict,
        scorer: Any,
        decider: Any,
        redis: Any,
        export_manager: Any = None,
        store: Optional[FingerprintStore] = None,
    ) -> None:
        self._config = config
        self._scorer = scorer
        self._decider = decider
        self._redis = redis
        self._export_manager = export_manager
        self._store: Optional[FingerprintStore] = store or (
            FingerprintStore(redis) if redis is not None else None
        )
        self._ban_ttl_s: int = int(
            config.get("tap_enforcement", {}).get("ban_ttl_s", 3600)
        )

    async def process(self, fp: ConnectionFingerprints) -> None:
        """Convert fingerprints → RiskSignals → score → TAP action → Redis."""
        try:
            signals = self._fingerprints_to_signals(fp)
            assessment = self._scorer.score(signals)
            score = assessment.total_score
            action = self._score_to_tap_action(score)

            fp.risk_score = score
            fp.action = action
            fp.signals = [
                {"name": s.name, "score": s.score, "reason": getattr(s, "reason", "")}
                for s in signals
            ]

            if self._store is not None:
                await self._store.write(fp)

            if action == "signal_ban":
                await self._write_ban(fp.client_ip, self._ban_ttl_s, fp.conn_id)
            elif action == "signal_block":
                await self._write_block_decision(fp.client_ip, fp.conn_id)

        except Exception:
            logger.exception(
                "tap_pipeline | event=process_error | conn_id=%s", fp.conn_id
            )

    def _fingerprints_to_signals(self, fp: ConnectionFingerprints) -> list:
        """Convert ConnectionFingerprints to a list of RiskSignal objects."""
        from src.security.risk_scorer import RiskSignal

        signals: list[RiskSignal] = []

        # JA4L distance mismatch (+20)
        if fp.ja4l and "_" in fp.ja4l:
            parts = fp.ja4l.split("_")
            try:
                client_km = int(parts[1])
                # If distance seems very large (> 15000 km = half earth), flag it
                if client_km > 15000:
                    signals.append(
                        RiskSignal(
                            name="ja4l_distance_mismatch",
                            score=20,
                            reason=f"client_km={client_km}",
                        )
                    )
            except (IndexError, ValueError):
                pass

        # No GREASE (+10) — bots rarely send GREASE; real browsers always do
        if fp.tls_ext_values is not None and fp.ja4 is not None:
            if len(fp.tls_ext_values.grease_values) == 0:
                signals.append(
                    RiskSignal(
                        name="tls_no_grease",
                        score=10,
                        reason="no GREASE values in ClientHello",
                    )
                )

        # Scanner JA4 (+20) — known scanner TLS version prefix
        if fp.ja4:
            for prefix in _SCANNER_JA4_PREFIXES:
                if fp.ja4.startswith(prefix):
                    signals.append(
                        RiskSignal(
                            name="scanner_ja4",
                            score=20,
                            reason=f"ja4={fp.ja4}",
                        )
                    )
                    break

        # Expired cert (+15)
        if fp.cert_is_expired:
            signals.append(
                RiskSignal(
                    name="cert_expired",
                    score=15,
                    reason="server certificate has expired",
                )
            )

        # Self-signed cert (+5)
        if fp.cert_is_self_signed:
            signals.append(
                RiskSignal(
                    name="cert_self_signed",
                    score=5,
                    reason="server certificate is self-signed",
                )
            )

        # H2 settings mismatch (+15) — H2 used but client not recognized
        if fp.h2_fingerprint and fp.h2_matched_client is None:
            signals.append(
                RiskSignal(
                    name="h2_settings_mismatch",
                    score=15,
                    reason="HTTP/2 SETTINGS not matched to known client",
                )
            )

        # OS vs H2 client contradiction (+15)
        # Safari only exists on Apple devices; seeing it with Linux/Windows OS = spoofed UA
        if fp.os_fingerprint and fp.h2_matched_client:
            os_family = fp.os_fingerprint.split("_")[0].lower()
            h2_client = fp.h2_matched_client.lower()
            if "safari" in h2_client and os_family not in ("macos", "ios", "apple"):
                signals.append(
                    RiskSignal(
                        name="os_ua_mismatch",
                        score=15,
                        reason=f"os_family={os_family} h2_client={fp.h2_matched_client}",
                    )
                )

        # SSH attack tool (+25)
        if fp.ja4ssh:
            for tool_kex in _ATTACK_TOOL_KEX:
                if tool_kex in fp.ja4ssh:
                    signals.append(
                        RiskSignal(
                            name="ssh_attack_tool",
                            score=25,
                            reason=f"kex={tool_kex}",
                        )
                    )
                    break

        return signals

    def _score_to_tap_action(self, score: int) -> str:
        """Map 0–100 score to TAP action string."""
        for threshold, action in _SCORE_ACTIONS:
            if score >= threshold:
                return action
        return "observe"

    async def _write_to_redis(self, fp: ConnectionFingerprints) -> None:
        """Write fingerprint record and indices to Redis."""
        if self._redis is None:
            return
        try:
            d = fp.to_redis_dict()
            conn_key = f"fp:conn:{fp.conn_id}"
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: self._redis.hset(conn_key, mapping=d)
            )
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: self._redis.expire(conn_key, _FP_CONN_TTL)
            )

            # IP → conn Sorted Set
            ts = fp.timestamp.timestamp()
            ip_key = f"fp:ip:{fp.client_ip}"
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: self._redis.zadd(ip_key, {fp.conn_id: ts})
            )
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._redis.zremrangebyrank(ip_key, 0, -1001),  # keep last 1000
            )
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: self._redis.expire(ip_key, _FP_IP_TTL)
            )

            # JA4 HyperLogLog + count
            if fp.ja4:
                hll_key = f"fp:ja4:hll:{fp.ja4}"
                count_key = f"fp:ja4:count:{fp.ja4}"
                await asyncio.get_event_loop().run_in_executor(
                    None, lambda: self._redis.pfadd(hll_key, fp.client_ip)
                )
                await asyncio.get_event_loop().run_in_executor(
                    None, lambda: self._redis.incr(count_key)
                )

        except Exception:
            logger.exception(
                "tap_pipeline | event=redis_write_error | conn_id=%s", fp.conn_id
            )

    async def _write_ban(self, ip: str, ttl: int, reason: str) -> None:
        """Write ban:{ip} key to Redis (read by passthrough proxy and enforcement bridge)."""
        if self._redis is None:
            return
        try:
            ban_key = f"ban:{ip}"
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: self._redis.set(ban_key, reason, ex=ttl)
            )
            logger.warning(
                '{"event": "tap_signal_ban", "ip": "%s", "ttl": %d, "reason": "%s"}',
                ip,
                ttl,
                reason,
            )
        except Exception:
            logger.exception("tap_pipeline | event=ban_write_error | ip=%s", ip)

    async def _write_block_decision(self, ip: str, reason: str) -> None:
        """Write block_decisions:block:{ip} key (advisory; enforcement layer checks)."""
        if self._redis is None:
            return
        try:
            block_key = f"block_decisions:block:{ip}"
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._redis.set(block_key, reason, ex=300),  # 5-minute advisory
            )
        except Exception:
            logger.exception("tap_pipeline | event=block_write_error | ip=%s", ip)


def _find_ssh_kexinit(data: bytes) -> Optional[int]:
    """Find the start of SSH_MSG_KEXINIT in the stream data."""
    # SSH banner: "SSH-2.0-...\r\n" then binary packets starting with MSG_KEXINIT (0x14)
    # Simple heuristic: scan for 0x14 preceded by a length header
    if len(data) < 10:
        return None
    # Skip SSH banner if present
    pos = 0
    if data[:4] == b"SSH-":
        banner_end = data.find(b"\n")
        if banner_end == -1:
            return None
        pos = banner_end + 1
    # Now look for a packet whose payload starts with 0x14
    while pos + 6 <= len(data):
        import struct

        pkt_len = struct.unpack_from("!I", data, pos)[0]
        if pkt_len < 2 or pkt_len > 35000:
            return None
        padding_len = data[pos + 4]
        payload_start = pos + 5
        payload_len = pkt_len - padding_len - 1
        if payload_start + payload_len > len(data):
            return None
        if payload_len > 0 and data[payload_start] == 0x14:
            return payload_start
        pos += 4 + pkt_len
    return None
