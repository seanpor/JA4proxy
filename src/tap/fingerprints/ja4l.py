"""
JA4L — Light-distance estimation from TCP handshake timing (Phase 20, Group 5-E).

Estimates client and server distances from RTT measurements derived from the
SYN → SYN-ACK → ACK timestamps recorded during the 3-way handshake.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# Speed of light in fibre, accounting for network overhead.
# Real-world propagation: ~200 000 km/s (2/3 of c in glass)
_C_FIBRE_KM_S = 200_000.0
_MAX_SANE_RTT_S = 10.0   # anything larger is noise / NTP drift


@dataclass
class JA4LResult:
    """Light-distance estimation from TCP handshake timing."""

    fingerprint: str
    client_distance_km: float
    server_distance_km: float
    rtt_client_ms: float
    rtt_server_ms: float
    geoip_distance_km: Optional[float]
    distance_mismatch: bool


def extract_ja4l(
    syn_ts: float,
    synack_ts: float,
    ack_ts: float,
    geoip_distance_km: Optional[float] = None,
    mismatch_threshold_km: float = 500.0,
) -> JA4LResult:
    """Estimate light-distances from 3-way handshake timestamps.

    Args:
        syn_ts:      Capture timestamp of the SYN packet (seconds).
        synack_ts:   Capture timestamp of the SYN-ACK packet.
        ack_ts:      Capture timestamp of the ACK packet.
        geoip_distance_km: GeoIP-derived distance between client and server (optional).
        mismatch_threshold_km: Threshold above which distance_mismatch is set True.

    Returns:
        JA4LResult — always returns a result, never raises.
    """
    try:
        return _compute(
            syn_ts, synack_ts, ack_ts, geoip_distance_km, mismatch_threshold_km
        )
    except Exception:
        return _zero(geoip_distance_km)


def _compute(
    syn_ts: float,
    synack_ts: float,
    ack_ts: float,
    geoip_km: Optional[float],
    threshold_km: float,
) -> JA4LResult:
    # RTT from client's perspective: time from SYN → SYN-ACK arrival
    rtt_client_s = max(0.0, synack_ts - syn_ts)
    # RTT from server's perspective: time from SYN-ACK → ACK arrival
    rtt_server_s = max(0.0, ack_ts - synack_ts)

    # Clamp to avoid noise / NTP drift producing nonsensical values
    rtt_client_s = min(rtt_client_s, _MAX_SANE_RTT_S)
    rtt_server_s = min(rtt_server_s, _MAX_SANE_RTT_S)

    # One-way propagation = RTT / 2
    client_km = (rtt_client_s / 2.0) * _C_FIBRE_KM_S
    server_km = (rtt_server_s / 2.0) * _C_FIBRE_KM_S

    rtt_client_ms = rtt_client_s * 1000.0
    rtt_server_ms = rtt_server_s * 1000.0

    # Distance mismatch: GeoIP says they're close, timing says they're far
    mismatch = False
    if geoip_km is not None:
        mismatch = abs(client_km - geoip_km) > threshold_km

    # Fingerprint: rounded km values
    c_km_r = round(client_km)
    s_km_r = round(server_km)
    fingerprint = f"ja4l_{c_km_r}_{s_km_r}"

    return JA4LResult(
        fingerprint=fingerprint,
        client_distance_km=client_km,
        server_distance_km=server_km,
        rtt_client_ms=rtt_client_ms,
        rtt_server_ms=rtt_server_ms,
        geoip_distance_km=geoip_km,
        distance_mismatch=mismatch,
    )


def _zero(geoip_km: Optional[float]) -> JA4LResult:
    return JA4LResult(
        fingerprint="ja4l_0_0",
        client_distance_km=0.0,
        server_distance_km=0.0,
        rtt_client_ms=0.0,
        rtt_server_ms=0.0,
        geoip_distance_km=geoip_km,
        distance_mismatch=False,
    )
