"""
JA4T — TCP client fingerprint extractor (Phase 20, Group 5-C).

Derives JA4T from raw TCP options bytes (from the SYN packet) and window size.
Format: {window_size}_{mss}_{options_order}_{window_scale}
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

# TCP option kinds
_OPT_EOL = 0
_OPT_NOP = 1
_OPT_MSS = 2
_OPT_WSCALE = 3
_OPT_SACK_PERMITTED = 4
_OPT_SACK = 5
_OPT_TIMESTAMP = 8

_OPTION_LETTERS = {
    _OPT_MSS: "M",
    _OPT_WSCALE: "W",
    _OPT_SACK_PERMITTED: "S",
    _OPT_TIMESTAMP: "T",
    _OPT_NOP: "N",
    _OPT_SACK: "K",
}


@dataclass
class JA4TResult:
    """TCP fingerprint from SYN options."""

    fingerprint: str          # e.g. "65535_1460_MSTNW_8"
    window_size: int
    mss: Optional[int]
    options_order: str        # letters for each option in appearance order
    window_scale: Optional[int]
    sack_permitted: bool
    timestamps: bool
    raw_options_hex: str


def extract_ja4t_from_syn(
    syn_tcp_opts: bytes,
    window_size: int,
) -> JA4TResult:
    """Derive JA4T fingerprint from raw TCP options bytes and window size.

    Args:
        syn_tcp_opts: Raw bytes of TCP options from the SYN packet.
        window_size:  TCP window size from the SYN packet header.

    Returns:
        JA4TResult (always; never raises or returns None).
    """
    try:
        return _parse(syn_tcp_opts, window_size)
    except Exception:
        return _empty(window_size, syn_tcp_opts)


def _parse(opts: bytes, window_size: int) -> JA4TResult:
    pos = 0
    n = len(opts)
    order_chars: list[str] = []
    mss: Optional[int] = None
    wscale: Optional[int] = None
    sack_permitted = False
    timestamps = False

    while pos < n:
        kind = opts[pos]
        if kind == _OPT_EOL:
            break
        if kind == _OPT_NOP:
            order_chars.append("N")
            pos += 1
            continue
        # All other options have a length byte
        if pos + 1 >= n:
            break
        opt_len = opts[pos + 1]
        if opt_len < 2 or pos + opt_len > n:
            break

        payload = opts[pos + 2:pos + opt_len]

        if kind == _OPT_MSS:
            letter = "M"
            if len(payload) >= 2:
                mss = struct.unpack_from("!H", payload)[0]
        elif kind == _OPT_WSCALE:
            letter = "W"
            if len(payload) >= 1:
                wscale = payload[0]
        elif kind == _OPT_SACK_PERMITTED:
            letter = "S"
            sack_permitted = True
        elif kind == _OPT_TIMESTAMP:
            letter = "T"
            timestamps = True
        elif kind == _OPT_SACK:
            letter = "K"
        else:
            letter = str(kind)

        order_chars.append(letter)
        pos += opt_len

    options_order = "".join(order_chars) or "none"
    mss_str = str(mss) if mss is not None else "0"
    wscale_str = str(wscale) if wscale is not None else "0"
    fingerprint = f"{window_size}_{mss_str}_{options_order}_{wscale_str}"

    return JA4TResult(
        fingerprint=fingerprint,
        window_size=window_size,
        mss=mss,
        options_order=options_order,
        window_scale=wscale,
        sack_permitted=sack_permitted,
        timestamps=timestamps,
        raw_options_hex=opts.hex(),
    )


def _empty(window_size: int, opts: bytes) -> JA4TResult:
    return JA4TResult(
        fingerprint=f"{window_size}_0_none_0",
        window_size=window_size,
        mss=None,
        options_order="none",
        window_scale=None,
        sack_permitted=False,
        timestamps=False,
        raw_options_hex=opts.hex() if opts else "",
    )
