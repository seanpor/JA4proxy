"""HAProxy config must use TCP mode for the proxy backend.

If HAProxy terminates TLS before forwarding to the JA4 proxy, the proxy receives
encrypted bytes instead of raw TLS ClientHello records, breaking JA4 fingerprinting.
"""

from pathlib import Path


def _find_haproxy_cfg() -> Path | None:
    for candidate in [
        "deploy/haproxy/haproxy.cfg",
        "config/haproxy.cfg",
    ]:
        p = Path(candidate)
        if p.exists():
            return p
    return None


def _backend_lines(text: str, name: str) -> list[str]:
    """Return the non-empty, non-comment lines inside a named backend block."""
    lines = text.splitlines()
    inside = False
    result: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(f"backend {name}") and stripped == f"backend {name}":
            inside = True
            continue
        if inside and stripped.startswith("backend "):
            break
        if inside and stripped and not stripped.startswith("#"):
            result.append(stripped)
    return result


def test_proxy_backend_not_http():
    """ja4proxy_backend must not use mode http (preserves raw ClientHello)."""
    cfg = _find_haproxy_cfg()
    if cfg is None:
        return

    body = _backend_lines(cfg.read_text(), "ja4proxy_backend")
    assert "mode http" not in body, (
        "ja4proxy_backend must NOT use mode http (breaks JA4 capture)"
    )
