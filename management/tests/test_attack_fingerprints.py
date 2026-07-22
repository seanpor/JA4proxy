"""Tests for Phase 250 botnet fingerprint detection endpoints."""

import json
import time

import pytest
from httpx import AsyncClient

# ── detect_botnet_signal unit tests ──────────────────────────────────────────

def test_botnet_signal_imports():
    """Import the helper from attack.py."""
    from management.api.routes.attack import detect_botnet_signal
    assert callable(detect_botnet_signal)


def test_botnet_signal_botnet():
    from management.api.routes.attack import detect_botnet_signal
    assert detect_botnet_signal(23, 82.0, False) == "botnet"


def test_botnet_signal_suspect():
    from management.api.routes.attack import detect_botnet_signal
    assert detect_botnet_signal(4, 61.0, False) == "suspect"


def test_botnet_signal_browser():
    from management.api.routes.attack import detect_botnet_signal
    # Known browser → always "browser", regardless of IP count or score.
    assert detect_botnet_signal(100, 99.0, True) == "browser"


def test_botnet_signal_tool():
    from management.api.routes.attack import detect_botnet_signal
    assert detect_botnet_signal(2, 10.0, False) == "tool"


def test_botnet_signal_unknown():
    from management.api.routes.attack import detect_botnet_signal
    assert detect_botnet_signal(1, 30.0, False) == "unknown"


def test_botnet_signal_attack_mode_lower_thresholds():
    from management.api.routes.attack import detect_botnet_signal
    # In normal mode, 3 IPs + score 55 → "suspect". In attack_mode → "botnet".
    assert detect_botnet_signal(3, 55.0, False, attack_mode=True) == "botnet"


# ── ja4_corpus tests ──────────────────────────────────────────────────────────

def test_corpus_loads():
    from management.api.ja4_corpus import corpus_size, is_known_browser
    assert corpus_size() >= 10


def test_known_browser_returns_true_for_corpus_entries():
    from management.api.ja4_corpus import _CORPUS, is_known_browser
    for fp in list(_CORPUS)[:5]:
        assert is_known_browser(fp), f"corpus entry not recognised: {fp}"


def test_known_browser_false_for_curl():
    from management.api.ja4_corpus import is_known_browser
    # curl fingerprint — NOT in corpus.
    assert not is_known_browser("t13d190900_9dc949149365_97f8aa674fd9")


def test_known_browser_false_for_python_requests():
    from management.api.ja4_corpus import is_known_browser
    assert not is_known_browser("t13d190900_9dc949149365_e7c285222651")


def test_browser_label_returns_string():
    from management.api.ja4_corpus import browser_label
    label = browser_label("t13d1516h2_8daaf6152771_02713d6af862")
    assert isinstance(label, str)
    assert "Chrome" in label


# ── /api/v1/attack/top-fingerprints API tests ─────────────────────────────────

def _make_event(ja4: str, ip: str, score: float, action: str = "flag", ja4t: str = "") -> dict:
    ev = {
        "source.ip": ip,
        "ja4proxy.fingerprint.ja4": ja4,
        "event.risk_score": score,
        "event.action": action,
    }
    if ja4t:
        ev["ja4proxy.fingerprint.ja4t"] = ja4t
    return ev


async def _seed_events(fake_redis, events: list) -> None:
    """Write mock events into the fake Redis event stream.

    Redis Stream IDs must be strictly increasing across XADD calls on the
    same stream — assign ascending ids (now_ms + i*100), not descending
    ones, or the second call fails with "ID ... equal or smaller than the
    target stream top item".
    """
    now_ms = int(time.time() * 1000)
    for i, ev in enumerate(events):
        entry_id = f"{now_ms + i * 100}-0"
        await fake_redis.xadd("events:connection", {"event": json.dumps(ev)}, id=entry_id)


@pytest.mark.asyncio
async def test_top_fingerprints_empty_stream(authenticated_client: AsyncClient) -> None:
    """Returns empty list when no events in stream."""
    r = await authenticated_client.get("/api/v1/attack/top-fingerprints")
    assert r.status_code == 200
    data = r.json()
    assert data["fingerprints"] == []


@pytest.mark.asyncio
async def test_top_fingerprints_sorted_by_unique_ips(
    authenticated_client: AsyncClient, fake_redis
) -> None:
    """Results sorted by unique_ip_count DESC."""
    bot_fp = "t13d190900_9dc949149365_e7c285222651"
    small_fp = "t13d190900_9dc949149365_a56c0480a5c1"
    events = (
        [_make_event(bot_fp, f"10.0.0.{i}", 80.0) for i in range(10)]
        + [_make_event(small_fp, "1.2.3.4", 50.0)]
    )
    await _seed_events(fake_redis, events)
    r = await authenticated_client.get("/api/v1/attack/top-fingerprints")
    data = r.json()
    fps = data["fingerprints"]
    assert fps[0]["ja4"] == bot_fp
    assert fps[0]["unique_ip_count"] == 10
    assert fps[0]["botnet_signal"] == "botnet"


@pytest.mark.asyncio
async def test_top_fingerprints_browser_signal(
    authenticated_client: AsyncClient, fake_redis
) -> None:
    """Known browser fingerprint gets botnet_signal='browser'."""
    chrome_fp = "t13d1516h2_8daaf6152771_02713d6af862"
    events = [_make_event(chrome_fp, f"10.0.{i}.1", 15.0) for i in range(100)]
    await _seed_events(fake_redis, events)
    r = await authenticated_client.get("/api/v1/attack/top-fingerprints")
    data = r.json()
    chrome_row = next((f for f in data["fingerprints"] if f["ja4"] == chrome_fp), None)
    assert chrome_row is not None
    assert chrome_row["botnet_signal"] == "browser"
    assert chrome_row["is_known_browser"] is True
    # sample_ips omitted for browser fingerprints.
    assert chrome_row["sample_ips"] == []


@pytest.mark.asyncio
async def test_top_fingerprints_ja4t_populated(
    authenticated_client: AsyncClient, fake_redis
) -> None:
    """ja4t_values populated when ja4t is present in events."""
    fp = "t13d190900_9dc949149365_00000000test"
    events = [
        _make_event(fp, f"10.0.0.{i}", 70.0, ja4t="1460_2_1_8192_7")
        for i in range(5)
    ]
    await _seed_events(fake_redis, events)
    r = await authenticated_client.get("/api/v1/attack/top-fingerprints")
    data = r.json()
    row = next((f for f in data["fingerprints"] if f["ja4"] == fp), None)
    assert row is not None
    assert "1460_2_1_8192_7" in row["ja4t_values"]


@pytest.mark.asyncio
async def test_top_fingerprints_attack_mode_threshold(
    authenticated_client: AsyncClient, fake_redis
) -> None:
    """attack_mode=true lowers botnet threshold (3 IPs + score 55 → botnet)."""
    fp = "t13d190900_0000000003ips_000000000000"
    events = [_make_event(fp, f"10.0.0.{i}", 55.0) for i in range(3)]
    await _seed_events(fake_redis, events)
    r = await authenticated_client.get("/api/v1/attack/top-fingerprints?attack_mode=true")
    data = r.json()
    row = next((f for f in data["fingerprints"] if f["ja4"] == fp), None)
    assert row is not None
    assert row["botnet_signal"] == "botnet"


# ── Safety gate tests ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_safety_gate_blocks_corpus_from_attack_ui(
    authenticated_client: AsyncClient,
) -> None:
    """POST /api/v1/lists/ja4/blacklist/{chrome_fp}?source=attack_ui → 422."""
    chrome_fp = "t13d1516h2_8daaf6152771_02713d6af862"
    r = await authenticated_client.post(
        f"/api/v1/lists/ja4/blacklist/{chrome_fp}?source=attack_ui"
    )
    assert r.status_code == 422
    assert "Safety gate" in r.json()["detail"]


@pytest.mark.asyncio
async def test_safety_gate_allows_bot_fp_from_attack_ui(
    authenticated_client: AsyncClient, fake_redis
) -> None:
    """POST /api/v1/lists/ja4/blacklist/{bot_fp}?source=attack_ui → 200."""
    bot_fp = "t13d190900_9dc949149365_e7c285222651"
    r = await authenticated_client.post(
        f"/api/v1/lists/ja4/blacklist/{bot_fp}?source=attack_ui"
    )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_safety_gate_not_applied_without_source(
    authenticated_client: AsyncClient, fake_redis
) -> None:
    """POST without ?source=attack_ui allows blocking any fingerprint (detail page path)."""
    chrome_fp = "t13d1516h2_8daaf6152771_02713d6af862"
    r = await authenticated_client.post(
        f"/api/v1/lists/ja4/blacklist/{chrome_fp}"
    )
    # No gate → should succeed (200 or whatever the normal response is).
    assert r.status_code == 200
