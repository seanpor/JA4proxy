"""PHASE_101 C6 — adversarial FP-corpus gate on TI feed ingestion.

A misconfigured or compromised TI feed could push a Chrome / Firefox /
Safari JA4 into our blocklists, producing a full-traffic outage on first
match. The C6 fix is a hard FP-corpus gate enforced inside every feed
client (``taxii``, ``rest_generic``, ``seed_file``) before the Management
API ``post_blocklist`` call.

This file drives the adversarial scenario end-to-end: the corpus file is
the real one shipped under ``fixtures/ti_feeds/ja4_fp_corpus.txt``, and
each feed client is asked to ingest a payload whose JA4 field is a known
Chrome 120 fingerprint from that corpus. The assertion is binary: the
Management API must **never** receive a ``post_blocklist`` call for it.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any, List

import pytest

from src.analytics.ti_feeds import ja4_safety

# A JA4 that is in fixtures/ti_feeds/ja4_fp_corpus.txt. The corpus file is
# the single source of truth; this constant is re-validated at collection
# time by ``_require_in_corpus`` so the test self-heals if the corpus is
# rewritten.
_CHROME_120_JA4 = "t13d1516h2_8daaf6152771_02713d6af862"
_FIREFOX_121_JA4 = "t13d1715h2_5b57614c22b0_3d5424432f57"


def _reload_corpus() -> None:
    """Drop the cached FP corpus so ``ja4_safe_to_block`` reloads it.

    ``ja4_safety`` caches the corpus in a module-level variable and in
    ``is_known_browser_ja4``'s LRU cache — both must be cleared when the
    corpus file or JA4PROXY_FP_CORPUS_PATH env var changes.
    """
    ja4_safety._JA4_FP_CORPUS = None
    ja4_safety.is_known_browser_ja4.cache_clear()
    importlib.reload(ja4_safety)


@pytest.fixture(autouse=True)
def _fresh_corpus_cache() -> None:
    """Guarantee each test sees a fresh corpus read, not a cached one."""
    _reload_corpus()
    yield
    _reload_corpus()


def _require_in_corpus(ja4: str) -> None:
    from src.analytics.ti_feeds.ja4_safety import ja4_safe_to_block

    safe, reason = ja4_safe_to_block(ja4)
    if safe:
        pytest.fail(
            f"Regression: {ja4} is NOT in the FP corpus at "
            f"fixtures/ti_feeds/ja4_fp_corpus.txt. Either add it back, or "
            f"update the constant in this test file."
        )


# ── Stub management client & state ──────────────────────────────────────────


@dataclass
class _PostCall:
    entry: str
    feed_id: str


class _StubMgmt:
    """Records every ``post_blocklist`` attempt. A single call for a JA4 in
    the FP corpus is a test failure — nothing should reach the API."""

    def __init__(self) -> None:
        self.posts: List[_PostCall] = []

    async def connect(self) -> None: ...
    async def close(self) -> None: ...

    async def post_blocklist(
        self,
        *,
        feed_id: str,
        entry: str,
        note: str | None = None,
        expires_at: str | None = None,
    ) -> Any:
        call = _PostCall(entry=entry, feed_id=feed_id)
        self.posts.append(call)

        class _Resource:
            id = f"fake-{entry}"

        return _Resource()


# ── JA4 safety helper — pure-function path ──────────────────────────────────


def test_chrome_120_ja4_is_unsafe_to_block() -> None:
    """Direct call to ``ja4_safe_to_block`` rejects the Chrome 120 JA4."""
    _require_in_corpus(_CHROME_120_JA4)

    from src.analytics.ti_feeds.ja4_safety import ja4_safe_to_block

    safe, reason = ja4_safe_to_block(_CHROME_120_JA4)
    assert safe is False
    assert reason == "known_browser"


def test_firefox_121_ja4_is_unsafe_to_block() -> None:
    _require_in_corpus(_FIREFOX_121_JA4)

    from src.analytics.ti_feeds.ja4_safety import ja4_safe_to_block

    safe, reason = ja4_safe_to_block(_FIREFOX_121_JA4)
    assert safe is False
    assert reason == "known_browser"


def test_unknown_attacker_ja4_is_safe_to_block() -> None:
    """A random JA4 that isn't a known browser is allowed through."""
    from src.analytics.ti_feeds.ja4_safety import ja4_safe_to_block

    safe, _ = ja4_safe_to_block("t13d1111h2_000000000000_deadbeefcafe")
    assert safe is True


# ── rest_generic path ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_rest_generic_refuses_chrome_120(monkeypatch: pytest.MonkeyPatch) -> None:
    """The REST-generic client must NOT post_blocklist a Chrome 120 JA4."""
    _require_in_corpus(_CHROME_120_JA4)

    from src.analytics.ti_feeds.base import FeedConfig, FeedPollResult
    from src.analytics.ti_feeds.rest_generic import RESTGenericClient

    cfg = FeedConfig(
        id="fp-test-rest",
        type="rest_generic",
        enabled=True,
        url="https://example.invalid/indicators",
        poll_interval_minutes=60,
        ja4_jsonpath="$.indicators[*].ja4",
    )

    mgmt = _StubMgmt()
    body = {"indicators": [{"ja4": _CHROME_120_JA4}]}

    # Drive the ingestion path directly. We call the internal parser the same
    # way RESTGenericClient.poll() would, minus the HTTP fetch.
    client = RESTGenericClient(cfg, mgmt, state=None)
    result = FeedPollResult(feed_id=cfg.id, stix_ids_seen=set(), created=[])
    await client._apply_body(body, result)

    assert mgmt.posts == [], (
        f"FP corpus gate breached in rest_generic: {mgmt.posts!r}"
    )
    assert any("false positive" in err.lower() for err in result.errors), (
        f"expected an explicit FP-blocked error entry, got {result.errors!r}"
    )


# ── seed_file path ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_seed_file_refuses_chrome_120(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The YAML seed-file loader must reject a Chrome 120 JA4 entry."""
    _require_in_corpus(_CHROME_120_JA4)

    seed_path = tmp_path / "seed.yaml"
    seed_path.write_text(
        "fingerprints:\n"
        f"  - ja4: {_CHROME_120_JA4}\n"
        "    name: ChromeFalsePositive\n"
        "    category: browser\n"
        "    source: adversarial-test\n"
        "    confidence: 90\n"
        "  - ja4: t13d1111h2_000000000000_deadbeefcafe\n"
        "    name: RealBadActor\n"
        "    category: malware\n"
        "    source: adversarial-test\n"
        "    confidence: 90\n"
    )

    import fakeredis

    from src.analytics.ti_feeds import seed_file as seed_module
    from src.analytics.ti_feeds.state import FeedState

    server = fakeredis.FakeServer()
    redis = fakeredis.FakeStrictRedis(server=server, decode_responses=True)
    state = FeedState(redis)
    mgmt = _StubMgmt()

    summary = await seed_module.run_once(
        mgmt=mgmt,
        state=state,
        path=str(seed_path),
        min_entries=1,
    )

    # Exactly one post: the non-browser JA4. The Chrome 120 entry is
    # counted as rejected.
    assert len(mgmt.posts) == 1, (
        f"expected exactly one post (the attacker JA4), got {mgmt.posts!r}"
    )
    assert mgmt.posts[0].entry == "t13d1111h2_000000000000_deadbeefcafe"
    assert summary["rejected"] >= 1, (
        f"expected >=1 rejection for the FP-corpus JA4, got summary={summary!r}"
    )
