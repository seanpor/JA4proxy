"""
tests/unit/test_fix_forward.py

Phase 847d — the fix-forward engine. Every decision must be provable from
injected fixtures: no network, no docker, no git. The real mcp/semgrep
constraint is pinned as a fixture so the one live "blocked" case in this repo
can never regress into a false "fixable", and the three-outcome discipline
(fixable / blocked / unknown, precedence blocked > unknown > fixable) is
asserted everywhere — an `unknown` must never claim either way.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

import pytest

from scripts import fix_forward as ff

Fetch = Callable[[str], Any]


def _routing_fetch(routes: dict[str, Any]) -> Fetch:
    """A fetch_json that serves canned payloads by URL prefix; anything else
    is an honest failure, not a silent empty dict."""

    def fetch(url: str) -> Any:
        for prefix, payload in routes.items():
            if url.startswith(prefix):
                return payload() if callable(payload) else payload
        raise ff.Indeterminate(f"no fixture for {url}")

    return fetch


def _pypi_doc(version: str, requires_dist: list[str] | None = None) -> dict:
    return {
        "info": {"version": version, "requires_dist": requires_dist or []},
        "releases": {version: [{"filename": "x"}]},
    }


# ── constraint engine ───────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "version,spec,excluded",
    [
        ("1.30.0", "==1.29.0", True),
        ("1.29.0", "==1.29.0", False),
        ("1.30.0", ">=1.29.0", False),
        ("1.28.0", ">=1.29.0", True),
        ("1.30.0", "~=1.29.0", True),
        ("1.29.5", "~=1.29.0", False),
        ("1.30.0", "<1.30.0", True),
        ("1.30.0", ">1.30.0", True),
        ("1.31.0", ">1.30.0", False),
        ("1.30.0", "!=1.30.0", True),
        ("1.29.0", "!=1.30.0", False),
        ("1.30.0", ">=1.29.0,<2", False),
        ("2.0.0", ">=1.29.0,<2", True),
        ("1.29.1", "==1.29.*", False),
        ("1.30.0", "==1.29.*", True),
    ],
)
def test_spec_excludes(version: str, spec: str, excluded: bool) -> None:
    got, evidence = ff.spec_excludes(version, spec)
    assert got is excluded
    if excluded:
        assert evidence


def test_spec_excludes_arbitrary_equality() -> None:
    assert ff.spec_excludes("1.29.0", "===1.29.0") == (False, "")
    assert ff.spec_excludes("1.29.0", "===1.29.1")[0] is True


def test_spec_excludes_indeterminate_on_pre_release() -> None:
    """A version the engine cannot compare must raise, never guess."""
    with pytest.raises(ff.Indeterminate):
        ff.spec_excludes("1.30.0rc1", ">=1.29.0")


def test_spec_excludes_indeterminate_on_unparseable_clause() -> None:
    with pytest.raises(ff.Indeterminate):
        ff.spec_excludes("1.30.0", "wat(1.0)")


@pytest.mark.parametrize(
    "line,expected",
    [
        ("mcp>=1.29.0", ("mcp", ">=1.29.0", "mcp")),
        ("mcp>=1.29.0  # floor matching semgrep", ("mcp", ">=1.29.0", "mcp")),
        ('uvloop>=0.21.0; sys_platform == "linux"', ("uvloop", ">=0.21.0", "uvloop")),
        ("pytest-asyncio>=1.4.0,<2", ("pytest-asyncio", ">=1.4.0,<2", "pytest-asyncio")),
        ("aiohttp (>=3.8.0)", ("aiohttp", ">=3.8.0", "aiohttp")),
        ("protobuf>=6.0.0  # required by mcp", ("protobuf", ">=6.0.0", "protobuf")),
        ("# comment", None),
        ("-r base.txt", None),
        ("requests", None),
        ("", None),
    ],
)
def test_parse_req_line(line: str, expected: tuple | None) -> None:
    assert ff.parse_req_line(line) == expected


def test_bump_requirements_raises_pin_and_keeps_comment() -> None:
    text = "mcp>=1.29.0  # CVE-2025-66416\nsemgrep>=1.176.0\n"
    out = ff.bump_requirements(text, "mcp", "1.30.0")
    assert "mcp>=1.30.0  # CVE-2025-66416" in out
    assert "semgrep>=1.176.0" in out


def test_bump_requirements_keeps_upper_bound() -> None:
    text = "pytest-asyncio>=1.4.0,<2\n"
    out = ff.bump_requirements(text, "pytest-asyncio", "1.9.0")
    assert "pytest-asyncio>=1.9.0,<2" in out


def test_bump_requirements_refuses_when_nothing_editable() -> None:
    """A deliberate bound is a human's call — the bot must not silently edit."""
    with pytest.raises(ValueError):
        ff.bump_requirements("click~=8.1.8\n", "click", "8.3.3")


def test_http_get_json_refuses_plain_http() -> None:
    with pytest.raises(ff.Indeterminate, match="non-HTTPS"):
        ff.http_get_json("http://pypi.org/pypi/mcp/json")


# ── PyPI checks ─────────────────────────────────────────────────────────────

def test_pypi_blocked_by_semgrep_pin_the_real_mcp_case() -> None:
    """The repo's one live case: mcp's fix exists and our floor allows it, but
    semgrep hard-pins the vulnerable version — genuinely blocked."""
    routes = {
        "https://pypi.org/pypi/mcp/json": _pypi_doc("1.30.0"),
        "https://pypi.org/pypi/semgrep/json": _pypi_doc(
            "1.181.0", ["mcp==1.29.0 ; python_version >= '3.9'", "requests"]
        ),
    }
    d = ff.check_pypi_fix(
        "CVE-2026-59951",
        {"package": "mcp", "installed": "1.29.0", "fixed": "1.30.0", "severity": "HIGH"},
        requirements_text="mcp>=1.29.0\nsemgrep>=1.176.0\n",
        fetch_json=_routing_fetch(routes),
    )
    assert d["decision"] == "blocked"
    assert "semgrep (1.181.0)" in d["evidence"]
    assert "mcp==1.29.0" in d["evidence"]
    assert d["recheck"] == "semgrep publishes a release allowing mcp >= 1.30.0"
    assert d["bump"] is None


def test_pypi_fixable_when_pin_is_ours_and_editable() -> None:
    routes = {
        "https://pypi.org/pypi/mcp/json": _pypi_doc("1.30.0"),
        "https://pypi.org/pypi/semgrep/json": _pypi_doc("1.181.0", []),
    }
    d = ff.check_pypi_fix(
        "CVE-2026-59951",
        {"package": "mcp", "installed": "1.29.0", "fixed": "1.30.0", "severity": "HIGH"},
        requirements_text="mcp==1.29.0\nsemgrep>=1.176.0\n",
        fetch_json=_routing_fetch(routes),
    )
    assert d["decision"] == "fixable"
    assert d["bump"] == {"kind": "pypi", "package": "mcp", "from": "1.29.0", "to": "1.30.0"}
    assert d["table"][0]["before"] == "mcp 1.29.0"
    assert d["table"][0]["after"] == "mcp 1.30.0"
    assert "requirements.txt specifier: `==1.29.0`" in d["evidence"]  # the blocked-evidence path is honest


def test_pypi_unknown_on_compatible_release_bound() -> None:
    routes = {"https://pypi.org/pypi/click/json": _pypi_doc("8.3.3")}
    d = ff.check_pypi_fix(
        "CVE-2026-99999",
        {"package": "click", "installed": "8.1.8", "fixed": "8.3.3"},
        requirements_text="click~=8.1.8\n",
        fetch_json=_routing_fetch(routes),
    )
    assert d["decision"] == "unknown"
    assert "relaxing" in d["evidence"]


def test_pypi_blocked_when_fix_not_published() -> None:
    routes = {"https://pypi.org/pypi/mcp/json": _pypi_doc("1.29.0")}
    d = ff.check_pypi_fix(
        "CVE-2026-59951",
        {"package": "mcp", "installed": "1.29.0", "fixed": "1.30.0"},
        requirements_text="mcp>=1.29.0\n",
        fetch_json=_routing_fetch(routes),
    )
    assert d["decision"] == "blocked"
    assert "not published on PyPI" in d["evidence"]


def test_pypi_blocked_when_osv_has_no_fix() -> None:
    routes = {
        "https://api.osv.dev/v1/vulns/CVE-2026-00042": {
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "mcp"},
                    "ranges": [{"events": [{"introduced": "1.0.0"}]}],
                }
            ]
        }
    }
    d = ff.check_pypi_fix(
        "CVE-2026-00042",
        {"package": "mcp", "installed": "1.29.0", "fixed": ""},
        requirements_text="mcp>=1.29.0\n",
        fetch_json=_routing_fetch(routes),
    )
    assert d["decision"] == "blocked"
    assert "no fixed version" in d["evidence"]


def test_pypi_unknown_when_not_a_direct_requirement() -> None:
    routes = {
        "https://pypi.org/pypi/mcp/json": _pypi_doc("1.30.0"),
        "https://pypi.org/pypi/semgrep/json": _pypi_doc("1.181.0", []),
    }
    d = ff.check_pypi_fix(
        "CVE-2026-59951",
        {"package": "mcp", "installed": "1.29.0", "fixed": "1.30.0"},
        requirements_text="semgrep>=1.176.0\n",
        fetch_json=_routing_fetch(routes),
    )
    assert d["decision"] == "unknown"
    assert "not a direct requirement" in d["evidence"]


def test_pypi_unknown_when_fetch_fails() -> None:
    def fetch(_url: str) -> Any:
        raise ff.Indeterminate("unreachable: https://pypi.org/pypi/mcp/json (timeout)")

    d = ff.check_pypi_fix(
        "CVE-2026-59951",
        {"package": "mcp", "installed": "1.29.0", "fixed": "1.30.0"},
        requirements_text="mcp>=1.29.0\n",
        fetch_json=fetch,
    )
    assert d["decision"] == "unknown"
    assert "unreachable" in d["evidence"]


def test_osv_fixed_version_prefers_last_fix_and_filters_ecosystem() -> None:
    doc = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "mcp"},
                "ranges": [
                    {
                        "events": [
                            {"introduced": "1.0.0"},
                            {"fixed": "1.29.5"},
                            {"fixed": "1.30.0"},
                        ]
                    }
                ],
            },
            {
                "package": {"ecosystem": "Go", "name": "mcp"},
                "ranges": [{"events": [{"fixed": "9.9.9"}]}],
            },
        ]
    }
    fixed, evidence = ff.osv_fixed_version(
        "CVE-2026-59951", "mcp", fetch_json=_routing_fetch({"https://api.osv.dev/": doc})
    )
    assert fixed == "1.30.0"
    assert "OSV" in evidence


def test_sweep_cap_raises_indeterminate() -> None:
    with pytest.raises(ff.Indeterminate, match="sweep cap"):
        ff.external_constraint_block(
            "mcp",
            "1.30.0",
            "a>=1\nb>=2\n",
            fetch_json=_routing_fetch({}),
            max_reverse_deps=1,
        )


# ── image checks ────────────────────────────────────────────────────────────

_TAGS = ["13.2.4-ubuntu", "13.3.1-ubuntu", "13.3.0-ubuntu", "14.0.0-alpine"]


def _finding(cve: str, severity: str = "CRITICAL") -> dict:
    return {cve: {"severity": severity, "package": "x", "installed": "1", "fixed": "2"}}


def test_image_fixable_newest_usable_tag_clears() -> None:
    current = _finding("CVE-2026-0001")
    d = ff.check_image_fix(
        "grafana/grafana:13.2.4-ubuntu",
        "image:grafana/grafana",
        {"CVE-2026-0001"},
        current,
        scanner=lambda ref: {},
        fetch_tags=lambda repo: _TAGS,
        today="2026-10-21",
    )
    assert [x["decision"] for x in d] == ["fixable"]
    assert d[0]["bump"] == {
        "kind": "image",
        "ref": "grafana/grafana:13.2.4-ubuntu",
        "name": "grafana/grafana",
        "from": "13.2.4-ubuntu",
        "to": "13.3.1-ubuntu",
    }
    row = {r["cve"]: r for r in d[0]["table"]}["CVE-2026-0001"]
    assert row["before"] == "present"
    assert row["after"] == "**cleared**"


def test_image_candidate_introducing_new_finding_is_skipped() -> None:
    current = _finding("CVE-2026-0001")

    def scanner(ref: str) -> dict:
        if ref.endswith("13.3.1-ubuntu"):
            return _finding("CVE-NEW-1", "HIGH")
        return {}

    d = ff.check_image_fix(
        "grafana/grafana:13.2.4-ubuntu",
        "image:grafana/grafana",
        {"CVE-2026-0001"},
        current,
        scanner=scanner,
        fetch_tags=lambda repo: _TAGS,
        today="2026-10-21",
    )
    assert d[0]["decision"] == "fixable"
    assert d[0]["bump"]["to"] == "13.3.0-ubuntu"
    assert "13.3.1-ubuntu (introduces CVE-NEW-1)" in d[0]["evidence"]


def test_image_blocked_decider_still_carries() -> None:
    current = _finding("CVE-2026-0001")

    def scanner(ref: str) -> dict:
        return _finding("CVE-2026-0001")

    d = ff.check_image_fix(
        "grafana/grafana:13.2.4-ubuntu",
        "image:grafana/grafana",
        {"CVE-2026-0001"},
        current,
        scanner=scanner,
        fetch_tags=lambda repo: _TAGS,
        today="2026-10-21",
    )
    assert [x["decision"] for x in d] == ["blocked"]
    assert "still carries CVE-2026-0001" in d[0]["evidence"]
    assert d[0]["recheck"]


def test_image_blocked_when_every_candidate_introduces() -> None:
    current = _finding("CVE-2026-0001")
    d = ff.check_image_fix(
        "grafana/grafana:13.2.4-ubuntu",
        "image:grafana/grafana",
        {"CVE-2026-0001"},
        current,
        scanner=lambda ref: _finding("CVE-NEW-1", "HIGH"),
        fetch_tags=lambda repo: _TAGS,
        today="2026-10-21",
    )
    assert [x["decision"] for x in d] == ["blocked"]
    assert "none usable" in d[0]["evidence"]
    assert "CVE-NEW-1" in d[0]["evidence"]


def test_image_blocked_when_no_newer_tag() -> None:
    d = ff.check_image_fix(
        "grafana/grafana:13.2.4-ubuntu",
        "image:grafana/grafana",
        {"CVE-2026-0001"},
        _finding("CVE-2026-0001"),
        scanner=lambda ref: {},
        fetch_tags=lambda repo: ["13.2.4-ubuntu"],
        today="2026-10-21",
    )
    assert [x["decision"] for x in d] == ["blocked"]
    assert "no published tag newer than 13.2.4-ubuntu" in d[0]["evidence"]


def test_image_unknown_when_nothing_scanned() -> None:
    """Failed scans prove nothing — that is `unknown`, never `blocked`."""

    def scanner(ref: str) -> dict:
        raise RuntimeError("trivy exited 1")

    d = ff.check_image_fix(
        "grafana/grafana:13.2.4-ubuntu",
        "image:grafana/grafana",
        {"CVE-2026-0001"},
        _finding("CVE-2026-0001"),
        scanner=scanner,
        fetch_tags=lambda repo: _TAGS,
        today="2026-10-21",
    )
    assert [x["decision"] for x in d] == ["unknown"]
    assert "scan failed" in d[0]["evidence"]


def test_image_unknown_on_digest_pinned_ref() -> None:
    d = ff.check_image_fix(
        "redis:7.4.11-alpine@sha256:abc123",
        "image:redis",
        {"CVE-2026-0001"},
        _finding("CVE-2026-0001"),
        scanner=lambda ref: {},
        fetch_tags=lambda repo: _TAGS,
        today="2026-10-21",
    )
    assert [x["decision"] for x in d] == ["unknown"]
    assert "digest-pinned" in d[0]["evidence"]


def test_image_unknown_for_first_party() -> None:
    d = ff.check_image_fix(
        "ja4proxy:2.0.0",
        "image:ja4proxy",
        {"CVE-2026-0001"},
        _finding("CVE-2026-0001"),
        scanner=lambda ref: {},
        fetch_tags=lambda repo: _TAGS,
        today="2026-10-21",
    )
    assert [x["decision"] for x in d] == ["unknown"]
    assert "first-party" in d[0]["evidence"]


def test_image_unknown_on_non_semver_tag() -> None:
    d = ff.check_image_fix(
        "grafana/grafana:latest",
        "image:grafana/grafana",
        {"CVE-2026-0001"},
        _finding("CVE-2026-0001"),
        scanner=lambda ref: {},
        fetch_tags=lambda repo: _TAGS,
        today="2026-10-21",
    )
    assert [x["decision"] for x in d] == ["unknown"]
    assert "non-semver" in d[0]["evidence"]


def test_image_unknown_when_tags_unreachable() -> None:
    def fetch_tags(repo: str) -> list[str]:
        raise RuntimeError("429 rate-limited")

    d = ff.check_image_fix(
        "grafana/grafana:13.2.4-ubuntu",
        "image:grafana/grafana",
        {"CVE-2026-0001"},
        _finding("CVE-2026-0001"),
        scanner=lambda ref: {},
        fetch_tags=fetch_tags,
        today="2026-10-21",
    )
    assert [x["decision"] for x in d] == ["unknown"]
    assert "no tags visible" in d[0]["evidence"]


# ── evaluation over a monitor state ─────────────────────────────────────────

def test_evaluate_dispatches_surfaces_and_skips_unfixed() -> None:
    current = {
        "pypi": {
            "findings": {
                "CVE-2026-59951": {
                    "package": "mcp",
                    "installed": "1.29.0",
                    "fixed": "1.30.0",
                },
                "CVE-2026-00000": {"package": "x", "installed": "1", "fixed": ""},
            }
        },
        "image:grafana/grafana": {
            "ref": "grafana/grafana:13.2.4-ubuntu",
            "findings": {},
        },
    }
    routes = {
        "https://pypi.org/pypi/mcp/json": _pypi_doc("1.30.0"),
        "https://pypi.org/pypi/semgrep/json": _pypi_doc("1.181.0", []),
    }
    decisions = ff.evaluate(
        current,
        requirements_text="mcp==1.29.0\nsemgrep>=1.176.0\n",
        fetch_json=_routing_fetch(routes),
        scanner=lambda ref: {},
        fetch_tags=lambda repo: _TAGS,
        today="2026-10-21",
    )
    # Only the finding with a published fix is evaluated; the empty image
    # surface produces nothing.
    assert len(decisions) == 1
    assert decisions[0]["cve"] == "CVE-2026-59951"
    assert decisions[0]["decision"] == "fixable"
    assert decisions[0]["surface"] == "pypi"


def test_group_fixable_one_unit_per_bump_target() -> None:
    decisions = [
        {
            "surface": "image:grafana/grafana",
            "cve": cve,
            "decision": "fixable",
            "evidence": f"e{cve}",
            "recheck": "",
            "table": [{"cve": cve, "severity": "HIGH", "before": "present", "after": "**cleared**"}],
            "bump": {
                "kind": "image",
                "ref": "grafana/grafana:13.2.4-ubuntu",
                "name": "grafana/grafana",
                "from": "13.2.4-ubuntu",
                "to": "13.3.1-ubuntu",
            },
        }
        for cve in ("CVE-2026-0001", "CVE-2026-0002")
    ]
    decisions.append(
        {
            "surface": "pypi",
            "cve": "CVE-2026-59951",
            "decision": "fixable",
            "evidence": "pe",
            "recheck": "",
            "table": [],
            "bump": {"kind": "pypi", "package": "mcp", "from": "1.29.0", "to": "1.30.0"},
        }
    )
    units = ff.group_fixable(decisions)
    assert len(units) == 2
    image = next(u for u in units if u["surface"] == "image:grafana/grafana")
    assert image["cves"] == ["CVE-2026-0001", "CVE-2026-0002"]
    assert "+1 more" in image["title"]
    assert image["branch"] == "bot/fix-forward-grafana-grafana-13-3-1-ubuntu"
    assert image["title"] == "bump grafana/grafana:13.2.4-ubuntu to 13.3.1-ubuntu (CVE-2026-0001+1 more)"


def test_group_fixable_ignores_non_fixable() -> None:
    decisions = [
        {"surface": "pypi", "cve": "CVE-1", "decision": "blocked", "bump": None, "evidence": "x", "table": None},
        {"surface": "pypi", "cve": "CVE-2", "decision": "unknown", "bump": None, "evidence": "x", "table": None},
    ]
    assert ff.group_fixable(decisions) == []


# ── registry recording ──────────────────────────────────────────────────────

def _registry() -> dict:
    return {
        "version": 1,
        "policy": {"max_window_days": 90, "default_owner": "security-oncall"},
        "waivers": [
            {
                "id": "CVE-2026-0001",
                "scope": "third-party",
                "severity": "HIGH",
                "source": "trivy",
                "carriers": ["img:1.0"],
                "rationale": "synthetic",
                "created": "2026-10-17",
                "expires": "2027-01-15",
            }
        ],
    }


def test_record_blocked_sets_false_with_trigger() -> None:
    reg = _registry()
    change = ff.record_fix_availability(
        reg,
        "CVE-2026-0001",
        {"decision": "blocked", "evidence": "no tag clears it", "recheck": "upstream ships a fix"},
        "2026-10-21",
    )
    assert change == "CVE-2026-0001: fix_available: false"
    entry = reg["waivers"][0]
    assert entry["fix_available"] is False
    assert "upstream ships a fix" in entry["recheck_trigger"]
    assert "2026-10-21" in entry["recheck_trigger"]
    # Idempotent: an already-recorded blocked entry is not re-recorded.
    assert ff.record_fix_availability(reg, "CVE-2026-0001", {"decision": "blocked"}, "2026-10-22") is None


def test_record_fixable_supersedes_stale_trigger() -> None:
    reg = _registry()
    reg["waivers"][0]["fix_available"] = False
    reg["waivers"][0]["recheck_trigger"] = "when upstream ships a fix"
    change = ff.record_fix_availability(reg, "CVE-2026-0001", {"decision": "fixable"}, "2026-10-21")
    assert change == "CVE-2026-0001: fix_available: true"
    entry = reg["waivers"][0]
    assert entry["fix_available"] is True
    assert "recheck_trigger" not in entry
    assert ff.record_fix_availability(reg, "CVE-2026-0001", {"decision": "fixable"}, "2026-10-22") is None


def test_record_unknown_and_missing_entry_record_nothing() -> None:
    reg = _registry()
    assert ff.record_fix_availability(reg, "CVE-2026-0001", {"decision": "unknown"}, "2026-10-21") is None
    assert ff.record_fix_availability(reg, "CVE-2099-99999", {"decision": "blocked"}, "2026-10-21") is None
    assert reg["waivers"][0].get("fix_available") is None


# ── scan cache ──────────────────────────────────────────────────────────────

def test_cached_scanner_roundtrip(tmp_path: Path) -> None:
    calls: list[str] = []

    def scanner(ref: str) -> dict:
        calls.append(ref)
        return _finding("CVE-X", "HIGH")

    cache_path = tmp_path / "cache.json"
    scan, save = ff.cached_scanner(scanner, cache_path=cache_path, ignore_digest="abc", today="2026-10-21")
    assert scan("img:1") == _finding("CVE-X", "HIGH")
    save()
    assert calls == ["img:1"]

    # Same ref + same ignore hash within max age: served from the cache.
    scan2, _ = ff.cached_scanner(scanner, cache_path=cache_path, ignore_digest="abc", today="2026-10-25")
    scan2("img:1")
    assert calls == ["img:1"]

    # A different ignorefile hash invalidates.
    scan3, _ = ff.cached_scanner(scanner, cache_path=cache_path, ignore_digest="def", today="2026-10-25")
    scan3("img:1")
    assert calls == ["img:1", "img:1"]

    # Beyond max age the entry is stale: re-scanned.
    scan4, _ = ff.cached_scanner(scanner, cache_path=cache_path, ignore_digest="abc", today="2026-11-01")
    scan4("img:1")
    assert calls == ["img:1", "img:1", "img:1"]


def test_cached_scanner_survives_corrupt_cache(tmp_path: Path) -> None:
    cache_path = tmp_path / "cache.json"
    cache_path.write_text("{not json", encoding="utf-8")
    scan, _save = ff.cached_scanner(lambda ref: {}, cache_path=cache_path, ignore_digest="abc", today="2026-10-21")
    assert scan("img:1") == {}


# ── edit builders ───────────────────────────────────────────────────────────

def _compose_repo(tmp_path: Path) -> Path:
    docker = tmp_path / "deploy" / "docker"
    docker.mkdir(parents=True)
    (docker / "docker-compose.test.yml").write_text(
        "services:\n  grafana:\n    image: grafana/grafana:13.2.4-ubuntu\n",
        encoding="utf-8",
    )
    (docker / "docker-compose.yml").write_text(
        "services:\n  grafana:\n    image: grafana/grafana:13.2.4-ubuntu  # pinned\n",
        encoding="utf-8",
    )
    (docker / "docker-compose.other.yml").write_text(
        "services:\n  redis:\n    image: redis:7.4.11-alpine\n",
        encoding="utf-8",
    )
    return tmp_path


def test_image_builder_replaces_every_pin(tmp_path: Path) -> None:
    root = _compose_repo(tmp_path)
    builder = ff._image_builder(
        {"name": "grafana/grafana", "from": "13.2.4-ubuntu", "to": "13.3.1-ubuntu"}
    )
    written = builder(root)
    assert len(written) == 2  # both compose files carrying the ref
    for path in written:
        text = path.read_text(encoding="utf-8")
        assert "grafana/grafana:13.3.1-ubuntu" in text
        assert "grafana/grafana:13.2.4-ubuntu" not in text
    untouched = (root / "deploy" / "docker" / "docker-compose.other.yml").read_text(encoding="utf-8")
    assert "redis:7.4.11-alpine" in untouched


def test_image_builder_errors_when_ref_missing(tmp_path: Path) -> None:
    root = tmp_path
    (root / "deploy" / "docker").mkdir(parents=True)
    builder = ff._image_builder({"name": "ghost/image", "from": "1.0.0", "to": "1.0.1"})
    with pytest.raises(ff.ProposeError, match="not found"):
        builder(root)


def test_requirements_builder_edits_in_place(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("mcp>=1.29.0\nsemgrep>=1.176.0\n", encoding="utf-8")
    builder = ff._requirements_builder(
        {"package": "mcp", "to": "1.30.0"}, Path("requirements.txt")
    )
    written = builder(tmp_path)
    assert written == [req]
    assert "mcp>=1.30.0" in req.read_text(encoding="utf-8")


# ── proposal authoring ──────────────────────────────────────────────────────

def _fake_sh(
    calls: list[list[str]], *, dirty: bool = False, staged: bool = True
) -> Callable[[list[str]], tuple[int, str, str]]:
    def runner(argv: list[str]) -> tuple[int, str, str]:
        calls.append(list(argv))
        joined = " ".join(argv)
        if joined.endswith("status --porcelain"):
            return 0, " M some/file\n" if dirty else "", ""
        if joined.endswith("diff --cached --quiet"):
            return (1 if staged else 0), "", ""
        if joined.endswith("remote get-url origin"):
            return 0, "https://github.com/seanpor/JA4proxy.git\n", ""
        if "rev-parse" in joined:
            return 0, "main\n", ""
        return 0, "", ""

    return runner


def test_propose_branch_commit_push_then_issue(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    issue_bodies: list[tuple[str, str]] = []

    def creator(title: str, body: str) -> str:
        issue_bodies.append((title, body))
        return "https://github.com/seanpor/JA4proxy/issues/999"

    result = ff.propose(
        branch="bot/fix-forward-test",
        title="bump grafana/grafana to 13.3.1-ubuntu (CVE-2026-0001)",
        body="BODY",
        edit_builder=lambda root: [tmp_path / "requirements.txt"],
        repo_root=tmp_path,
        sh_runner=_fake_sh(calls),
        issue_creator=creator,
    )
    assert result == {"branch": "bot/fix-forward-test", "issue": "https://github.com/seanpor/JA4proxy/issues/999"}
    argvs = [" ".join(c) for c in calls]
    assert any("fetch origin main" in a for a in argvs)
    assert any("checkout -B bot/fix-forward-test origin/main" in a for a in argvs)
    assert any("add --" in a for a in argvs)
    assert any(a.endswith("commit -m Fix-forward: bump grafana/grafana to 13.3.1-ubuntu (CVE-2026-0001)") for a in argvs)
    assert any("push --force-with-lease -u origin bot/fix-forward-test" in a for a in argvs)
    # The issue carries the one-click compare link.
    title, body = issue_bodies[0]
    assert title == "Fix-forward: bump grafana/grafana to 13.3.1-ubuntu (CVE-2026-0001)"
    assert "https://github.com/seanpor/JA4proxy/compare/main...bot/fix-forward-test?expand=1" in body


def test_propose_refuses_dirty_tree(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    with pytest.raises(ff.ProposeError, match="not clean"):
        ff.propose(
            branch="bot/x",
            title="t",
            body="b",
            edit_builder=lambda root: [],
            repo_root=tmp_path,
            sh_runner=_fake_sh(calls, dirty=True),
            issue_creator=lambda t, b: "i",
        )
    # Refused before any branch moved.
    assert not any("checkout" in " ".join(c) for c in calls)


def test_propose_errors_when_nothing_staged(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    with pytest.raises(ff.ProposeError, match="no staged changes"):
        ff.propose(
            branch="bot/x",
            title="t",
            body="b",
            edit_builder=lambda root: [tmp_path / "a.txt"],
            repo_root=tmp_path,
            sh_runner=_fake_sh(calls, staged=False),
            issue_creator=lambda t, b: "i",
        )
    # Never reached the push or the issue.
    assert not any("push" in " ".join(c) for c in calls)


def test_propose_restores_branch_when_edit_fails(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def broken(root: Path) -> list[Path]:
        raise ff.ProposeError("edit exploded")

    with pytest.raises(ff.ProposeError, match="edits failed"):
        ff.propose(
            branch="bot/x",
            title="t",
            body="b",
            edit_builder=broken,
            repo_root=tmp_path,
            sh_runner=_fake_sh(calls),
            issue_creator=lambda t, b: "i",
        )
    # The -B checkout back to the pre-existing ref ran (idempotent restore).
    assert any("checkout -B bot/x HEAD" in " ".join(c) for c in calls)


# ── report + bodies ─────────────────────────────────────────────────────────

def test_report_emits_fixable_queue_metric() -> None:
    decisions = [
        {"surface": "pypi", "cve": "CVE-1", "decision": "fixable", "evidence": "e"},
        {"surface": "pypi", "cve": "CVE-2", "decision": "blocked", "evidence": "e"},
        {"surface": "pypi", "cve": "CVE-3", "decision": "unknown", "evidence": "e"},
    ]
    text = ff.render_report(decisions, ["r1"], [{"branch": "b", "issue": "i"}])
    assert "FIXABLE_QUEUE evaluated=3 fixable=1 blocked=1 unknown=1 proposed=1" in text


def test_report_steady_state() -> None:
    text = ff.render_report([], [], [])
    assert "Steady state" in text
    assert "FIXABLE_QUEUE evaluated=0 fixable=0 blocked=0 unknown=0 proposed=0" in text


def test_evidence_comment_body_marker_and_snippet() -> None:
    body = ff.evidence_comment_body(
        {
            "cve": "CVE-2026-0001",
            "decision": "blocked",
            "evidence": "no tag clears it",
            "recheck": "upstream ships a fixed tag",
        },
        "2026-10-21",
    )
    assert body.startswith(ff.ISSUE_MARKER)
    assert "fix_available: false" in body
    assert "recheck_trigger:" in body
    assert "no tag clears it" in body


def test_proposal_body_table_and_bot_note() -> None:
    unit = {
        "bump": {"kind": "image", "ref": "grafana/grafana:13.2.4-ubuntu", "name": "grafana/grafana", "to": "13.3.1-ubuntu"},
        "table": [{"cve": "CVE-2026-0001", "severity": "CRITICAL", "before": "present", "after": "**cleared**"}],
        "evidence": ["checked 2026-10-21: ..."],
    }
    body = ff.proposal_body(unit, "2026-10-21")
    assert "| CVE-2026-0001 | CRITICAL | present | **cleared** |" in body
    assert "never merges its own" in body


# ── CLI (main) ──────────────────────────────────────────────────────────────

def _state(tmp_path: Path, current: dict) -> Path:
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"generated_at": "2026-10-21", "current": current}), encoding="utf-8")
    return path


def _decision(**over: Any) -> dict:
    base = {
        "surface": "pypi",
        "cve": "CVE-2026-59951",
        "decision": "fixable",
        "evidence": "e",
        "recheck": "",
        "table": None,
        "bump": {"kind": "pypi", "package": "mcp", "from": "1.29.0", "to": "1.30.0"},
    }
    base.update(over)
    return base


def test_main_report_only_never_proposes(tmp_path: Path, monkeypatch, capsys) -> None:
    state = _state(tmp_path, {})
    monkeypatch.setattr(ff, "default_scanner", lambda: (lambda ref: {}))

    def fail_propose(**_kw: Any) -> dict:
        raise AssertionError("report mode must never propose")

    monkeypatch.setattr(ff, "propose", fail_propose)
    rc = ff.main(["--state", str(state)])
    assert rc == 0
    assert "Steady state" in capsys.readouterr().out


def test_main_apply_refuses_dirty_tree(tmp_path: Path, monkeypatch) -> None:
    state = _state(tmp_path, {})
    monkeypatch.setattr(ff, "default_scanner", lambda: (lambda ref: {}))
    monkeypatch.setattr(ff, "evaluate", lambda *a, **kw: [])
    monkeypatch.setattr(ff, "sh", _fake_sh([], dirty=True))

    def fail_issues() -> dict:
        raise AssertionError("must not reach GitHub before the guard")

    monkeypatch.setattr(ff, "issues_by_title", fail_issues)
    assert ff.main(["--state", str(state), "--apply"]) == 2


def test_main_apply_dedups_existing_proposal(tmp_path: Path, monkeypatch, capsys) -> None:
    state = _state(tmp_path, {"pypi": {"findings": {"CVE-2026-59951": {"fixed": "1.30.0"}}}})
    monkeypatch.setattr(ff, "default_scanner", lambda: (lambda ref: {}))
    monkeypatch.setattr(ff, "evaluate", lambda *a, **kw: [_decision()])
    calls: list[list[str]] = []
    monkeypatch.setattr(ff, "sh", _fake_sh(calls))
    monkeypatch.setattr(
        ff,
        "issues_by_title",
        lambda: {"Fix-forward: bump mcp to 1.30.0 (CVE-2026-59951)": {"number": 7, "state": "OPEN"}},
    )

    def fail_propose(**_kw: Any) -> dict:
        raise AssertionError("a known proposal must not be re-authored")

    monkeypatch.setattr(ff, "propose", fail_propose)
    rc = ff.main(["--state", str(state), "--apply", "--requirements", str(tmp_path / "requirements.txt")])
    assert rc == 0
    assert "already proposed" in capsys.readouterr().out


def test_main_apply_records_blocked_evidence_and_proposes_batch(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    registry_path = tmp_path / "waivers.yaml"
    registry_path.write_text(
        "version: 1\n"
        "policy:\n"
        "  max_window_days: 90\n"
        "  default_owner: security-oncall\n"
        "waivers:\n"
        "  - id: CVE-2026-0001\n"
        "    scope: third-party\n"
        "    severity: HIGH\n"
        "    source: trivy\n"
        '    carriers: ["img:1.0"]\n'
        "    rationale: synthetic entry for the 847d CLI tests\n"
        "    created: 2026-10-17\n"
        "    expires: 2027-01-15\n",
        encoding="utf-8",
    )
    state = _state(tmp_path, {})
    blocked = _decision(
        cve="CVE-2026-0001",
        decision="blocked",
        evidence="no tag clears it",
        recheck="upstream ships a fixed tag",
        bump=None,
    )
    monkeypatch.setattr(ff, "default_scanner", lambda: (lambda ref: {}))
    monkeypatch.setattr(ff, "evaluate", lambda *a, **kw: [blocked])
    monkeypatch.setattr(ff, "sh", _fake_sh([]))
    monkeypatch.setattr(ff, "issues_by_title", lambda: {})
    # Derived re-render must never touch the repo's real files in tests.
    monkeypatch.setattr(ff, "write_derived", lambda rendered: [])
    captured: dict[str, Any] = {}

    def fake_propose(**kw: Any) -> dict:
        captured.update(kw)
        kw["edit_builder"](tmp_path)  # execute the real edit path
        return {"branch": kw["branch"], "issue": "https://example/issues/1"}

    monkeypatch.setattr(ff, "propose", fake_propose)
    rc = ff.main(
        [
            "--state",
            str(state),
            "--apply",
            "--registry",
            str(registry_path),
            "--repo-root",
            str(tmp_path),
        ]
    )
    assert rc == 0
    assert captured["branch"] == "bot/fix-forward-no-fix-20261021"
    # The batched edit wrote the recording to the registry itself.
    text = registry_path.read_text(encoding="utf-8")
    assert "    fix_available: false" in text
    assert "recheck_trigger:" in text
    out = capsys.readouterr().out
    assert "registry records changed: **1**" in out
    assert "proposals authored: **1**" in out


def test_main_apply_comments_evidence_on_monitor_issue(tmp_path: Path, monkeypatch, capsys) -> None:
    state = _state(tmp_path, {})
    blocked = _decision(
        cve="CVE-2027-00001",
        surface="image:grafana/grafana",
        decision="blocked",
        evidence="no tag clears it",
        recheck="upstream ships a fixed tag",
        bump=None,
    )
    monkeypatch.setattr(ff, "default_scanner", lambda: (lambda ref: {}))
    monkeypatch.setattr(ff, "evaluate", lambda *a, **kw: [blocked])
    monkeypatch.setattr(ff, "sh", _fake_sh([]))
    monkeypatch.setattr(
        ff,
        "issues_by_title",
        lambda: {ff.issue_title("image:grafana/grafana", "CVE-2027-00001"): {"number": 9, "state": "OPEN"}},
    )
    monkeypatch.setattr(ff, "issue_has_marker", lambda number, **_kw: False)
    comments: list[tuple[int, str]] = []
    monkeypatch.setattr(ff, "comment_issue", lambda number, body, **_kw: comments.append((number, body)))
    monkeypatch.setattr(ff, "propose", lambda **_kw: (_ for _ in ()).throw(AssertionError("no entry → no branch")))

    rc = ff.main(["--state", str(state), "--apply"])
    assert rc == 0
    assert comments and comments[0][0] == 9
    assert comments[0][1].startswith(ff.ISSUE_MARKER)
    assert "fix_available: false" in comments[0][1]
    assert "evidence comment on #9" in capsys.readouterr().out


def test_main_unreadable_state_is_a_hard_error(tmp_path: Path, capsys) -> None:
    rc = ff.main(["--state", str(tmp_path / "missing.json")])
    assert rc == 2
    assert "unreadable state file" in capsys.readouterr().err


def test_pypi_metadata_uses_the_larger_cap(monkeypatch) -> None:
    """Regression guard for a bug the live end-to-end check found: real PyPI
    metadata for a project with history (aiohttp) exceeds the 256 KiB default
    cap, which made the mcp/semgrep `blocked` verdict unreachable. PyPI
    metadata fetches must pass the larger cap; OSV lookups must not."""
    seen: list[tuple[str, int]] = []

    def spy(url: str, *, timeout: float = 15.0, limit: int = ff.HTTP_LIMIT) -> dict:
        seen.append((url, limit))
        return {}

    monkeypatch.setattr(ff, "http_get_json", spy)
    ff.pypi_fetch("https://pypi.org/pypi/aiohttp/json")
    ff.pypi_fetch("https://api.osv.dev/v1/vulns/CVE-2026-59951")
    assert seen[0] == ("https://pypi.org/pypi/aiohttp/json", ff.PYPI_METADATA_LIMIT)
    assert seen[1][1] == ff.HTTP_LIMIT
    assert ff.PYPI_METADATA_LIMIT > ff.HTTP_LIMIT


def test_bytes_report_records_largest_first(tmp_path: Path) -> None:
    ff._BYTES_SEEN = [("https://a/1", 10), ("https://b/2", 999)]
    out = tmp_path / "bytes.json"
    try:
        ff._write_bytes_report(out)
    finally:
        ff._BYTES_SEEN = None
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["count"] == 2
    assert doc["largest"][0] == {"url": "https://b/2", "bytes": 999}


def test_bytes_report_never_raises_on_unwritable_path(tmp_path: Path) -> None:
    ff._BYTES_SEEN = [("https://a/1", 10)]
    try:
        ff._write_bytes_report(tmp_path / "no-such-dir" / "bytes.json")  # no exception
    finally:
        ff._BYTES_SEEN = None
