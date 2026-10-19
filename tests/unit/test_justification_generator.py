"""Phase 829b, outcomes O5/O6/O7 — carrier claims are generated, reasoning is not.

Reworked for Phase 847a: the generated artifact is now `security/waivers.yaml`
(rendered into `.trivyignore.*` by scripts/render_waivers.py), so the generator's
job changed from splicing prose into the ignorefile to rewriting each waiver's
`carriers:` list and re-rendering.

WHY THIS EXISTS
---------------
18 of 56 third-party exceptions claimed to cover images that had been removed
from the deployment — `promtail:3.6.11`, `grafana:13.0.4-ubuntu`,
`prom/haproxy-exporter:v0.15.0`. The waivers were correct; the stated reason was
false, which is the entire point of a *justified* exception.

The important half of this file is what the generator must NOT touch. The
`rationale` ("why not exploitable here") is a human judgement about our
deployment — "cadvisor is an internal-only sidecar with no host port published" —
and no scanner knows that. Generating it would produce confident text nobody had
thought about, which is worse than stale text someone once did.
"""

from __future__ import annotations

from pathlib import Path

from scripts import render_waivers
from scripts.refresh_trivyignore_justifications import refresh


def _reg(*entries):
    return {
        "version": 1,
        "policy": {"max_window_days": 90, "default_owner": "security-oncall"},
        "waivers": list(entries),
    }


def _entry(cve, carriers, rationale="HUMAN JUDGEMENT — never machine-written"):
    return {
        "id": cve,
        "scope": "third-party",
        "severity": "HIGH",
        "source": "trivy",
        "carriers": list(carriers),
        "rationale": rationale,
        "created": "2026-01-01",
        "expires": "2026-03-01",
    }


def test_carrier_claim_tracks_scan_data():
    reg = _reg(_entry("CVE-2026-1111", ["promtail:3.6.11"]))
    changed = refresh(reg, {"CVE-2026-1111": ["cadvisor:v0.52.1", "alloy:v1.18.1"]})
    assert changed == ["CVE-2026-1111"]
    assert reg["waivers"][0]["carriers"] == ["alloy:v1.18.1", "cadvisor:v0.52.1"]
    assert "promtail:3.6.11" not in reg["waivers"][0]["carriers"]


def test_generator_is_idempotent():
    """A second run with the same scan data must be a no-op."""
    reg = _reg(_entry("CVE-2026-1111", ["old:1.0"]))
    seen = {"CVE-2026-1111": ["cadvisor:v0.52.1"]}
    assert refresh(reg, seen) == ["CVE-2026-1111"]
    assert refresh(reg, seen) == []  # nothing left to change


def test_human_reasoning_is_untouched():
    """O6 — the judgement half must survive byte-identical."""
    reg = _reg(
        _entry(
            "CVE-2026-1111",
            ["old:1.0"],
            rationale="internal-only monitoring components with no host port published",
        )
    )
    refresh(reg, {"CVE-2026-1111": ["cadvisor:v0.52.1"]})
    assert (
        reg["waivers"][0]["rationale"]
        == "internal-only monitoring components with no host port published"
    )


def test_entry_count_is_unchanged():
    """A generator that dropped an entry would delete a waiver and break the gate."""
    reg = _reg(_entry("CVE-2026-1111", ["a"]), _entry("CVE-2026-2222", ["b"]))
    refresh(reg, {"CVE-2026-1111": ["x"], "CVE-2026-2222": ["y"]})
    assert {w["id"] for w in reg["waivers"]} == {"CVE-2026-1111", "CVE-2026-2222"}


def test_entry_with_no_measured_carriers_is_left_untouched():
    """An entry the scan reports nothing for is NOT blanked.

    A registry entry must name at least one carrier; clearing it would make the
    registry invalid. Such entries are surfaced as DEAD by
    check_trivyignore_drift.py instead (Phase 847d makes that a removal).
    """
    reg = _reg(_entry("CVE-2026-1111", ["kept:1.0"]))
    assert refresh(reg, {"CVE-2026-1111": []}) == []
    assert reg["waivers"][0]["carriers"] == ["kept:1.0"]


def test_pip_audit_entries_have_no_carriers_rewritten():
    reg = _reg(_entry("CVE-2026-1111", ["img:1.0"]))
    reg["waivers"][0]["source"] = "pip-audit"
    assert refresh(reg, {"CVE-2026-1111": ["other:2.0"]}) == []


def test_long_carrier_lists_wrap_in_render():
    """Six carriers must not produce a 200-column comment line."""
    many = [f"image-number-{i}:v1.2.3" for i in range(6)]
    reg = _reg(_entry("CVE-2026-1111", many))
    out = render_waivers.render_trivy(reg, "third-party")
    assert max(len(line) for line in out.splitlines()) <= 80


def test_real_registry_round_trips():
    """Sanity check against the real registry: refresh must not lose an entry.

    The unit fixtures are small and tidy; the real registry is large. Losing an
    entry would delete a waiver and break `make scan-images`.
    """
    registry = render_waivers.load_registry()
    before = {w["id"] for w in registry["waivers"]}
    refresh(registry, {wid: ["some-image:v1"] for wid in before})
    after = {w["id"] for w in registry["waivers"]}
    assert before == after, f"entries lost: {sorted(before - after)}"


def test_render_waivers_is_deterministic():
    registry = render_waivers.load_registry()
    first = render_waivers.render_all(registry)
    second = render_waivers.render_all(registry)
    assert {p.name: t for p, t in first.items()} == {p.name: t for p, t in second.items()}
