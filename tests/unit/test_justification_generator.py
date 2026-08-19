"""Phase 829b, outcomes O5/O6/O7 — carrier claims are generated, reasoning is not.

WHY THIS EXISTS
---------------
18 of 56 third-party exceptions claimed to cover images that had been removed
from the deployment — `promtail:3.6.11`, `grafana:13.0.4-ubuntu`,
`prom/haproxy-exporter:v0.15.0`. The waivers were correct; the stated reason was
false, which is the entire point of a *justified* exception. A reviewer trusting
that text was being told the waiver covered something it did not.

They were fixed by hand once (#459). Nothing stopped them rotting again.

The important half of this file is what the generator must NOT touch. "Why not
exploitable here" is a human judgement about our deployment — "cadvisor is an
internal-only sidecar with no host port published" — and no scanner knows that.
Generating it would produce confident text nobody had thought about, which is
worse than stale text someone once did.
"""

from __future__ import annotations

import json
from pathlib import Path

from scripts.refresh_trivyignore_justifications import MARKER, build_claim, refresh


def _carriers(**kw) -> dict:
    return {k: list(v) for k, v in kw.items()}


SAMPLE = """\
# =============================================================================
# Header — dated history lives here and must never be regenerated.
#
# ── 2026-08-06 remediation (Phase 818) ──
#   Historical record: promtail 3.6.11 and grafana 13.0.4-ubuntu were the
#   carriers at the time. This text is TRUE AS OF THEN and must survive.
# =============================================================================

# Why no fix: Affects grafana:13.0.4-ubuntu and promtail:3.6.11 (both
# already on newest stable tag) as a transitive dependency.
# Why not exploitable: internal-only monitoring components with no host port
# published; none terminates TLS from an untrusted peer.
# Re-review at expiry: check for upstream rebuilds.
CVE-2026-1111 exp:2026-08-26

# Why no fix: Affects promtail v3.6.11 (EOL, no newer tag exists).
# Why not exploitable: log shipper on an internal network.
CVE-2026-2222 exp:2026-08-26
"""


def test_carrier_line_matches_scan_data(tmp_path: Path) -> None:
    out = refresh(
        SAMPLE,
        _carriers(**{"CVE-2026-1111": ["cadvisor v0.52.1"], "CVE-2026-2222": ["alloy v1.18.1"]}),
        "2026-08-19",
    )

    assert "cadvisor v0.52.1" in out
    assert "alloy v1.18.1" in out
    # The false claims are gone.
    assert "promtail:3.6.11" not in out.split("CVE-2026-1111")[1]


def test_generator_is_idempotent(tmp_path: Path) -> None:
    """A second run must be a no-op.

    Without a marker the generator would stack a new claim above the previous
    one on every weekly invocation, and the file would grow forever — which is
    the disease, not the cure.
    """
    once = refresh(SAMPLE, _carriers(**{"CVE-2026-1111": ["cadvisor v0.52.1"],
                                        "CVE-2026-2222": ["alloy v1.18.1"]}), "2026-08-19")
    twice = refresh(once, _carriers(**{"CVE-2026-1111": ["cadvisor v0.52.1"],
                                       "CVE-2026-2222": ["alloy v1.18.1"]}), "2026-08-19")

    assert once == twice
    assert once.count(MARKER) == 2, "one claim per entry, not one per run"


def test_human_reasoning_is_untouched() -> None:
    """O6 — the judgement half must survive byte-identical.

    This is the line that matters most in the file and the one a generator has
    no business writing.
    """
    out = refresh(SAMPLE, _carriers(**{"CVE-2026-1111": ["cadvisor v0.52.1"]}), "2026-08-19")

    assert (
        "# Why not exploitable: internal-only monitoring components with no host port"
        in out
    )
    assert "# Re-review at expiry: check for upstream rebuilds." in out
    assert "# Why not exploitable: log shipper on an internal network." in out


def test_dated_history_is_untouched() -> None:
    """O7 — history records what was true then; rewriting it would falsify it."""
    out = refresh(SAMPLE, _carriers(**{"CVE-2026-1111": ["cadvisor v0.52.1"]}), "2026-08-19")

    header = out.split("# Why no fix")[0]
    assert "promtail 3.6.11 and grafana 13.0.4-ubuntu were the" in header
    assert "This text is TRUE AS OF THEN and must survive." in header


def test_entry_count_is_unchanged() -> None:
    """A generator that dropped an entry would delete a waiver and break the gate."""
    out = refresh(SAMPLE, _carriers(**{"CVE-2026-1111": ["x"], "CVE-2026-2222": ["y"]}),
                  "2026-08-19")

    for cve in ("CVE-2026-1111", "CVE-2026-2222"):
        assert f"{cve} exp:2026-08-26" in out
    assert out.count("exp:2026-08-26") == SAMPLE.count("exp:2026-08-26")


def test_dead_entry_is_labelled_as_deletable() -> None:
    """An entry nothing carries should say so, not claim a phantom carrier."""
    out = refresh(SAMPLE, _carriers(**{"CVE-2026-1111": []}), "2026-08-19")

    block = out.split("CVE-2026-1111")[0]
    assert "NO deployed image carries this any more" in block
    assert "DEAD" in block


def test_long_carrier_lists_wrap() -> None:
    """Six carriers must not produce a 200-column line."""
    many = [f"image-number-{i} v1.2.3" for i in range(6)]
    lines = build_claim("CVE-1", many, "2026-08-19")

    assert all(len(line) <= 80 for line in lines), [line for line in lines if len(line) > 80]
    for name in many:
        assert any(name in line for line in lines)


def test_unknown_cve_is_treated_as_dead_not_skipped() -> None:
    """A CVE absent from the scan data has no carriers — say so.

    Silently leaving the old claim would preserve exactly the staleness this
    script exists to remove.
    """
    out = refresh(SAMPLE, _carriers(**{"CVE-2026-1111": ["cadvisor v0.52.1"]}), "2026-08-19")

    tail = out.split("CVE-2026-1111 exp:2026-08-26")[1]
    assert "NO deployed image carries this any more" in tail


def test_real_ignorefile_round_trips(tmp_path: Path) -> None:
    """Sanity check against the actual file: no entry may be lost.

    The unit fixtures are small and tidy; the real file has 56 entries, wrapped
    prose, unicode arrows and several hand-written formats. Losing an entry here
    would delete a waiver and break `make scan-images`.
    """
    real = Path(__file__).resolve().parents[2] / ".trivyignore.third-party"
    if not real.exists():
        return
    text = real.read_text(encoding="utf-8")

    import re

    entry_re = re.compile(r"^(CVE-\d{4}-\d+|GHSA-[\w-]{4,})(?=\s|$)", re.M)
    before = set(entry_re.findall(text))

    out = refresh(text, {cve: ["some-image v1"] for cve in before}, "2026-08-19")
    after = set(entry_re.findall(out))

    assert before == after, f"entries lost: {sorted(before - after)}"
