"""
Phase 822 — the .trivyignore first-/third-party split must stay separated.

WHY THIS EXISTS
---------------
Until Phase 822 there was a single `.trivyignore`, and the Makefile passed it
to BOTH `scan-images` (third-party) and `scan-first-party`. Trivy's ignorefile
has no per-image scoping, so every waiver granted to an abandoned monitoring
sidecar also suppressed the same finding in the proxy we ship.

That was not hypothetical. CVE-2026-39821 and CVE-2026-46600 were waived with
justifications written entirely about Grafana/Promtail/Alertmanager/cAdvisor,
while both were live in `ja4proxy:2.0.0` — an internet-facing TLS proxy — where
they were fixed outright by bumping the Go builder 1.26.5 -> 1.26.6.

The failure was silent in both directions: the scan passed, and the file gave
no way to express "this waiver is for someone else's container". These tests
make the separation structural rather than a convention someone has to
remember.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent.parent

FIRST_PARTY = ROOT / ".trivyignore.first-party"
THIRD_PARTY = ROOT / ".trivyignore.third-party"
LEGACY = ROOT / ".trivyignore"
MAKEFILE = ROOT / "Makefile"

ENTRY_RE = re.compile(
    r"^\s*((?:CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}))\s+exp:", re.M
)

# Fixed by the Go 1.26.5 -> 1.26.6 bump in this phase. They legitimately remain
# in the THIRD-party file (pinned upstream images still carry them), but must
# never reappear on the first-party side — that would mean we had gone back to
# waiving a CVE in our own image that a rebuild already clears.
FIXED_FOR_US_BY_GO_BUMP = {
    "CVE-2026-39821",
    "CVE-2026-46600",
    "CVE-2026-33818",
    "CVE-2026-56853",
    "CVE-2026-56858",
    "CVE-2026-56859",
    "CVE-2026-56860",
    "CVE-2026-56862",
}


def entries(path: Path) -> set[str]:
    return set(ENTRY_RE.findall(path.read_text(encoding="utf-8")))


class TestSplitExists:
    def test_both_files_exist(self):
        assert FIRST_PARTY.exists(), ".trivyignore.first-party is missing"
        assert THIRD_PARTY.exists(), ".trivyignore.third-party is missing"

    def test_legacy_single_file_is_gone(self):
        """A resurrected `.trivyignore` would silently re-merge the scopes."""
        assert not LEGACY.exists(), (
            ".trivyignore has reappeared. It was split in Phase 822 because one "
            "shared ignorefile let a third-party sidecar waiver suppress the same "
            "finding in an image we build."
        )


class TestMakefileWiring:
    def test_scan_targets_use_different_ignorefiles(self):
        content = MAKEFILE.read_text()
        assert "/scan/.trivyignore.third-party" in content, (
            "scan-images must use .trivyignore.third-party"
        )
        assert "/scan/.trivyignore.first-party" in content, (
            "scan-first-party must use .trivyignore.first-party"
        )

    def test_no_makefile_reference_to_the_retired_single_file(self):
        """`--ignorefile /scan/.trivyignore \\` must not survive anywhere."""
        content = MAKEFILE.read_text()
        stale = re.findall(r"--ignorefile\s+\S*\.trivyignore(?![.\w-])", content)
        assert not stale, (
            f"Makefile still references the retired single ignorefile: {stale}"
        )

    def test_each_scan_target_references_only_its_own_scope(self):
        """Guard the exact mis-edit made while implementing this phase.

        A single sed over both occurrences pointed scan-first-party at the
        third-party file — which would have restored the original bug while
        looking like the fix.
        """
        lines = MAKEFILE.read_text().splitlines()
        target, seen = None, {}
        for line in lines:
            if line.startswith("scan-images:"):
                target = "scan-images"
            elif line.startswith("scan-first-party:"):
                target = "scan-first-party"
            elif line and not line[0].isspace() and line.endswith(":"):
                target = None
            if target and "--ignorefile" in line:
                seen.setdefault(target, []).append(line.strip())

        assert "scan-images" in seen and "scan-first-party" in seen, (
            f"could not locate both scan targets' ignorefile lines: {seen}"
        )
        for line in seen["scan-images"]:
            assert "third-party" in line, f"scan-images uses wrong scope: {line}"
        for line in seen["scan-first-party"]:
            assert "first-party" in line, f"scan-first-party uses wrong scope: {line}"


class TestScopeSeparation:
    def test_no_cve_appears_in_both_files(self):
        """A CVE in both files is a waiver we forgot to fix on our own side."""
        both = entries(FIRST_PARTY) & entries(THIRD_PARTY)
        assert not both, (
            f"CVE(s) waived in BOTH scopes: {sorted(both)}. If our image really "
            "carries it too, fix it there (base/dep bump) rather than waiving it "
            "— that is the whole point of the split."
        )

    def test_go_bump_fixed_cves_are_not_waived_first_party(self):
        overlap = FIXED_FOR_US_BY_GO_BUMP & entries(FIRST_PARTY)
        assert not overlap, (
            f"{sorted(overlap)} are waived first-party but were FIXED for our "
            "images by the Go 1.26.6 bump. Rebuild instead of waiving."
        )

    def test_first_party_list_is_small_and_deliberate(self):
        """The stricter rule should keep this list short; a jump needs review."""
        count = len(entries(FIRST_PARTY))
        assert count <= 8, (
            f"{count} first-party waivers. The rule for images we build is that a "
            "fix reachable by ANY rebuild is not a waiver candidate — re-check "
            "each entry before raising this bound."
        )


class TestFormatPolicy:
    @pytest.mark.parametrize("path", [FIRST_PARTY, THIRD_PARTY], ids=["first", "third"])
    def test_every_entry_has_an_expiry(self, path):
        """Phase 226: no undated waivers, in either scope."""
        bare = re.findall(
            r"^\s*((?:CVE-\d{4}-\d+|GHSA-[a-z0-9-]+))\s*$",
            path.read_text(encoding="utf-8"),
            re.M,
        )
        assert not bare, f"{path.name}: entries with no exp: date: {bare}"

    @pytest.mark.parametrize("path", [FIRST_PARTY, THIRD_PARTY], ids=["first", "third"])
    def test_header_states_the_scope_rule(self, path):
        head = path.read_text(encoding="utf-8")[:3000]
        assert "phase 822" in head.lower() or "Phase 822" in head, (
            f"{path.name} header should record why the split exists"
        )
