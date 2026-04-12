"""
Unit tests for scripts/sync-roadmap.py

Tests that action_plan paths preserve their directory prefix (e.g. archive/)
rather than being stripped to a bare filename by os.path.basename().
"""

import os
import sys

import pytest

# Allow importing scripts/ as a module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))

import importlib.util

# Import sync-roadmap.py via importlib since the filename contains a hyphen
_script_path = os.path.join(
    os.path.dirname(__file__), "..", "..", "scripts", "sync-roadmap.py"
)
_spec = importlib.util.spec_from_file_location("sync_roadmap", _script_path)
sync_roadmap = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sync_roadmap)


def _make_manifest(action_plan: str, status: str = "IN_PROGRESS") -> dict:
    """Return a minimal manifest dict with a single phase using the given action_plan."""
    return {
        "epics": [],
        "phases": {
            5: {
                "name": "Test Phase",
                "status": status,
                "summary": "A test phase",
                "action_plan": action_plan,
                "gaps": [],
                "tasks_remaining": [],
            }
        },
    }


class TestActionPlanLinkPreservesPrefix:
    """action_plan links in generated TODO.md must preserve the path relative
    to docs/phases/ so that archive/ and other subdirectory prefixes are not lost.
    """

    def test_archive_prefix_preserved_in_progress(self):
        """An IN_PROGRESS phase with an archive/ action_plan path must include
        the archive/ prefix in the generated link, not just the bare filename.
        """
        manifest = _make_manifest("docs/phases/archive/PHASE_05.md", status="IN_PROGRESS")
        output = sync_roadmap.generate_todo(manifest)

        # The link text and href should NOT be the bare filename
        assert "[PHASE_05.md](PHASE_05.md)" not in output, (
            "os.path.basename() is stripping the archive/ prefix from the link"
        )

        # The link should preserve the archive/ prefix
        assert "archive/PHASE_05.md" in output, (
            "The archive/ prefix must be preserved in the generated action_plan link"
        )

    def test_archive_prefix_preserved_planned(self):
        """A PROPOSED phase with an archive/ action_plan path must also preserve
        the archive/ prefix.
        """
        manifest = _make_manifest("docs/phases/archive/PHASE_05.md", status="PROPOSED")
        output = sync_roadmap.generate_todo(manifest)

        assert "[PHASE_05.md](PHASE_05.md)" not in output, (
            "os.path.basename() is stripping the archive/ prefix from the link"
        )
        assert "archive/PHASE_05.md" in output, (
            "The archive/ prefix must be preserved in the generated action_plan link"
        )

    def test_plain_phase_path_still_works(self):
        """A standard docs/phases/PHASE_13.md path (no subdirectory) should
        still produce a correct link.
        """
        manifest = _make_manifest("docs/phases/PHASE_13.md", status="IN_PROGRESS")
        output = sync_roadmap.generate_todo(manifest)

        # With no subdirectory, the filename alone is acceptable — but we want
        # the path relative to docs/phases/ which is just PHASE_13.md
        assert "PHASE_13.md" in output

    def test_link_is_relative_to_docs_phases(self):
        """The generated link href should be relative to docs/phases/ (the
        directory containing TODO.md), so that in-repo navigation works.

        For docs/phases/archive/PHASE_05.md the href must be archive/PHASE_05.md.
        """
        manifest = _make_manifest("docs/phases/archive/PHASE_05.md", status="IN_PROGRESS")
        output = sync_roadmap.generate_todo(manifest)

        # Confirm the exact expected markdown link fragment appears
        assert "[archive/PHASE_05.md](archive/PHASE_05.md)" in output, (
            "Expected markdown link [archive/PHASE_05.md](archive/PHASE_05.md) "
            f"not found in output:\n{output}"
        )
