"""
Phase documents must be filed according to their manifest status.

WHY THIS EXISTS
---------------
`docs/phases/` holds open work; `complete/` and `cancelled/` are the archives.
Nothing enforced the split, so a phase could be marked COMPLETE in
`manifest.yaml` while its plan sat in the root indefinitely. Found 2026-08-17
with three such docs (820, 822, 823) — all closed in the preceding days, none
moved, because "move the doc" is a close-out step that lives only in a human's
memory.

The failure is quiet: nothing breaks, the root directory just slowly stops
meaning "open work", and the phase list becomes noise.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
PHASES = REPO / "docs" / "phases"
MANIFEST = PHASES / "manifest.yaml"

# Statuses that mean "no longer open work", and where their doc belongs.
# CLOSED is deliberately mapped to None: the repo files CLOSED phases in BOTH
# complete/ (2) and cancelled/ (3), so there is no convention to enforce — only
# that they are not left in the root. Inventing one here would fail on
# pre-existing history for no benefit.
ARCHIVED: dict[str, str | None] = {
    "COMPLETE": "complete",
    "CANCELLED": "cancelled",
    "SUPERSEDED": "complete",
    "CLOSED": None,
}
_DOC_RE = re.compile(r"^PHASE_([0-9]+[a-z]?)(?:_notes)?\.md$")


def _status_by_id() -> dict[str, str]:
    data = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))["phases"]
    return {str(k): (v or {}).get("status", "") for k, v in data.items()}


def _docs_in(folder: Path) -> list[tuple[str, str]]:
    """(phase_id, filename) for every phase doc directly in `folder` on disk OR in git index."""
    names: set[str] = {f.name for f in folder.glob("PHASE_*.md")}

    # Also inspect git index so files removed on disk via `mv` but still tracked in git are caught
    try:
        rel = folder.relative_to(REPO)
        res = subprocess.run(
            ["git", "-c", "safe.directory=*", "ls-files", f"{rel}/PHASE_*.md"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                line = line.strip()
                if line:
                    names.add(Path(line).name)
    except Exception:
        pass

    out = []
    for name in sorted(names):
        m = _DOC_RE.match(name)
        if m:
            out.append((m.group(1), name))
    return out


def test_archived_phases_are_not_left_in_the_root():
    """A COMPLETE/CANCELLED phase's doc belongs in its archive folder."""
    status = _status_by_id()
    stranded = [
        (name, status[pid])
        for pid, name in _docs_in(PHASES)
        if status.get(pid) in ARCHIVED
    ]
    assert not stranded, (
        "phase doc(s) left in docs/phases/ after being archived in manifest.yaml "
        "— move them to the folder matching their status:\n  "
        + "\n  ".join(
            f"{n} is {st} → docs/phases/{ARCHIVED[st]}/"
            if ARCHIVED[st]
            else f"{n} is {st} → docs/phases/complete/ or cancelled/"
            for n, st in stranded
        )
    )


def test_open_phases_are_not_buried_in_an_archive():
    """The reverse: open work must not be filed away where nobody looks."""
    status = _status_by_id()
    buried = []
    for folder in ("complete", "cancelled"):
        d = PHASES / folder
        if not d.is_dir():
            continue
        for pid, name in _docs_in(d):
            st = status.get(pid)
            if st and st not in ARCHIVED:
                buried.append((folder, name, st))
    assert not buried, (
        "open phase doc(s) filed in an archive folder:\n  "
        + "\n  ".join(f"{f}/{n} is {st}" for f, n, st in buried)
    )


@pytest.mark.parametrize("field", ["action_plan"])
def test_manifest_action_plan_paths_resolve(field):
    """`action_plan` must point at a file that exists.

    Moving a doc without updating the manifest leaves a dangling pointer, and
    `make sync` renders that path into the generated views.
    """
    data = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))["phases"]
    missing = [
        f"{pid}: {(v or {}).get(field)}"
        for pid, v in data.items()
        if (v or {}).get(field) and not (REPO / (v or {})[field]).is_file()
    ]
    assert not missing, "manifest action_plan path(s) do not exist:\n  " + "\n  ".join(missing)


def test_git_tracked_zombie_docs_are_detected(monkeypatch):
    """If a phase doc is deleted on disk but remains tracked in git, _docs_in must catch it."""
    fake_run = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout="docs/phases/PHASE_9999.md\n",
        stderr="",
    )
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: fake_run)
    docs = dict(_docs_in(PHASES))
    assert "9999" in docs
    assert docs["9999"] == "PHASE_9999.md"

