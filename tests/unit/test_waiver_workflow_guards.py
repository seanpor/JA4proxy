"""
tests/unit/test_waiver_workflow_guards.py

Unit tests for the workflow wiring of the waiver lifecycle (Phase 847d).

These are not tests of the scripts — they are tests of the THIRD-PARTY
CONTEXT the scripts run in, and specifically of the ways that context can
make a check measure nothing while reporting success.

The defect this file exists for: Phase 829a (2026-08-19) added
`check_image_versions.py --list-third-party` to the re-affirmation workflow
without installing PyYAML. `setup-python` provides a CLEAN interpreter, so the
command exited 2, the command substitution swallowed it, the image list came
back EMPTY, the Trivy loop scanned NOTHING, the drift check ran against an
empty directory, and `renew_trivyignore.py` died with a traceback that
`| tee` hid. The job reported SUCCESS every day for 63 days.

A check that measures nothing and reports success is worse than no check: it
looks like coverage while providing none. These tests assert the guards that
make that failure mode loud.
"""
from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).parent.parent.parent
_WORKFLOWS = _ROOT / ".github" / "workflows"

RENEWAL = _WORKFLOWS / "trivyignore-renewal.yml"
MONITOR = _WORKFLOWS / "scan-baseline-monitor.yml"
CI = _WORKFLOWS / "ci.yml"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _run_blocks(path: Path) -> list[str]:
    """The `run:` script bodies of a workflow, de-indented."""
    import yaml

    doc = yaml.safe_load(_text(path))
    bodies: list[str] = []
    for job in doc["jobs"].values():
        for step in job.get("steps", []):
            if "run" in step:
                bodies.append(step["run"])
    return bodies


def _step_run(path: Path, name: str) -> str:
    """The `run:` body of the named step."""
    import yaml

    doc = yaml.safe_load(_text(path))
    for job in doc["jobs"].values():
        for step in job.get("steps", []):
            if step.get("name") == name:
                return step["run"]
    raise AssertionError(f"no step named {name!r} in {path.name}")


# ── the root cause: PyYAML on the runner ─────────────────────────────────────

def test_renewal_workflow_installs_pyyaml() -> None:
    """`setup-python` gives a clean interpreter, so PyYAML must be installed.

    Without it `check_image_versions.py` exits 2 at import time and the
    image list comes back empty.
    """
    body = _text(RENEWAL)
    assert "actions/setup-python" in body
    assert re.search(r"pip install[^\n]*pyyaml", body), (
        "the re-affirmation workflow runs scripts that import yaml at module "
        "level, so it must install pyyaml on the runner"
    )


def test_monitor_workflow_installs_pyyaml() -> None:
    """Same trap, same fix: the monitor runs the same scripts on the runner."""
    body = _text(MONITOR)
    assert "actions/setup-python" in body
    assert re.search(r"pip install[^\n]*pyyaml", body), (
        "the monitor workflow runs scripts that import yaml, so it must "
        "install pyyaml on the runner"
    )


def test_the_requirement_is_real_not_spurious() -> None:
    """The workflows need PyYAML because these scripts really import it.

    Without this, the two assertions above could be satisfied by a stray
    `pip install pyyaml` that no step needs — and the real breakage could
    come back.
    """
    versions = (_ROOT / "scripts" / "check_image_versions.py").read_text(encoding="utf-8")
    assert re.search(r"^\s*import yaml$", versions, re.MULTILINE), (
        "check_image_versions.py is expected to import yaml; if that changed, "
        "revisit the workflow dependency"
    )

    registry = (_ROOT / "scripts" / "render_waivers.py").read_text(encoding="utf-8")
    assert re.search(r"^\s*import yaml$", registry, re.MULTILINE), (
        "render_waivers.load_registry() is expected to need yaml"
    )


# ── "measured nothing" must be loud ──────────────────────────────────────────

def test_renewal_fails_loudly_when_the_image_list_is_empty() -> None:
    """An empty image list is a broken measurement, not a clean one.

    This is the exact shape of the 63-day failure: the list came back empty
    and the scan loop simply scanned nothing.
    """
    body = _step_run(RENEWAL, "Scan deployed images (no ignorefile) and diff against the waivers")
    assert "if ! images=" in body, "the listing must be guarded, not assumed"
    assert 'if [ -z "$images" ]' in body, "an empty image list must be an explicit error"
    assert "::error::" in body, "the failure must be annotated, not silent"


def test_renewal_reports_how_many_images_it_scanned() -> None:
    """The run must say what it measured, so 'nothing' is visible in the log."""
    body = _step_run(RENEWAL, "Scan deployed images (no ignorefile) and diff against the waivers")
    assert "scanning" in body and "third-party image(s)" in body


# ── exit codes must not be confused ──────────────────────────────────────────

def test_reaffirm_step_distinguishes_needs_human_from_broken() -> None:
    """Exit 1 means "a human must look"; exit 2+ means the script broke.

    The two must not look alike: a crash that reads as "nothing to do" is a
    silent failure, and `| tee` alone reports the pipeline as successful
    because the status it returns is tee's.
    """
    body = _step_run(RENEWAL, "Re-affirm entries expiring within 5 days")
    assert "${PIPESTATUS[0]}" in body, "the script's own exit code must be read"
    assert '"$rc" -gt 1' in body, "a broken script must fail the step"
    assert '"$rc" -eq 1' in body, "exit 1 must be recognised as 'needs a human'"


def test_reaffirm_step_does_not_swallow_the_exit_code() -> None:
    """`|| true` would discard exactly the signal the step needs."""
    body = _step_run(RENEWAL, "Re-affirm entries expiring within 5 days")
    assert "|| true" not in body


def test_drift_step_does_not_abort_on_a_clean_drift_finding() -> None:
    """The drift check exits 1 when it FINDS unwaived findings — its job.

    The runner runs `bash -e`, so an unguarded pipeline aborts the step on
    that exit and skips the justification refresh that follows.
    """
    body = _step_run(RENEWAL, "Scan deployed images (no ignorefile) and diff against the waivers")
    assert "${PIPESTATUS[0]}" in body
    assert "set +e" in body and "set -e" in body


# ── an escalation must reach a human ─────────────────────────────────────────

def test_issue_is_filed_on_needs_human_not_only_on_a_file_change() -> None:
    """A pure ESCALATION changes nothing on disk — and is exactly the case
    where a person has to decide. Gating the issue on "did a file change?"
    drops it on the floor."""
    import yaml

    doc = yaml.safe_load(_text(RENEWAL))
    steps = {s.get("name"): s for job in doc["jobs"].values() for s in job.get("steps", [])}
    issue_step = steps["File or refresh the tracking issue"]
    assert "needs_human" in issue_step["if"], (
        "the tracking issue must be filed whenever a human is needed"
    )
    assert "changed" not in issue_step["if"], (
        "the issue must not be gated on a file change alone"
    )


def test_the_branch_is_still_pushed_only_when_something_changed() -> None:
    """The branch carries deletions; there is nothing to push otherwise."""
    import yaml

    doc = yaml.safe_load(_text(RENEWAL))
    steps = {s.get("name"): s for job in doc["jobs"].values() for s in job.get("steps", [])}
    push_step = steps["Push branch if the registry changed"]
    assert "changed" in push_step["if"]


def test_fix_forward_step_announces_its_failures_distinctly() -> None:
    """Exit 2 means the bot did not run at all; that is not a quiet day."""
    body = _step_run(MONITOR, "Fix-forward proposals and recheck evidence")
    assert "::error::" in body, "a bot that could not run must say so"
    assert "::warning::" in body


# ── the CI trigger and the gate must ask the same question ──────────────────

def _job(path: Path, name: str) -> dict:
    import yaml

    doc = yaml.safe_load(_text(path))
    return doc["jobs"][name]


def test_ci_uses_the_gates_own_waiver_comparison() -> None:
    """Two definitions of "the waiver set changed" is a divergent list.

    The trigger in CI and the trigger in the gate must be the same question,
    asked the same way. The gate compares the applied ENTRIES; a byte-level
    paths-filter cannot, and put every surface in scope for a documentation
    edit — which then failed on an upstream CVE disclosed overnight, on a PR
    that had nothing to do with it.
    """
    body = _text(CI)
    assert "scan_regression.py --base origin/main --waiver-set-changed" in body, (
        "CI must ask the gate, not re-implement the question"
    )
    scope = _job(CI, "scan-scope")
    assert not [s for s in scope["steps"] if "paths-filter" in str(s.get("uses", ""))], (
        "the byte-level paths-filter cannot tell a waiver edit from a "
        "documentation edit"
    )


def test_ci_trigger_fails_closed() -> None:
    """A trigger that silently stops firing is the one failure a trigger must not have.

    If the detection job fails, is skipped, or never sets its output, the full
    scan must still run: the condition is "not unchanged", never "changed".
    """
    condition = _job(CI, "scan")["if"]
    assert "!= 'false'" in condition
    assert "== 'true'" not in condition


def test_ci_scan_scope_installs_pyyaml() -> None:
    """The gate imports `check_image_versions`, which imports yaml at module level."""
    scope = _job(CI, "scan-scope")
    assert any("setup-python" in str(s.get("uses", "")) for s in scope["steps"])
    assert re.search(r"pip install[^\n]*pyyaml", _text(CI))


def test_ci_trigger_reads_the_scripts_own_exit_code() -> None:
    """Three answers, three exit codes: changed, unchanged, and could-not-tell.

    "Could not tell" has to be distinguishable, or the caller cannot choose
    the safe answer. The runner runs `bash -e`, so the call must be guarded.
    """
    body = _step_run(CI, "Did the waiver set change?")
    assert "rc=$?" in body
    assert "waivers=true" in body and "waivers=false" in body
    assert "set +e" in body and "set -e" in body
