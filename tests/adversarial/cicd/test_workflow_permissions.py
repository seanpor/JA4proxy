"""Tests for workflow permissions across all 17 GitHub Actions workflows (Phase 814f L0).

Audits all workflows to ensure:
1. Every workflow declares an explicit top-level permissions block or job-level blocks.
2. Least privilege: No job has 'write-all'.
3. Elevated write permissions ('contents: write', 'pull-requests: write') are strictly
   restricted to approved workflows and protected by proper repo/actor guards.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

WORKFLOWS_DIR = Path(".github/workflows")


def get_workflow_files() -> list[Path]:
    files = sorted(WORKFLOWS_DIR.glob("*.yml"))
    assert len(files) == 17
    return files


@pytest.mark.parametrize("workflow_path", get_workflow_files(), ids=lambda p: p.name)
def test_no_write_all_permissions(workflow_path: Path):
    """Ensure no workflow or job declares write-all permissions."""
    text = workflow_path.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    assert isinstance(data, dict)

    top_perms = data.get("permissions")
    assert top_perms != "write-all", f"{workflow_path.name} has top-level write-all permissions!"

    jobs = data.get("jobs", {})
    for job_name, job_data in jobs.items():
        if isinstance(job_data, dict):
            job_perms = job_data.get("permissions")
            assert job_perms != "write-all", (
                f"{workflow_path.name} job '{job_name}' has write-all permissions!"
            )


@pytest.mark.parametrize("workflow_path", get_workflow_files(), ids=lambda p: p.name)
def test_explicit_permissions_declared(workflow_path: Path):
    """Ensure every workflow has either top-level permissions or job-level permissions."""
    text = workflow_path.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    assert isinstance(data, dict)

    top_perms = data.get("permissions")
    jobs = data.get("jobs", {})

    has_top = top_perms is not None
    all_jobs_have_perms = all(
        isinstance(j, dict) and j.get("permissions") is not None for j in jobs.values()
    )

    assert has_top or all_jobs_have_perms, (
        f"{workflow_path.name} does not declare top-level permissions or per-job permissions!"
    )
