"""Tests for expression injection across all GitHub Actions workflows (Phase 814f L0).

Audits all 16 GitHub Actions workflow files for unsafe inline expansion of
${{ ... }} expressions inside `run:` blocks. Values derived from untrusted
contexts (head_ref, PR title/body, commit message, issue content, etc.) must
never be interpolated directly into shell strings. Instead, they must be passed
via intermediate environment variables (`env:`).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

WORKFLOWS_DIR = Path(".github/workflows")

# Patterns matching untrusted contexts that an external actor can influence.
UNTRUSTED_EXPRESSION_PATTERNS = [
    re.compile(r"\$\{\{\s*github\.head_ref\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.pull_request\.title\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.pull_request\.body\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.pull_request\.head\.ref\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.pull_request\.head\.label\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.issue\.title\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.issue\.body\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.comment\.body\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.review\.body\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.review_comment\.body\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.commits\[.*\]\.message\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.head_commit\.message\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.head_commit\.author\..*\s*\}\}"),
]


def get_workflow_files() -> list[Path]:
    files = sorted(WORKFLOWS_DIR.glob("*.yml"))
    assert len(files) == 16, f"Expected 16 workflow files in {WORKFLOWS_DIR}, found {len(files)}"
    return files


@pytest.mark.parametrize("workflow_path", get_workflow_files(), ids=lambda p: p.name)
def test_no_untrusted_expression_injection_in_run_steps(workflow_path: Path):
    """Every run step in every workflow must pass untrusted expressions via env, never inline."""
    text = workflow_path.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    assert isinstance(data, dict), f"Failed to parse workflow YAML in {workflow_path}"

    jobs = data.get("jobs", {})
    assert isinstance(jobs, dict), f"No jobs defined in {workflow_path}"

    violations: list[str] = []
    for job_id, job_data in jobs.items():
        if not isinstance(job_data, dict):
            continue
        steps = job_data.get("steps", [])
        for step_idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            run_block = step.get("run")
            if not isinstance(run_block, str):
                continue

            for pattern in UNTRUSTED_EXPRESSION_PATTERNS:
                matches = pattern.findall(run_block)
                if matches:
                    violations.append(
                        f"Job '{job_id}' step #{step_idx} ('{step.get('name', 'unnamed')}') "
                        f"contains unsafe inline expression: {matches}"
                    )

    assert not violations, (
        f"Untrusted expression injection detected in {workflow_path.name}:\n"
        + "\n".join(f"  - {v}" for v in violations)
    )


def test_synthetic_expression_injection_negative_control():
    """Verify scanner catches simulated inline expression injection."""
    bad_run = "git checkout ${{ github.head_ref }}\necho 'done'"
    found = False
    for pattern in UNTRUSTED_EXPRESSION_PATTERNS:
        if pattern.search(bad_run):
            found = True
            break
    assert found, "Negative control failed to detect simulated github.head_ref injection"
