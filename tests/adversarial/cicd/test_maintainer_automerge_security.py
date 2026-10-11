"""Tests for maintainer-automerge workflow security boundaries (Phase 814f L0/L1).

Audits .github/workflows/maintainer-automerge.yml:
Ensures that the job condition cannot be satisfied by an external PR from a fork,
even if the author creates a branch beginning with 'phase-' or attempts to spoof
the maintainer actor login.

Regression test for JA4PROXY-2026-0106.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

WORKFLOW_FILE = Path(".github/workflows/maintainer-automerge.yml")


def load_workflow() -> dict:
    return yaml.safe_load(WORKFLOW_FILE.read_text(encoding="utf-8"))


def test_maintainer_automerge_workflow_structure():
    """Verify workflow triggers on pull_request_target with appropriate permissions."""
    wf = load_workflow()
    triggers = wf.get("on", wf.get(True))
    assert "pull_request_target" in triggers

    perms = wf.get("permissions")
    assert isinstance(perms, dict)
    assert perms.get("contents") == "write"
    assert perms.get("pull-requests") == "write"


def evaluate_gate_condition(
    condition_expr: str,
    *,
    actor: str,
    head_ref: str,
    is_draft: bool,
    head_repo_full_name: str,
    base_repo_full_name: str,
) -> bool:
    """Simulate GitHub Actions expression evaluation of the workflow 'if' condition.

    Simulates GitHub context semantics:
    - github.actor
    - github.head_ref
    - github.event.pull_request.draft
    - github.event.pull_request.head.repo.full_name
    - github.repository
    """
    # Normalized evaluation based on expression rules
    if "github.event.pull_request.head.repo.full_name == github.repository" not in condition_expr:
        # Vulnerable version: missing repo qualification
        is_actor_or_branch = (actor == "seanpor" or head_ref.startswith("phase-"))
        return is_actor_or_branch and not is_draft
    else:
        # Hardened version: requires same-repository origin
        is_internal_repo = (head_repo_full_name == base_repo_full_name)
        is_actor_or_branch = (actor == "seanpor" or head_ref.startswith("phase-"))
        return is_internal_repo and is_actor_or_branch and not is_draft


def test_maintainer_automerge_condition_rejects_fork_phase_branch():
    """Adversarial Simulation: An external fork author names branch 'phase-exploit'.

    The workflow MUST NOT run or trigger auto-merge on external fork PRs.
    """
    wf = load_workflow()
    job = wf["jobs"]["maintainer-automerge"]
    condition = job.get("if", "")

    # Invariant: the workflow 'if' condition MUST explicitly verify that the PR
    # originates from the base repository itself, not an external fork.
    assert "github.event.pull_request.head.repo.full_name == github.repository" in condition, (
        f"CRITICAL: maintainer-automerge condition allows untrusted forks to execute! Current condition: {condition}"
    )


def test_simulation_reproduction_and_fix():
    """Verify that without repo qualification, an external attacker bypasses the gate,

    and with repo qualification, the external attacker is rejected.
    """
    vulnerable_expr = "(github.actor == 'seanpor' || startsWith(github.head_ref, 'phase-')) && !github.event.pull_request.draft"
    hardened_expr = "(github.event.pull_request.head.repo.full_name == github.repository) && (github.actor == 'seanpor' || startsWith(github.head_ref, 'phase-')) && !github.event.pull_request.draft"

    attacker_context = {
        "actor": "attacker-user",
        "head_ref": "phase-pwn",
        "is_draft": False,
        "head_repo_full_name": "attacker/JA4proxy",
        "base_repo_full_name": "seanpor/JA4proxy",
    }

    # Under the vulnerable expression, the attacker would trigger the workflow!
    assert evaluate_gate_condition(vulnerable_expr, **attacker_context) is True

    # Under the hardened expression, the attacker is rejected!
    assert evaluate_gate_condition(hardened_expr, **attacker_context) is False

    # Legitimate maintainer / phase branch from the base repository is accepted
    legitimate_context = {
        "actor": "seanpor",
        "head_ref": "phase-814f-pentest-supply-chain-cicd",
        "is_draft": False,
        "head_repo_full_name": "seanpor/JA4proxy",
        "base_repo_full_name": "seanpor/JA4proxy",
    }
    assert evaluate_gate_condition(hardened_expr, **legitimate_context) is True
