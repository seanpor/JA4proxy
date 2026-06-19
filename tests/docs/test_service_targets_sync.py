"""
tests/docs/test_service_targets_sync.py — Phase 106 sub-task 5.3.

Structure / sync test for ``docs/reference/SERVICE_TARGETS.md``. Asserts that the
consolidated service-targets doc stays in sync with the canonical SLO
runbooks under ``docs/runbooks/slo_*.md`` and contains the SLIs the
phase document enumerates. If a runbook adds a new SLO or this doc
drifts from its sources, these tests fail until SERVICE_TARGETS is
updated.
"""

import re
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def repo_root() -> Path:
    """Walk up from this file until a directory containing ``docs/`` is found."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "docs" / "reference" / "SERVICE_TARGETS.md").is_file():
            return parent
    raise RuntimeError("Could not locate repo root (docs/reference/SERVICE_TARGETS.md not found)")


@pytest.fixture(scope="module")
def service_targets_path(repo_root: Path) -> Path:
    return repo_root / "docs" / "reference" / "SERVICE_TARGETS.md"


@pytest.fixture(scope="module")
def service_targets_text(service_targets_path: Path) -> str:
    return service_targets_path.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def slo_runbooks(repo_root: Path) -> list[Path]:
    runbooks = sorted((repo_root / "docs" / "runbooks").glob("slo_*.md"))
    assert runbooks, "expected at least one docs/runbooks/slo_*.md runbook"
    return runbooks


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_service_targets_lists_every_slo_runbook(
    service_targets_text: str, slo_runbooks: list[Path]
) -> None:
    """Every slo_*.md runbook must be referenced by filename in SERVICE_TARGETS.md."""
    missing = [rb.name for rb in slo_runbooks if rb.name not in service_targets_text]
    assert not missing, (
        f"docs/reference/SERVICE_TARGETS.md does not reference SLO runbooks: {missing}. "
        "Add a row + cross-reference for each new runbook."
    )


def test_service_targets_has_required_slis(service_targets_text: str) -> None:
    """SLIs the phase doc enumerates must appear (case-insensitive substring)."""
    body = service_targets_text.lower()
    required = [
        "p50",
        "p99",
        "fp rate",
        "availability",
        "redis",
        "risk-score",
        "signal-collection",
    ]
    missing = [token for token in required if token.lower() not in body]
    assert not missing, (
        f"docs/reference/SERVICE_TARGETS.md is missing required SLI references: {missing}. "
        "Phase 106 enumerates: connection-accept latency p50/p99, FP rate, "
        "proxy availability, Redis availability, risk-score compute latency, "
        "signal-collection error rate."
    )


def test_service_targets_has_error_budget_section(service_targets_text: str) -> None:
    """Phase 106 requires an explicit error-budget policy section."""
    assert "error budget" in service_targets_text.lower() or (
        "error-budget" in service_targets_text.lower()
    ), "docs/reference/SERVICE_TARGETS.md must contain an 'error budget' / 'error-budget' section."


def test_service_targets_internal_links_resolve(
    service_targets_text: str, service_targets_path: Path
) -> None:
    """Every relative markdown link [text](path) in SERVICE_TARGETS must resolve."""
    base = service_targets_path.parent
    link_re = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
    broken: list[str] = []
    for _text, target in link_re.findall(service_targets_text):
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        path_part = target.split("#", 1)[0].split("?", 1)[0]
        if not path_part:
            continue
        resolved = (base / path_part).resolve()
        if not resolved.exists():
            broken.append(f"{target} -> {resolved}")
    assert not broken, f"Broken relative links in SERVICE_TARGETS.md: {broken}"
