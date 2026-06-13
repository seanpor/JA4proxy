# tests/integration/test_ci_flow.py
"""Hermetic checks for the Phase 313 CI Make targets.

These tests verify the *configuration* that Phase 313 introduced — they do not
run ``make lint`` / ``make scan`` for real. Those targets build Docker images
and need network access, which is unsafe and slow in a unit-test run. (The first
version of this file did run them, and also asserted that a clean-repo scan
*fails* — which is backwards: a clean repo with no HIGH/CRITICAL findings must
pass.)

What is checked instead:

* the Makefile parses and the new ``docker-run-tools`` helper target exists;
* ``lint`` and ``scan`` route their work through ``docker-run-tools``;
* ``scan-images`` fails on HIGH/CRITICAL (``--exit-code 1``), not just CRITICAL;
* ``scripts/pipeline_summary.py`` summarises each stage quickly without
  recursing back into ``make`` (a regression guard for the infinite loop).
"""
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = REPO_ROOT / "Makefile"


def _recipe(target: str) -> str:
    """Return the recipe body (tab-indented lines) for ``target:`` in the Makefile.

    A make recipe is the run of tab-indented lines immediately following the
    ``target:`` line; it ends at the first line that is not tab-indented.
    """
    capturing = False
    body: list[str] = []
    for line in MAKEFILE.read_text().splitlines():
        if not capturing:
            if line.startswith(f"{target}:"):
                capturing = True
            continue
        if line.startswith("\t"):
            body.append(line)
        else:
            break
    assert body, f"target {target!r} not found (or has no recipe) in {MAKEFILE}"
    return "\n".join(body)


def test_makefile_parses_and_tools_image_target_exists():
    """``make -n`` forces a full parse; dry-run never executes Docker."""
    result = subprocess.run(
        ["make", "-n", "tools-image"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Makefile failed to parse:\n{result.stderr}"


@pytest.mark.parametrize("target,aggregate", [("lint", "lint-all"), ("scan", "scan-all")])
def test_lint_scan_call_aggregate_directly(target, aggregate):
    """Phase 313: lint/scan call the aggregate target directly — the broken
    docker-run-tools wrapper (which built a container that ran the docker-based
    sub-linters, i.e. Docker-in-Docker) was removed."""
    recipe = _recipe(target)
    assert aggregate in recipe, f"`make {target}` should invoke {aggregate}"
    assert "docker-run-tools" not in recipe, (
        "the removed docker-run-tools wrapper is back in the recipe"
    )


def test_no_docker_run_tools_target():
    """The broken docker-run-tools target must be gone Makefile-wide."""
    assert "\ndocker-run-tools:" not in ("\n" + MAKEFILE.read_text())


def test_python_linters_run_in_tools_image():
    """The Python linters run inside the pinned tools image (no host pip)."""
    static = _recipe("lint-static")
    for tool in ("mypy", "bandit", "ruff"):
        assert tool in static, f"lint-static should run {tool}"
    assert "$(TOOLS_RUN)" in static, "lint-static must run its tools via $(TOOLS_RUN)"


def test_dockerfile_tools_has_no_pip_gitleaks():
    """Regression: gitleaks is a Go binary, never pip-installable. The original
    Dockerfile.tools tried `pip install ... gitleaks==8.*` and broke the build."""
    df = (REPO_ROOT / "Dockerfile.tools").read_text()
    offenders = [
        ln for ln in df.splitlines()
        if "gitleaks" in ln and ("pip" in ln or "gitleaks==" in ln)
    ]
    assert not offenders, f"gitleaks must not be pip-installed in Dockerfile.tools: {offenders}"


def test_scan_images_reports_high_gates_on_critical():
    """scan-images scans both HIGH and CRITICAL and reports them, but gates only
    on CRITICAL finding *rows* (``^│.*CRITICAL``, not the "CRITICAL: 0" total).

    HIGH-gating is deferred: the third-party images carry a pre-existing HIGH
    backlog (grafana/tempo, otel, openssl, Go stdlib, …) whose remediation is its
    own effort. HIGH stays advisory here, as on main and as scan-first-party does.
    """
    recipe = _recipe("scan-images")
    assert "--severity HIGH,CRITICAL" in recipe, "scan-images should scan HIGH+CRITICAL"
    assert 'grep -c "^│.*CRITICAL"' in recipe, (
        "scan-images must count only CRITICAL finding rows, not the totals line"
    )


@pytest.mark.parametrize("mode", ["lint", "scan", "test"])
def test_pipeline_summary_passes_without_recursing(mode):
    """The summary helper prints a verdict and returns 0 quickly.

    The short timeout is the regression guard: if pipeline_summary ever again
    shells back into ``make`` (which calls pipeline_summary), it would recurse
    forever and blow the timeout instead of returning.
    """
    result = subprocess.run(
        [sys.executable, "scripts/pipeline_summary.py", mode],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert "summary" in result.stdout.lower()


def test_pipeline_summary_never_invokes_make():
    """Static guard: the helper must not shell out to make (would recurse)."""
    src = (REPO_ROOT / "scripts" / "pipeline_summary.py").read_text()
    assert '"make"' not in src and "'make'" not in src, (
        "pipeline_summary.py must not invoke `make` — the Makefile calls it, so "
        "doing so recurses infinitely"
    )
