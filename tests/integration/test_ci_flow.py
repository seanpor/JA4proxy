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
* ``scan-images`` / ``scan-first-party`` run the Phase 847b JSON gate and fail on
  HIGH *and* CRITICAL — not just CRITICAL;
* ``scripts/pipeline_summary.py`` summarises each stage quickly without
  recursing back into ``make`` (a regression guard for the infinite loop).
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = REPO_ROOT / "Makefile"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import trivy_image_report  # noqa: E402


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


def _one_finding_report(severity: str) -> str:
    """A minimal Trivy report containing exactly one finding of `severity`."""
    return json.dumps({
        "SchemaVersion": 2,
        "ArtifactName": "example/img:1",
        "Results": [{"Vulnerabilities": [{
            "VulnerabilityID": "CVE-2026-00001",
            "Severity": severity,
            "PkgName": "pkg",
            "InstalledVersion": "1.0.0",
        }]}],
    })


def test_scan_images_gates_on_high_and_critical(tmp_path, monkeypatch):
    """scan-images scans **both** HIGH and CRITICAL, and fails on either.

    The previous version of this test asserted ``grep -c "HIGH"`` in the recipe —
    pinning the token-counting defect itself (Phase 847b) — and its docstring
    claimed HIGH was "advisory" for third-party images, which the recipe
    contradicted (``if high -gt 0 || crit -gt 0 → fail=1``). Severity policy now
    lives in the gate, so the assertions follow the code: the recipe must invoke
    the gate and propagate its failure, the gate's *argv* must carry the policy,
    and both severities must actually fail.
    """
    monkeypatch.chdir(REPO_ROOT)
    recipe = _recipe("scan-images")
    assert "scripts/trivy_image_report.py" in recipe, "scan-images no longer runs the JSON gate"
    assert "|| fail=1" in recipe, "a gate that fails must redden the target"
    assert "--ignorefile /scan/.trivyignore.third-party" in recipe

    argv = trivy_image_report.trivy_cmd(
        "example/img:1", "/scan/.trivyignore.third-party", str(tmp_path)
    )
    assert argv[argv.index("--severity") + 1] == "HIGH,CRITICAL", "gate must scan HIGH+CRITICAL"
    assert argv[argv.index("--format") + 1] == "json", "the gate must count JSON, not table text"
    assert argv[argv.index("--ignorefile") + 1] == "/scan/.trivyignore.third-party"
    assert trivy_image_report.TRIVY_IMAGE in argv, "the pinned Trivy image must be the one run"
    assert "/var/run/docker.sock:/var/run/docker.sock" not in argv, (
        "third-party images come from registries; the gate must not get host socket access"
    )

    # HIGH must block, not just CRITICAL (this is the assertion the old test named).
    for severity in ("HIGH", "CRITICAL"):
        report = tmp_path / f"{severity}.json"
        report.write_text(_one_finding_report(severity))
        assert trivy_image_report.main(["--json-file", str(report)]) == 1, (
            f"a {severity} finding must fail scan-images"
        )


def test_scan_first_party_gates_on_high_and_critical(tmp_path, monkeypatch):
    """Phase 317: first-party images are ours, so scan-first-party gates on HIGH+
    CRITICAL (not just CRITICAL). It also builds the profile-gated CI-only
    test/trafficgen images first so they are actually scanned, not scanned-as-absent.

    Phase 847b: this target carried the identical token-counting defect as
    scan-images, so it now runs the same gate — which needs the docker socket
    (locally-built images exist in no registry) and the first-party ignorefile.
    """
    monkeypatch.chdir(REPO_ROOT)
    recipe = _recipe("scan-first-party")
    assert "scripts/trivy_image_report.py" in recipe, "scan-first-party no longer runs the JSON gate"
    assert "|| fail=1" in recipe, "a gate that fails must redden the target"
    assert "--ignorefile /scan/.trivyignore.first-party" in recipe
    assert "--docker-socket" in recipe, "locally-built images cannot be pulled from a registry"
    assert "Dockerfile.test" in recipe and "Dockerfile.trafficgen" in recipe, (
        "scan-first-party must build the profile-gated test/trafficgen images so they "
        "are not scanned-as-absent (a vacuous pass)"
    )

    argv = trivy_image_report.trivy_cmd(
        "ja4proxy:2.0.0", "/scan/.trivyignore.first-party", str(tmp_path), docker_socket=True
    )
    assert argv[argv.index("--severity") + 1] == "HIGH,CRITICAL"
    assert argv[argv.index("--ignorefile") + 1] == "/scan/.trivyignore.first-party"
    assert "/var/run/docker.sock:/var/run/docker.sock" in argv


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
