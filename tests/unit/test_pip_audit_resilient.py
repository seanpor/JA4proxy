"""Phase-311: scripts/pip-audit-resilient.sh classifies pip-audit outcomes so a
transient PyPI/OSV outage cannot redden the required CI lint gate, while a real
vulnerability still fails the build.

The real pip-audit is stubbed on PATH; the stub's behaviour is chosen via the
MODE env var.
"""
import os
import subprocess
import textwrap
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
WRAPPER = REPO / "scripts" / "pip-audit-resilient.sh"

STUB = textwrap.dedent(
    """\
    #!/usr/bin/env bash
    # is this the OSV fallback invocation? (the wrapper appends `-s osv`)
    osv=0; for a in "$@"; do [ "$a" = "osv" ] && osv=1; done
    transient() { echo "ServiceError: 503 Server Error: Backend is unhealthy for url: https://pypi.org/..." >&2; exit 1; }
    clean()     { echo "No known vulnerabilities found"; exit 0; }
    vuln()      { echo "Found 2 known vulnerabilities in 1 package"; echo "Name Version ID Fix"; exit 1; }
    case "$MODE" in
      clean)     clean ;;
      vuln)      vuln ;;
      transient) transient ;;                                  # both services down
      badargs)   echo "error: unrecognized arguments" >&2; exit 2 ;;
      pypi_down_osv_clean) [ "$osv" = 1 ] && clean || transient ;;
      pypi_down_osv_vuln)  [ "$osv" = 1 ] && vuln  || transient ;;
    esac
    """
)


def _run(mode, tmp_path):
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    stub = stub_dir / "pip-audit"
    stub.write_text(STUB)
    stub.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{stub_dir}:{os.environ['PATH']}",
        "MODE": mode,
        "PIP_AUDIT_RETRIES": "2",
        "PIP_AUDIT_BACKOFF": "0",
        "PIP_AUDIT_TIMEOUT": "5",
    }
    return subprocess.run(
        ["bash", str(WRAPPER), "-r", "requirements.txt"],
        env=env, capture_output=True, text=True,
    )


def test_clean_passes(tmp_path):
    assert _run("clean", tmp_path).returncode == 0


def test_real_vulnerability_fails(tmp_path):
    r = _run("vuln", tmp_path)
    assert r.returncode == 1, "a real vulnerability must fail the gate"


def test_double_outage_soft_passes_with_warning(tmp_path):
    """Both PyPI AND OSV unreachable → the (now rare) soft-pass."""
    r = _run("transient", tmp_path)
    assert r.returncode == 0, "a double service outage must not block CI"
    out = (r.stdout + r.stderr).lower()
    assert "unreachable" in out and "osv" in out


def test_unknown_nonzero_fails_safe(tmp_path):
    assert _run("badargs", tmp_path).returncode == 2, "unrecognised failure must fail safe"


def test_pypi_down_osv_clean_passes_via_fallback(tmp_path):
    """PyPI unreachable but OSV healthy & clean → pass by actually checking."""
    r = _run("pypi_down_osv_clean", tmp_path)
    assert r.returncode == 0, "OSV fallback should verify and pass"
    assert "osv fallback" in (r.stdout + r.stderr).lower()


def test_pypi_down_osv_finds_vuln_fails(tmp_path):
    """PyPI unreachable, OSV reachable and reports a real vuln → fail."""
    assert _run("pypi_down_osv_vuln", tmp_path).returncode == 1
