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
    case "$MODE" in
      clean)     echo "No known vulnerabilities found"; exit 0 ;;
      vuln)      echo "Found 2 known vulnerabilities in 1 package"; echo "Name Version ID Fix"; exit 1 ;;
      transient) echo "ServiceError: 503 Server Error: Backend is unhealthy for url: https://pypi.org/pypi/scapy/2.7.0/json" >&2; exit 1 ;;
      badargs)   echo "error: unrecognized arguments" >&2; exit 2 ;;
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


def test_transient_outage_soft_passes_with_warning(tmp_path):
    r = _run("transient", tmp_path)
    assert r.returncode == 0, "a transient service outage must not block CI"
    assert "unreachable" in (r.stdout + r.stderr).lower()


def test_unknown_nonzero_fails_safe(tmp_path):
    assert _run("badargs", tmp_path).returncode == 2, "unrecognised failure must fail safe"
