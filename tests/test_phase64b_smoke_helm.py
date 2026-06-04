"""Phase 64b — TDD validation for scripts/smoke/test_helm_kind.sh.

Checks structural correctness of the Helm + kind smoke script without
requiring kind or helm to be installed.
"""

import os
import stat

import pytest

SCRIPT_PATH = os.path.join(
    os.path.dirname(__file__), "..", "scripts", "smoke", "test_helm_kind.sh"
)
SCRIPT_PATH = os.path.normpath(SCRIPT_PATH)


@pytest.fixture
def script_content():
    with open(SCRIPT_PATH, "r") as f:
        return f.read()


class TestHelmKindSmokeScript:
    """Validate the Helm + kind smoke test script structure."""

    def test_script_exists(self):
        assert os.path.isfile(SCRIPT_PATH), f"Script not found at {SCRIPT_PATH}"

    def test_script_is_executable(self):
        mode = os.stat(SCRIPT_PATH).st_mode
        assert mode & stat.S_IXUSR, "Script must be executable (user)"

    def test_shebang(self, script_content):
        assert script_content.startswith(
            "#!/usr/bin/env bash"
        ), "Script must start with #!/usr/bin/env bash"

    def test_strict_mode(self, script_content):
        assert "set -euo pipefail" in script_content

    def test_skip_when_kind_absent(self, script_content):
        # Script must check for kind and exit 0 with SKIP message
        assert "command -v kind" in script_content
        assert "SKIP:" in script_content

    def test_fail_when_helm_absent(self, script_content):
        # Script must check for helm and fail (not skip)
        assert "command -v helm" in script_content
        # The helm check should use fail(), not exit 0
        lines = script_content.splitlines()
        for i, line in enumerate(lines):
            if "command -v helm" in line:
                # Look at surrounding lines for fail (not exit 0)
                context = "\n".join(lines[max(0, i - 2) : i + 4])
                assert (
                    "fail" in context.lower()
                ), "Missing helm should call fail(), not exit 0"
                break

    def test_cluster_name(self, script_content):
        assert "ja4proxy-smoke" in script_content

    def test_cleanup_trap(self, script_content):
        assert "trap cleanup EXIT" in script_content or "trap cleanup" in script_content
        assert "kind delete cluster" in script_content

    def test_helm_chart_path(self, script_content):
        assert "deploy/charts/ja4proxy/" in script_content

    def test_result_file(self, script_content):
        # The script defines RESULTS_DIR="test-results/smoke" and writes to
        # "$RESULTS_DIR/helm-kind.result" — check both pieces are present.
        assert 'RESULTS_DIR="test-results/smoke"' in script_content
        assert "helm-kind.result" in script_content

    def test_no_docker_compose_v1(self, script_content):
        # Must not use hyphenated docker-compose (v1 syntax)
        assert (
            "docker-compose" not in script_content
        ), "Script must not use docker-compose (v1). Use 'docker compose' (v2) if needed."
