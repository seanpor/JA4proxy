"""TDD validation for the Docker Compose smoke test script.

Checks structural correctness of scripts/smoke/test_docker_compose.sh
without requiring Docker to be running.
"""

import os
import stat

import pytest

SCRIPT_PATH = os.path.join(
    os.path.dirname(__file__), os.pardir, "scripts", "smoke", "test_docker_compose.sh"
)
SCRIPT_PATH = os.path.normpath(SCRIPT_PATH)


@pytest.fixture(scope="module")
def script_content():
    """Read the smoke test script content once for all tests."""
    with open(SCRIPT_PATH, "r") as f:
        return f.read()


class TestSmokeScriptExists:
    def test_script_file_exists(self):
        assert os.path.isfile(SCRIPT_PATH), (
            f"Smoke script not found at {SCRIPT_PATH}"
        )

    def test_script_is_executable(self):
        mode = os.stat(SCRIPT_PATH).st_mode
        assert mode & stat.S_IXUSR, "Script must be executable (user)"
        assert mode & stat.S_IXGRP, "Script must be executable (group)"


class TestSmokeScriptStructure:
    def test_shebang(self, script_content):
        assert script_content.startswith("#!/usr/bin/env bash"), (
            "Script must start with #!/usr/bin/env bash"
        )

    def test_set_euo_pipefail(self, script_content):
        lines = script_content.splitlines()
        assert "set -euo pipefail" in lines, (
            "Script must contain 'set -euo pipefail' as a standalone line"
        )

    def test_uses_docker_compose_v2(self, script_content):
        assert "docker compose" in script_content, (
            "Script must use 'docker compose' (v2 space-separated syntax)"
        )

    def test_does_not_use_docker_compose_v1(self, script_content):
        # Check for the v1 hyphenated command form, excluding comments and filenames
        import re
        # Match "docker-compose" used as a command (not in a filename/string context)
        for line in script_content.splitlines():
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            # Only flag lines where docker-compose appears as a command invocation
            if re.search(r'(?<!\w)docker-compose\s', stripped):
                raise AssertionError(
                    f"Script must not use 'docker-compose' (v1 hyphenated command): {stripped}"
                )


class TestSmokeScriptBehavior:
    def test_creates_results_directory(self, script_content):
        assert "mkdir -p" in script_content
        assert "test-results/smoke" in script_content

    def test_health_url_default(self, script_content):
        assert "HEALTH_URL" in script_content
        assert "http://localhost:8090/api/v1/health/deep" in script_content

    def test_writes_result_file(self, script_content):
        assert "docker-compose.result" in script_content

    def test_tears_down_with_docker_compose_down(self, script_content):
        assert "docker compose" in script_content
        assert "down -v" in script_content

    def test_cleanup_trap_exists(self, script_content):
        """Teardown must run on all exit paths via a trap, not just the happy path."""
        assert "trap cleanup" in script_content, (
            "Script must use 'trap cleanup EXIT' to ensure teardown on failure"
        )
