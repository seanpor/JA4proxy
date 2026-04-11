"""Phase 64h — TDD tests for MTTR baseline measurement script.

Validates structural correctness of scripts/measure_mttr.sh WITHOUT running Docker:
- Script exists and is executable
- Proper bash shebang and strict mode
- Uses docker compose v2 (space-separated), never docker-compose v1
- References HEALTH_URL with correct default
- Produces output to MTTR_BASELINE.md
- Tests 4 scenarios (1, 2, 4, 5 — NOT scenario 3 which is GameDay-only)
- Derives Redis volume name dynamically (no hardcoded volume name)
- Has a require_healthy function
- Uses COMPOSE variable for all compose commands
"""

import os
import pathlib
import re
import stat

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "scripts" / "measure_mttr.sh"


@pytest.fixture(scope="module")
def script_text():
    """Load the MTTR measurement script text."""
    assert SCRIPT_PATH.exists(), f"{SCRIPT_PATH} does not exist"
    return SCRIPT_PATH.read_text()


@pytest.fixture(scope="module")
def script_lines(script_text):
    """Return lines of the script for line-by-line checks."""
    return script_text.splitlines()


class TestScriptExists:
    """Script file presence and permissions."""

    def test_script_file_exists(self):
        assert SCRIPT_PATH.exists(), "scripts/measure_mttr.sh must exist"

    def test_script_is_executable(self):
        mode = SCRIPT_PATH.stat().st_mode
        assert mode & stat.S_IXUSR, "Script must be executable (user execute bit)"


class TestShebangAndStrictMode:
    """Bash shebang and strict mode at the top of the script."""

    def test_shebang_line(self, script_lines):
        assert script_lines[0] == "#!/usr/bin/env bash", (
            "First line must be #!/usr/bin/env bash"
        )

    def test_strict_mode(self, script_text):
        assert "set -euo pipefail" in script_text, (
            "Script must use 'set -euo pipefail'"
        )


class TestDockerComposeV2:
    """Script must use docker compose v2 (space-separated), never v1 hyphenated."""

    def test_no_docker_compose_v1(self, script_text):
        # Match docker-compose as a command (not inside a comment about v1)
        # but exclude the pattern inside variable assignments or comparisons
        lines = script_text.splitlines()
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            assert "docker-compose" not in line, (
                f"Line {i} uses docker-compose v1 syntax: {line.strip()}"
            )

    def test_compose_variable_defined(self, script_text):
        assert re.search(r'COMPOSE=.*docker compose', script_text), (
            "Script must define COMPOSE variable defaulting to 'docker compose'"
        )

    def test_uses_compose_variable(self, script_text):
        # All compose invocations should use $COMPOSE, not bare 'docker compose'
        lines = script_text.splitlines()
        in_heredoc = False
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            # Track heredoc blocks (output templates, not commands)
            if "<<EOF" in line or "<<'EOF'" in line:
                in_heredoc = True
                continue
            if stripped == "EOF":
                in_heredoc = False
                continue
            if in_heredoc:
                continue
            if stripped.startswith("#"):
                continue
            # Skip the COMPOSE variable definition line itself
            if "COMPOSE=" in line:
                continue
            # Skip log/echo lines that mention docker compose as prose
            if stripped.startswith("log ") or stripped.startswith("echo "):
                continue
            # If line has 'docker compose' it should be via $COMPOSE
            if "docker compose" in line and "$COMPOSE" not in line:
                pytest.fail(
                    f"Line {i} uses bare 'docker compose' instead of $COMPOSE: "
                    f"{line.strip()}"
                )


class TestHealthURL:
    """HEALTH_URL variable with correct default."""

    def test_health_url_defined(self, script_text):
        assert "HEALTH_URL" in script_text, "Script must reference HEALTH_URL"

    def test_health_url_default(self, script_text):
        assert "http://localhost:8090/api/v1/health/deep" in script_text, (
            "HEALTH_URL default must be http://localhost:8090/api/v1/health/deep"
        )


class TestOutputFile:
    """Script must produce MTTR_BASELINE.md."""

    def test_output_variable(self, script_text):
        assert re.search(r'OUTPUT=.*MTTR_BASELINE\.md', script_text), (
            "Script must set OUTPUT to MTTR_BASELINE.md"
        )

    def test_writes_output_file(self, script_text):
        assert re.search(r'cat\s*>\s*"\$OUTPUT"', script_text), (
            "Script must write to $OUTPUT via heredoc"
        )


class TestScenarios:
    """Script must test scenarios 1, 2, 4, 5 (NOT 3)."""

    def test_scenario_1_redis_failure(self, script_text):
        assert "Scenario 1" in script_text, "Must include Scenario 1: Redis failure"
        assert re.search(r'MEASURED_S\[1\]', script_text), (
            "Must record MEASURED_S[1]"
        )

    def test_scenario_2_single_node(self, script_text):
        assert "Scenario 2" in script_text, "Must include Scenario 2: Single node failure"
        assert re.search(r'MEASURED_S\[2\]', script_text), (
            "Must record MEASURED_S[2]"
        )

    def test_scenario_4_dial_corruption(self, script_text):
        assert "Scenario 4" in script_text, "Must include Scenario 4: Dial corruption"
        assert re.search(r'MEASURED_S\[4\]', script_text), (
            "Must record MEASURED_S[4]"
        )

    def test_scenario_5_redis_data_loss(self, script_text):
        assert "Scenario 5" in script_text, "Must include Scenario 5: Redis data loss"
        assert re.search(r'MEASURED_S\[5\]', script_text), (
            "Must record MEASURED_S[5]"
        )

    def test_no_scenario_3(self, script_text):
        # Scenario 3 is GameDay-only, should not be automated
        assert not re.search(r'MEASURED_S\[3\]', script_text), (
            "Scenario 3 must NOT be automated (GameDay-only)"
        )

    def test_scenario_3_mentioned_as_gameday(self, script_text):
        assert "GameDay" in script_text or "gameday" in script_text.lower(), (
            "Script should mention Scenario 3 is GameDay-only"
        )


class TestDynamicRedisVolume:
    """Redis volume name must be derived dynamically, never hardcoded."""

    def test_derives_redis_volume(self, script_text):
        assert re.search(r'REDIS_VOLUME=.*volume\s+ls', script_text), (
            "REDIS_VOLUME must be derived from 'volume ls' command"
        )

    def test_no_hardcoded_redis_volume(self, script_text):
        # Common hardcoded patterns to reject
        hardcoded = [
            "ja4proxy2_redis_data",
            "ja4proxy_redis_data",
            "redis-data",
        ]
        for pattern in hardcoded:
            assert pattern not in script_text, (
                f"Redis volume name must not be hardcoded as '{pattern}'"
            )


class TestRequireHealthy:
    """Script must have a require_healthy function."""

    def test_require_healthy_function_defined(self, script_text):
        assert re.search(r'require_healthy\s*\(\)', script_text), (
            "Script must define a require_healthy() function"
        )

    def test_require_healthy_uses_curl(self, script_text):
        # Extract the function body (rough: from definition to next function or end)
        match = re.search(
            r'require_healthy\s*\(\)\s*\{(.*?)\n\}',
            script_text,
            re.DOTALL,
        )
        assert match, "Could not find require_healthy function body"
        body = match.group(1)
        assert "curl" in body, "require_healthy must use curl to check health"

    def test_require_healthy_has_timeout(self, script_text):
        match = re.search(
            r'require_healthy\s*\(\)\s*\{(.*?)\n\}',
            script_text,
            re.DOTALL,
        )
        assert match, "Could not find require_healthy function body"
        body = match.group(1)
        assert "timeout" in body.lower(), (
            "require_healthy must support a timeout parameter"
        )


class TestRTOTargets:
    """Verify RTO targets are present in the output table."""

    def test_rto_300s_for_scenario_1(self, script_text):
        assert "300s" in script_text, "Must reference 300s RTO"

    def test_rto_120s_for_scenario_2(self, script_text):
        assert "120s" in script_text, "Must reference 120s RTO"

    def test_rto_180s_for_scenario_4(self, script_text):
        assert "180s" in script_text, "Must reference 180s RTO"


class TestRedisKeyNames:
    """Verify correct Redis key names are used (not phantom keys)."""

    def test_uses_correct_dial_key(self, script_text):
        """Script must use config:dial, not ja4proxy:dial."""
        # Filter out comments and heredoc template lines
        for i, line in enumerate(script_text.splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if "ja4proxy:dial" in line:
                pytest.fail(
                    f"Line {i} uses phantom key 'ja4proxy:dial' — "
                    f"should be 'config:dial': {line.strip()}"
                )

    def test_uses_correct_reload_channel(self, script_text):
        """Script must use config:reload, not ja4proxy:config_reload."""
        for i, line in enumerate(script_text.splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if "ja4proxy:config_reload" in line:
                pytest.fail(
                    f"Line {i} uses phantom channel 'ja4proxy:config_reload' — "
                    f"should be 'config:reload': {line.strip()}"
                )

    def test_config_dial_present(self, script_text):
        assert "config:dial" in script_text, (
            "Script must reference the correct Redis key 'config:dial'"
        )

    def test_config_reload_present(self, script_text):
        assert "config:reload" in script_text, (
            "Script must reference the correct Redis channel 'config:reload'"
        )


class TestOverallResult:
    """Script must compute and report overall PASS/FAIL."""

    def test_overall_result(self, script_text):
        assert "OVERALL" in script_text, (
            "Script must compute an OVERALL result"
        )

    def test_exits_nonzero_on_failure(self, script_text):
        assert "exit 1" in script_text, (
            "Script must exit 1 on overall failure"
        )
