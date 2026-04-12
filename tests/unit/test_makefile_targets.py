"""Tests that required Makefile targets are defined. Phase 100."""
import re
from pathlib import Path

MAKEFILE_PATH = Path(__file__).parent.parent.parent / "Makefile"


def _get_makefile_targets() -> set:
    """Parse Makefile and return all defined target names."""
    content = MAKEFILE_PATH.read_text()
    # Match lines like "target-name:" or "target-name: deps"
    # Exclude variable assignments (lines with := or =) and pattern rules (%)
    targets = set()
    for match in re.finditer(r"^([a-zA-Z0-9_\-]+)\s*:", content, re.MULTILINE):
        name = match.group(1)
        targets.add(name)
    return targets


def test_quick_start_target_exists():
    """Makefile must define a quick-start target (phase-100-I)."""
    targets = _get_makefile_targets()
    assert "quick-start" in targets, (
        f"'quick-start' target not found in Makefile. Found targets include: "
        f"{sorted(t for t in targets if 'quick' in t or 'start' in t)}"
    )


def test_perf_test_basic_target_exists():
    """Makefile must define a perf-test-basic target (phase-100-I)."""
    targets = _get_makefile_targets()
    assert "perf-test-basic" in targets, (
        f"'perf-test-basic' target not found in Makefile. Found targets include: "
        f"{sorted(t for t in targets if 'perf' in t or 'test' in t)}"
    )


def test_quick_start_script_exists():
    """scripts/quick-start.sh must exist for the quick-start Makefile target."""
    script = Path(__file__).parent.parent.parent / "scripts" / "quick-start.sh"
    assert script.exists(), f"scripts/quick-start.sh not found at {script}"


def test_basic_perf_test_script_exists():
    """scripts/basic_perf_test.sh must exist for the perf-test-basic Makefile target."""
    script = Path(__file__).parent.parent.parent / "scripts" / "basic_perf_test.sh"
    assert script.exists(), f"scripts/basic_perf_test.sh not found at {script}"
