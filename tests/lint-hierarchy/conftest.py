"""
Shared fixtures for Phase 92 lint hierarchy tests.
"""

import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
MAKEFILE = REPO_ROOT / "Makefile"


@pytest.fixture(scope="session")
def makefile_text():
    """Return full Makefile text."""
    return MAKEFILE.read_text()


@pytest.fixture(scope="session")
def makefile_targets(makefile_text):
    """Return set of all target names declared in the Makefile."""
    targets = set()
    for line in makefile_text.splitlines():
        m = re.match(r'^([a-zA-Z0-9_][a-zA-Z0-9_\-]*):', line)
        if m:
            targets.add(m.group(1))
    return targets


@pytest.fixture(scope="session")
def phony_targets(makefile_text):
    """Return set of all .PHONY-declared targets."""
    phony = set()
    for line in makefile_text.splitlines():
        if line.startswith(".PHONY:"):
            phony.update(line[len(".PHONY:"):].split())
    return phony


@pytest.fixture(scope="session")
def make_help_output():
    """Run 'make help' and return stdout. Fails test if make crashes."""
    result = subprocess.run(
        ["make", "help"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result

