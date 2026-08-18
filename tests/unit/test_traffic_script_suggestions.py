"""
Commands a script tells the operator to run must actually work when pasted.

scripts/generate-tls-traffic.sh printed:

    curl -s -H Authorization: Bearer <token> http://localhost:11390/metrics

with no quotes, because the inner `"` characters sat inside an already
double-quoted echo string and closed the outer quoting rather than being
printed. Bash then splits that into separate arguments: curl sees
`-H Authorization:` — an empty header, which DELETES the header — and treats
the rest as URLs. The request went out unauthenticated and returned 401.

Copy-pasting the tool's own suggestion could never work.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPTS = sorted((REPO / "scripts").glob("*.sh"))


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_suggested_curl_commands_quote_their_headers(script: Path):
    """Any printed `-H` must carry quotes that survive into the output."""
    bad = []
    for lineno, line in enumerate(script.read_text(encoding="utf-8").splitlines(), 1):
        if "-H " not in line or "curl" not in line:
            continue
        if not line.lstrip().startswith(("echo", "printf")):
            continue  # a real invocation, not a suggestion
        # In an echoed string the quotes must be escaped (\") to be printed.
        if re.search(r'-H\s+\\"', line):
            continue
        # Single-quoted echo bodies pass quotes through literally.
        if re.search(r"-H\s+'", line) or re.search(r"echo\s+'", line.lstrip()):
            continue
        if re.search(r'-H\s+[A-Za-z-]+:', line):
            bad.append(f"{script.name}:{lineno}")
    assert not bad, (
        "printed curl suggestion(s) have an unquoted -H header — pasting them "
        "sends the request with NO auth header and gets 401:\n  "
        + "\n  ".join(bad)
    )
