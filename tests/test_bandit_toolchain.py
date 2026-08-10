"""Guard the bandit SAST toolchain pin — regression test for the PR #340 silent-coverage-loss.

Bandit's B502/B604/B607 plugins reference ``ast.Num``, removed in Python 3.12.
Running bandit on 3.12+ does not fail the build — it raises per-file exceptions,
drops the offending files, and **still exits 0**. The gate stays green while
scanning almost nothing.

That is not hypothetical. `Dockerfile.bandit` was pinned to ``python:3.11-slim``
in PR #163 precisely for this reason, with an explanatory comment. PR #340
("build(deps): bump python from 3.11-slim to 3.14-slim") bumped it anyway.
Measured effect of that bump on ``src/analytics/`` (33 files, 6731 LOC):

    python:3.11-slim   42 plugins loaded    0 file errors    full coverage
    python:3.14-slim   36 plugins loaded   32 file errors    ~no coverage

Six plugins (B104-B108) vanished from the extension loader entirely, which is
why the run also emitted ``WARNING Unknown test found in profile: B104`` — the
Makefile skips B104, but on 3.14 no such test is registered.

Because bandit exits 0 in the broken state, no scan gate can detect this. These
static assertions are the only thing standing between a routine base-image bump
and the silent loss of Python SAST coverage.

Unblocks removal of the pin: a bandit release whose plugins no longer reference
``ast.Num``. At that point bump the tag and delete this file.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE_BANDIT = REPO_ROOT / "Dockerfile.bandit"
MAKEFILE = REPO_ROOT / "Makefile"

# `FROM python:<tag>` — captures the tag.
FROM_RE = re.compile(r"^FROM\s+python:(\S+)", re.MULTILINE)

# A Makefile line that invokes bandit. Captures the text preceding `bandit`.
BANDIT_INVOCATION_RE = re.compile(r"^\s*@?(.*?)\bbandit\b\s+-r", re.MULTILINE)


def test_bandit_dockerfile_pinned_to_python_311() -> None:
    """Dockerfile.bandit must stay on Python 3.11 — see module docstring."""
    tags = FROM_RE.findall(DOCKERFILE_BANDIT.read_text(encoding="utf-8"))

    assert tags, f"no `FROM python:<tag>` line found in {DOCKERFILE_BANDIT.name}"
    assert len(tags) == 1, f"expected exactly one FROM python line, got {tags}"

    assert tags[0].startswith("3.11"), (
        f"{DOCKERFILE_BANDIT.name} is on python:{tags[0]}, but bandit's plugins "
        "require Python 3.11 (`ast.Num` was removed in 3.12).\n"
        "On 3.12+ bandit drops whole files with 'module ast has no attribute "
        "Num' AND STILL EXITS 0 — the gate goes green with no real coverage.\n"
        "This is a deliberate pin, not staleness. Do not bump it; see the "
        "comment in Dockerfile.bandit and this file's docstring."
    )


def test_bandit_always_runs_through_the_pinned_image() -> None:
    """Every Makefile bandit call must go via $(BANDIT_RUN), not the host python.

    The 3.11 pin only protects the scan if the scan actually runs inside that
    image. A bare `bandit -r ...` recipe would silently use whatever Python the
    host or tools image has, reintroducing the same coverage loss by another
    route.
    """
    invocations = BANDIT_INVOCATION_RE.findall(MAKEFILE.read_text(encoding="utf-8"))

    assert invocations, "no `bandit -r` invocations found in Makefile"

    unpinned = [prefix for prefix in invocations if "BANDIT_RUN" not in prefix]
    assert not unpinned, (
        "Makefile invokes bandit outside the pinned $(BANDIT_RUN) image; these "
        f"recipes would run on an unpinned Python: {unpinned}\n"
        "Route them through $(BANDIT_RUN) so the 3.11 pin applies."
    )


@pytest.mark.parametrize("skipped_id", ["B104"])
def test_skipped_bandit_ids_are_documented(skipped_id: str) -> None:
    """IDs passed to `--skip` must be justified in a Makefile comment.

    `--skip` on an ID bandit does not know is a no-op that only warns
    ("Unknown test found in profile"), so a typo'd or vanished ID silently
    weakens nothing but hides intent. Requiring the justification comment keeps
    the suppression reviewable.
    """
    makefile = MAKEFILE.read_text(encoding="utf-8")

    assert f"--skip {skipped_id}" in makefile, (
        f"{skipped_id} is no longer skipped in the Makefile; drop it from this "
        "test's parametrize list."
    )

    comment_lines = [
        line
        for line in makefile.splitlines()
        if line.lstrip().startswith("#") and skipped_id in line
    ]
    assert comment_lines, (
        f"bandit --skip {skipped_id} has no explanatory Makefile comment. "
        "Every suppression needs a stated reason."
    )
