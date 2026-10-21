"""
tests/unit/test_go_toolchain_pins.py

The Go toolchain that CI builds and audits with must itself be patched.

The defect this file exists for: on 2026-10-21 the Go standard library
published **GO-2026-6809** (CVE-2026-111943), "Distrust compromised
intermediate certificates in crypto/x509". It affects every Go before
1.26.10 and 1.27.0 through 1.27.2. This repository calls the affected
symbol — `x509.Certificate.Verify` — at `internal/security/mtls.go:50`, so
govulncheck reported it as REACHABLE and exited 3.

That exit code came from a **required** job ("Go dependency audit
(govulncheck)") which pins its own Go — and it pinned 1.27.2, the
vulnerable one. Every pull request in the repository failed, and the
failure had nothing to do with the pull request: the repository's own
source did not change.

The toolchain that *ships* is a separate question. The first-party images
are still built on `golang:1.27.2-alpine`, Trivy still reports that, and
Phase 847g is that bump. This file is about the audit being meaningful:
auditing the source with a known-vulnerable compiler answers a question
nobody asked, because the finding is about the compiler, not about this
repository's code.

The last test asserts the guard is load-bearing — that the repository
really does call the affected symbol — so the pin requirement cannot be
quietly dropped on the grounds that "the CVE does not affect us".
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"

# GO-2026-6809 / CVE-2026-111943.
#   affected: every Go before 1.26.10, and 1.27.0 - 1.27.2
#   fixed in: 1.26.10 and 1.27.3
#   symbol:   crypto/x509.Certificate.Verify


def _version_parts(version: str) -> tuple[int, int, int]:
    parts = version.strip().split(".")
    while len(parts) < 3:
        parts.append("0")
    return int(parts[0]), int(parts[1]), int(parts[2])


def _is_patched(version: str) -> bool:
    """True when *version* is outside GO-2026-6809's affected range."""
    major, minor, patch = _version_parts(version)
    if major != 1:
        return False
    if minor <= 25:
        return False  # the 1.25 line is end-of-life and will not get a fix
    if minor == 26:
        return patch >= 10
    if minor == 27:
        return patch >= 3
    return True  # 1.28 and later


def _pinned_versions() -> list[tuple[str, str, str]]:
    """`(file, job, version)` for every Go version pinned in a workflow."""
    found: list[tuple[str, str, str]] = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for job_name, job in (doc.get("jobs") or {}).items():
            for step in job.get("steps") or []:
                pinned = (step.get("with") or {}).get("go-version")
                if pinned:
                    found.append((path.name, job_name, str(pinned)))
    return found


def test_no_workflow_pins_a_toolchain_with_the_x509_cve() -> None:
    """A required check pinned to a vulnerable compiler fails on every PR.

    With Go 1.27.2 pinned, govulncheck exited 3 on GO-2026-6809 and the
    required "Go dependency audit (govulncheck)" job failed for every pull
    request in the repository — verified locally against both toolchains.
    """
    pins = _pinned_versions()
    assert pins, "no Go version is pinned in any workflow — the guard has nothing to check"
    for filename, job, version in pins:
        assert _is_patched(version), (
            f"{filename}:{job} pins Go {version}, which is in GO-2026-6809's "
            "affected range (fixed in 1.26.10 / 1.27.3)"
        )


def test_the_module_directive_is_patched() -> None:
    """`go-version-file: go.mod` installs Go from the module's directive.

    The release workflows build the published CLI binary with that version,
    so the directive is a shipped-toolchain decision, not a formality.
    """
    text = (ROOT / "go.mod").read_text(encoding="utf-8")
    match = re.search(r"^go (\d+\.\d+(?:\.\d+)?)$", text, re.MULTILINE)
    assert match, "go.mod has no `go` directive"
    version = match.group(1)
    assert _is_patched(version), (
        f"go.mod requires Go {version}, which is in GO-2026-6809's affected range"
    )


def test_the_guard_is_load_bearing() -> None:
    """The repository really does call the affected symbol.

    Without this, the pin requirement could be quietly dropped on the
    grounds that "the CVE does not affect us" — and the day it does affect
    us, the guard would have been deleted along with the reason.
    """
    callers: list[str] = []
    for directory in ("internal", "cmd"):
        for path in (ROOT / directory).rglob("*.go"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            if "x509" in text and re.search(r"\.Verify\(", text):
                callers.append(str(path.relative_to(ROOT)))
    assert callers, (
        "no Go source calls x509.Certificate.Verify any more — re-check "
        "whether GO-2026-6809 still applies before relaxing the pins"
    )
