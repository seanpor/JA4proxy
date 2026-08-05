"""Unit tests for scripts/check_finding_spec.py (Phase 814a).

The gate exists to stop a finding leaving an assessment workstream in a state
only its author can act on. These tests pin the three checks that encode
observed failure modes rather than hypothetical ones:

  * §6 must name real files — stopping at the first file is how fixes
    half-land (Phase 522's role-default fix rippled through ~40 call sites).
  * §7 must be present — for this product the tempting wrong fix is usually
    "make it fail closed", trading a security bug for an outage (clause C-4).
  * §9 must state BOTH verification states — a test that passes before and
    after the fix proves nothing.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

_spec = importlib.util.spec_from_file_location(
    "check_finding_spec", ROOT / "scripts" / "check_finding_spec.py"
)
assert _spec and _spec.loader
check_finding_spec = importlib.util.module_from_spec(_spec)
sys.modules["check_finding_spec"] = check_finding_spec
_spec.loader.exec_module(check_finding_spec)


COMPLETE_SPEC = """\
## JA4PROXY-2026-0042 — Example finding used by the test-suite

**Severity:** HIGH (rubric clause H-3)  **CWE:** CWE-807
**CVSS v3.1:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N  **Lane:** go-proxy
**Discovered:** 2026-08-05  **Persona:** P2  **Workstream:** 814d
**Found against:** abc123def456 | sha256:aaaa | config sha256:bbbb

### 1. Where it is
`internal/security/scorer.go:120-134` — current code, pasted verbatim:

    if signal.Score > threshold {
        return Block
    }

### 2. What is wrong
The comparison uses the raw attacker-supplied value without bounding it, so a
single signal can push the total past the block threshold on its own.

### 3. Why it matters here
A remote unauthenticated client can force a BLOCK decision for an address it
does not control, which is a false positive at scale — the expensive failure
for this product.

### 4. Reproduce it

    docker compose -p ja4range exec attacker python3 /fixtures/poc.py

Expected output on the VULNERABLE build:

    decision=BLOCK score=140

### 5. The fix
Before / after:

    - total += signal.Score
    + total += min(signal.Score, signalCap)

**The invariant this restores:** no single signal may contribute more than its
documented maximum to the composite score.

**Copy this existing pattern:** `internal/security/asn.go:88` already clamps.

### 6. Every file that must change

| File | Change | Why it ripples |
|---|---|---|
| `internal/security/scorer.go` | clamp the contribution | the defect itself |
| `internal/security/scorer_test.go` | add boundary cases | asserts the clamp |
| `docs/reference/REDIS_SCHEMA.md` | none | verified unaffected |

### 7. Do NOT do this
Do not "fix" this by rejecting the connection when the score overflows. That
converts a scoring bug into a fail-closed path and creates a C-4 regression.
Clamp the contribution and keep failing open.

### 8. Anticipated questions
You might think the cap belongs in the signal module. It does not — signals are
independently testable and the composite is where the invariant lives.

### 9. Verification
- Test to create: `internal/security/scorer_test.go`
- Command: `make verify-finding FINDING=JA4PROXY-2026-0042`
- Expected on unfixed build: FAIL (TestScorerClampsSignal fails on overflow)
- Expected on fixed build: PASS
- Permanent home once verified: `internal/security/scorer_test.go`

### 10. Performance impact
Hot path. Run `make bench-micro`; a `min()` call must not move p99 measurably.

### 11. Blast radius and rollback
Scoring only; no schema change. Hot-reloadable. Revert is a one-line change.

### 12. Definition of done
- [ ] Every file in §6 changed
- [ ] Verification script fails pre-fix and passes post-fix
"""


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "finding.md"
    path.write_text(body, encoding="utf-8")
    return path


def test_complete_spec_passes(tmp_path: Path) -> None:
    result = check_finding_spec.check_spec(_write(tmp_path, COMPLETE_SPEC))
    assert result.ok, f"complete spec should pass, got: {result.errors}"


def test_missing_section_is_reported(tmp_path: Path) -> None:
    body = COMPLETE_SPEC.replace("### 7. Do NOT do this", "### 7. Something else")
    result = check_finding_spec.check_spec(_write(tmp_path, body))
    assert not result.ok
    assert any("§7" in e for e in result.errors)


def test_placeholder_section_is_rejected(tmp_path: Path) -> None:
    """A heading with TBD under it is not a filled-in section."""
    body = COMPLETE_SPEC.replace(
        "Do not \"fix\" this by rejecting the connection when the score overflows. That\n"
        "converts a scoring bug into a fail-closed path and creates a C-4 regression.\n"
        "Clamp the contribution and keep failing open.",
        "TBD",
    )
    result = check_finding_spec.check_spec(_write(tmp_path, body))
    assert not result.ok
    assert any("placeholder" in e or "empty" in e for e in result.errors)


def test_file_list_without_real_files_is_rejected(tmp_path: Path) -> None:
    """§6 is the anti-half-fix check — a promise is not a file list."""
    body = COMPLETE_SPEC.replace(
        "| File | Change | Why it ripples |\n"
        "|---|---|---|\n"
        "| `internal/security/scorer.go` | clamp the contribution | the defect itself |\n"
        "| `internal/security/scorer_test.go` | add boundary cases | asserts the clamp |\n"
        "| `docs/reference/REDIS_SCHEMA.md` | none | verified unaffected |",
        "The implementer should work out which files are affected during the fix.",
    )
    result = check_finding_spec.check_spec(_write(tmp_path, body))
    assert not result.ok
    assert any("names no actual file" in e for e in result.errors)


def test_verification_missing_a_state_is_rejected(tmp_path: Path) -> None:
    """The two-state proof is the whole point; one state is not enough."""
    body = COMPLETE_SPEC.replace(
        "- Expected on unfixed build: FAIL (TestScorerClampsSignal fails on overflow)\n",
        "",
    )
    result = check_finding_spec.check_spec(_write(tmp_path, body))
    assert not result.ok
    assert any("BOTH" in e for e in result.errors)


def test_missing_canonical_id_is_rejected(tmp_path: Path) -> None:
    body = COMPLETE_SPEC.replace(
        "## JA4PROXY-2026-0042 — Example finding used by the test-suite",
        "## Some finding I found today",
    )
    result = check_finding_spec.check_spec(_write(tmp_path, body))
    assert not result.ok
    assert any("canonical title" in e for e in result.errors)


def test_missing_provenance_field_is_rejected(tmp_path: Path) -> None:
    """Without 'Found against', a retest cannot distinguish fixed from
    no-longer-reproducible (PROGRAMME.md §13)."""
    body = COMPLETE_SPEC.replace(
        "**Found against:** abc123def456 | sha256:aaaa | config sha256:bbbb\n", ""
    )
    result = check_finding_spec.check_spec(_write(tmp_path, body))
    assert not result.ok
    assert any("found against" in e.lower() for e in result.errors)


@pytest.mark.parametrize("missing", [1, 4, 5, 9, 12])
def test_each_required_section_is_enforced(tmp_path: Path, missing: int) -> None:
    """Every numbered section is load-bearing; none is optional."""
    body = COMPLETE_SPEC.replace(f"### {missing}. ", f"### {missing}X. ", 1)
    result = check_finding_spec.check_spec(_write(tmp_path, body))
    assert not result.ok
    assert any(f"§{missing}" in e for e in result.errors)


def test_no_specs_is_not_a_failure(capsys: pytest.CaptureFixture[str]) -> None:
    """An empty findings directory is the normal state before the first
    workstream finds anything — it must not redden CI."""
    assert check_finding_spec.main([]) == 0
    assert "no specifications" in capsys.readouterr().out
