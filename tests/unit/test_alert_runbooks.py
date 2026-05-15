"""Phase 86g — Validate that all 7 runbook files exist and have required sections."""

from pathlib import Path

import pytest

RUNBOOKS_DIR = Path(__file__).parent.parent.parent / "docs" / "runbooks"

REQUIRED_SECTIONS = [
    "## Severity",
    "## Impact",
    "## Diagnosis",
    "## Resolution",
    "## Escalation",
]

EXPECTED_RUNBOOKS = [
    "ja4proxy_node_unhealthy.md",
    "ja4proxy_redis_latency_high.md",
    "ja4proxy_certificate_expiring.md",
    "ja4proxy_block_rate_high.md",
    "ja4proxy_campaign_detected.md",
    "ja4proxy_dial_change_unexpected.md",
    "ja4proxy_tarpit_pool_full.md",
]


class TestRunbookFiles:
    """Every expected runbook must exist with all required sections."""

    @pytest.mark.parametrize("filename", EXPECTED_RUNBOOKS)
    def test_runbook_exists(self, filename):
        filepath = RUNBOOKS_DIR / filename
        assert filepath.exists(), f"Runbook {filename} not found in {RUNBOOKS_DIR}"

    @pytest.mark.parametrize("filename", EXPECTED_RUNBOOKS)
    def test_runbook_has_required_sections(self, filename):
        filepath = RUNBOOKS_DIR / filename
        if not filepath.exists():
            pytest.skip(f"{filename} not found — caught by test_runbook_exists")
        content = filepath.read_text()
        for section in REQUIRED_SECTIONS:
            assert section in content, f"Runbook {filename} missing section: {section}"

    @pytest.mark.parametrize("filename", EXPECTED_RUNBOOKS)
    def test_runbook_not_empty(self, filename):
        filepath = RUNBOOKS_DIR / filename
        if not filepath.exists():
            pytest.skip(f"{filename} not found")
        content = filepath.read_text().strip()
        assert len(content) > 200, (
            f"Runbook {filename} seems too short ({len(content)} chars). "
            "Expected a full runbook with diagnosis and resolution steps."
        )
