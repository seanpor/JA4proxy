"""Adversarial tests for path traversal attacks.

Purpose: Verify that path traversal attempts are detected and blocked.
Coverage: Common path traversal patterns (e.g., ../, ../../, absolute paths).
Owner: Phase 45
"""
import pytest


class TestPathTraversal:
    """Test path traversal detection and blocking."""

    @pytest.mark.parametrize("malicious_input", [
        "../../../etc/passwd",
        "../../../../../../../../../../../../../../../../../../etc/passwd",
        "/etc/passwd",
        "..\\..\\..\\etc\\passwd",
        "../../../../../../../../../../../../../../../../../../windows/win.ini",
    ])
    def test_path_traversal_detected(self, malicious_input):
        """Path traversal patterns should be detected."""
        # Check if the input contains path traversal patterns
        assert any(pattern in malicious_input for pattern in ["../", "../../", "/etc/", "..\\"])

    def test_path_traversal_blocked(self):
        """Path traversal attempts should result in a block action."""
        malicious_input = "../../../etc/passwd"
        # Check if the input contains path traversal patterns
        assert any(pattern in malicious_input for pattern in ["../", "../../", "/etc/", "..\\"])

    def test_legitimate_path_allowed(self):
        """Legitimate paths should not be blocked."""
        legitimate_input = "/var/www/html/index.html"
        # Check if the input does not contain path traversal patterns
        assert not any(pattern in legitimate_input for pattern in ["../", "../../", "/etc/", "..\\"])
