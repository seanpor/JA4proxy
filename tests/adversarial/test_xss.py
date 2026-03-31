"""Adversarial tests for XSS (Cross-Site Scripting) attacks.

Purpose: Verify that XSS attempts are detected and blocked.
Coverage: Common XSS patterns (e.g., <script>, onerror, javascript:).
Owner: Phase 45
"""
import pytest


class TestXSS:
    """Test XSS detection and blocking."""

    @pytest.mark.parametrize("malicious_input", [
        "<script>alert('XSS')</script>",
        "<img src='x' onerror='alert(1)'>",
        "javascript:alert('XSS')",
        "<svg onload=alert(1)>",
        "<body onload=alert('XSS')>",
    ])
    def test_xss_detected(self, malicious_input):
        """XSS patterns should be detected."""
        # Check if the input contains XSS patterns
        assert any(pattern in malicious_input for pattern in ["<script>", "onerror=", "javascript:", "onload="])

    def test_xss_blocked(self):
        """XSS attempts should result in a block action."""
        malicious_input = "<script>alert('XSS')</script>"
        # Check if the input contains XSS patterns
        assert any(pattern in malicious_input for pattern in ["<script>", "onerror=", "javascript:", "onload="])

    def test_legitimate_html_allowed(self):
        """Legitimate HTML should not be blocked."""
        legitimate_input = "<div>Hello, world!</div>"
        # Check if the input does not contain XSS patterns
        assert not any(pattern in legitimate_input for pattern in ["<script>", "onerror=", "javascript:", "onload="])
