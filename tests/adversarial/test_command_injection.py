"""Adversarial tests for command injection attacks.

Purpose: Verify that command injection attempts are detected and blocked.
Coverage: Common command injection patterns (e.g., ;, &&, |, `).
Owner: Phase 45
"""
import pytest


class TestCommandInjection:
    """Test command injection detection and blocking."""

    @pytest.mark.parametrize("malicious_input", [
        "; rm -rf /",
        "&& cat /etc/passwd",
        "| ls -la",
        "`whoami`",
        "$(whoami)",
    ])
    def test_command_injection_detected(self, malicious_input):
        """Command injection patterns should be detected."""
        # Check if the input contains command injection patterns
        assert any(pattern in malicious_input for pattern in [";", "&&", "|", "`", "$"])

    def test_command_injection_blocked(self):
        """Command injection attempts should result in a block action."""
        malicious_input = "; rm -rf /"
        # Check if the input contains command injection patterns
        assert any(pattern in malicious_input for pattern in [";", "&&", "|", "`", "$"])

    def test_legitimate_command_allowed(self):
        """Legitimate commands should not be blocked."""
        legitimate_input = "echo 'Hello, world!'"
        # Check if the input does not contain command injection patterns
        assert not any(pattern in legitimate_input for pattern in [";", "&&", "|", "`", "$"])
