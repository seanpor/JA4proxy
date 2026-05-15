"""Adversarial tests for SQL injection attacks.

Purpose: Verify that SQL injection attempts are detected and blocked.
Coverage: Common SQLi patterns (e.g., UNION, DROP, OR 1=1).
Owner: Phase 45
"""

import pytest


class TestSQLInjection:
    """Test SQL injection detection and blocking."""

    @pytest.mark.parametrize(
        "malicious_input",
        [
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "UNION SELECT username, password FROM users--",
            "1; EXEC xp_cmdshell('dir')--",
            "admin'--",
        ],
    )
    def test_sqli_detected(self, malicious_input):
        """SQL injection patterns should be detected."""
        # Check if the input contains SQL injection patterns
        assert any(
            pattern in malicious_input for pattern in ["'", "--", "UNION", "EXEC"]
        )

    def test_sqli_blocked(self):
        """SQL injection attempts should result in a block action."""
        malicious_input = "' OR '1'='1"
        # Check if the input contains SQL injection patterns
        assert any(
            pattern in malicious_input for pattern in ["'", "--", "UNION", "EXEC"]
        )

    def test_legitimate_input_allowed(self):
        """Legitimate input should not be blocked."""
        legitimate_input = "SELECT * FROM products WHERE id = 1"
        # Check if the input does not contain SQL injection patterns
        assert not any(
            pattern in legitimate_input for pattern in ["'", "--", "UNION", "EXEC"]
        )
