import subprocess
import os
import pytest
from pathlib import Path

# Absolute paths
ROOT = "/home/sean/LLM/JA4proxy2"
JA4P_BIN = f"{ROOT}/bin/ja4p"
JA4PD_BIN = f"{ROOT}/bin/ja4pd"

@pytest.mark.skipif(not os.path.exists(JA4P_BIN), reason="ja4p binary not built")
class TestJa4pCLI:
    """System tests for the unified ja4p CLI tool."""

    def test_version(self):
        """Verify ja4p version command."""
        result = subprocess.run([JA4P_BIN, "version"], capture_output=True, text=True, check=True, cwd=ROOT)
        assert "JA4proxy v2.0.0" in result.stdout
        assert "Built:" in result.stdout

    def test_config_validate_valid(self):
        """Verify ja4p validate with standard config."""
        result = subprocess.run([JA4P_BIN, "validate", "-c", "config/proxy.yml"], capture_output=True, text=True, check=True, cwd=ROOT)
        assert "Configuration is valid" in result.stdout

    def test_config_validate_invalid(self, tmp_path):
        """Verify ja4p validate catches bad config."""
        bad_config = tmp_path / "bad_proxy.yml"
        bad_config.write_text("proxy:\n  bind_port: 999999\n")
        
        result = subprocess.run([JA4P_BIN, "validate", "-c", str(bad_config)], capture_output=True, text=True, cwd=ROOT)
        assert result.returncode != 0
        assert "validation failed" in result.stderr or "invalid proxy bind port" in result.stderr

    def test_init_poc(self, tmp_path):
        """Verify ja4p init generates .env correctly in POC mode."""
        # Run with tmp_path as CWD
        result = subprocess.run([JA4P_BIN, "init"], input="1\n", capture_output=True, text=True, check=True, cwd=tmp_path)
        
        assert "POC Setup complete" in result.stdout
        env_file = tmp_path / ".env"
        assert env_file.exists()
        
        env_content = env_file.read_text()
        assert "REDIS_PASSWORD=" in env_content
        assert "ENVIRONMENT=development" in env_content
        assert "BACKEND_HOST=backend" in env_content

    def test_test_ip_simulation(self):
        """Verify ja4p test ip simulation logic."""
        result = subprocess.run([JA4P_BIN, "test", "ip", "1.1.1.1"], capture_output=True, text=True, check=True, cwd=ROOT)
        assert "Results for IP: 1.1.1.1" in result.stdout
        assert "Action:" in result.stdout
        assert "Score:" in result.stdout
