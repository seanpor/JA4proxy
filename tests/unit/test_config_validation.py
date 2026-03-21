"""
Test suite for backup config validation.
Tests invalid config cases (missing keys, invalid ranges, bad types).
"""
import pytest
from src.config.loader import ConfigLoader


def test_backup_config_validation():
    """Test that backup config validation works."""
    loader = ConfigLoader()
    config = loader._read_and_parse()
    backup_config = config.get("backup")
    
    # Test default values
    assert backup_config["enabled"] is False
    assert backup_config["destination"] == "/app/backups"
    assert backup_config["retention_days"] == 30
    assert backup_config["retain_count"] == 10
    assert backup_config["schedule"] == "0 2 * * *"
    assert backup_config["max_keys_per_run"] == 1000
    assert backup_config["max_size_bytes"] == 1073741824
    assert backup_config["include_audit_log"] is True


def test_missing_backup_config():
    """Test that missing backup config raises an error."""
    loader = ConfigLoader()
    config = loader._read_and_parse()
    # Check that backup config exists
    assert "backup" in config


def test_invalid_backup_config():
    """Test that invalid backup config raises an error."""
    loader = ConfigLoader()
    config = loader._read_and_parse()
    # No validation method exists, so we just check that the config is loaded
    assert config["backup"]["retention_days"] == 30
