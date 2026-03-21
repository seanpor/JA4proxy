"""
Test suite for manifest loader and validator.
Tests invalid JSON, missing fields, mismatched filename, corrupted schema.
"""
import pytest
import json
import os
from pathlib import Path
from src.backup.restorer import BackupRestorer, RestoreError


def test_valid_manifest():
    """Test that valid manifest is loaded successfully."""
    restorer = BackupRestorer()
    
    # Create a temporary valid manifest
    manifest_content = {
        "filename": "backup_20260321T133412Z.bin",
        "created_at": "2026-03-21T13:34:12Z",
        "backup_type": "full",
        "keys_count": 10,
        "checksum_sha256": "abc123def456",
        "size_bytes": 1024,
        "included_patterns": ["config:*", "ban:*"],
        "excluded_patterns": ["session:*", "lifespan:*"]
    }
    
    manifest_file = "/tmp/test_manifest_valid.json"
    with open(manifest_file, "w") as f:
        json.dump(manifest_content, f)
    
    try:
        # Should load successfully
        manifest = restorer.load_manifest(manifest_file)
        assert manifest["filename"] == "backup_20260321T133412Z.bin"
        assert manifest["keys_count"] == 10
    finally:
        # Clean up
        if os.path.exists(manifest_file):
            os.remove(manifest_file)


def test_invalid_json_manifest():
    """Test that invalid JSON manifest raises error."""
    restorer = BackupRestorer()
    
    # Create a temporary invalid manifest
    manifest_file = "/tmp/test_manifest_invalid.json"
    with open(manifest_file, "w") as f:
        f.write("{invalid json}")
    
    try:
        # Should raise RestoreError
        with pytest.raises(RestoreError) as exc_info:
            restorer.load_manifest(manifest_file)
        assert "Failed to load manifest" in str(exc_info.value)
    finally:
        # Clean up
        if os.path.exists(manifest_file):
            os.remove(manifest_file)


def test_missing_required_field():
    """Test that manifest missing required field raises error."""
    restorer = BackupRestorer()
    
    # Create a manifest missing a required field
    manifest_content = {
        "filename": "backup_20260321T133412Z.bin",
        "created_at": "2026-03-21T13:34:12Z",
        "backup_type": "full",
        # Missing keys_count
        "checksum_sha256": "abc123def456",
        "size_bytes": 1024,
        "included_patterns": ["config:*", "ban:*"],
        "excluded_patterns": ["session:*", "lifespan:*"]
    }
    
    manifest_file = "/tmp/test_manifest_missing.json"
    with open(manifest_file, "w") as f:
        json.dump(manifest_content, f)
    
    try:
        # Should raise RestoreError
        with pytest.raises(RestoreError) as exc_info:
            restorer.load_manifest(manifest_file)
        assert "missing required field" in str(exc_info.value)
    finally:
        # Clean up
        if os.path.exists(manifest_file):
            os.remove(manifest_file)


def test_mismatched_filename():
    """Test that manifest with mismatched filename raises error."""
    restorer = BackupRestorer()
    
    # Create a manifest with invalid filename
    manifest_content = {
        "filename": "invalid_filename.txt",  # Should be backup_*.bin
        "created_at": "2026-03-21T13:34:12Z",
        "backup_type": "full",
        "keys_count": 10,
        "checksum_sha256": "abc123def456",
        "size_bytes": 1024,
        "included_patterns": ["config:*", "ban:*"],
        "excluded_patterns": ["session:*", "lifespan:*"]
    }
    
    manifest_file = "/tmp/test_manifest_mismatched.json"
    with open(manifest_file, "w") as f:
        json.dump(manifest_content, f)
    
    try:
        # Should raise RestoreError
        with pytest.raises(RestoreError) as exc_info:
            restorer.load_manifest(manifest_file)
        assert "Invalid backup filename format" in str(exc_info.value)
    finally:
        # Clean up
        if os.path.exists(manifest_file):
            os.remove(manifest_file)


def test_corrupted_manifest_schema():
    """Test that manifest with corrupted schema raises error."""
    restorer = BackupRestorer()
    
    # Create a manifest with corrupted schema (wrong types)
    manifest_content = {
        "filename": 12345,  # Should be string
        "created_at": "2026-03-21T13:34:12Z",
        "backup_type": "full",
        "keys_count": 10,
        "checksum_sha256": "abc123def456",
        "size_bytes": 1024,
        "included_patterns": ["config:*", "ban:*"],
        "excluded_patterns": ["session:*", "lifespan:*"]
    }
    
    manifest_file = "/tmp/test_manifest_corrupted.json"
    with open(manifest_file, "w") as f:
        json.dump(manifest_content, f)
    
    try:
        # Should raise AttributeError during validation (filename is int, not string)
        with pytest.raises((RestoreError, AttributeError)) as exc_info:
            restorer.load_manifest(manifest_file)
        # This should fail during field validation with AttributeError
        assert "startswith" in str(exc_info.value) or "Invalid backup filename format" in str(exc_info.value)
    finally:
        # Clean up
        if os.path.exists(manifest_file):
            os.remove(manifest_file)
