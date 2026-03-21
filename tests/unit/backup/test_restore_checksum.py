"""
Test suite for checksum verification.
Tests corruption detection before restoration.
"""
import pytest
import json
import os
import hashlib
from pathlib import Path
from src.backup.restorer import BackupRestorer, RestoreError


def test_valid_checksum():
    """Test that valid checksum verification passes."""
    restorer = BackupRestorer()
    
    # Create test data
    test_data = b"test backup data for checksum verification"
    expected_checksum = hashlib.sha256(test_data).hexdigest()
    
    # Create backup file
    backup_file = "/tmp/test_backup_valid.bin"
    with open(backup_file, "wb") as f:
        f.write(test_data)
    
    try:
        # Should verify successfully
        result = restorer.verify_checksum(backup_file, expected_checksum)
        assert result is True
    finally:
        # Clean up
        if os.path.exists(backup_file):
            os.remove(backup_file)


def test_invalid_checksum():
    """Test that invalid checksum verification fails."""
    restorer = BackupRestorer()
    
    # Create test data
    test_data = b"test backup data for checksum verification"
    wrong_checksum = "0000000000000000000000000000000000000000000000000000000000000000"
    
    # Create backup file
    backup_file = "/tmp/test_backup_invalid.bin"
    with open(backup_file, "wb") as f:
        f.write(test_data)
    
    try:
        # Should fail verification
        result = restorer.verify_checksum(backup_file, wrong_checksum)
        assert result is False
    finally:
        # Clean up
        if os.path.exists(backup_file):
            os.remove(backup_file)


def test_corrupted_backup_file():
    """Test that corrupted backup file raises error."""
    restorer = BackupRestorer()
    
    # Create a backup file that can't be read
    backup_file = "/tmp/test_backup_corrupted.bin"
    # Don't create the file - this will cause FileNotFoundError
    
    # Should raise RestoreError
    with pytest.raises(RestoreError) as exc_info:
        restorer.verify_checksum(backup_file, "abc123")
    assert "Failed to read backup file" in str(exc_info.value)


def test_tampered_backup_rejection():
    """Test that tampered backup is rejected during restore."""
    restorer = BackupRestorer()
    
    # Create a valid backup and manifest
    test_data = b"original backup data"
    expected_checksum = hashlib.sha256(test_data).hexdigest()
    
    backup_file = "/tmp/backup_20260321T133412Z_tampered.bin"
    manifest_file = "/tmp/backup_20260321T133412Z_tampered.bin.manifest.json"
    
    try:
        # Create original backup
        with open(backup_file, "wb") as f:
            f.write(test_data)
        
        # Create manifest
        manifest = {
            "filename": "backup_20260321T133412Z_tampered.bin",
            "created_at": "2026-03-21T13:34:12Z",
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": expected_checksum,
            "size_bytes": len(test_data),
            "included_patterns": [],
            "excluded_patterns": []
        }
        with open(manifest_file, "w") as f:
            json.dump(manifest, f)
        
        # Tamper with the backup file
        with open(backup_file, "wb") as f:
            f.write(b"tampered backup data")
        
        # Should reject during restore due to checksum mismatch
        with pytest.raises(RestoreError) as exc_info:
            restorer.restore_backup(backup_file, manifest_file, destructive=False)
        assert "Checksum verification failed" in str(exc_info.value)
        
    finally:
        # Clean up
        for f in [backup_file, manifest_file]:
            if os.path.exists(f):
                os.remove(f)


def test_manifest_tampering_rejection():
    """Test that tampered manifest is rejected."""
    restorer = BackupRestorer()
    
    # Create a valid backup and manifest
    test_data = b"original backup data"
    expected_checksum = hashlib.sha256(test_data).hexdigest()
    
    backup_file = "/tmp/backup_20260321T133412Z_manifest_tampered.bin"
    manifest_file = "/tmp/backup_20260321T133412Z_manifest_tampered.bin.manifest.json"
    
    try:
        # Create original backup
        with open(backup_file, "wb") as f:
            f.write(test_data)
        
        # Create manifest with wrong checksum
        manifest = {
            "filename": "backup_20260321T133412Z_manifest_tampered.bin",
            "created_at": "2026-03-21T13:34:12Z",
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": "wrong_checksum_123456789",  # Wrong checksum
            "size_bytes": len(test_data),
            "included_patterns": [],
            "excluded_patterns": []
        }
        with open(manifest_file, "w") as f:
            json.dump(manifest, f)
        
        # Should reject during restore due to checksum mismatch
        with pytest.raises(RestoreError) as exc_info:
            restorer.restore_backup(backup_file, manifest_file, destructive=False)
        assert "Checksum verification failed" in str(exc_info.value)
        
    finally:
        # Clean up
        for f in [backup_file, manifest_file]:
            if os.path.exists(f):
                os.remove(f)
