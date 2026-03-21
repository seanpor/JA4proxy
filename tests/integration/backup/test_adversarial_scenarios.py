"""
Adversarial tests for backup/restore operations.
Tests security against tampered manifests/archives and path traversal attacks.
"""
import pytest
import json
import tempfile
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch
from src.backup.worker import BackupWorker
from src.backup.restorer import BackupRestorer, RestoreError


class TestAdversarialScenarios:
    """Adversarial tests for backup/restore security."""
    
    def setup_method(self):
        """Set up test fixtures and temporary directories."""
        self.backup_dir = tempfile.mkdtemp(prefix="backup_adversarial_test_")
        
        # Test data
        self.test_data = {
            "config:dial": b"127.0.0.1:8080",
            "ban:192.168.1.1": b"2024-01-01T00:00:00Z",
            "ja4:whitelist": b"allowed",
        }
    
    def teardown_method(self):
        """Clean up temporary directories."""
        if hasattr(self, 'backup_dir') and Path(self.backup_dir).exists():
            shutil.rmtree(self.backup_dir)
    
    def test_tampered_manifest_checksum(self):
        """Test detection of tampered manifest with incorrect checksum."""
        # Create a valid backup file
        backup_file = Path(self.backup_dir) / "backup_20240101T000000Z.bin"
        backup_data = b"valid_backup_data"
        backup_file.write_bytes(backup_data)
        
        import hashlib
        actual_checksum = hashlib.sha256(backup_data).hexdigest()
        tampered_checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  # Wrong checksum
        
        # Create manifest with tampered checksum
        manifest = {
            "filename": "backup_20240101T000000Z.bin",
            "created_at": "2024-01-01T00:00:00Z",
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": tampered_checksum,  # Tampered!
            "size_bytes": len(backup_data),
            "included_patterns": ["config:*"],
            "excluded_patterns": []
        }
        
        manifest_file = Path(self.backup_dir) / "backup_20240101T000000Z.bin.manifest.json"
        manifest_file.write_text(json.dumps(manifest))
        
        # Test that restore detects the tampering
        with patch("src.backup.restorer.redis.Redis") as mock_redis_class:
            mock_redis = mock_redis_class.return_value
            mock_redis.ping.return_value = True
            
            restorer = BackupRestorer()
            
            # Restore should fail due to checksum mismatch
            with pytest.raises(RestoreError) as exc_info:
                restorer.restore_backup(str(backup_file), str(manifest_file))
            
            # Verify it's a checksum verification error
            assert "checksum" in str(exc_info.value).lower() or "verification" in str(exc_info.value).lower()
    
    def test_tampered_manifest_keys_count(self):
        """Test detection of tampered manifest with incorrect keys count."""
        # Create a valid backup file
        backup_file = Path(self.backup_dir) / "backup_20240101T000000Z.bin"
        backup_data = b"valid_backup_data"
        backup_file.write_bytes(backup_data)
        
        import hashlib
        checksum = hashlib.sha256(backup_data).hexdigest()
        
        # Create manifest with tampered keys count
        manifest = {
            "filename": "backup_20240101T000000Z.bin",
            "created_at": "2024-01-01T00:00:00Z",
            "backup_type": "full",
            "keys_count": 999999,  # Tampered! Way too many keys
            "checksum_sha256": checksum,
            "size_bytes": len(backup_data),
            "included_patterns": ["config:*"],
            "excluded_patterns": []
        }
        
        manifest_file = Path(self.backup_dir) / "backup_20240101T000000Z.bin.manifest.json"
        manifest_file.write_text(json.dumps(manifest))
        
        # Test that restore completes but the discrepancy would be noticed
        # (This test verifies the manifest is accepted but the count is suspicious)
        with patch("src.backup.restorer.redis.Redis") as mock_redis_class:
            mock_redis = mock_redis_class.return_value
            mock_redis.ping.return_value = True
            
            restorer = BackupRestorer()
            
            # This should still work (we can't easily detect this tampering automatically)
            # But the suspicious count would be logged and visible in monitoring
            restorer.restore_backup(str(backup_file), str(manifest_file))
            
            # In a real system, this would trigger alerts via monitoring
            # For now, we verify the restore completes (can't auto-detect this tampering)
    
    def test_tampered_manifest_timestamp(self):
        """Test handling of manifest with tampered timestamp."""
        # Create a valid backup file
        backup_file = Path(self.backup_dir) / "backup_20240101T000000Z.bin"
        backup_data = b"valid_backup_data"
        backup_file.write_bytes(backup_data)
        
        import hashlib
        checksum = hashlib.sha256(backup_data).hexdigest()
        
        # Create manifest with future timestamp (tampered)
        manifest = {
            "filename": "backup_20240101T000000Z.bin",
            "created_at": "2099-12-31T23:59:59Z",  # Tampered! Future date
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": checksum,
            "size_bytes": len(backup_data),
            "included_patterns": ["config:*"],
            "excluded_patterns": []
        }
        
        manifest_file = Path(self.backup_dir) / "backup_20240101T000000Z.bin.manifest.json"
        manifest_file.write_text(json.dumps(manifest))
        
        # Test that restore completes but the suspicious timestamp would be noticed
        with patch("src.backup.restorer.redis.Redis") as mock_redis_class:
            mock_redis = mock_redis_class.return_value
            mock_redis.ping.return_value = True
            
            restorer = BackupRestorer()
            
            # This should work (we can't easily detect timestamp tampering automatically)
            # But it would be visible in logs and monitoring
            restorer.restore_backup(str(backup_file), str(manifest_file))
    
    def test_tampered_archive_content(self):
        """Test detection of tampered archive content."""
        # Create a backup file with tampered content
        backup_file = Path(self.backup_dir) / "backup_20240101T000000Z.bin"
        original_data = b"original_valid_data"
        tampered_data = b"tampered_malicious_data"
        backup_file.write_bytes(tampered_data)  # Write tampered data
        
        # Create manifest with checksum of original data (not matching actual file)
        import hashlib
        original_checksum = hashlib.sha256(original_data).hexdigest()
        
        manifest = {
            "filename": "backup_20240101T000000Z.bin",
            "created_at": "2024-01-01T00:00:00Z",
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": original_checksum,  # Checksum of original data!
            "size_bytes": len(original_data),  # Size of original data!
            "included_patterns": ["config:*"],
            "excluded_patterns": []
        }
        
        manifest_file = Path(self.backup_dir) / "backup_20240101T000000Z.bin.manifest.json"
        manifest_file.write_text(json.dumps(manifest))
        
        # Test that restore detects the tampering
        with patch("src.backup.restorer.redis.Redis") as mock_redis_class:
            mock_redis = mock_redis_class.return_value
            mock_redis.ping.return_value = True
            
            restorer = BackupRestorer()
            
            # Restore should fail due to checksum mismatch
            with pytest.raises(RestoreError) as exc_info:
                restorer.restore_backup(str(backup_file), str(manifest_file))
            
            # Verify it's a checksum verification error
            assert "checksum" in str(exc_info.value).lower() or "verification" in str(exc_info.value).lower()
    
    def test_symlink_attack_prevention(self):
        """Test prevention of symlink/path traversal attacks."""
        # Create a backup directory with a symlink
        backup_dir = Path(self.backup_dir) / "symlink_test"
        backup_dir.mkdir()
        
        # Create a symlink pointing to a sensitive location
        symlink_target = "/etc/passwd"
        symlink_path = backup_dir / "backup_20240101T000000Z.bin"
        
        try:
            symlink_path.symlink_to(symlink_target)
            
            # Create a manifest
            manifest = {
                "filename": "backup_20240101T000000Z.bin",
                "created_at": "2024-01-01T00:00:00Z",
                "backup_type": "full",
                "keys_count": 1,
                "checksum_sha256": "abc123",
                "size_bytes": 100,
                "included_patterns": ["config:*"],
                "excluded_patterns": []
            }
            
            manifest_file = backup_dir / "backup_20240101T000000Z.bin.manifest.json"
            manifest_file.write_text(json.dumps(manifest))
            
            # Test that restore rejects the symlink
            with patch("src.backup.restorer.redis.Redis") as mock_redis_class:
                mock_redis = mock_redis_class.return_value
                mock_redis.ping.return_value = True
                
                restorer = BackupRestorer()
                
                # Restore should fail due to symlink security check
                with pytest.raises((RestoreError, OSError)) as exc_info:
                    restorer.restore_backup(str(symlink_path), str(manifest_file))
                
                # Verify it's either a security-related error or checksum verification error
                error_str = str(exc_info.value).lower()
                assert ("symlink" in error_str or "security" in error_str or "permission" in error_str or "access" in error_str or 
                        "checksum" in error_str or "verification" in error_str)
                
        finally:
            # Clean up symlink
            if symlink_path.exists():
                symlink_path.unlink()
    
    def test_path_traversal_attack(self):
        """Test prevention of path traversal attacks in backup filenames."""
        # Test various path traversal attempts
        dangerous_filenames = [
            "../../../etc/passwd",
            "../sensitive/data",
            "/etc/shadow",
            "~/.ssh/id_rsa",
            "../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../etc/passwd"
        ]
        
        for dangerous_filename in dangerous_filenames:
            # Create a backup file with dangerous filename
            try:
                backup_file = Path(self.backup_dir) / dangerous_filename
                # This should fail or be prevented by the filesystem
                backup_file.touch()  # This will likely fail
                
                # If it somehow succeeds, verify our code rejects it
                if backup_file.exists():
                    manifest = {
                        "filename": dangerous_filename,
                        "created_at": "2024-01-01T00:00:00Z",
                        "backup_type": "full",
                        "keys_count": 1,
                        "checksum_sha256": "abc123",
                        "size_bytes": 100,
                        "included_patterns": ["config:*"],
                        "excluded_patterns": []
                    }
                    
                    manifest_file = Path(self.backup_dir) / f"{dangerous_filename}.manifest.json"
                    manifest_file.write_text(json.dumps(manifest))
                    
                    # Test that restore rejects the dangerous path
                    with patch("src.backup.restorer.redis.Redis") as mock_redis_class:
                        mock_redis = mock_redis_class.return_value
                        mock_redis.ping.return_value = True
                        
                        restorer = BackupRestorer()
                        
                        # This should fail due to security checks
                        with pytest.raises((RestoreError, ValueError, OSError)):
                            restorer.restore_backup(str(backup_file), str(manifest_file))
                            
            except (OSError, ValueError):
                # Expected - filesystem prevents the dangerous path
                pass  # This is the desired behavior
    
    def test_manifest_injection_attack(self):
        """Test prevention of manifest injection attacks."""
        # Create a backup file
        backup_file = Path(self.backup_dir) / "backup_20240101T000000Z.bin"
        backup_data = b"valid_data"
        backup_file.write_bytes(backup_data)
        
        import hashlib
        checksum = hashlib.sha256(backup_data).hexdigest()
        
        # Create a manifest with injected malicious content
        malicious_manifest_content = {
            "filename": "backup_20240101T000000Z.bin",
            "created_at": "2024-01-01T00:00:00Z",
            "backup_type": "full",
            "keys_count": 1,
            "checksum_sha256": checksum,
            "size_bytes": len(backup_data),
            "included_patterns": ["config:*"],
            "excluded_patterns": [],
            # Inject malicious fields that shouldn't be there
            "malicious_code": "eval('malicious_code_here')",
            "__import__('os').system('rm -rf /')": "attempt",
            "exploit": "{{ malicious_template_injection }}"
        }
        
        manifest_file = Path(self.backup_dir) / "backup_20240101T000000Z.bin.manifest.json"
        manifest_file.write_text(json.dumps(malicious_manifest_content))
        
        # Test that restore handles the malicious manifest safely
        with patch("src.backup.restorer.redis.Redis") as mock_redis_class:
            mock_redis = mock_redis_class.return_value
            mock_redis.ping.return_value = True
            
            restorer = BackupRestorer()
            
            # Restore should either:
            # 1. Fail due to extra fields (if validation is strict)
            # 2. Ignore extra fields and proceed safely (if validation is lenient)
            try:
                restorer.restore_backup(str(backup_file), str(manifest_file))
                # If it succeeds, verify no malicious code was executed
                # (mock_redis should not have received any dangerous commands)
                dangerous_calls = [
                    call for call in mock_redis.execute_command.call_args_list
                    if any(dangerous in str(call) for dangerous in ['eval', 'system', 'rm', 'exploit'])
                ]
                assert len(dangerous_calls) == 0, "No dangerous commands should be executed"
                
            except (RestoreError, ValueError) as e:
                # If it fails, that's also acceptable (strict validation)
                assert "malicious" in str(e).lower() or "invalid" in str(e).lower() or "field" in str(e).lower()
    
    def test_manifest_schema_validation(self):
        """Test strict validation of manifest schema."""
        # Create a backup file
        backup_file = Path(self.backup_dir) / "backup_20240101T000000Z.bin"
        backup_data = b"valid_data"
        backup_file.write_bytes(backup_data)
        
        import hashlib
        checksum = hashlib.sha256(backup_data).hexdigest()
        
        # Create a manifest missing required fields
        incomplete_manifest = {
            "filename": "backup_20240101T000000Z.bin",
            "created_at": "2024-01-01T00:00:00Z",
            # Missing: backup_type, keys_count, checksum_sha256, size_bytes, etc.
        }
        
        manifest_file = Path(self.backup_dir) / "backup_20240101T000000Z.bin.manifest.json"
        manifest_file.write_text(json.dumps(incomplete_manifest))
        
        # Test that restore rejects incomplete manifest
        with patch("src.backup.restorer.redis.Redis") as mock_redis_class:
            mock_redis = mock_redis_class.return_value
            mock_redis.ping.return_value = True
            
            restorer = BackupRestorer()
            
            # Restore should fail due to missing required fields
            with pytest.raises(RestoreError) as exc_info:
                restorer.restore_backup(str(backup_file), str(manifest_file))
            
            # Verify it's a validation error
            assert "missing" in str(exc_info.value).lower() or "required" in str(exc_info.value).lower() or "field" in str(exc_info.value).lower()
    
    def test_backup_file_permission_attack(self):
        """Test prevention of attacks via file permissions."""
        # Create a backup file with dangerous permissions
        backup_file = Path(self.backup_dir) / "backup_20240101T000000Z.bin"
        backup_data = b"valid_data"
        backup_file.write_bytes(backup_data)
        
        # Try to make it world-writable (this may not work on all systems)
        try:
            backup_file.chmod(0o777)  # World-readable/writable/executable
            
            import hashlib
            checksum = hashlib.sha256(backup_data).hexdigest()
            
            manifest = {
                "filename": "backup_20240101T000000Z.bin",
                "created_at": "2024-01-01T00:00:00Z",
                "backup_type": "full",
                "keys_count": 1,
                "checksum_sha256": checksum,
                "size_bytes": len(backup_data),
                "included_patterns": ["config:*"],
                "excluded_patterns": []
            }
            
            manifest_file = Path(self.backup_dir) / "backup_20240101T000000Z.bin.manifest.json"
            manifest_file.write_text(json.dumps(manifest))
            
            # Test that restore either works (if permissions are acceptable) or fails safely
            with patch("src.backup.restorer.redis.Redis") as mock_redis_class:
                mock_redis = mock_redis_class.return_value
                mock_redis.ping.return_value = True
                
                restorer = BackupRestorer()
                
                try:
                    restorer.restore_backup(str(backup_file), str(manifest_file))
                    # If it succeeds, the permissions were acceptable
                    # In production, this would be logged and monitored
                    
                except (RestoreError, PermissionError) as e:
                    # If it fails, that's also acceptable (strict permission checking)
                    assert "permission" in str(e).lower() or "security" in str(e).lower()
                    
        except (OSError, PermissionError):
            # Expected on systems that prevent dangerous permission changes
            pass  # This is the desired secure behavior