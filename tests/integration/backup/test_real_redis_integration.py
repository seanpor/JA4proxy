"""
Integration tests for real Redis backup/restore operations.
Tests end-to-end happy-path for backup then restore with actual Redis instances.

Requires a live Redis on localhost:6379 (no auth).
Excluded from `make test`; use `make test-live` when Redis is running.
"""
import pytest
import redis

# All tests require a live Redis instance — excluded from the fast local test run.
pytestmark = pytest.mark.live_services
import json
import shutil
import tempfile
from pathlib import Path

from src.backup.restorer import BackupRestorer
from src.backup.worker import BackupWorker


class TestRealRedisIntegration:
    """Integration tests with real Redis instances."""
    
    def setup_method(self):
        """Set up test Redis instance and temporary directories."""
        # Use a temporary Redis database (db=9) to avoid conflicts
        self.redis_host = "localhost"
        self.redis_port = 6379
        self.redis_db = 9  # Use a separate database for testing

        # Skip gracefully when Redis is not reachable (CI without live services)
        try:
            probe = redis.Redis(host=self.redis_host, port=self.redis_port, db=self.redis_db)
            probe.ping()
        except redis.RedisError:
            pytest.skip(f"Redis not reachable at {self.redis_host}:{self.redis_port}")

        # Create temporary backup directory
        self.backup_dir = tempfile.mkdtemp(prefix="backup_test_")

        # Clean Redis database before each test
        self.redis_client = redis.Redis(
            host=self.redis_host,
            port=self.redis_port,
            db=self.redis_db
        )
        self.redis_client.flushdb()
        
        # Create test data
        self.test_data = {
            "config:dial": "127.0.0.1:8080",
            "ban:192.168.1.1": "2024-01-01T00:00:00Z",
            "whitelist:example.com": "allowed",
        }
        
        # Populate Redis with test data
        for key, value in self.test_data.items():
            self.redis_client.set(key, value)
    
    def teardown_method(self):
        """Clean up test Redis data and temporary directories."""
        # Clean Redis database
        self.redis_client.flushdb()
        
        # Remove temporary backup directory
        if hasattr(self, 'backup_dir') and Path(self.backup_dir).exists():
            shutil.rmtree(self.backup_dir)
    
    def test_end_to_end_backup_restore(self):
        """Test complete backup and restore cycle with real Redis."""
        # Create backup worker
        worker = BackupWorker(
            redis_host=self.redis_host,
            redis_port=self.redis_port,
            redis_db=self.redis_db
        )
        
        # Create backup
        backup_path = worker.create_backup(self.backup_dir)
        
        # Verify backup files were created
        assert backup_path.exists(), "Backup artifact should exist"
        assert backup_path.stat().st_size > 0, "Backup artifact should not be empty"
        
        manifest_path = Path(str(backup_path) + ".manifest.json")
        assert manifest_path.exists(), "Manifest file should exist"
        
        # Verify manifest content
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
        
        assert "timestamp" in manifest
        assert "keys" in manifest
        assert "checksum_sha256" in manifest
        assert "size_bytes" in manifest
        
        # Verify all test keys are in the manifest
        for key in self.test_data.keys():
            assert key in manifest["keys"], f"Key {key} should be in manifest"
        
        # Now test restore
        restorer = BackupRestorer()
        
        # Restore the backup (non-destructive by default)
        # First, add a new key to verify non-destructive restore
        self.redis_client.set("new_key_added_after_backup", "new_value")
        
        # Perform restore
        restore_result = restorer.restore_backup(str(backup_path))
        
        # Verify restore result
        assert restore_result.success is True
        assert restore_result.keys_restored == len(self.test_data)
        
        # Verify original data was restored
        for key, expected_value in self.test_data.items():
            restored_value = self.redis_client.get(key)
            assert restored_value is not None, f"Key {key} should exist after restore"
            assert restored_value.decode('utf-8') == expected_value, \
                f"Key {key} should have correct value after restore"
        
        # Verify new key is still present (non-destructive restore)
        new_key_value = self.redis_client.get("new_key_added_after_backup")
        assert new_key_value is not None, "New key should still exist after non-destructive restore"
        assert new_key_value.decode('utf-8') == "new_value"
    
    def test_backup_with_various_data_types(self):
        """Test backup and restore with various Redis data types."""
        # Add various data types to Redis
        self.redis_client.set("string_key", "string_value")
        self.redis_client.hset("hash_key", mapping={"field1": "value1", "field2": "value2"})
        self.redis_client.sadd("set_key", "member1", "member2", "member3")
        self.redis_client.lpush("list_key", "item1", "item2")
        
        # Create backup
        worker = BackupWorker(
            redis_host=self.redis_host,
            redis_port=self.redis_port,
            redis_db=self.redis_db
        )
        
        backup_path = worker.create_backup(self.backup_dir)
        
        # Verify backup was created
        assert backup_path.exists()
        
        # Restore to verify data integrity
        restorer = BackupRestorer()
        restore_result = restorer.restore_backup(str(backup_path))
        
        # Verify restore was successful
        assert restore_result.success is True
        assert restore_result.keys_restored == 4  # string, hash, set, list
        
        # Verify data types were restored correctly
        assert self.redis_client.get("string_key").decode('utf-8') == "string_value"
        assert self.redis_client.hget("hash_key", "field1").decode('utf-8') == "value1"
        assert self.redis_client.hget("hash_key", "field2").decode('utf-8') == "value2"
        assert "member1" in self.redis_client.smembers("set_key")
        assert "member2" in self.redis_client.smembers("set_key")
        assert "member3" in self.redis_client.smembers("set_key")
        assert self.redis_client.lindex("list_key", 1).decode('utf-8') == "item1"  # item2, item1 (LPUSH order)
        assert self.redis_client.lindex("list_key", 0).decode('utf-8') == "item2"
    
    def test_backup_empty_database(self):
        """Test backup and restore of empty Redis database."""
        # Database is already empty from setup
        
        worker = BackupWorker(
            redis_host=self.redis_host,
            redis_port=self.redis_port,
            redis_db=self.redis_db
        )
        
        backup_path = worker.create_backup(self.backup_dir)
        
        # Verify backup was created even for empty database
        assert backup_path.exists()
        
        # Verify manifest shows 0 keys
        manifest_path = Path(str(backup_path) + ".manifest.json")
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
        
        assert manifest["keys_count"] == 0
        assert len(manifest["keys"]) == 0
        
        # Restore should succeed but restore 0 keys
        restorer = BackupRestorer()
        restore_result = restorer.restore_backup(str(backup_path))
        
        assert restore_result.success is True
        assert restore_result.keys_restored == 0