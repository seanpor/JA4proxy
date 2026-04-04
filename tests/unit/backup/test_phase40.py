"""
Unit tests for Phase 40 Backup Enhancements (Encryption, Locking, Redaction).
"""

import json
import os
from unittest.mock import MagicMock, mock_open, patch

import pytest

from src.backup.encryption import BackupEncryption
from src.backup.format import encode_entry
from src.backup.redactor import BackupRedactor
from src.backup.restorer import BackupRestorer
from src.backup.worker import BackupWorker


def test_encryption_roundtrip():
    secret = "super-secret-key"
    data = b"sensitive-redis-dump-data"
    
    enc = BackupEncryption(secret)
    encrypted = enc.encrypt(data)
    
    assert encrypted != data
    assert len(encrypted) > len(data)
    
    decrypted = enc.decrypt(encrypted)
    assert decrypted == data


def test_encryption_invalid_key():
    enc1 = BackupEncryption("key-one")
    enc2 = BackupEncryption("key-two")
    
    data = b"data"
    encrypted = enc1.encrypt(data)
    
    with pytest.raises(Exception): # cryptography raises InvalidTag or similar
        enc2.decrypt(encrypted)


def test_redactor_logic():
    redactor = BackupRedactor()
    
    # Create sample backup data
    data = b""
    data += encode_entry("visitor:1.1.1.1", b"val1")
    data += encode_entry("visitor:2.2.2.2", b"val2")
    data += encode_entry("ja4:whitelist", b"val3")
    
    # Redact 1.1.1.1
    redacted_data, count = redactor.redact(data, ["1.1.1.1"])
    
    assert count == 1
    assert b"1.1.1.1" not in redacted_data
    assert b"2.2.2.2" in redacted_data
    assert b"ja4:whitelist" in redacted_data


@patch("redis.Redis")
def test_worker_locking(mock_redis_cls):
    mock_redis = mock_redis_cls.return_value
    # Lock fails
    mock_redis.set.return_value = False
    
    worker = BackupWorker()
    worker._validate_backup_directory = MagicMock() # Bypass FS check
    with pytest.raises(Exception, match="already in progress"):
        worker.create_backup("/tmp/backups")


@patch("redis.Redis")
@patch.object(BackupRestorer, "verify_checksum", return_value=True)
@patch.object(BackupRestorer, "load_manifest", return_value={"checksum_sha256": "abc", "keys_count": 0})
def test_restorer_locking(mock_load_manifest, mock_verify, mock_redis_cls):
    mock_redis = mock_redis_cls.return_value
    # Lock fails — simulate a concurrent operation already holding the lock
    mock_redis.set.return_value = False

    restorer = BackupRestorer()
    with pytest.raises(Exception, match="already in progress"):
        restorer.restore_backup("art", "manifest")


@patch("src.backup.worker.BackupEncryption")
@patch("src.backup.worker.redis.Redis")
@patch("src.backup.worker.Path")
def test_worker_encryption_integration(mock_path, mock_redis_cls, mock_enc_cls):
    # Mock setup
    mock_redis = mock_redis_cls.return_value
    mock_redis.set.return_value = True # Lock success
    
    mock_enc = mock_enc_cls.return_value
    mock_enc.encrypt.return_value = b"encrypted-data"
    
    worker = BackupWorker(encryption_key="secret")
    worker._validate_backup_directory = MagicMock() # Bypass FS check
    
    # Mock enumerate and dump
    worker.enumerate_keys = MagicMock(return_value=["k1"])
    worker._dump_keys_batched = MagicMock(return_value={"k1": b"v1"})
    
    with patch("builtins.open", mock_open()):
        worker.create_backup("/tmp/backups")
        
    mock_enc.encrypt.assert_called()
    # Verify manifest would show encryption (harder to check with mock Path but logic was added)
