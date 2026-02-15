#!/usr/bin/env python3
"""
GDPR compliance tests for data retention and privacy.

These tests verify that the system complies with GDPR requirements:
- Data minimization
- Storage limitation (automatic expiration)
- Accuracy (current data only)
- Integrity and confidentiality
"""

import pytest
import time
from unittest.mock import Mock, MagicMock

from src.security.gdpr_storage import GDPRStorage, DataCategory


@pytest.fixture
def mock_redis():
    """Create mock Redis client."""
    redis = Mock()
    redis.ping.return_value = True
    redis.setex.return_value = True
    redis.keys.return_value = []
    redis.ttl.return_value = 3600
    redis.get.return_value = None
    return redis


@pytest.fixture
def gdpr_storage(mock_redis):
    """Create GDPR storage instance."""
    config = {
        'gdpr': {
            'enabled': True,
            'audit_logging': True,
        }
    }
    return GDPRStorage(mock_redis, config)


class TestDataCategory:
    """Test DataCategory enum and retention periods."""
    
    def test_default_ttls(self):
        """Test default TTL values for each category."""
        assert DataCategory.RATE_TRACKING.get_default_ttl() == 60
        assert DataCategory.FINGERPRINTS.get_default_ttl() == 3600
        assert DataCategory.SUSPICIOUS.get_default_ttl() == 1800
        assert DataCategory.TEMP_BLOCKS.get_default_ttl() == 3600
        assert DataCategory.BANS.get_default_ttl() == 604800
        assert DataCategory.AUDIT_LOGS.get_default_ttl() == 2592000
    
    def test_max_ttls(self):
        """Test maximum TTL values for GDPR compliance."""
        assert DataCategory.RATE_TRACKING.get_max_ttl() == 300  # 5 minutes
        assert DataCategory.FINGERPRINTS.get_max_ttl() == 86400  # 24 hours
        assert DataCategory.SUSPICIOUS.get_max_ttl() == 3600  # 1 hour
        assert DataCategory.TEMP_BLOCKS.get_max_ttl() == 7200  # 2 hours
        assert DataCategory.BANS.get_max_ttl() == 2592000  # 30 days
        assert DataCategory.AUDIT_LOGS.get_max_ttl() == 7776000  # 90 days
    
    def test_max_greater_than_default(self):
        """Test that max TTL is always >= default TTL."""
        for category in DataCategory:
            assert category.get_max_ttl() >= category.get_default_ttl()


class TestGDPRStorageInit:
    """Test GDPRStorage initialization."""
    
    def test_init_successful(self, mock_redis):
        """Test successful initialization."""
        storage = GDPRStorage(mock_redis)
        assert storage.redis == mock_redis
        mock_redis.ping.assert_called_once()
    
    def test_init_redis_none(self):
        """Test initialization fails with None Redis client."""
        with pytest.raises(ValueError, match="Redis client is required"):
            GDPRStorage(None)
    
    def test_init_redis_connection_fails(self):
        """Test initialization fails when Redis connection fails."""
        redis = Mock()
        redis.ping.side_effect = Exception("Connection failed")
        
        with pytest.raises(Exception, match="Connection failed"):
            GDPRStorage(redis)
    
    def test_init_loads_default_retention(self, mock_redis):
        """Test default retention periods are loaded."""
        storage = GDPRStorage(mock_redis)
        
        assert storage.retention_periods[DataCategory.RATE_TRACKING] == 60
        assert storage.retention_periods[DataCategory.FINGERPRINTS] == 3600
        assert storage.retention_periods[DataCategory.BANS] == 604800
    
    def test_init_loads_custom_retention(self, mock_redis):
        """Test custom retention periods from config."""
        config = {
            'gdpr': {
                'retention_periods': {
                    'rate_tracking': 120,  # 2 minutes (within max)
                    'fingerprints': 7200,  # 2 hours (within max)
                }
            }
        }
        storage = GDPRStorage(mock_redis, config)
        
        assert storage.retention_periods[DataCategory.RATE_TRACKING] == 120
        assert storage.retention_periods[DataCategory.FINGERPRINTS] == 7200
    
    def test_init_enforces_max_retention(self, mock_redis):
        """Test that retention periods exceeding max are capped."""
        config = {
            'gdpr': {
                'retention_periods': {
                    'rate_tracking': 1000,  # Exceeds max of 300
                }
            }
        }
        storage = GDPRStorage(mock_redis, config)
        
        # Should be capped at maximum
        assert storage.retention_periods[DataCategory.RATE_TRACKING] == 300


class TestStore:
    """Test data storage with TTL enforcement."""
    
    def test_store_with_default_ttl(self, gdpr_storage, mock_redis):
        """Test storing data with default TTL."""
        result = gdpr_storage.store(
            key="test:key",
            value="test_value",
            category=DataCategory.FINGERPRINTS,
        )
        
        assert result is True
        mock_redis.setex.assert_called()
        
        # Check TTL is default for category
        call_args = mock_redis.setex.call_args_list[0]
        assert call_args[0][0] == "test:key"
        assert call_args[0][1] == 3600  # Default for FINGERPRINTS
        assert call_args[0][2] == "test_value"
    
    def test_store_with_custom_ttl(self, gdpr_storage, mock_redis):
        """Test storing data with custom TTL."""
        result = gdpr_storage.store(
            key="test:key",
            value="test_value",
            category=DataCategory.FINGERPRINTS,
            custom_ttl=1800,  # 30 minutes
        )
        
        assert result is True
        call_args = mock_redis.setex.call_args_list[0]
        assert call_args[0][1] == 1800
    
    def test_store_enforces_max_ttl(self, gdpr_storage, mock_redis):
        """Test that custom TTL exceeding max is capped."""
        result = gdpr_storage.store(
            key="test:key",
            value="test_value",
            category=DataCategory.RATE_TRACKING,
            custom_ttl=1000,  # Exceeds max of 300
        )
        
        assert result is True
        call_args = mock_redis.setex.call_args_list[0]
        assert call_args[0][1] == 300  # Capped at maximum
    
    def test_store_rejects_empty_key(self, gdpr_storage, mock_redis):
        """Test storing with empty key fails."""
        result = gdpr_storage.store(
            key="",
            value="test_value",
            category=DataCategory.FINGERPRINTS,
        )
        
        assert result is False
        mock_redis.setex.assert_not_called()
    
    def test_store_rejects_negative_ttl(self, gdpr_storage, mock_redis):
        """Test storing with negative custom TTL uses default."""
        result = gdpr_storage.store(
            key="test:key",
            value="test_value",
            category=DataCategory.FINGERPRINTS,
            custom_ttl=-1,
        )
        
        assert result is True
        call_args = mock_redis.setex.call_args_list[0]
        assert call_args[0][1] == 3600  # Default for FINGERPRINTS
    
    def test_store_handles_redis_error(self, gdpr_storage, mock_redis):
        """Test graceful handling of Redis errors."""
        mock_redis.setex.side_effect = Exception("Redis error")
        
        result = gdpr_storage.store(
            key="test:key",
            value="test_value",
            category=DataCategory.FINGERPRINTS,
        )
        
        assert result is False


class TestComplianceVerification:
    """Test GDPR compliance verification."""
    
    def test_verify_all_compliant(self, gdpr_storage, mock_redis):
        """Test verification when all keys have TTLs."""
        mock_redis.keys.return_value = [b"key1", b"key2", b"key3"]
        mock_redis.ttl.return_value = 3600  # All keys have TTL
        
        result = gdpr_storage.verify_compliance()
        
        assert result['compliant_keys'] == 3
        assert result['non_compliant_keys'] == 0
        assert result['compliance_rate'] == 1.0
        assert len(result['violations']) == 0
    
    def test_verify_with_violations(self, gdpr_storage, mock_redis):
        """Test verification with non-compliant keys."""
        mock_redis.keys.return_value = [b"key1", b"key2", b"key3"]
        
        # key1 has TTL, key2 and key3 don't
        def ttl_side_effect(key):
            if key == b"key1":
                return 3600
            else:
                return -1  # No TTL (violation)
        
        mock_redis.ttl.side_effect = ttl_side_effect
        
        result = gdpr_storage.verify_compliance()
        
        assert result['compliant_keys'] == 1
        assert result['non_compliant_keys'] == 2
        assert result['compliance_rate'] == 1/3
        assert len(result['violations']) == 2
    
    def test_verify_empty_database(self, gdpr_storage, mock_redis):
        """Test verification with no keys."""
        mock_redis.keys.return_value = []
        
        result = gdpr_storage.verify_compliance()
        
        assert result['compliant_keys'] == 0
        assert result['non_compliant_keys'] == 0
        assert result['compliance_rate'] == 1.0
        assert result['total_keys'] == 0
    
    def test_verify_handles_errors(self, gdpr_storage, mock_redis):
        """Test verification handles Redis errors gracefully."""
        mock_redis.keys.side_effect = Exception("Redis error")
        
        result = gdpr_storage.verify_compliance()
        
        assert 'error' in result
        assert result['compliance_rate'] == 0.0


class TestRetentionReport:
    """Test retention reporting."""
    
    def test_get_retention_report(self, gdpr_storage, mock_redis):
        """Test getting retention report."""
        mock_redis.keys.return_value = []
        
        report = gdpr_storage.get_retention_report()
        
        assert 'retention_periods' in report
        assert 'key_counts' in report
        assert 'timestamp' in report
        
        # Check retention periods are reported
        assert 'rate_tracking' in report['retention_periods']
        assert 'fingerprints' in report['retention_periods']
        
        # Check each category has required fields
        for category, info in report['retention_periods'].items():
            assert 'configured_ttl' in info
            assert 'max_allowed_ttl' in info
            assert 'compliant' in info
    
    def test_retention_report_counts_keys(self, gdpr_storage, mock_redis):
        """Test retention report counts keys per category."""
        def keys_side_effect(pattern):
            if pattern == 'rate:*':
                return [b'rate:1', b'rate:2']
            elif pattern == 'fingerprint:*':
                return [b'fingerprint:1']
            else:
                return []
        
        mock_redis.keys.side_effect = keys_side_effect
        
        report = gdpr_storage.get_retention_report()
        
        assert report['key_counts']['rate_tracking'] == 2
        assert report['key_counts']['fingerprints'] == 1


class TestGDPRCompliance:
    """Integration tests for GDPR compliance."""
    
    def test_no_permanent_storage(self, gdpr_storage, mock_redis):
        """Test that all stored data has TTLs (no permanent storage)."""
        # Store various types of data
        categories = [
            DataCategory.RATE_TRACKING,
            DataCategory.FINGERPRINTS,
            DataCategory.SUSPICIOUS,
            DataCategory.TEMP_BLOCKS,
            DataCategory.BANS,
        ]
        
        for i, category in enumerate(categories):
            gdpr_storage.store(
                key=f"test:{i}",
                value=f"value_{i}",
                category=category,
            )
        
        # All calls should have used setex (which includes TTL)
        # Each store creates 2 calls: data + audit log
        expected_calls = len(categories) * 2
        assert mock_redis.setex.call_count == expected_calls
        
        # Verify all calls had TTL > 0
        for call in mock_redis.setex.call_args_list:
            ttl = call[0][1]
            assert ttl > 0, f"TTL must be positive, got {ttl}"
    
    def test_retention_within_gdpr_limits(self, gdpr_storage):
        """Test all retention periods are within GDPR limits."""
        for category, ttl in gdpr_storage.retention_periods.items():
            max_ttl = category.get_max_ttl()
            assert ttl <= max_ttl, \
                f"{category.value}: TTL {ttl}s exceeds max {max_ttl}s"
    
    def test_data_minimization(self, gdpr_storage, mock_redis):
        """Test that only minimal data is stored."""
        # Store data
        gdpr_storage.store(
            key="minimal:test",
            value="minimal_value",
            category=DataCategory.RATE_TRACKING,
        )
        
        # Should use shortest retention period for minimal data
        call_args = mock_redis.setex.call_args_list[0]
        ttl = call_args[0][1]
        assert ttl == 60  # Rate tracking has shortest default TTL
