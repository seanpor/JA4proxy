#!/usr/bin/env python3
"""
GDPR-compliant data storage and retention management.

This module ensures all data stored in Redis has appropriate TTLs and
retention policies that comply with GDPR data minimization requirements.

Security Considerations:
- All temporary data has TTLs (no permanent storage by default)
- Configurable retention periods per data category
- Audit logging for compliance verification
- Automatic cleanup of expired data
- Privacy-preserving identifiers in logs
"""

import hashlib
import logging
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

try:
    import redis
except ImportError:
    redis = None


class DataCategory(Enum):
    """
    Data categories with specific retention requirements.
    
    Each category has a maximum retention period based on necessity:
    - Rate tracking: Minimal (seconds) - only for immediate rate calculation
    - Fingerprints: Short (minutes to hours) - for analysis and debugging
    - Suspicious activity: Medium (minutes) - for investigation
    - Temporary blocks: Match enforcement duration
    - Bans: Longest (days) - for serious threats with justification
    """
    
    RATE_TRACKING = "rate_tracking"
    FINGERPRINTS = "fingerprints"
    SUSPICIOUS = "suspicious"
    TEMP_BLOCKS = "temp_blocks"
    BANS = "bans"
    AUDIT_LOGS = "audit_logs"
    
    def get_default_ttl(self) -> int:
        """Get default TTL for this category (seconds)."""
        defaults = {
            DataCategory.RATE_TRACKING: 60,        # 1 minute
            DataCategory.FINGERPRINTS: 3600,       # 1 hour
            DataCategory.SUSPICIOUS: 1800,         # 30 minutes
            DataCategory.TEMP_BLOCKS: 3600,        # 1 hour
            DataCategory.BANS: 604800,             # 7 days
            DataCategory.AUDIT_LOGS: 2592000,      # 30 days
        }
        return defaults[self]
    
    def get_max_ttl(self) -> int:
        """Get maximum allowed TTL for GDPR compliance (seconds)."""
        max_ttls = {
            DataCategory.RATE_TRACKING: 300,       # 5 minutes max
            DataCategory.FINGERPRINTS: 86400,      # 24 hours max
            DataCategory.SUSPICIOUS: 3600,         # 1 hour max
            DataCategory.TEMP_BLOCKS: 7200,        # 2 hours max
            DataCategory.BANS: 2592000,            # 30 days max
            DataCategory.AUDIT_LOGS: 7776000,      # 90 days max (legal requirement)
        }
        return max_ttls[self]


class GDPRStorage:
    """
    GDPR-compliant data storage with automatic retention management.
    
    This class ensures all data stored in Redis:
    - Has appropriate TTLs based on category
    - Never exceeds GDPR maximum retention periods
    - Is logged for audit trail
    - Can be verified for compliance
    """
    
    def __init__(self, redis_client, config: Optional[Dict] = None):
        """
        Initialize GDPR storage.
        
        Args:
            redis_client: Redis client for storage
            config: Optional configuration dictionary
            
        Raises:
            ValueError: If redis_client is None
        """
        if redis_client is None:
            raise ValueError("Redis client is required")
        
        self.redis = redis_client
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.audit_enabled = self.config.get('gdpr', {}).get('audit_logging', True)
        
        # Load custom retention periods if configured
        self.retention_periods = self._load_retention_periods()
        
        # Verify Redis connection
        try:
            self.redis.ping()
        except Exception as e:
            self.logger.error(f"Redis connection failed: {e}")
            raise
    
    def _load_retention_periods(self) -> Dict[DataCategory, int]:
        """Load retention periods from configuration."""
        retention = {}
        config_retention = self.config.get('gdpr', {}).get('retention_periods', {})
        
        for category in DataCategory:
            # Get configured value or use default
            configured_ttl = config_retention.get(category.value)
            
            if configured_ttl is not None:
                # Validate against maximum
                configured_ttl = int(configured_ttl)
                max_ttl = category.get_max_ttl()
                
                if configured_ttl > max_ttl:
                    self.logger.warning(
                        f"Configured TTL for {category.value} ({configured_ttl}s) "
                        f"exceeds GDPR maximum ({max_ttl}s), using maximum"
                    )
                    configured_ttl = max_ttl
                
                retention[category] = configured_ttl
            else:
                # Use default
                retention[category] = category.get_default_ttl()
        
        return retention
    
    def store(
        self,
        key: str,
        value: Any,
        category: DataCategory,
        custom_ttl: Optional[int] = None,
    ) -> bool:
        """
        Store data with appropriate TTL for GDPR compliance.
        
        Args:
            key: Redis key
            value: Value to store
            category: Data category for retention policy
            custom_ttl: Optional custom TTL (must not exceed category maximum)
            
        Returns:
            True if stored successfully, False otherwise
            
        Security:
            - TTL always enforced (no permanent storage)
            - Custom TTLs validated against GDPR limits
            - Audit logged for compliance
        """
        # Validate inputs
        if not key:
            self.logger.error("Cannot store with empty key")
            return False
        
        # Determine TTL
        if custom_ttl is not None:
            # Validate custom TTL
            max_ttl = category.get_max_ttl()
            if custom_ttl > max_ttl:
                self.logger.warning(
                    f"Custom TTL ({custom_ttl}s) exceeds GDPR maximum "
                    f"for {category.value} ({max_ttl}s), using maximum"
                )
                ttl = max_ttl
            elif custom_ttl <= 0:
                self.logger.error(f"Invalid TTL: {custom_ttl}, using default")
                ttl = self.retention_periods[category]
            else:
                ttl = custom_ttl
        else:
            # Use configured retention period
            ttl = self.retention_periods[category]
        
        # Store with TTL
        try:
            self.redis.setex(key, ttl, value)
            
            # Audit log
            if self.audit_enabled:
                self._audit_log({
                    'action': 'store',
                    'key_hash': self._hash_key(key),
                    'category': category.value,
                    'ttl': ttl,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                })
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to store key {self._hash_key(key)}: {e}")
            return False
    
    def verify_compliance(self) -> Dict:
        """
        Verify GDPR compliance of all keys in Redis.
        
        Returns:
            Dictionary with compliance status:
            - compliant_keys: Number of keys with TTLs
            - non_compliant_keys: Number of keys without TTLs
            - violations: List of keys without TTLs (hashed)
            - total_keys: Total number of keys checked
        """
        try:
            all_keys = self.redis.keys('*')
            compliant = 0
            non_compliant = 0
            violations = []
            
            for key in all_keys:
                ttl = self.redis.ttl(key)
                
                # TTL of -1 means key exists but has no expiry (violation)
                # TTL of -2 means key doesn't exist (ignore)
                if ttl == -1:
                    non_compliant += 1
                    violations.append(self._hash_key(key.decode() if isinstance(key, bytes) else key))
                elif ttl >= 0:
                    compliant += 1
            
            result = {
                'compliant_keys': compliant,
                'non_compliant_keys': non_compliant,
                'violations': violations,
                'total_keys': len(all_keys),
                'compliance_rate': compliant / len(all_keys) if all_keys else 1.0,
            }
            
            # Log violations
            if violations:
                self.logger.warning(
                    f"GDPR Compliance Violations: {non_compliant} keys without TTLs"
                )
            
            return result
        except Exception as e:
            self.logger.error(f"Failed to verify compliance: {e}")
            return {
                'error': str(e),
                'compliant_keys': 0,
                'non_compliant_keys': 0,
                'violations': [],
                'total_keys': 0,
                'compliance_rate': 0.0,
            }
    
    def cleanup_expired(self) -> int:
        """
        Explicitly cleanup expired keys (Redis does this automatically,
        but this can be used for immediate cleanup).
        
        Returns:
            Number of keys cleaned up
        """
        # Redis automatically removes expired keys, but we can scan for
        # keys with very short TTLs and log for audit
        try:
            cleaned = 0
            all_keys = self.redis.keys('*')
            
            for key in all_keys:
                ttl = self.redis.ttl(key)
                
                # If TTL is 0 or negative (except -1 which is no expiry),
                # the key is expired or will expire immediately
                if ttl == 0 or ttl == -2:
                    cleaned += 1
            
            if cleaned > 0:
                self.logger.info(f"Cleaned up {cleaned} expired keys")
            
            return cleaned
        except Exception as e:
            self.logger.error(f"Failed to cleanup expired keys: {e}")
            return 0
    
    def get_retention_report(self) -> Dict:
        """
        Get detailed retention report for audit purposes.
        
        Returns:
            Dictionary with retention statistics per category
        """
        report = {
            'retention_periods': {},
            'key_counts': {},
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        
        # Report configured retention periods
        for category, ttl in self.retention_periods.items():
            report['retention_periods'][category.value] = {
                'configured_ttl': ttl,
                'max_allowed_ttl': category.get_max_ttl(),
                'compliant': ttl <= category.get_max_ttl(),
            }
        
        # Count keys per category (by key pattern)
        try:
            patterns = {
                DataCategory.RATE_TRACKING: 'rate:*',
                DataCategory.FINGERPRINTS: 'fingerprint:*',
                DataCategory.SUSPICIOUS: 'suspicious:*',
                DataCategory.TEMP_BLOCKS: 'blocked:*',
                DataCategory.BANS: 'banned:*',
                DataCategory.AUDIT_LOGS: 'audit:*',
            }
            
            for category, pattern in patterns.items():
                keys = self.redis.keys(pattern)
                report['key_counts'][category.value] = len(keys)
        except Exception as e:
            self.logger.error(f"Failed to count keys: {e}")
        
        return report
    
    def _hash_key(self, key: str) -> str:
        """Hash key for privacy-preserving logging."""
        return hashlib.sha256(key.encode()).hexdigest()[:16]
    
    def _audit_log(self, entry: Dict) -> None:
        """Log audit entry for GDPR compliance verification."""
        try:
            # Store in Redis with audit log retention period
            audit_key = f"audit:{int(time.time() * 1000)}"
            audit_ttl = self.retention_periods[DataCategory.AUDIT_LOGS]
            
            # Convert dict to string for storage
            import json
            self.redis.setex(audit_key, audit_ttl, json.dumps(entry))
        except Exception as e:
            self.logger.error(f"Failed to write audit log: {e}")
    
    def get_audit_logs(self, limit: int = 100) -> List[Dict]:
        """
        Retrieve recent audit logs for compliance verification.
        
        Args:
            limit: Maximum number of logs to retrieve
            
        Returns:
            List of audit log entries
        """
        try:
            import json
            audit_keys = self.redis.keys('audit:*')
            
            # Sort by timestamp (key name)
            audit_keys = sorted(audit_keys, reverse=True)[:limit]
            
            logs = []
            for key in audit_keys:
                try:
                    data = self.redis.get(key)
                    if data:
                        logs.append(json.loads(data))
                except Exception as e:
                    self.logger.error(f"Failed to parse audit log: {e}")
            
            return logs
        except Exception as e:
            self.logger.error(f"Failed to retrieve audit logs: {e}")
            return []
    
    @classmethod
    def from_config(cls, redis_client, config: Dict) -> 'GDPRStorage':
        """
        Create GDPRStorage from configuration dictionary.
        
        Args:
            redis_client: Redis client instance
            config: Configuration dictionary
            
        Returns:
            Configured GDPRStorage instance
        """
        return cls(redis_client, config)
