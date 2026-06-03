"""
Backup key-policy contract module.
Defines include/exclude patterns and forbidden keys.
"""


class KeyPolicy:
    """Defines backup key-policy contract."""

    def __init__(self):
        # Include patterns: keys that should be backed up
        self.include_patterns = [
            "config:*",
            "ban:*",
            "ja4:whitelist",
            "ja4:blacklist",
            "tor:exit:ips",
            "dns:ptr:*",
            # abuseipdb:score:* intentionally omitted: these are external
            # reputation scores re-fetchable from the AbuseIPDB API and do not
            # need to survive a Redis failure.  worker.py also lists abuseipdb:*
            # in _KEY_PATTERNS_NEVER_BACKUP as a defence-in-depth guard.
            "rdap:ip:*",
            "rdap:org:*",
            "analytics:*",
            # attribution:profile:* — 90-day-TTL attacker fingerprint correlation
            # profiles built up over weeks; must survive a Redis failure.
            "attribution:profile:*",
            # attribution:ips:* — 30-day-TTL IP sets correlated to a JA4
            # fingerprint; losing them requires weeks of re-accumulation.
            "attribution:ips:*",
        ]

        # Exclude patterns: keys that should not be backed up
        self.exclude_patterns = [
            "session:*",
            "lifespan:*",
            "concurrent:*",
            "visitor:*",
            "tls_alerts:*",
            "beacon:*",
            "bloom:*",
            "browser:seen:*",
        ]

        # Forbidden keys: keys that must never be backed up
        self.forbidden_keys = [
            "backup:latest",
            "backup:last_success",
            "backup:last_failure",
        ]

    def should_backup(self, key: str) -> bool:
        """Determine if a key should be backed up.

        Args:
            key: Redis key to check.

        Returns:
            True if the key should be backed up, False otherwise.
        """
        # Check forbidden keys first
        if key in self.forbidden_keys:
            return False

        # Check include patterns
        for pattern in self.include_patterns:
            if self._matches_pattern(key, pattern):
                return True

        # Check exclude patterns
        for pattern in self.exclude_patterns:
            if self._matches_pattern(key, pattern):
                return False

        # Default: do not back up
        return False

    def _matches_pattern(self, key: str, pattern: str) -> bool:
        """Check if a key matches a pattern.

        Args:
            key: Redis key to check.
            pattern: Pattern to match against.

        Returns:
            True if the key matches the pattern, False otherwise.
        """
        # Simple wildcard matching
        if pattern.endswith("*"):
            prefix = pattern[:-1]
            return key.startswith(prefix)
        else:
            return key == pattern

    def order_keys(self, keys: list[str]) -> list[str]:
        """Order keys deterministically.

        Args:
            keys: List of Redis keys.

        Returns:
            List of keys ordered deterministically.
        """
        return sorted(keys)
