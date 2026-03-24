"""
Backup worker module.
Implements deterministic key enumeration, backup artifact creation, and retention.
"""
import getpass
import hashlib
import json
import logging
import os
import socket
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List

import redis
from prometheus_client import Counter, Gauge, Histogram

from src.backup.format import encode_entry
from src.backup.policy import KeyPolicy

logger = logging.getLogger(__name__)


# Never-backup key patterns: keys that must never appear in backups
_KEY_PATTERNS_NEVER_BACKUP = [
    "abuseipdb:*",            # Any abuseipdb key (API keys, etc.)
    "config:redis_password",    # Passwords should never be in Redis
    "*:auth_token",           # Any auth token pattern
]

# Prometheus metrics for backup operations
BACKUP_OPERATIONS_TOTAL = Counter(
    "ja4proxy_backup_operations_total",
    "Total number of backup operations attempted",
    ["status"]  # success, failure
)

BACKUP_KEYS_PROCESSED_TOTAL = Counter(
    "ja4proxy_backup_keys_processed_total",
    "Total number of keys processed during backups"
)

BACKUP_DURATION_SECONDS = Histogram(
    "ja4proxy_backup_duration_seconds",
    "Duration of backup operations in seconds",
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0]
)

BACKUP_SIZE_BYTES = Histogram(
    "ja4proxy_backup_size_bytes",
    "Size of backup artifacts in bytes",
    buckets=[1024, 10240, 102400, 1048576, 10485760, 1073741824]
)

BACKUP_LAST_SUCCESS_TIMESTAMP = Gauge(
    "ja4proxy_backup_last_success_timestamp",
    "Unix timestamp of last successful backup"
)

BACKUP_LAST_FAILURE_TIMESTAMP = Gauge(
    "ja4proxy_backup_last_failure_timestamp",
    "Unix timestamp of last failed backup"
)

BACKUP_CURRENTLY_RUNNING = Gauge(
    "ja4proxy_backup_currently_running",
    "1 if backup is currently running, 0 otherwise"
)


class BackupWorker:
    """Backup worker for Redis state."""

    def __init__(
        self,
        redis_host: str = "localhost",
        redis_port: int = 6379,
        redis_db: int = 0,
        max_keys_per_run: int = 1000,
    ):
        """Initialize backup worker.

        Args:
            redis_host: Redis host.
            redis_port: Redis port.
            redis_db: Redis database.
            max_keys_per_run: Maximum keys to back up per run.
        """
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.redis_db = redis_db
        self.max_keys_per_run = max_keys_per_run
        self.policy = KeyPolicy()

    def enumerate_keys(self) -> List[str]:
        """Enumerate keys to back up using SCAN.

        Returns:
            List of keys to back up, filtered and ordered.
        """
        redis_client = redis.Redis(
            host=self.redis_host,
            port=self.redis_port,
            db=self.redis_db,
        )

        keys = []
        cursor = 0
        while True:
            cursor, batch = redis_client.scan(cursor=cursor, count=100)  # type: ignore[misc]
            keys.extend(batch)
            if cursor == 0:
                break

        # Filter and dedup
        filtered_keys = []
        seen = set()
        for key in keys:
            if key not in seen and self.policy.should_backup(key):
                seen.add(key)
                filtered_keys.append(key)

        # Order deterministically
        filtered_keys.sort()

        # Apply max_keys_per_run cap
        return filtered_keys[: self.max_keys_per_run]

    def _validate_backup_directory(self, dest_path: Path) -> None:
        """Validate backup directory permissions and security.

        Args:
            dest_path: Path to backup directory.

        Raises:
            Exception: If directory permissions are insecure or invalid.
        """
        # Check if directory exists and is accessible
        if not os.access(str(dest_path), os.R_OK | os.W_OK | os.X_OK):
            raise Exception(f"Backup directory {dest_path} is not accessible (read/write/execute)")

        # Check ownership first (should be owned by current user)
        stat_info = os.stat(str(dest_path))
        if stat_info.st_uid != os.getuid():
            raise Exception(f"Backup directory {dest_path} is not owned by current user")

        # Check directory permissions (should not be world-writable)
        mode = stat_info.st_mode
        if mode & 0o002:  # World-writable bit
            raise Exception(f"Backup directory {dest_path} has insecure permissions (world-writable)")
        if mode & 0o020:  # Group-writable bit
            raise Exception(f"Backup directory {dest_path} has insecure permissions (group-writable)")

    def create_backup(self, destination_dir: str) -> Path:
        """Create backup artifact and manifest.

        Args:
            destination_dir: Directory to save backup files.

        Returns:
            Path to backup artifact file.
        """
        # Ensure destination directory exists
        dest_path = Path(destination_dir)
        dest_path.mkdir(parents=True, exist_ok=True)

        # Validate directory permissions and security
        try:
            self._validate_backup_directory(dest_path)
        except Exception as e:
            logger.error(
                json.dumps({
                    "ts": datetime.utcnow().isoformat() + "Z",
                    "type": "system",
                    "level": "ERROR",
                    "subsystem": "backup",
                    "event": "filesystem_validation_failed",
                    "error": str(e),
                    "directory": str(dest_path)
                })
            )
            raise

        redis_client = None
        start_time = datetime.utcnow()
        BACKUP_CURRENTLY_RUNNING.set(1)
        BACKUP_OPERATIONS_TOTAL.labels(status="started").inc()

        try:
            # Log backup start (before any operations that might fail)
            logger.info(
                json.dumps({
                    "ts": datetime.utcnow().isoformat() + "Z",
                    "type": "system",
                    "level": "INFO",
                    "subsystem": "backup",
                    "event": "backup_started"
                })
            )

            # Get keys to back up
            keys = self.enumerate_keys()

            # Log keys enumeration result
            logger.info(
                json.dumps({
                    "ts": datetime.utcnow().isoformat() + "Z",
                    "type": "system",
                    "level": "INFO",
                    "subsystem": "backup",
                    "event": "keys_enumerated",
                    "keys_expected": len(keys)
                })
            )

            BACKUP_KEYS_PROCESSED_TOTAL.inc(len(keys))

            # Filter out never-backup keys and log warnings
            safe_keys = []
            never_backup_keys_found = []

            for key in keys:
                if self._is_never_backup_key(key):
                    never_backup_keys_found.append(key)
                    logger.warning(
                        json.dumps({
                            "ts": datetime.utcnow().isoformat() + "Z",
                            "type": "system",
                            "level": "WARN",
                            "subsystem": "backup",
                            "event": "sensitive_key_detected",
                            "key": key,
                            "message": f"Key {key} matches never-backup pattern and will be excluded"
                        })
                    )
                else:
                    safe_keys.append(key)

            # Create backup artifact
            backup_data = b""
            redis_client = redis.Redis(
                host=self.redis_host,
                port=self.redis_port,
                db=self.redis_db,
            )

            for key in safe_keys:
                key_str = key.decode("utf-8") if isinstance(key, bytes) else key
                dumped = redis_client.dump(key)
                if dumped:
                    # Encode key name alongside dump data so restore can
                    # write each value back to the correct key.
                    backup_data += encode_entry(key_str, dumped)  # type: ignore[operator,arg-type]

            # Generate checksum
            checksum = hashlib.sha256(backup_data).hexdigest()

            # Create artifact file
            timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            backup_filename = f"backup_{timestamp}.bin"
            backup_path = dest_path / backup_filename

            backup_path.write_bytes(backup_data)

            # Record backup size metric
            BACKUP_SIZE_BYTES.observe(len(backup_data))

            # Create manifest
            manifest = {
                "filename": backup_filename,
                "created_at": datetime.utcnow().isoformat() + "Z",
                "backup_type": "full",
                "keys_count": len(keys),
                "checksum_sha256": checksum,
                "size_bytes": len(backup_data),
                "included_patterns": self.policy.include_patterns,
                "excluded_patterns": self.policy.exclude_patterns,
                # Extensibility block for Phase 21 encryption (always false in Phase 19)
                "encryption": {
                    "enabled": False,
                    "provider": None,   # Phase 21: "aws-kms" | "vault" | "local-aes"
                    "key_id": None,     # Phase 21: KMS key ARN or Vault key path
                    "algorithm": None,  # Phase 21: "AES-256-GCM"
                },
            }

            manifest_path = dest_path / f"{backup_filename}.manifest.json"
            manifest_path.write_text(json.dumps(manifest, indent=2))

            # Update control keys on success
            redis_client.set("backup:latest", backup_filename)
            redis_client.set("backup:last_success", datetime.utcnow().isoformat() + "Z")

            # Record success metrics
            duration = (datetime.utcnow() - start_time).total_seconds()
            BACKUP_DURATION_SECONDS.observe(duration)
            BACKUP_OPERATIONS_TOTAL.labels(status="success").inc()
            BACKUP_LAST_SUCCESS_TIMESTAMP.set(datetime.utcnow().timestamp())
            BACKUP_CURRENTLY_RUNNING.set(0)

            # Log backup success
            logger.info(
                json.dumps({
                    "ts": datetime.utcnow().isoformat() + "Z",
                    "type": "system",
                    "level": "INFO",
                    "subsystem": "backup",
                    "event": "backup_succeeded",
                    "keys_processed": len(keys),
                    "size_bytes": len(backup_data),
                    "duration_ms": int(duration * 1000),
                    "artifact_path": str(backup_path),
                    "checksum": checksum
                })
            )

            # Write audit log entry
            audit_entry = {
                "event": "backup_completed",
                "actor_ip": f"{getpass.getuser()}@{socket.gethostname()}",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "detail": {
                    "type": "full",
                    "keys_exported": len(safe_keys),
                    "filename": backup_filename,
                    "size_bytes": len(backup_data),
                    "duration_seconds": duration,
                    "triggered_by": "manual"
                }
            }
            redis_client.lpush("management:audit_log", json.dumps(audit_entry))
            redis_client.ltrim("management:audit_log", -1000, -1)

            return backup_path

        except Exception as e:
            # Update control keys on failure
            if redis_client:
                redis_client.set("backup:last_failure", datetime.utcnow().isoformat() + "Z")

            # Record failure metrics
            duration = (datetime.utcnow() - start_time).total_seconds()
            BACKUP_DURATION_SECONDS.observe(duration)
            BACKUP_OPERATIONS_TOTAL.labels(status="failure").inc()
            BACKUP_LAST_FAILURE_TIMESTAMP.set(datetime.utcnow().timestamp())
            BACKUP_CURRENTLY_RUNNING.set(0)

            # Log backup failure
            logger.error(
                json.dumps({
                    "ts": datetime.utcnow().isoformat() + "Z",
                    "type": "system",
                    "level": "ERROR",
                    "subsystem": "backup",
                    "event": "backup_failed",
                    "error": str(e),
                    "duration_ms": int(duration * 1000)
                })
            )

            # Write audit log entry for failure
            if redis_client:
                audit_entry = {
                    "event": "backup_failed",
                    "actor_ip": f"{getpass.getuser()}@{socket.gethostname()}",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "detail": {
                        "error": str(e),
                        "duration_seconds": duration,
                        "triggered_by": "manual"
                    }
                }
                redis_client.lpush("management:audit_log", json.dumps(audit_entry))
                redis_client.ltrim("management:audit_log", -1000, -1)

            raise

    def _is_never_backup_key(self, key: str) -> bool:
        """Check if a key matches any never-backup pattern.

        Args:
            key: Redis key to check.

        Returns:
            True if the key should never be backed up, False otherwise.
        """
        import fnmatch
        for pattern in _KEY_PATTERNS_NEVER_BACKUP:
            if fnmatch.fnmatch(key, pattern):
                return True
        return False

    def apply_retention(
        self, backup_dir: str, retain_count: int = None, retention_days: int = None
    ) -> None:
        """Apply retention policy to backup directory.

        Args:
            backup_dir: Directory containing backup files.
            retain_count: Maximum number of backups to keep (None to disable).
            retention_days: Maximum age of backups to keep in days (None to disable).
        """
        backup_path = Path(backup_dir)

        if not backup_path.exists():
            return

        # Get all backup files with their manifests
        backup_files = list(backup_path.glob("backup_*.bin"))

        if not backup_files:
            return

        # Parse backup information from manifests
        backups = []
        for backup_file in backup_files:
            manifest_file = backup_file.with_suffix(backup_file.suffix + ".manifest.json")

            if manifest_file.exists():
                try:
                    with open(manifest_file, "r") as fh:
                        manifest = json.load(fh)

                    created_at = datetime.fromisoformat(manifest["created_at"].rstrip("Z"))

                    backups.append({
                        "file": backup_file,
                        "manifest": manifest_file,
                        "created_at": created_at,
                        "filename": manifest["filename"]
                    })
                except (json.JSONDecodeError, KeyError):
                    # Skip invalid manifests
                    continue

        if not backups:
            return

        # Sort by creation time (newest first)
        backups.sort(key=lambda x: x["created_at"], reverse=True)

        # Apply age-based retention first
        if retention_days is not None:
            cutoff = datetime.utcnow() - timedelta(days=retention_days)
            backups = [b for b in backups if b["created_at"] >= cutoff]

        # Apply count-based retention
        if retain_count is not None and len(backups) > retain_count:
            backups = backups[:retain_count]

        # Delete backups not in the retention list
        all_backup_files = set(backup_path.glob("backup_*.bin"))
        all_manifest_files = set(backup_path.glob("backup_*.bin.manifest.json"))

        to_keep_files = {b["file"] for b in backups}
        to_keep_manifests = {b["manifest"] for b in backups}

        to_delete_files = all_backup_files - to_keep_files
        to_delete_manifests = all_manifest_files - to_keep_manifests

        # Delete files
        for f in to_delete_files:
            try:
                f.unlink()
            except OSError:
                pass

        # Delete manifests
        for f in to_delete_manifests:
            try:
                f.unlink()
            except OSError:
                pass
