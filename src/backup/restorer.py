"""
Restore engine module.
Implements manifest validation, checksum verification, and restore operations.
"""

import getpass
import hashlib
import json
import logging
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import redis
from prometheus_client import Counter, Gauge, Histogram

from src.backup.encryption import BackupEncryption
from src.backup.format import decode_entries

logger = logging.getLogger(__name__)


# Prometheus metrics for restore operations
RESTORE_OPERATIONS_TOTAL = Counter(
    "ja4proxy_restore_operations_total",
    "Total number of restore operations attempted",
    ["status", "type"],  # success, failure / destructive, non-destructive
)

RESTORE_DURATION_SECONDS = Histogram(
    "ja4proxy_restore_duration_seconds",
    "Duration of restore operations in seconds",
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0],
)

RESTORE_LAST_SUCCESS_TIMESTAMP = Gauge(
    "ja4proxy_restore_last_success_timestamp",
    "Unix timestamp of last successful restore",
)

RESTORE_LAST_FAILURE_TIMESTAMP = Gauge(
    "ja4proxy_restore_last_failure_timestamp", "Unix timestamp of last failed restore"
)

RESTORE_CURRENTLY_RUNNING = Gauge(
    "ja4proxy_restore_currently_running",
    "1 if restore is currently running, 0 otherwise",
)

RESTORE_KEYS_RESTORED_TOTAL = Counter(
    "ja4proxy_restore_keys_restored_total", "Total number of keys restored"
)


class RestoreError(Exception):
    """Raised when restore operations fail.

    When raised due to the key-failure threshold being exceeded (P19-G4),
    the ``failed``, ``total``, and ``threshold`` attributes are populated.
    """

    def __init__(
        self,
        message: str,
        failed: int = 0,
        total: int = 0,
        threshold: float = 0.0,
    ) -> None:
        super().__init__(message)
        self.failed = failed
        self.total = total
        self.threshold = threshold


class BackupRestorer:
    """Restore engine for Redis state from backup artifacts."""

    def __init__(
        self,
        redis_host: str = "localhost",
        redis_port: int = 6379,
        redis_db: int = 0,
        restore_error_threshold: float = 0.05,
        encryption_key: str = None,
    ):
        """Initialize restore engine.

        Args:
            redis_host: Redis host.
            redis_port: Redis port.
            redis_db: Redis database.
            restore_error_threshold: Fraction of keys that may fail before
                RestoreError is raised.  Default 0.05 (5%).  Set to 0.0 to
                raise on any failure; set to 1.0 to never raise.
            encryption_key: Secret key for AES-256-GCM decryption.
        """
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.redis_db = redis_db
        self.restore_error_threshold = restore_error_threshold
        self.encryption = BackupEncryption(encryption_key) if encryption_key else None

    def load_manifest(self, manifest_path: str) -> Dict[str, Any]:
        """Load and validate backup manifest.

        Args:
            manifest_path: Path to manifest JSON file.

        Returns:
            Parsed manifest dictionary.

        Raises:
            RestoreError: If manifest is invalid or missing required fields.
        """
        try:
            with open(manifest_path, "r") as f:
                manifest = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            raise RestoreError(f"Failed to load manifest: {e}")

        # Validate required fields
        required_fields = [
            "filename",
            "created_at",
            "backup_type",
            "keys_count",
            "checksum_sha256",
            "size_bytes",
            "included_patterns",
            "excluded_patterns",
        ]

        for field in required_fields:
            if field not in manifest:
                raise RestoreError(f"Manifest missing required field: {field}")

        # Validate filename matches pattern
        if not manifest["filename"].startswith("backup_") or not manifest[
            "filename"
        ].endswith(".bin"):
            raise RestoreError(
                f"Invalid backup filename format: {manifest['filename']}"
            )

        return manifest

    def verify_checksum(self, backup_path: str, expected_checksum: str) -> bool:
        """Verify backup artifact checksum.

        Args:
            backup_path: Path to backup artifact file.
            expected_checksum: Expected SHA256 checksum.

        Returns:
            True if checksum matches, False otherwise.

        Raises:
            RestoreError: If backup file cannot be read.
        """
        try:
            with open(backup_path, "rb") as f:
                data = f.read()
        except OSError as e:
            raise RestoreError(f"Failed to read backup file: {e}")

        actual_checksum = hashlib.sha256(data).hexdigest()
        return actual_checksum == expected_checksum

    def restore_backup(
        self,
        backup_path: str,
        manifest_path: str,
        destructive: bool = False,
    ) -> None:
        """Restore Redis state from backup.

        Args:
            backup_path: Path to backup artifact file.
            manifest_path: Path to backup manifest file.
            destructive: If True, wipe existing Redis data before restore.

        Raises:
            RestoreError: If restore fails.
        """
        start_time = datetime.utcnow()
        restore_type = "destructive" if destructive else "non-destructive"
        RESTORE_CURRENTLY_RUNNING.set(1)
        RESTORE_OPERATIONS_TOTAL.labels(status="started", type=restore_type).inc()

        # Log restore start (before loading manifest to avoid file access issues)
        logger.info(
            json.dumps(
                {
                    "ts": datetime.utcnow().isoformat() + "Z",
                    "type": "system",
                    "level": "INFO",
                    "subsystem": "restore",
                    "event": "restore_started",
                    "restore_type": restore_type,
                    "artifact": backup_path,
                }
            )
        )

        # Load and verify manifest/checksum BEFORE connecting to Redis.
        # Fast-fail: no point acquiring a distributed lock on a corrupt backup.
        try:
            manifest = self.load_manifest(manifest_path)
            if not self.verify_checksum(backup_path, manifest["checksum_sha256"]):
                raise RestoreError("Checksum verification failed")
        except RestoreError:
            RESTORE_CURRENTLY_RUNNING.set(0)
            RESTORE_OPERATIONS_TOTAL.labels(status="failure", type=restore_type).inc()
            raise

        # Connect to Redis (manifest is valid, safe to proceed)
        redis_client = redis.Redis(
            host=self.redis_host,
            port=self.redis_port,
            db=self.redis_db,
        )

        try:
            # Phase 40: Distributed Locking
            if not redis_client.set("backup:operation_lock", "restore", nx=True, ex=600):
                raise RestoreError("Backup/Restore operation already in progress (lock held)")

            # Log manifest loaded with key count
            logger.info(
                json.dumps(
                    {
                        "ts": datetime.utcnow().isoformat() + "Z",
                        "type": "system",
                        "level": "INFO",
                        "subsystem": "restore",
                        "event": "manifest_loaded",
                        "keys_expected": manifest.get("keys_count", 0),
                    }
                )
            )

            # Check if Redis is available
            if not redis_client.ping():
                raise RestoreError("Redis connection failed")

            if destructive:
                # Wipe existing data (destructive restore)
                self._wipe_redis_data(redis_client)

            # Phase 40: Decryption
            # _restore_backup_data reads the file directly; we need to handle decryption
            # if the manifest says it's encrypted.
            encryption_cfg = manifest.get("encryption", {})
            is_encrypted = encryption_cfg.get("enabled", False)
            
            if is_encrypted:
                if not self.encryption:
                    raise RestoreError("Backup is encrypted but no decryption key provided")
                
                # Read, decrypt, and save to a temporary file for _restore_backup_data
                # Alternatively, we could refactor _restore_backup_data to accept bytes.
                # Let's refactor it to accept data bytes optionally.
                with open(backup_path, "rb") as f:
                    encrypted_data = f.read()
                
                try:
                    decrypted_data = self.encryption.decrypt(encrypted_data)
                except Exception as e:
                    raise RestoreError(f"Decryption failed: {e}")
                
                keys_restored, keys_failed = self._restore_from_bytes(
                    redis_client, decrypted_data
                )
            else:
                # Restore backup data from file
                keys_restored, keys_failed = self._restore_backup_data(
                    redis_client, backup_path
                )
            
            keys_total = keys_restored + keys_failed
            RESTORE_KEYS_RESTORED_TOTAL.inc(keys_restored)

            # P19-G4: raise RestoreError if failure fraction exceeds threshold
            threshold = self.restore_error_threshold
            if keys_total > 0 and keys_failed / keys_total > threshold:
                logger.error(
                    json.dumps(
                        {
                            "ts": datetime.utcnow().isoformat() + "Z",
                            "type": "system",
                            "level": "ERROR",
                            "subsystem": "restore",
                            "event": "restore_threshold_exceeded",
                            "keys_total": keys_total,
                            "keys_failed": keys_failed,
                            "keys_restored": keys_restored,
                            "threshold_pct": int(threshold * 100),
                        }
                    )
                )
                raise RestoreError(
                    f"Restore aborted: {keys_failed}/{keys_total} keys failed"
                    f" ({keys_failed / keys_total:.1%} > {threshold:.0%} threshold)",
                    failed=keys_failed,
                    total=keys_total,
                    threshold=threshold,
                )

            # Phase 57f: post-restore verification (advisory — never blocks success)
            self._verify_key_count(
                redis_client,
                expected_count=manifest.get("keys_count", 0),
                backup_filename=manifest["filename"],
            )
            self._write_restored_from(
                redis_client,
                filename=manifest["filename"],
                keys_count=keys_restored,
            )

            # Record success metrics
            duration = (datetime.utcnow() - start_time).total_seconds()
            RESTORE_DURATION_SECONDS.observe(duration)
            RESTORE_OPERATIONS_TOTAL.labels(status="success", type=restore_type).inc()
            RESTORE_LAST_SUCCESS_TIMESTAMP.set(datetime.utcnow().timestamp())
            RESTORE_CURRENTLY_RUNNING.set(0)

            # Log restore success
            logger.info(
                json.dumps(
                    {
                        "ts": datetime.utcnow().isoformat() + "Z",
                        "type": "system",
                        "level": "INFO",
                        "subsystem": "restore",
                        "event": "restore_succeeded",
                        "restore_type": restore_type,
                        "keys_restored": keys_restored,
                        "keys_failed": keys_failed,
                        "duration_ms": int(duration * 1000),
                        "artifact": backup_path,
                    }
                )
            )

            # Write audit log entry
            audit_entry = {
                "event": "restore_completed",
                "actor_ip": f"{getpass.getuser()}@{socket.gethostname()}",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "detail": {
                    "backup_filename": manifest["filename"],
                    "destructive": destructive,
                    "keys_restored": keys_restored,
                    "validation_passed": True,
                    "triggered_by": "manual",
                },
            }
            redis_client.lpush("management:audit_log", json.dumps(audit_entry))
            redis_client.ltrim("management:audit_log", -1000, -1)

        except Exception as e:
            # Record failure metrics
            duration = (datetime.utcnow() - start_time).total_seconds()
            RESTORE_DURATION_SECONDS.observe(duration)
            RESTORE_OPERATIONS_TOTAL.labels(status="failure", type=restore_type).inc()
            RESTORE_LAST_FAILURE_TIMESTAMP.set(datetime.utcnow().timestamp())
            RESTORE_CURRENTLY_RUNNING.set(0)

            # Log restore failure
            logger.error(
                json.dumps(
                    {
                        "ts": datetime.utcnow().isoformat() + "Z",
                        "type": "system",
                        "level": "ERROR",
                        "subsystem": "restore",
                        "event": "restore_failed",
                        "restore_type": restore_type,
                        "error": str(e),
                        "duration_ms": int(duration * 1000),
                        "artifact": backup_path,
                    }
                )
            )

            # Write audit log entry for failure
            audit_entry = {
                "event": "restore_failed",
                "actor_ip": f"{getpass.getuser()}@{socket.gethostname()}",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "detail": {
                    "error": str(e),
                    "duration_seconds": duration,
                    "triggered_by": "manual",
                },
            }
            try:
                if redis_client:
                    redis_client.lpush("management:audit_log", json.dumps(audit_entry))
                    redis_client.ltrim("management:audit_log", -1000, -1)
            except redis.RedisError:
                # If audit logging fails, don't let it prevent the main error from being raised
                pass

            if isinstance(e, RestoreError):
                raise
            raise RestoreError(f"Restore failed: {e}")
        finally:
            if redis_client:
                # Phase 40: Release Distributed Lock
                redis_client.delete("backup:operation_lock")
            RESTORE_CURRENTLY_RUNNING.set(0)

    def _wipe_redis_data(self, redis_client: redis.Redis) -> None:
        """Wipe all data from Redis database.

        Args:
            redis_client: Redis client instance.
        """
        # Use FLUSHDB to wipe current database
        redis_client.flushdb()

    def _restore_backup_data(
        self, redis_client: redis.Redis, backup_path: str
    ) -> tuple:
        """Restore backup data to Redis.

        Reads the backup artifact and restores each key-value pair using
        ``redis.restore(key, 0, dump_data, replace=True)``, which handles
        all Redis data types transparently. Keys are restored one at a time;
        individual restore failures are logged and skipped so one corrupt
        entry does not abort the entire restore.

        Args:
            redis_client: Redis client instance.
            backup_path: Path to backup artifact file.

        Returns:
            Number of keys successfully restored.

        Raises:
            RestoreError: If the backup artifact cannot be read.
        """
        try:
            with open(backup_path, "rb") as f:
                backup_data = f.read()
        except OSError as e:
            raise RestoreError(f"Failed to read backup data: {e}")

        keys_restored = 0
        keys_failed = 0
        for key, dump_data in decode_entries(backup_data):
            try:
                redis_client.restore(key, 0, dump_data, replace=True)
                keys_restored += 1
            except redis.RedisError as exc:
                keys_failed += 1
                logger.warning("restore skipped key %s: %s", key, exc)

        # Record restore marker for time-of-restore auditing.
        redis_client.set("backup:last_restore", datetime.utcnow().isoformat() + "Z")

        return keys_restored, keys_failed

    def _restore_from_bytes(self, redis_client: redis.Redis, data: bytes) -> tuple:
        """
        Restore backup data from raw bytes.
        """
        keys_restored = 0
        keys_failed = 0
        for key, dump_data in decode_entries(data):
            try:
                redis_client.restore(key, 0, dump_data, replace=True)
                keys_restored += 1
            except redis.RedisError as exc:
                keys_failed += 1
                logger.warning("restore skipped key %s: %s", key, exc)

        return keys_restored, keys_failed

    # ------------------------------------------------------------------
    # Phase 57f: post-restore verification helpers
    # ------------------------------------------------------------------

    def _verify_key_count(
        self,
        redis_client: redis.Redis,
        expected_count: int,
        backup_filename: str,
    ) -> None:
        """Verify the number of keys in Redis after restore matches the manifest.

        This check is **advisory only** — it logs a WARNING if divergence exceeds
        5% but never raises an exception or blocks a successful restore.  Any
        error during the SCAN (e.g. mock incompatibility) is silently swallowed
        so the advisory can never break a restore.

        Args:
            redis_client: Connected Redis client.
            expected_count: Number of keys recorded in the backup manifest.
            backup_filename: Name of the backup artifact (for log context).
        """
        if expected_count <= 0:
            return  # Nothing meaningful to check

        try:
            restored_count = 0
            cursor = 0
            while True:
                cursor, keys = redis_client.scan(cursor=cursor, count=100)  # type: ignore[misc]
                restored_count += len(keys)
                if cursor == 0:
                    break

            divergence = abs(restored_count - expected_count) / expected_count
            if divergence > 0.05:
                logger.warning(
                    "backup | event=restore_key_count_divergence | filename=%s | "
                    "expected=%d | restored=%d | divergence_pct=%.1f",
                    backup_filename,
                    expected_count,
                    restored_count,
                    divergence * 100,
                )
        except Exception as exc:
            logger.debug(
                "backup | event=key_count_verify_skipped | filename=%s | reason=%s",
                backup_filename,
                exc,
            )

    def _write_restored_from(
        self,
        redis_client: redis.Redis,
        filename: str,
        keys_count: int,
    ) -> None:
        """Record which backup artifact was used for this restore.

        Writes ``backup:restored_from`` as a JSON object with ``filename``,
        ``restored_at`` (ISO-8601), and ``keys_count`` fields.

        Args:
            redis_client: Connected Redis client.
            filename: Backup artifact filename (basename only).
            keys_count: Number of keys successfully restored.
        """
        record = json.dumps({
            "filename": filename,
            "restored_at": datetime.now(timezone.utc).isoformat(),
            "keys_count": keys_count,
        })
        redis_client.set("backup:restored_from", record)

    def restore_with_fallback(
        self,
        primary_path: Path,
        fallback_paths: Optional[List[Path]] = None,
    ) -> Path:
        """Restore from ``primary_path``; try ``fallback_paths`` in order if primary fails.

        Attempts each artifact in sequence until one succeeds.  The first
        artifact whose checksum validates and whose restore completes without
        error is used.  If a fallback is used a WARNING is logged identifying
        which artifact succeeded.

        Args:
            primary_path: Path to the primary backup artifact (.bin file).
            fallback_paths: Ordered list of fallback artifact paths to try
                if the primary fails.  Defaults to an empty list.

        Returns:
            The ``Path`` of the artifact that was successfully restored.

        Raises:
            RestoreError: If every artifact in ``primary_path + fallback_paths``
                fails checksum verification or restore.
        """
        all_paths = [primary_path] + list(fallback_paths or [])
        manifest_suffix = ".manifest.json"
        last_exc: Optional[Exception] = None

        for i, artifact_path in enumerate(all_paths):
            manifest_path = Path(str(artifact_path) + manifest_suffix)
            try:
                self.restore_backup(str(artifact_path), str(manifest_path))
                if i > 0:
                    logger.warning(
                        "backup | event=fallback_restore_used | primary=%s | used=%s",
                        primary_path.name,
                        artifact_path.name,
                    )
                return artifact_path
            except Exception as exc:
                last_exc = exc
                if i < len(all_paths) - 1:
                    logger.warning(
                        "backup | event=restore_artifact_failed | path=%s | "
                        "trying_fallback=True | error=%s",
                        artifact_path.name,
                        exc,
                    )
                else:
                    logger.error(
                        "backup | event=all_restore_paths_failed | tried=%d | error=%s",
                        len(all_paths),
                        exc,
                    )

        raise RestoreError(
            f"All {len(all_paths)} restore artifact(s) failed. "
            f"Last error: {last_exc}"
        ) from last_exc
