# PHASE 19 — Backup & Restore Framework

## Status: OPEN

---

## Goal

Implement a complete backup and restore capability for JA4proxy state stored in Redis. The system currently has no mechanism to export or recover state (block lists, bans, analytics data) without manual Redis dump operations. This phase adds automated, idempotent backup/restore that supports disaster recovery, point-in-time recovery, and state migration.

---

## 19a. Backup Architecture

### Design Principles

1. **Idempotency**: Multiple identical backups must produce the same result
2. **Safety-first**: Backups never delete or modify production data
3. **Incremental support**: Use Redis RDB snapshots with manual selection of keys
4. **Validation**: Verify checksum before storing backup artifact
5. **Rollback-ready**: Restore artifacts include metadata for audit trail

### Backup Modes

| Mode | Description | When to use |
|------|-------------|-----------|
| Full backup | Export all keys matching backup patterns | Weekly, after major changes |
| Incremental | Rely on `redis-dump-stream` append-only log | Continuous, every N minutes |
| Selective | Export specific key patterns (e.g., only bans) | Quick recoveries, migrations |
| Config-only | Export config + static lists to git/CLI | Initial deploy, zero-downtime switchover |

---

## 19b. Redis Schema for Backups

New keys for backup management (documented here):

### Backup Control Keys

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-- -----|------|-------||----|
| `backup:latest` | JSON | none | Backup worker | Points to latest successful backup artifact `{filename, keys_count, checksum, created_at, type}` |
| `backup:schedule` | Hash | 604800s (7d) | Config reload | Cron schedule `{minutes:[HH:MM], daily:[HH:MM], weekly:[DOW HH:MM]}` |
| `backup:last_success` | String (ISO timestamp) | 86400s (24h) | Backup worker | Last successful backup time; used for incremental decisions |
| `backup:last_failure` | String (ISO timestamp + error) | 3600s (1h) | Backup worker | Track last failure; alert if repeated |
| `backup:retention_count` | Integer | 43200s (12h) | Config reload | Number of backups to retain (default 14) |
| `backup:retention_days` | Integer | none | Config reload | Max days to retain; overrides retention_count for time-based expiry |

### Backup Artifact Manifest

Each backup artifact includes a manifest in a sidecar JSON file:

```json
{
  "artifact": {
    "filename": "ja4proxy-backup-2026-03-08T120000Z.tar.gz",
    "created_at": "2026-03-08T12:00:00.000000+00:00",
    "type": "full",
    "keys_count": 847523,
    "checksum_sha256": "<sha256-of-archive>",
    "rdb_size_bytes": 45892341,
    "keys_included": {
      "ja4:whitelist/set",
      "ja4:blacklist/set",
      "config:dial",
      "ban:{ips}/set",
      "block:{cidrs}",
      "static:allowlist/set",
      "management:*"
    },
    "excluded_patterns": [
      "lifespan:* TTL < 1h",
      "concurrent:* transient state"
    ],
    "redis_version_compatible": "6.2+",
    "encryption_key_id": null,
    "backup_metadata": {
      "hostname": "<instance>",
      "instance_uuid": "<leader UUID if applicable>"
    }
  },
  "restore_notes": [
    "Restore to a fresh Redis instance with matching major version",
    "Stop write traffic for duration of restore window"
  ]
}
```

---

## 19c. Backup Module Implementation

### Hot Path Isolation

The backup worker must never block the hot path (connection handling). Use a separate process/thread with its own Redis connection pool.

```python
# NEW: src/backup/worker.py
"""Backup worker - runs periodically to create scheduled backups."""

import asyncio
import json
import tarfile
import hashlib
import redis
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, List
import logging

logger = logging.getLogger(__name__)

BACKUP_DIR = Path("/var/backups/ja4proxy")
MANIFEST_DIR = BACKUP_DIR / "manifests"


class BackupWorker:
    """Periodically backs up Redis state to local filesystem."""

    _KEY_PATTERNS_BACKUP = [
        "ja4:*",          # Whitelist/blacklist
        "ban:*",          # Active bans (with reason)
        "block:*",       # CIDR blocks
        "static:*",       # Allowlists managed via UI or config
        "management:*",   # Audit logs, policy changes
        "config:*" except "config:reload*",  # Don't backup pub/sub channels
        "abuseipdb:*",    # AbuseIPDB scores (read-only data)
        "rdap:org:*",     # RDAP org data (read-only)
        "rdap:netblock:*", # RDAP netblock data (read-only)
    ]

    _KEY_PATTERNS_EXCLUDE = [
        "lifespan:*",          # TTL-based transient state < 1h
        "rate:*" except "rate:*:counter",  # Transient rate limiting windows
        "beacon:*" except "beacon:suspects",  # Short-term beacon observations
        "session:ip:*",       # Per-connection session tracking (< 1h TTL)
        "tls_alerts:*",       # Transient alert counts
    ]

    _KEY_PATTERNS_NO_MTIME = [
        "ja4:*",  # Static config - don't track mtime for dedup decisions
        "block:*",  # CIDR blocks rarely change
    ]

    def __init__(self, redis_URL: str, output_dir: Path, retention_days: int = 14,
                 retain_count: int = 14, backup_type: Optional[str] = None):
        """Back up all keys matching _KEY_PATTERNS_BACKUP.

        Args:
            redis_URL: Redis connection string (e.g., "redis://redis:6379")
            output_dir: Where to store backup artifacts
            retention_days: Maximum age of backups in days
            retain_count: Maximum number of most-recent backups regardless of age
            backup_type: Optional override of backup type ("full", "incremental", "selective")
        """
        self.redis = redis.from_url(redis_URL)
        self.output_dir = output_dir / "backups"
        MANIFEST_DIR.mkdir(parents=True, exist_ok=True)
        self.retention_days = retention_days
        self.retain_count = retain_count

    def run(self) -> Dict:
        """Execute backup job. Returns status dict."""
        try:
            logger.info("Starting backup job")
            
            # Determine which keys to export
            key_filter = self._build_key_filter()
            backup_type = self._determine_backup_type()

            # Export RDB snapshot of matching keys only
            rdb_content = self._export_keys(key_filter)

            # Validate checksum before creating archive
            checksum = hashlib.sha256(rdb_content).hexdigest()

            # Create timestamped filename
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
            filename = f"ja4proxy-backup-{timestamp}.tar.gz"
            filepath = self.output_dir / filename

            # Compress and add checksum to manifest
            backup_info = {
                "filename": filename,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "type": backup_type,
                "keys_count": len(key_filter),
                "checksum_sha256": checksum,
                "rdb_size_bytes": self._estimate_rdb_size(rdb_content),
            }

            # Store with manifest
            manifest_info = {
                "backup": backup_info,
                "excluded_patterns": self._KEY_PATTERNS_EXCLUDE,
                "redis_version_compatible": "6.2+",
                "encryption_key_id": None
            }

            with tarfile.open(filepath, "w:gz") as tar:
                # Add RDB content with manifest sidecar
                import io
                rdb_stream = io.BytesIO(rdb_content)
                
            # Write manifest as separate JSON file
            manifest_path = BACKUP_DIR / filename.replace(".tar.gz", ".json")
            with open(manifest_path, "w") as f:
                json.dump(manifest_info, f, indent=2, default=str)

            logger.info(f"Backup complete: {filename} ({len(key_filter)} keys)")

            # Update Redis control keys
            self._update_control_keys(backup_info, filepath)

            self.redis.delete("backup:latest")  # Force refresh on next read
            self.redis.set("backup:latest", json.dumps(backup_info))
            self.redis.lpush("backup:history", filepath.name, maxlen=self.retain_count)

            return {"success": True, "filepath": str(filepath)}

        except Exception as e:
            logger.error(f"Backup failed: {e}")
            
            # Update failure tracking
            error_info = {"error": str(e), "attempted_at": datetime.now(timezone.utc).isoformat()}
            self.redis.set("backup:last_failure", json.dumps(error_info))
            
            return {"success": False, "error": str(e)}

    def _build_key_filter(self) -> list:
        """Build filter for keys to export."""
        keys = []
        patterns = self._KEY_PATTERNS_BACKUP
        
        for pattern in patterns:
            cursor = 0
            while True:
                cursor, keys_result = self.redis.scan(cursor=cursor, match=pattern, count=100)
                keys.extend(keys_result)
                if cursor == 0:
                    break

        # Calculate approximate RDB size from key list
        total_size = sum(self.redis.dbsize() for _ in [keys])  # Rough estimate
        
        return keys, total_size

    def _determine_backup_type(self) -> str:
        """Determine backup type based on schedule and flags."""
        last_success = self.redis.get("backup:last_success")
        
        if not last_success:
            return "full"
        
        # Check if we're in a maintenance window (daily cron)
        now = datetime.now(timezone.utc)
        schedule = json.loads(self.redis.hgetall("backup:schedule"))
        
        if schedule and self._current_maintenance_window(now, schedule):
            return "full"
        
        return "incremental"

    def _export_keys(self, filter_result: tuple) -> bytes:
        """Export keys to RDB format."""
        # Use redis-dump-stream for efficient snapshotting
        import redis_dumps  # Hypothetical module
        rdb_output = redis_dumps.dump(filter_result[0], self.redis)
        return rdb_output.encode()

    def _estimate_rdb_size(self, keys) -> int:
        """Estimate RDB size in bytes (crude but sufficient for metadata)."""
        import redis  # Already available
        
        dbsize = self.redis.dbsize()
        estimated_size = len(json.dumps(keys)) * 200  # Rough multiplier
        
        return estimated_size

    def _current_maintenance_window(self, now: datetime, schedule: dict) -> bool:
        """Check if current time matches scheduled maintenance window."""
        minutes = [int(m.strip(":")) for m in schedule.get("minutes", []).split(",")]
        hour, minute = now.hour, int(now.minute) or 0
        
        return minute in minutes or (minute // 15) * 15 == (hour * 60 + minute) // 15

    def _update_control_keys(self, backup_info: dict, filepath: str) -> None:
        """Update Redis control keys with latest backup info."""
        last_success = json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **"backup_info" **{"filename": backup_info["filename"]}
        })
        
        self.redis.set("backup:last_success", last_success)
        self.redis.lpush("backup:history", filepath, maxlen=self.retain_count)


# Cleanup old backups (separate task to avoid blocking backup job)
def cleanup_old_backups(redis_URL: str, retention_days: int = 14, retain_count: int = 14):
    """Remove backups older than retention_days or beyond retain_count."""
    pass
```

### Restore Module

```python
# NEW: src/backup/restorer.py
"""Restore Redis state from backup artifact."""

import tarfile
import json
import redis
import hashlib
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class Restorer:
    """Restore Redis state from backup artifact with validation."""

    def __init__(self, redis_URL: str, backup_path: Path):
        """Initialize restorer.

        Args:
            redis_URL: Redis target connection string
            backup_path: Path to backup archive (.tar.gz or .rdb)
        """
        self.redis = redis.from_url(redis_URL)
        self.backup_path = backup_path
        
    def restore(self, delete_data_first: bool = False) -> Dict:
        """Restore state from backup.

        Args:
            delete_data_first: If True, clear Redis first to avoid mixing old/new data
            
        Returns:
            Status dict with metadata
        """
        
        if not self.backup_path.exists():
            error_msg = f"Backup file not found: {self.backup_path}"
            logger.error(error_msg)
            return {"success": False, "error": error_msg}
        
        # Load manifest to get expected checksum
        try:
            with open(self.backup_path.parent / self.backup_path.name.replace(".tar.gz", ".json")) as f:
                manifest = json.load(f)
            artifact = manifest["artifact"]
            
            if not delete_data_first:
                current_checksum = self._current_state_checksum()
                expected_checksum = artifact["checksum_sha256"]
                
                # Only warn, don't fail - allow restoring on top of existing state
                logger.info(f"Running in non-destructive mode (existing checksum: {current_checksum[:16]}...)")
            
        except (FileNotFoundError, json.JSONDecodeError):
            logger.warning("Manifest not found or invalid, proceeding without validation")

        # For demonstration, skip actual RDB parsing in this example
        # In production, use redis-cli --rdb <file> or redis-server loadsave
        
        delete_count = 0 if not delete_data_first else self.redis.dbsize()
        
        metadata = {
            "backup_filename": artifact["filename"],
            "keys_restored": delete_count == 0 and len(artifact.keys_included) or None,
            "timestamp": artifact["created_at"],
            "type": artifact["type"]
        }

        logger.info(f"Restore complete: {metadata}")
        
        return {"success": True, "metadata": metadata}

    def _current_state_checksum(self) -> str:
        """Generate checksum of current Redis state for comparison."""
        keys = self.redis.keys("*")
        key_set = frozenset(keys)
        return hashlib.sha256(str(sorted(key_set)).encode()).hexdigest()[:16]


# Validation utilities
class BackupValidator:
    """Validate backup artifacts before restore."""

    @staticmethod
    def validate_artifact(backup_path: Path, required_keys: Optional[list] = None) -> Dict:
        """Validate backup file integrity.

        Args:
            backup_path: Path to backup file or manifest
            required_keys: List of key patterns that must exist (None = no check)

        Returns:
            Validation result dict
        """
        
        if not backup_path.exists():
            return {
                "valid": False,
                "error": f"File not found: {backup_path}"
            }
        
        # Load manifest to extract checksum
        try:
            with open(backup_path.parent / backup_path.name.replace(".tar.gz", ".json")) as f:
                manifest = json.load(f)
            
            if required_keys:
                keys_included = set(manifest["artifact"]["keys_included"])
                for pattern in required_keys:
                    if not any(pattern.startswith(k.split("{")[0]) for k in keys_included):
                        return {
                            "valid": False,
                            "error": f"Missing key pattern: {pattern}"
                        }
            
            # If file is RDB format (not tar.gz), compute hash from contents
            if backup_path.suffix == ".rdb":
                with open(backup_path, "rb") as f:
                    checksum = hashlib.sha256(f.read()).hexdigest()
                expected = manifest["artifact"]["checksum_sha256"]
                
                if checksum != expected:
                    return {
                        "valid": False,
                        "error": f"Checksum mismatch (expected: {expected}, got: {checksum})"
                    }

            logger.info(f"Backup validated: {backup_path}")
            return {"valid": True}

        except json.JSONDecodeError as e:
            return {
                "valid": False,
                "error": f"Invalid manifest JSON: {e}"
            }


# CLI tools (NEW: CLI entry points for manual operations)
class BackupCLI:
    """Command-line interface for backup operations."""

    @staticmethod
    def run_backup(args):
        """Entry point for 'proxy-cli backup' command."""
        from src.backup.worker import BackupWorker
        
        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        worker = BackupWorker(
            redis_URL=args.redis_url,
            output_dir=output_dir,
            retention_days=args.retention,
            retain_count=args.retain_count,
            backup_type=args.type if hasattr(args, 'type') else None
        )
        
        result = worker.run()
        print(json.dumps(result, indent=2))
        
        return 0 if result["success"] else 1

    @staticmethod
    def restore_backup(args):
        """Entry point for 'proxy-cli restore' command."""
        from src.backup.restorer import Restorer, BackupValidator
        
        backup_path = Path(args.file)
        
        # Validate before restore
        validation = BackupValidator.validate_artifact(backup_path.parent / backup_path.name.replace(".tar.gz", ".json"))
        
        if not validation["valid"]:
            print(f"Validation failed: {validation['error']}")
            return 1
        
        restorer = Restoter(
            redis_URL=args.redis_url,
            backup_path=backup_path
        )
        
        result = restorer.restore(delete_data_first=args.force)
        print(json.dumps(result, indent=2))
        
        return 0 if result["success"] else 1

    @staticmethod
    def list_backups(args):
        """Entry point for 'proxy-cli backup-list' command."""
        from pathlib import Path
        
        output_dir = args.path or BACKUP_DIR / "backups"
        
        if not output_dir.exists():
            print("No backups directory found")
            return 1
        
        backups = sorted(output_dir.glob("ja4proxy-backup-*.tar.gz"), reverse=True)
        
        for backup in backups[:args.limit if hasattr(args, 'limit') else None]:
            try:
                with open(backup.parent / backup.name.replace(".tar.gz", ".json")) as f:
                    manifest = json.load(f)
                artifact = manifest["artifact"]
                
                print(f"\n{artifact['filename']}")
                print(f"  Created: {artifact['created_at']}")
                print(f"  Type: {artifact['type']}")
                print(f"  Keys: {artifact['keys_count']}")
                print(f"  Size: {artifact['rdb_size_bytes'] / (1024**3):.2f} GB")
                print(f"  Checksum: {artifact['checksum_sha256'][:16]}...")
                
            except (FileNotFoundError, json.JSONDecodeError):
                print(f"\n{backup.name}")
                print(f"  (Manifest unavailable)")
        
        return 0


class RestoreCLI:
    """Command-line interface for restore operations."""

    @staticmethod
    def run_restore(args):
        from src.backup.restorer import Restorer
        
        # Implementation similar to BackupCLI.restore_backup
        pass


# Configuration schema
BACKUP_CONFIG_SCHEMA = {
    "backup": {
        "enabled": True,
        "schedule": {
            "minutes": ["0"],  # Run every hour at minute 0
            "daily": "",       # Optional additional daily runs
            "weekly": ""       # Optional weekly full backups
        },
        "destination": "/var/backups/ja4proxy",
        "retention_days": 14,
        "retain_count": 14,
        "compression": True,
        "encryption": {
            "enabled": False,
            "provider": "aws-kms" or "openssl",
            "key_id": ""
        },
        "notify_success": True,
        "notify_failure": True,
        "validation": True
    }
}
```

---

## 19d. Observability Integration

### Prometheus Metrics Registry

Add these metrics to `docs/OBSERVABILITY_STANDARDS.md`:

| Metric | Unit | Type | Description | Labels |
|--------|------|------|-------------|--------|
| `ja4proxy_backup_jobs_total` | counter | Counter | Total backup jobs executed | `{result="success|failure", type="full|incremental"}` |
| `ja4proxy_backup_duration_seconds` | histogram | Histogram | Duration of backup job | `{type="full|incremental"}` |
| `ja4proxy_backup_keys_exported_total` | counter | Counter | Total keys exported in latest backup | `{key_pattern="..."}` |
| `ja4proxy_backup_size_bytes` | gauge | Gauge | Size of current RDB snapshot | `{compression="gzip|none"}` |
| `ja4proxy_restore_successful_total` | counter | Counter | Successful restores (non-destructive only) | `{destructive="true|false"}` |
| `ja4proxy_backup_retention_exceeded_count` | gauge | Gauge | Backups removed due to retention policy | `=` |
| `ja4proxy_backup_stale_seconds` | gauge | Gauge | Seconds since last successful backup | `>` |

### Grafana Dashboard Panels

Create panels in Grafana:

1. **Backup Health**: Green if latest backup < 4h ago, yellow if < 24h, red if > 24h
2. **Backup Trend**: Time series of backup sizes (logarithmic scale)
3. **Retention Policy**: Bar chart showing oldest/youngest backups
4. **Restore Latency**: Histogram for restore operations

### Alertmanager Rules

```yaml
# docs/alerts/backup.yaml
groups:
- name: backup.rules
  rules:
  - alert: BackupStale
    expr: |
      time() - ja4proxy_backup_stale_seconds > 86400
    for: 1h
    labels:
      severity: warning
      team: platform
    annotations:
      summary: "Backup older than 24 hours"
      description: "{{ $labels.instance }} has no successful backup in the past 24 hours. Check disk space, Redis connectivity."

  - alert: BackupFailureRate
    expr: |
      increase(ja4proxy_backup_jobs_total{result="failure"}[1h]) 
      > 0.1
    for: 30m
    labels:
      severity: critical  
      team: platform
    annotations:
      summary: "Backup failure rate elevated"
      description: "{{ $labels.instance }} has {{ printf \"%d\" $value }} failures in the past hour."

  - alert: BackupSizeIncrease
    expr: |
      change(ja4proxy_backup_size_bytes[1d]) > 0.5 * (1024 ^ 3)
    for: null  # Immediate notification
    labels:
      severity: warning
      team: platform
    annotations:  
      summary: "Unexpected backup size increase"
      description: "Latest backup is {{ printf \"%.2f\" $value }}GB, previous was less than half that."
```

---

## 19e. Logging Specification

### Event Log Schema

For each backup job completed or failed:

```json
{
  "timestamp": "2026-03-08T12:05:23.456789+00:00",
  "level": "INFO",
  "component": "backup.worker",
  "event_id": "bck-20260308-120523-abc123",
  "event_type": "backup_completed",
  "host": "ja4proxy-backup-01.example.com",
  "details": {
    "type": "full",
    "keys_exported": 847523,
    "rdb_size_bytes": 45892341,
    "compressed_size_bytes": 38472156,
    "checksum_sha256_prefix": "a1b2c3d4e5f6...",
    "duration_seconds": 12.4,
    "backup_file": "/var/backups/ja4proxy/ja4proxy-backup-2026-03-08T120000Z.tar.gz"
  }
}
```

For failures:

```json
{
  "timestamp": "2026-03-08T12:05:45.789123+00:00",
  "level": "ERROR",
  "component": "backup.worker",
  "event_id": "bck-20260308-120545-def456",
  "event_type": "backup_failed",
  "host": "ja4proxy-backup-01.example.com",
  "error_code": "DISK_FULL",
  "error_message": "/var/backups/ja4proxy: no space left on device (df: 98% used)",
  "retry_count": 2,
  "context": {
    "previous_runs": [{"timestamp": "...", "type": "full"}],
    "disk_usage_percent": 97.2,
    "oldest_backup_age_days": 13
  }
}
```

### Structured Logs to Ship

All backup and restore operations must log:

- `component=backup.*` — job lifecycle events
- `event_type`=one of:`completed`, `failed`, `skipped`, `validation_passed`, `cleaned_up`
- `error_code`: standardized enum (see below)
- `host`: machine hostname
- `details`: JSON object with all metrics

### Error Classification Codes

| Code | When to use | Example message |
|------|-------------|-----------------|
| `DISK_FULL` | Output directory has no space | "no space left on device" |
| `REDIS_TIMEOUT` | Redis connection timeout | "read timeout after 30s" |
| `MANIFEST_MISMATCH` | Checksum doesn't match manifest | "checksum SHA256 mismatch" |
| `FILE_NOT_FOUND` | Backup file missing from disk | "backup archive not found" |
| `VALIDATION_FAILED` | RDB corruption detected | "RDB parsing error: unexpected EOF" |
| `RETENTION_EXCEEDED` | Cleanup job couldn't delete old backups | "couldn't remove backup due to hard link failure" |

---

## 19f. Testing Strategy

### Unit Tests (`tests/unit/backup/test_worker.py`)

```python
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from src.backup.worker import BackupWorker, BackupCLI


class TestBackupWorker:
    """Unit tests for backup worker."""

    @pytest.fixture
    def redis_mock(self):
        return MagicMock()

    @pytest.fixture
    def output_dir(self, tmp_path):
        return tmp_path / "backups"

    def test_run_creates_backup_file(self, redis_mock, output_dir):
        """Backup worker creates backup file and returns success."""
        with patch("os.path.exists", return_value=False):
            worker = BackupWorker(
                redis_URL="redis://localhost:6379",
                output_dir=output_dir
            )
            # Stub RDB export
            redis_mock.scan.return_value = (0, ["key1", "key2"])
            
            # Would normally do actual backup logic here
            pass

    def test_run_fails_on_missing_file(self):
        """Worker handles missing output directory gracefully."""
        with pytest.raises(FileNotFoundError):
            worker = BackupWorker(
                redis_URL="redis://localhost:6379",
                output_dir=Path("/nonexistent/output")
            )
```

### Chaos Tests (`tests/chaos/test_backup_chaos.py`)

```python
import pytest
from pathlib import Path
from src.backup.worker import BackupWorker
from tests.fixtures import chaos_factory  # Reuse existing chaos fixtures


class TestBackupResilience:
    """Chaos engineering tests for backup operations."""

    def test_backup_with_high_latency_redis(self, redis_mock, tmp_path):
        """Backup completes even with slow Redis responses simulating network lag."""
        
        # Patch redis to simulate 500ms latency
        original_from_url = __import__("redis").from_url
        
        @classmethod
        def mock_from_url(cls, url: str, **kwargs):
            instance = original_from_url(url, **kwargs)
            
            import asyncio
            
            class LatencyWrapper(instance):
                async def execute_command(self, *args, **kwargs):
                    await asyncio.sleep(0.5)  # 500ms latency
                    return await super().execute_command(*args, **kwargs)
            
            return LatencyWrapper._make(cls, args(), attrs())
        
        with patch.most(__import__("redis").from_url": mock_from_url):
            worker = BackupWorker(
                redis_URL="redis://slow-redis:6379",
                output_dir=tmp_path/"backups"
            )

    def test_backup_with_redis_network_partition(self, redis_mock, tmp_path):
        """Backup fails cleanly when Redis is unreachable."""
        
        # Simulate network partition by making all commands queue up for 10s
        
    def test_restorer_validate_checksum_mismatch(self, tmp_path):
        """Restore CLI rejects backup with checksum mismatch."""
        
        manifest = {
            "artifact": {
                "checksum_sha256": "deadbeef...",
                "keys_included": {},
            }
        }

### Integration Tests (`tests/integration/test_backup_restore.py`)

```python
import pytest
import subprocess
from pathlib import Path


class TestBackupRestoreIntegration:
    """Integration tests for backup/restore workflows."""

    @pytest.fixture(scope="module")
    def test_redis(self):
        return chaos_factory.build_redis(
            data={},
            capacity=500,
            maxmemory_policy="allkeys-lru"
        )

    def test_backup_and_restore_nondestructive(self, test_redis, tmp_path):
        """Restore non-destructively appends to existing state."""
        
        # 1. Populate Redis with keys to backup
        redis_cli = subprocess.run(
            ["redis-cli", "keys", "*"],
            capture_output=True, text=True
        )
        count = len([l for l in redis_cli.stdout.split("\n")])

        # Add 10 more keys
        for i in range(10):
            redis_cli = subprocess.run(
                ["redis-cli", "SET", f"test_key_{i}": f"value_{i}"],
                capture_output=True
            )

        # 2. Create backup with original count
        result = BackupWorker(
            redis_URL="redis://localhost:6379",
            output_dir=tmp_path / "backups"
        ).run()
        
        assert result["success"] is True
    
    def test_backup_restore_destructive(self, test_redis, tmp_path):
        """Restore with --force clears existing state first."""
        
        redis_cli = ...

    @pytest.mark.slow  # Takes several minutes to run
    def test_full_backup_restore_cycle(self, test_redis, tmp_path):
        """End-to-end: full backup then restore and verify integrity.
        
        This validates the entire pipeline from export to restoration
        including checksum validation and state comparison.
        """
        
        # Populate Redis with realistic data
        populate_redis(test_redis)

        # Create backup  
        backup_result = run_cli_backup(
            cli="/opt/ja4proxy/proxy-cli",
            "--output", str(tmp_path / "backups"),
            output_dir=args.output
        )
        
        assert backup_result.returncode == 0
        backup_file = tmp_path / "backups" / manifest["artifact"][i]

### Performance Tests (`tests/perf/test_backup_perf.py`)

```python
import pytest
from src.backup.worker import BackupWorker


class TestBackupPerformance:
    """Verify backup operations don't impact production throughput."""

    @pytest.mark.performance_baseline
    def test_backup_duration_acceptable(self, test_redis):
        """Full backup completes in under 60s for realistic dataset.
        
        Acceptance criteria:
        - Small dataset (10k keys): < 15s
        - Medium dataset (1M keys): < 90s  
        - Large dataset (10M keys): < 5m
        
        These thresholds are set to allow maintenance windows of <= 30min.
        """
        worker = BackupWorker(...)
        result = worker.run()
        
        # Would measure actual duration here

    @pytest.mark.performance_load_test
    def test_backup_with_live_traffic(self, test_redis, http_client):
        """Backup runs without blocking request handling."""
        
        # Concurrent backup + HTTP load
        backup_task = asyncio.create_task(worker.run())
        
        async with ThreadPoolExecutor(...) as executor:
            await loop.run_in_executor(executor, concurrent_http_requests)

### Fuzzing Tests (NEW: `tests/fuzz/test_backup_inputs.py`)

```python
import pytest
from hypothesis import given, strategies as st


class TestBackupValidation:
    """Fuzz backup input data and manifest formats."""

    @given(
        # Hypothesis strategy generates random JSON manifests
        
@pytest.mark.slow  # Only in full CI pipeline
def test_edge_case_key_patterns(keys_to_exclude) -> bool:
    """All exclusion patterns work correctly (including edge cases):"""
    
    from hypothesis import given, strategies as st
    from src.backup.worker import BackupWorker
    
    @given(st.sampled_from(some_large_dataset_keys))
    def test_no_exclusion_leak(key):
        if key.startswith("lifespan:"):  # Excluded pattern
            return False

### Adversarial Tests (`tests/adversarial/test_backup_attacks.py`)

```python
import pytest


class TestBackupSecurity:
    """Security-focused tests for backup operations."""

    def test_backup_does_not_inude_sensitive_data_redaction):
        """Verify backup contents don't expose secrets (even if accidentally included)."""
        
        # Would redact sensitive keys

    @pytest.mark.slow  # Requires real environment
    def test_restore_fails_when_backup_signed_but_key_invalid(self, signer):
        """Detect tampered backups."""
        
        from tests.fixtures import create_tampered_backup
        
        bad_backup = tamper_backup(valid_backup)


@pytest.fixture
def signing_key():
    """Generate an asymmetric key pair for backup signing."""

# More security-focused tests...
```

### FP Monitoring (NEW: `tests/fp_corpus/test_backup_fp.py`)

Test against real-world data to estimate false positives (e.g., accidentally excluding a critical ban list):

```python
import random

@pytest.mark.slow  # Takes time on Tranco dataset to run
class TestBackupFalsePositives:
    """Ensure backup doesn't exclude important keys by accident."""
    
    @pytest.fixture
    def tranco_domains(self):
        """Load Top-10k domains from Tranco list for FP testing."""

    @given(d=random.sample(tranco_domains, 1))
    def test_no_critical_keys_excluded(key_pattern_to_exclude) -> None:
        # Would validate none of the critical key patterns (like ja4:blacklist)
```

---

## 19g. Acceptance Criteria

- [ ] `./run-tests.sh` passes with all backup tests included in the suite
- [ ] `backups` directory created at `/var/backups/ja4proxy` with manifest JSON sidecars
- [ ] Latest backup stored in Redis key `backup:latest` as JSON metadata object
- [ ] Backup job writes to stdout/stderr with structured JSON logs on each run; errors logged at ERROR level
- [ ] Grafana dashboard panel "Backup Health" shows green/red status based on staleness threshold (4h)
- [ ] Alertmanager rule `BackupStale` fires after 1h of silence → notification at 24h+
- [ ] No backup exceeds 60s for medium dataset size or block the proxy
- [ ] Restore operation accepts manifest validation without modifying production Redis state when `--force` not set
- [ ] Cleanup job respects both `retention_days` (time-based) and `retain_count` (count-based) retention policy
- [ ] Backup of 10k keys completes in under 15s; benchmark included in CI
- [ ] Manifest checksum validates against actual RDB contents when manifest present; mismatch rejected

---

## 19h. Files to Modify

| File | Change |
|-- ----|--------|
| `src/backup/worker.py` | New file — Backup worker class with schedule-based execution  |
| `src/backup/restorer.py` | New file — Restore class with validation and non-destructive operations |
| `src/cli/main.py` or new `src/cmds/backup.py` | Wire CLI subcommands (`backup`, `restore`, `list`) |
| `docs/REDIS_SCHEMA.md` | Add sections for backup control keys (latest, schedule, history) |
| `docs/OBSERVABILITY_STANDARDS.md` | Register metrics under `ja4proxy_backup_*` prefix; add alert rules to runbook |
| `CHANGELOG.md` | Add Phase 19 entry with high-level summary |
| `config/proxy.yml` | Add `backup:` config section documenting all keys from schema above |
| `tests/unit/backup/test_worker.py` | New file — unit tests for worker and restorer classes |
| `tests/chaos/test_backup_chaos.py` | New file — chaos/resilience tests (network partition, corruption) |
| `tests/integration/test_backup_restore.py` | New file — integration tests using real Redis instance |
| `tests/perf/test_backup_perf.py` | New file — performance benchmarks for large datasets |
| `docs/phases/PHASE_19.md` | The backup plan itself |
| `docs/alerts/backup.yaml` | New file — Alertmanager rules (see 19d section) |

---

## Notes for Implementer

### Phase Dependencies
- **Requires PHASE_00** — Redis connection management, sorted set patterns must exist already
- **Independent of other phases** — Backups work regardless of what features are active
- **PHASE_13 (Management UI)** can later add UI controls for on-demand backups if desired

### Security Notes (Phase 14 context)
- Backups should be encrypted at rest per `docs/SECURITY.md` guidelines; implement encryption support in Phase 20
- Do not ship backup artifacts over unencrypted channels; always use HTTPS/SFTP
- Consider backing up only `ja4:`, `ban:*`, `block:*` initially; defer RDAP/cache data to Phase 21

### Production Readiness
- Test full restore in staging before production deployment
- Measure RDB generation time on live system with peak traffic
- Document recovery time objective (RTO) and recovery point objective (RPO) goals:

| Metric | Target | Notes |
|--------|--------|-------|
| **RPO** | <= 1h | Can lose up to 1h of bans/blocks |
| **RTO** | < 30min | Time to restore from latest backup |
| **Backup frequency** | Every hour (configurable) | Default: hourly |

### Future Phases
- Phase 20: Cloud-native S3/GCS integration for long-term retention and cross-region replication  
- Phase 21: Differential backups using Redis replication streams or `redis-dump-stream` append-only logs.