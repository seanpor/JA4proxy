"""
S3 cloud storage adapter for JA4proxy backup artifacts.

Uses boto3 + asyncio.to_thread() for async-safe synchronous S3 calls.
Credentials are read from environment variables only (AWS_ACCESS_KEY_ID,
AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN).  Never pass credentials through
config file values.

Fail-open: upload() returns None on any error — the local backup artifact
has already been written before upload() is called, so a cloud failure
never loses data.

Phase 57b.
"""

import asyncio
import hashlib
import logging
from pathlib import Path

import boto3
from botocore.exceptions import ClientError
from prometheus_client import Counter
from src.backup.storage_adapter import StorageAdapter, StorageMetadata

logger = logging.getLogger(__name__)

CLOUD_UPLOAD_TOTAL = Counter(
    "ja4proxy_backup_cloud_upload_total",
    "Total cloud backup upload attempts",
    ["provider", "result"],  # provider: s3|gcs, result: success|failure
)


class S3StorageAdapter(StorageAdapter):
    """AWS S3 (or S3-compatible) storage adapter for backup artifacts.

    Args:
        bucket:        S3 bucket name.
        prefix:        Key prefix (folder) within the bucket.  Trailing slash
                       is added automatically if absent.
        region:        AWS region name (e.g. ``"us-east-1"``).
        storage_class: S3 storage class (e.g. ``"STANDARD"``, ``"GLACIER"``).
    """

    MAX_RETRIES = 3

    def __init__(
        self,
        bucket: str,
        prefix: str = "backups/",
        region: str = "us-east-1",
        storage_class: str = "STANDARD",
    ) -> None:
        self.bucket = bucket
        self.prefix = prefix.rstrip("/") + "/"
        self.region = region
        self.storage_class = storage_class
        # boto3 reads AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
        # from environment automatically — never inject credentials from config.
        self._client = boto3.client("s3", region_name=region)

    # ------------------------------------------------------------------
    # StorageAdapter interface
    # ------------------------------------------------------------------

    async def upload(self, local_path: Path, manifest: dict) -> StorageMetadata | None:
        """Upload artifact to S3.

        Returns ``StorageMetadata`` on success, ``None`` on failure (fail-open).
        Never raises — the caller's local backup is already safe on disk.

        Args:
            local_path: Path to the local backup artifact.
            manifest:   Manifest dict; ``created_at`` is forwarded to metadata.

        Returns:
            ``StorageMetadata`` with ``provider="s3"``, or ``None`` if all
            retries failed.
        """
        key = self.prefix + local_path.name
        data = local_path.read_bytes()
        checksum = hashlib.sha256(data).hexdigest()

        for attempt in range(self.MAX_RETRIES):
            try:
                await asyncio.to_thread(
                    self._client.put_object,
                    Bucket=self.bucket,
                    Key=key,
                    Body=data,
                    StorageClass=self.storage_class,
                    Metadata={"sha256": checksum},
                )
                CLOUD_UPLOAD_TOTAL.labels(provider="s3", result="success").inc()
                logger.info(
                    "backup | event=cloud_upload_success | provider=s3 | key=%s", key
                )
                return StorageMetadata(
                    uri=f"s3://{self.bucket}/{key}",
                    filename=local_path.name,
                    size_bytes=len(data),
                    checksum_sha256=checksum,
                    created_at=manifest.get("created_at", ""),
                    provider="s3",
                    extra={
                        "bucket": self.bucket,
                        "key": key,
                        "storage_class": self.storage_class,
                    },
                )
            except ClientError as exc:
                wait = 2**attempt
                if attempt < self.MAX_RETRIES - 1:
                    logger.warning(
                        "backup | event=cloud_upload_retry | attempt=%d | error=%s",
                        attempt + 1,
                        exc,
                    )
                    await asyncio.sleep(wait)
                else:
                    logger.error(
                        "backup | event=cloud_upload_failed | provider=s3 | error=%s",
                        exc,
                    )
                    CLOUD_UPLOAD_TOTAL.labels(provider="s3", result="failure").inc()
                    return None  # fail-open: local backup already written

        # Should not reach here, but be safe
        return None  # pragma: no cover

    async def download(self, remote_uri: str, local_path: Path) -> Path:
        """Download a backup artifact from S3 to *local_path*.

        Args:
            remote_uri: ``s3://bucket/key`` URI returned by a previous
                        ``upload()`` call.
            local_path: Destination path on the local filesystem.

        Returns:
            *local_path* after the file has been written.
        """
        key = remote_uri.removeprefix(f"s3://{self.bucket}/")
        response = await asyncio.to_thread(
            self._client.get_object, Bucket=self.bucket, Key=key
        )
        data = response["Body"].read()
        local_path.write_bytes(data)
        return local_path

    async def list_backups(self, prefix: str = "") -> list[StorageMetadata]:
        """List backup artifacts in the bucket, optionally filtered by *prefix*.

        Uses ``list_objects_v2``; returns up to 1000 objects (sufficient for
        any normal retention window).

        Args:
            prefix: Filename prefix filter (e.g. ``"backup_full"``).  Empty
                    string lists all objects under ``self.prefix``.

        Returns:
            List of ``StorageMetadata`` sorted by URI ascending.
        """
        full_prefix = self.prefix + prefix
        response = await asyncio.to_thread(
            self._client.list_objects_v2,
            Bucket=self.bucket,
            Prefix=full_prefix,
        )
        results: list[StorageMetadata] = []
        for obj in response.get("Contents", []):
            results.append(
                StorageMetadata(
                    uri=f"s3://{self.bucket}/{obj['Key']}",
                    filename=obj["Key"].split("/")[-1],
                    size_bytes=obj["Size"],
                    checksum_sha256="",  # not available in list response
                    created_at=obj["LastModified"].isoformat(),
                    provider="s3",
                    extra={"bucket": self.bucket, "key": obj["Key"]},
                )
            )
        return sorted(results, key=lambda m: m.uri)

    async def delete(self, remote_uri: str) -> None:
        """Delete a backup artifact from S3.

        Does not raise if the object does not exist.

        Args:
            remote_uri: ``s3://bucket/key`` URI of the object to delete.
        """
        key = remote_uri.removeprefix(f"s3://{self.bucket}/")
        # delete_object is idempotent — it succeeds even if the key is absent
        await asyncio.to_thread(self._client.delete_object, Bucket=self.bucket, Key=key)

    async def verify_checksum(self, remote_uri: str, expected_sha256: str) -> bool:
        """Verify the SHA-256 checksum of a stored artifact.

        The checksum is read from the object's user-defined metadata
        (stored as ``sha256`` by ``upload()``).

        Args:
            remote_uri:       ``s3://bucket/key`` URI.
            expected_sha256:  Hex-encoded SHA-256 digest to compare against.

        Returns:
            ``True`` if the stored digest matches; ``False`` otherwise
            (including when the object does not exist).
        """
        key = remote_uri.removeprefix(f"s3://{self.bucket}/")
        try:
            response = await asyncio.to_thread(
                self._client.head_object, Bucket=self.bucket, Key=key
            )
            stored = response.get("Metadata", {}).get("sha256", "")
            return stored == expected_sha256
        except ClientError:
            return False
