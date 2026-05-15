"""
Google Cloud Storage adapter for JA4proxy backup artifacts.

Uses google-cloud-storage (sync) wrapped in asyncio.to_thread() for async safety.
Credentials are resolved by the google-auth library in the standard way:
  1. GOOGLE_APPLICATION_CREDENTIALS env var (path to service account JSON)
  2. Workload Identity / metadata server (GKE, Cloud Run, Compute Engine)
  3. ``credentials_path`` constructor arg (explicit path to service account JSON)

Fail-open: upload() returns None on any error — the local backup artifact has
already been written before upload() is called, so a cloud failure never loses data.

Phase 57c.
"""

import asyncio
import hashlib
import logging
from pathlib import Path

from src.backup.storage_adapter import StorageAdapter, StorageMetadata

logger = logging.getLogger(__name__)

# Reuse the same Prometheus counter registered by s3_adapter so both providers
# share one metric distinguished by the ``provider`` label.  Fall back to
# creating a fresh counter only if s3_adapter itself is not importable (e.g.
# boto3 absent in the test environment).
try:
    from src.backup.cloud.s3_adapter import CLOUD_UPLOAD_TOTAL
except ImportError:
    from prometheus_client import Counter as _Counter

    CLOUD_UPLOAD_TOTAL = _Counter(
        "ja4proxy_backup_cloud_upload_total",
        "Total cloud backup upload attempts",
        ["provider", "result"],
    )


class GCSStorageAdapter(StorageAdapter):
    """Google Cloud Storage adapter for backup artifacts.

    Args:
        bucket:           GCS bucket name.
        project_id:       Google Cloud project ID.
        prefix:           Object name prefix (folder) within the bucket.
                          A trailing slash is added automatically if absent.
        credentials_path: Optional path to a service account JSON file.
                          When ``None`` the adapter uses Application Default
                          Credentials (ADC) — recommended for production.
        storage_class:    GCS storage class (e.g. ``"STANDARD"``, ``"NEARLINE"``).
    """

    MAX_RETRIES = 3

    def __init__(
        self,
        bucket: str,
        project_id: str,
        prefix: str = "backups/",
        credentials_path: str | None = None,
        storage_class: str = "STANDARD",
    ) -> None:
        try:
            from google.cloud import storage as gcs
        except ImportError as exc:
            raise ImportError(
                "google-cloud-storage is required for GCSStorageAdapter. "
                "Install it with: pip install google-cloud-storage"
            ) from exc

        self.bucket_name = bucket
        self.prefix = prefix.rstrip("/") + "/"
        self.storage_class = storage_class

        if credentials_path:
            self._client = gcs.Client.from_service_account_json(
                credentials_path, project=project_id
            )
        else:
            self._client = gcs.Client(project=project_id)

        self._bucket = self._client.bucket(bucket)

    # ------------------------------------------------------------------
    # StorageAdapter interface
    # ------------------------------------------------------------------

    async def upload(self, local_path: Path, manifest: dict) -> StorageMetadata | None:
        """Upload artifact to GCS.

        Returns ``StorageMetadata`` on success, ``None`` on failure (fail-open).
        Never raises — the caller's local backup is already safe on disk.

        Args:
            local_path: Path to the local backup artifact.
            manifest:   Manifest dict; ``created_at`` is forwarded to metadata.

        Returns:
            ``StorageMetadata`` with ``provider="gcs"``, or ``None`` if all
            retries failed.
        """
        blob_name = self.prefix + local_path.name
        data = local_path.read_bytes()
        checksum = hashlib.sha256(data).hexdigest()

        for attempt in range(self.MAX_RETRIES):
            try:
                blob = self._bucket.blob(blob_name)
                blob.metadata = {"sha256": checksum}
                await asyncio.to_thread(
                    blob.upload_from_string,
                    data,
                    content_type="application/octet-stream",
                )
                CLOUD_UPLOAD_TOTAL.labels(provider="gcs", result="success").inc()
                logger.info(
                    "backup | event=cloud_upload_success | provider=gcs | blob=%s",
                    blob_name,
                )
                return StorageMetadata(
                    uri=f"gs://{self.bucket_name}/{blob_name}",
                    filename=local_path.name,
                    size_bytes=len(data),
                    checksum_sha256=checksum,
                    created_at=manifest.get("created_at", ""),
                    provider="gcs",
                    extra={"bucket": self.bucket_name, "blob": blob_name},
                )
            except Exception as exc:  # noqa: BLE001
                wait = 2**attempt
                if attempt < self.MAX_RETRIES - 1:
                    logger.warning(
                        "backup | event=cloud_upload_retry | provider=gcs"
                        " | attempt=%d | error=%s",
                        attempt + 1,
                        exc,
                    )
                    await asyncio.sleep(wait)
                else:
                    logger.error(
                        "backup | event=cloud_upload_failed | provider=gcs | error=%s",
                        exc,
                    )
                    CLOUD_UPLOAD_TOTAL.labels(provider="gcs", result="failure").inc()
                    return None  # fail-open: local backup already written

        return None  # pragma: no cover

    async def download(self, remote_uri: str, local_path: Path) -> Path:
        """Download a backup artifact from GCS to *local_path*.

        Args:
            remote_uri: ``gs://bucket/blob`` URI returned by a previous
                        ``upload()`` call.
            local_path: Destination path on the local filesystem.

        Returns:
            *local_path* after the file has been written.
        """
        blob_name = remote_uri.removeprefix(f"gs://{self.bucket_name}/")
        blob = self._bucket.blob(blob_name)
        await asyncio.to_thread(blob.download_to_filename, str(local_path))
        return local_path

    async def list_backups(self, prefix: str = "") -> list[StorageMetadata]:
        """List backup artifacts in the bucket, optionally filtered by *prefix*.

        Args:
            prefix: Filename prefix filter (e.g. ``"backup_full"``).  Empty
                    string lists all objects under ``self.prefix``.

        Returns:
            List of ``StorageMetadata`` sorted by URI ascending.
        """
        full_prefix = self.prefix + prefix
        blobs = await asyncio.to_thread(
            list, self._client.list_blobs(self.bucket_name, prefix=full_prefix)
        )
        results: list[StorageMetadata] = []
        for blob in blobs:
            results.append(
                StorageMetadata(
                    uri=f"gs://{self.bucket_name}/{blob.name}",
                    filename=blob.name.split("/")[-1],
                    size_bytes=blob.size or 0,
                    checksum_sha256=(blob.metadata or {}).get("sha256", ""),
                    created_at=blob.updated.isoformat() if blob.updated else "",
                    provider="gcs",
                )
            )
        return sorted(results, key=lambda m: m.uri)

    async def delete(self, remote_uri: str) -> None:
        """Delete a backup artifact from GCS.

        Does not raise if the object does not exist.

        Args:
            remote_uri: ``gs://bucket/blob`` URI of the object to delete.
        """
        blob_name = remote_uri.removeprefix(f"gs://{self.bucket_name}/")
        blob = self._bucket.blob(blob_name)
        await asyncio.to_thread(blob.delete)

    async def verify_checksum(self, remote_uri: str, expected_sha256: str) -> bool:
        """Verify the SHA-256 checksum of a stored artifact.

        The checksum is read from the object's user-defined metadata
        (stored as ``sha256`` by ``upload()``).

        Args:
            remote_uri:       ``gs://bucket/blob`` URI.
            expected_sha256:  Hex-encoded SHA-256 digest to compare against.

        Returns:
            ``True`` if the stored digest matches; ``False`` otherwise
            (including when the object does not exist or metadata is absent).
        """
        blob_name = remote_uri.removeprefix(f"gs://{self.bucket_name}/")
        try:
            blob = self._bucket.blob(blob_name)
            await asyncio.to_thread(blob.reload)
            stored = (blob.metadata or {}).get("sha256", "")
            return stored == expected_sha256
        except Exception:  # noqa: BLE001
            return False
