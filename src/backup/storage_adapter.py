"""
StorageAdapter — abstract base class for pluggable backup storage backends.

Phase 57a introduces the ABC and a LocalStorageAdapter (filesystem passthrough).
Future phases add S3Adapter (Phase 57b) and GCSAdapter (Phase 57c).

No new pip dependencies: uses only stdlib (abc, hashlib, shutil, pathlib, dataclasses).
"""

import hashlib
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class StorageMetadata:
    """Metadata returned by storage operations.

    Attributes:
        uri:              Canonical reference to the artifact (file path or cloud URI).
        filename:         Basename of the artifact file.
        size_bytes:       Size of the artifact in bytes.
        checksum_sha256:  Hex-encoded SHA-256 digest of the artifact content.
        created_at:       ISO-8601 creation timestamp (empty string if unknown).
        provider:         Storage backend identifier: ``"local"``, ``"s3"``, ``"gcs"``.
        extra:            Provider-specific metadata (e.g. S3 bucket, GCS object ID).
    """

    uri: str
    filename: str
    size_bytes: int
    checksum_sha256: str
    created_at: str  # ISO-8601
    provider: str    # "local", "s3", "gcs"
    extra: dict = field(default_factory=dict)


class StorageAdapter(ABC):
    """Abstract base class for backup storage backends.

    All methods are coroutines so that I/O-bound cloud adapters (S3, GCS) can
    use ``aiohttp`` / ``aioboto3`` without blocking the event loop.  The local
    adapter wraps synchronous stdlib calls — they complete quickly enough that
    an extra thread is not warranted at this scale.

    Subclasses MUST implement all five abstract methods.
    """

    @abstractmethod
    async def upload(self, local_path: Path, manifest: dict) -> StorageMetadata:
        """Upload a local backup artifact to the storage backend.

        The file at *local_path* already exists on disk.  For ``LocalStorageAdapter``
        this is a no-op (the file is already in the right place); for cloud adapters
        it performs the actual PUT/upload.

        Args:
            local_path: Path to the backup artifact on the local filesystem.
            manifest:   Manifest dict as written by ``BackupWorker.create_backup()``;
                        ``created_at`` is used to populate ``StorageMetadata.created_at``.

        Returns:
            ``StorageMetadata`` describing the stored artifact.
        """

    @abstractmethod
    async def download(self, remote_uri: str, local_path: Path) -> Path:
        """Download a backup artifact to a local path.

        Args:
            remote_uri: URI returned by a previous ``upload()`` call.
            local_path: Destination path on the local filesystem.

        Returns:
            *local_path* after the file has been written.
        """

    @abstractmethod
    async def list_backups(self, prefix: str = "") -> list[StorageMetadata]:
        """List available backup artifacts, optionally filtered by *prefix*.

        Args:
            prefix: Filename prefix filter (e.g. ``"backup_full"``).  Empty
                    string means list all backups.

        Returns:
            List of ``StorageMetadata`` objects sorted by filename ascending.
        """

    @abstractmethod
    async def delete(self, remote_uri: str) -> None:
        """Delete a backup artifact.

        Must not raise if the artifact does not exist.

        Args:
            remote_uri: URI of the artifact to delete.
        """

    @abstractmethod
    async def verify_checksum(self, remote_uri: str, expected_sha256: str) -> bool:
        """Verify the SHA-256 checksum of a stored artifact.

        Args:
            remote_uri:       URI of the artifact to verify.
            expected_sha256:  Hex-encoded expected digest.

        Returns:
            ``True`` if the computed digest matches *expected_sha256*; ``False``
            otherwise.
        """


class LocalStorageAdapter(StorageAdapter):
    """Local-filesystem storage adapter (passthrough).

    Treats the local filesystem as the backing store.  ``upload()`` is a no-op
    because the artifact already exists at *local_path*.  ``download()`` copies
    the file to *local_path*.  Intended for single-host deployments and as a
    reference implementation for testing.

    Args:
        base_dir: Base directory that ``list_backups()`` scans for artifacts.
    """

    def __init__(self, base_dir: Path) -> None:
        self.base_dir = Path(base_dir)

    async def upload(self, local_path: Path, manifest: dict) -> StorageMetadata:
        """Return metadata for an already-written local file (no-op upload).

        Args:
            local_path: Path to the existing backup artifact.
            manifest:   Manifest dict; ``created_at`` is forwarded to metadata.

        Returns:
            ``StorageMetadata`` with ``provider="local"``.
        """
        local_path = Path(local_path)
        data = local_path.read_bytes()
        return StorageMetadata(
            uri=str(local_path),
            filename=local_path.name,
            size_bytes=len(data),
            checksum_sha256=hashlib.sha256(data).hexdigest(),
            created_at=manifest.get("created_at", ""),
            provider="local",
        )

    async def download(self, remote_uri: str, local_path: Path) -> Path:
        """Copy the artifact at *remote_uri* to *local_path*.

        For the local adapter, *remote_uri* is itself a filesystem path.

        Args:
            remote_uri: Source file path.
            local_path: Destination file path.

        Returns:
            *local_path* after the copy.
        """
        local_path = Path(local_path)
        shutil.copy2(remote_uri, local_path)
        return local_path

    async def list_backups(self, prefix: str = "") -> list[StorageMetadata]:
        """List all ``*.bin`` files in ``base_dir`` matching *prefix*.

        Args:
            prefix: Filename prefix filter.  Empty string matches all ``.bin`` files.

        Returns:
            List of ``StorageMetadata`` sorted by filename ascending.
        """
        results: list[StorageMetadata] = []
        for f in sorted(self.base_dir.glob(f"{prefix}*.bin")):
            data = f.read_bytes()
            results.append(
                StorageMetadata(
                    uri=str(f),
                    filename=f.name,
                    size_bytes=len(data),
                    checksum_sha256=hashlib.sha256(data).hexdigest(),
                    created_at="",
                    provider="local",
                )
            )
        return results

    async def delete(self, remote_uri: str) -> None:
        """Delete the file at *remote_uri*.

        Does nothing if the file does not exist.

        Args:
            remote_uri: File path to delete.
        """
        Path(remote_uri).unlink(missing_ok=True)

    async def verify_checksum(self, remote_uri: str, expected_sha256: str) -> bool:
        """Compute SHA-256 of the file at *remote_uri* and compare to *expected_sha256*.

        Args:
            remote_uri:       File path to check.
            expected_sha256:  Hex-encoded expected SHA-256 digest.

        Returns:
            ``True`` if digests match; ``False`` otherwise.
        """
        data = Path(remote_uri).read_bytes()
        return hashlib.sha256(data).hexdigest() == expected_sha256
