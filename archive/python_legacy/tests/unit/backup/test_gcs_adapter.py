"""
Unit tests for GCSStorageAdapter (Phase 57c).

Uses unittest.mock.patch to mock google.cloud.storage.Client — no real GCP
credentials or network calls.

Covers:
- upload() returns correct StorageMetadata with provider="gcs" on success
- verify_checksum() returns True/False correctly (stored sha256 in blob metadata)
- upload() returns None on failure — does NOT raise (fail-open)
- Prometheus counter incremented on success (provider="gcs", result="success")
- Prometheus counter incremented on failure (provider="gcs", result="failure")
- list_backups() returns sorted StorageMetadata entries
- download() calls blob.download_to_filename with correct path
- delete() calls blob.delete with correct blob name
- verify_checksum_match: True when metadata sha256 matches
- verify_checksum_mismatch: False when metadata sha256 does not match
"""

import asyncio
import datetime
import hashlib
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

# Skip entire module if google-cloud-storage is not importable. We can't use
# pytest.importorskip alone because, on Python 3.14, google-protobuf's C++
# _upb extension raises `TypeError: Metaclasses with custom tp_new are not
# supported.` during import — not ImportError — so importorskip won't catch
# it. Wrap the probe to skip on either failure mode until protobuf ships a
# 3.14-compatible upb. The adapter under test guards the same import, so
# these tests are vacuously satisfied in that case.
try:
    import google.cloud.storage as gcs_lib  # noqa: F401
except (ImportError, TypeError) as _gcs_exc:
    pytest.skip(
        f"google.cloud.storage not importable: {_gcs_exc}",
        allow_module_level=True,
    )

from src.backup.storage_adapter import (
    StorageMetadata,
)  # noqa: E402 — after importorskip

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def run(coro):
    """Run an async coroutine synchronously."""
    return asyncio.run(coro)


def _make_gcs_error(message: str = "simulated GCS error"):
    """Return a GoogleAPIError-compatible exception."""
    try:
        from google.api_core.exceptions import GoogleAPIError

        exc = GoogleAPIError(message)
    except ImportError:
        exc = Exception(message)
    return exc


def _make_adapter(
    bucket: str = "test-gcs-bucket",
    project_id: str = "test-project",
    prefix: str = "backups/",
):
    """Instantiate GCSStorageAdapter with a fully mocked gcs.Client."""
    from unittest.mock import patch as _patch

    mock_client_cls = MagicMock()
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client

    with _patch("google.cloud.storage.Client", mock_client_cls):
        from src.backup.cloud.gcs_adapter import GCSStorageAdapter

        adapter = GCSStorageAdapter(
            bucket=bucket,
            project_id=project_id,
            prefix=prefix,
        )

    # Replace internal client with a fresh mock for test control
    adapter._client = mock_client
    adapter._bucket = mock_client.bucket.return_value

    return adapter, mock_client


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    """A small .bin file with known content."""
    f = tmp_path / "backup_20260406T000000Z.bin"
    f.write_bytes(b"phase-57c test payload")
    return f


@pytest.fixture
def adapter(tmp_path):
    """GCSStorageAdapter with fully mocked GCS client."""
    a, _client = _make_adapter()
    return a


# ---------------------------------------------------------------------------
# Test 1 — upload success
# ---------------------------------------------------------------------------


class TestUploadSuccess:
    def test_upload_returns_storage_metadata(self, adapter, sample_file):
        manifest = {"created_at": "2026-04-06T00:00:00Z"}
        mock_blob = MagicMock()
        adapter._bucket.blob.return_value = mock_blob

        meta = run(adapter.upload(sample_file, manifest))

        assert meta is not None
        assert isinstance(meta, StorageMetadata)

    def test_upload_uri_has_gcs_scheme(self, adapter, sample_file):
        mock_blob = MagicMock()
        adapter._bucket.blob.return_value = mock_blob

        meta = run(adapter.upload(sample_file, {}))

        assert meta.uri.startswith("gs://test-gcs-bucket/")

    def test_upload_uri_contains_filename(self, adapter, sample_file):
        mock_blob = MagicMock()
        adapter._bucket.blob.return_value = mock_blob

        meta = run(adapter.upload(sample_file, {}))

        assert sample_file.name in meta.uri

    def test_upload_size_bytes_correct(self, adapter, sample_file):
        mock_blob = MagicMock()
        adapter._bucket.blob.return_value = mock_blob
        content = sample_file.read_bytes()

        meta = run(adapter.upload(sample_file, {}))

        assert meta.size_bytes == len(content)

    def test_upload_checksum_sha256_correct(self, adapter, sample_file):
        mock_blob = MagicMock()
        adapter._bucket.blob.return_value = mock_blob
        content = sample_file.read_bytes()
        expected = hashlib.sha256(content).hexdigest()

        meta = run(adapter.upload(sample_file, {}))

        assert meta.checksum_sha256 == expected

    def test_upload_provider_is_gcs(self, adapter, sample_file):
        mock_blob = MagicMock()
        adapter._bucket.blob.return_value = mock_blob

        meta = run(adapter.upload(sample_file, {}))

        assert meta.provider == "gcs"

    def test_upload_filename_correct(self, adapter, sample_file):
        mock_blob = MagicMock()
        adapter._bucket.blob.return_value = mock_blob

        meta = run(adapter.upload(sample_file, {}))

        assert meta.filename == sample_file.name

    def test_upload_created_at_from_manifest(self, adapter, sample_file):
        mock_blob = MagicMock()
        adapter._bucket.blob.return_value = mock_blob
        manifest = {"created_at": "2026-04-06T12:00:00Z"}

        meta = run(adapter.upload(sample_file, manifest))

        assert meta.created_at == "2026-04-06T12:00:00Z"

    def test_upload_extra_contains_bucket(self, adapter, sample_file):
        mock_blob = MagicMock()
        adapter._bucket.blob.return_value = mock_blob

        meta = run(adapter.upload(sample_file, {}))

        assert meta.extra.get("bucket") == "test-gcs-bucket"

    def test_upload_calls_upload_from_string(self, adapter, sample_file):
        """upload_from_string is called exactly once on success."""
        mock_blob = MagicMock()
        adapter._bucket.blob.return_value = mock_blob

        run(adapter.upload(sample_file, {}))

        mock_blob.upload_from_string.assert_called_once()

    def test_upload_stores_sha256_in_blob_metadata(self, adapter, sample_file):
        """sha256 checksum is stored in blob.metadata before uploading."""
        mock_blob = MagicMock()
        adapter._bucket.blob.return_value = mock_blob
        content = sample_file.read_bytes()
        expected_sha256 = hashlib.sha256(content).hexdigest()

        run(adapter.upload(sample_file, {}))

        assert mock_blob.metadata == {"sha256": expected_sha256}


# ---------------------------------------------------------------------------
# Test 2 — verify checksum
# ---------------------------------------------------------------------------


class TestVerifyChecksum:
    def test_correct_hash_returns_true(self, adapter, sample_file):
        content = sample_file.read_bytes()
        correct_hash = hashlib.sha256(content).hexdigest()

        mock_blob = MagicMock()
        mock_blob.metadata = {"sha256": correct_hash}
        adapter._bucket.blob.return_value = mock_blob

        uri = f"gs://test-gcs-bucket/backups/{sample_file.name}"
        result = run(adapter.verify_checksum(uri, correct_hash))

        assert result is True

    def test_wrong_hash_returns_false(self, adapter, sample_file):
        content = sample_file.read_bytes()
        correct_hash = hashlib.sha256(content).hexdigest()

        mock_blob = MagicMock()
        mock_blob.metadata = {"sha256": correct_hash}
        adapter._bucket.blob.return_value = mock_blob

        uri = f"gs://test-gcs-bucket/backups/{sample_file.name}"
        wrong_hash = "0" * 64

        result = run(adapter.verify_checksum(uri, wrong_hash))

        assert result is False

    def test_exception_returns_false(self, adapter):
        """An exception during reload returns False (fail-open)."""
        mock_blob = MagicMock()
        mock_blob.reload.side_effect = Exception("network error")
        adapter._bucket.blob.return_value = mock_blob

        result = run(
            adapter.verify_checksum("gs://test-gcs-bucket/backups/missing.bin", "abc")
        )

        assert result is False


# ---------------------------------------------------------------------------
# Test 3 — upload failure does NOT raise (fail-open)
# ---------------------------------------------------------------------------


class TestUploadFailure:
    def test_upload_failure_returns_none(self, adapter, sample_file):
        """upload() must return None on GoogleAPIError, never raise."""
        mock_blob = MagicMock()
        mock_blob.upload_from_string.side_effect = _make_gcs_error("upload failed")
        adapter._bucket.blob.return_value = mock_blob
        adapter.MAX_RETRIES = 1

        result = run(adapter.upload(sample_file, {}))

        assert result is None

    def test_upload_failure_does_not_raise(self, adapter, sample_file):
        """upload() must swallow all exceptions on failure."""
        mock_blob = MagicMock()
        mock_blob.upload_from_string.side_effect = Exception("arbitrary error")
        adapter._bucket.blob.return_value = mock_blob
        adapter.MAX_RETRIES = 1

        # Must not raise — must only return None
        result = run(adapter.upload(sample_file, {}))

        assert result is None


# ---------------------------------------------------------------------------
# Test 4 — Prometheus counter on success
# ---------------------------------------------------------------------------


class TestPrometheusCounterSuccess:
    def test_success_increments_counter(self, adapter, sample_file):
        from src.backup.cloud.gcs_adapter import CLOUD_UPLOAD_TOTAL

        mock_blob = MagicMock()
        adapter._bucket.blob.return_value = mock_blob

        before = CLOUD_UPLOAD_TOTAL.labels(
            provider="gcs", result="success"
        )._value.get()
        run(adapter.upload(sample_file, {}))
        after = CLOUD_UPLOAD_TOTAL.labels(provider="gcs", result="success")._value.get()

        assert after == before + 1


# ---------------------------------------------------------------------------
# Test 5 — Prometheus counter on failure
# ---------------------------------------------------------------------------


class TestPrometheusCounterFailure:
    def test_failure_increments_failure_counter(self, adapter, sample_file):
        from src.backup.cloud.gcs_adapter import CLOUD_UPLOAD_TOTAL

        mock_blob = MagicMock()
        mock_blob.upload_from_string.side_effect = Exception("injected failure")
        adapter._bucket.blob.return_value = mock_blob
        adapter.MAX_RETRIES = 1

        before = CLOUD_UPLOAD_TOTAL.labels(
            provider="gcs", result="failure"
        )._value.get()
        run(adapter.upload(sample_file, {}))
        after = CLOUD_UPLOAD_TOTAL.labels(provider="gcs", result="failure")._value.get()

        assert after == before + 1


# ---------------------------------------------------------------------------
# Test 6 — list_backups
# ---------------------------------------------------------------------------


class TestListBackups:
    def _make_mock_blob(self, name: str, size: int = 10) -> MagicMock:
        blob = MagicMock()
        blob.name = name
        blob.size = size
        blob.metadata = {"sha256": "abc123"}
        blob.updated = datetime.datetime(2026, 4, 6, 12, 0, 0)
        return blob

    def test_list_returns_three_entries(self, adapter):
        blobs = [
            self._make_mock_blob("backups/backup_file00.bin"),
            self._make_mock_blob("backups/backup_file01.bin"),
            self._make_mock_blob("backups/backup_file02.bin"),
        ]
        adapter._client.list_blobs.return_value = blobs

        results = run(adapter.list_backups())

        assert len(results) == 3

    def test_list_returns_storage_metadata(self, adapter):
        blobs = [self._make_mock_blob("backups/backup_single.bin")]
        adapter._client.list_blobs.return_value = blobs

        results = run(adapter.list_backups())

        for m in results:
            assert isinstance(m, StorageMetadata)

    def test_list_sorted_by_uri(self, adapter):
        blobs = [
            self._make_mock_blob("backups/backup_c.bin"),
            self._make_mock_blob("backups/backup_a.bin"),
            self._make_mock_blob("backups/backup_b.bin"),
        ]
        adapter._client.list_blobs.return_value = blobs

        results = run(adapter.list_backups())
        uris = [m.uri for m in results]

        assert uris == sorted(uris)

    def test_list_provider_is_gcs(self, adapter):
        blobs = [self._make_mock_blob("backups/backup_prov.bin")]
        adapter._client.list_blobs.return_value = blobs

        results = run(adapter.list_backups())

        assert all(m.provider == "gcs" for m in results)

    def test_list_uri_has_gcs_scheme(self, adapter):
        blobs = [self._make_mock_blob("backups/backup_uri.bin")]
        adapter._client.list_blobs.return_value = blobs

        results = run(adapter.list_backups())

        assert results[0].uri.startswith("gs://test-gcs-bucket/")

    def test_list_filename_extracted_from_blob_name(self, adapter):
        blobs = [self._make_mock_blob("backups/backup_name.bin")]
        adapter._client.list_blobs.return_value = blobs

        results = run(adapter.list_backups())

        assert results[0].filename == "backup_name.bin"


# ---------------------------------------------------------------------------
# Test 7 — download
# ---------------------------------------------------------------------------


class TestDownload:
    def test_download_calls_download_to_filename(self, adapter, tmp_path):
        mock_blob = MagicMock()
        adapter._bucket.blob.return_value = mock_blob

        dest = tmp_path / "downloaded.bin"
        uri = "gs://test-gcs-bucket/backups/backup_20260406T000000Z.bin"
        run(adapter.download(uri, dest))

        mock_blob.download_to_filename.assert_called_once_with(str(dest))

    def test_download_returns_local_path(self, adapter, tmp_path):
        mock_blob = MagicMock()
        adapter._bucket.blob.return_value = mock_blob

        dest = tmp_path / "dl.bin"
        uri = "gs://test-gcs-bucket/backups/backup_20260406T000000Z.bin"
        result = run(adapter.download(uri, dest))

        assert result == dest

    def test_download_strips_gcs_prefix_from_blob_name(self, adapter, tmp_path):
        """blob.name passed to bucket.blob() must not contain the gs://bucket/ prefix."""
        mock_blob = MagicMock()
        adapter._bucket.blob.return_value = mock_blob

        dest = tmp_path / "dl2.bin"
        uri = "gs://test-gcs-bucket/backups/some_backup.bin"
        run(adapter.download(uri, dest))

        adapter._bucket.blob.assert_called_once_with("backups/some_backup.bin")


# ---------------------------------------------------------------------------
# Test 8 — delete
# ---------------------------------------------------------------------------


class TestDelete:
    def test_delete_calls_blob_delete(self, adapter):
        mock_blob = MagicMock()
        adapter._bucket.blob.return_value = mock_blob

        uri = "gs://test-gcs-bucket/backups/backup_to_delete.bin"
        run(adapter.delete(uri))

        mock_blob.delete.assert_called_once()

    def test_delete_strips_gcs_prefix_from_blob_name(self, adapter):
        mock_blob = MagicMock()
        adapter._bucket.blob.return_value = mock_blob

        uri = "gs://test-gcs-bucket/backups/specific_file.bin"
        run(adapter.delete(uri))

        adapter._bucket.blob.assert_called_once_with("backups/specific_file.bin")


# ---------------------------------------------------------------------------
# Test 9 — verify_checksum match
# ---------------------------------------------------------------------------


class TestVerifyChecksumMatch:
    def test_matching_sha256_returns_true(self, adapter):
        expected = "a" * 64
        mock_blob = MagicMock()
        mock_blob.metadata = {"sha256": expected}
        adapter._bucket.blob.return_value = mock_blob

        uri = "gs://test-gcs-bucket/backups/backup_match.bin"
        result = run(adapter.verify_checksum(uri, expected))

        assert result is True

    def test_blob_reload_is_called(self, adapter):
        """verify_checksum must call blob.reload() to fetch fresh metadata."""
        mock_blob = MagicMock()
        mock_blob.metadata = {"sha256": "abc"}
        adapter._bucket.blob.return_value = mock_blob

        run(adapter.verify_checksum("gs://test-gcs-bucket/backups/x.bin", "abc"))

        mock_blob.reload.assert_called_once()


# ---------------------------------------------------------------------------
# Test 10 — verify_checksum mismatch
# ---------------------------------------------------------------------------


class TestVerifyChecksumMismatch:
    def test_mismatching_sha256_returns_false(self, adapter):
        stored = "b" * 64
        wrong = "c" * 64

        mock_blob = MagicMock()
        mock_blob.metadata = {"sha256": stored}
        adapter._bucket.blob.return_value = mock_blob

        uri = "gs://test-gcs-bucket/backups/backup_mismatch.bin"
        result = run(adapter.verify_checksum(uri, wrong))

        assert result is False

    def test_empty_metadata_returns_false(self, adapter):
        """If blob.metadata is None/empty, checksum can never match."""
        mock_blob = MagicMock()
        mock_blob.metadata = {}
        adapter._bucket.blob.return_value = mock_blob

        uri = "gs://test-gcs-bucket/backups/backup_no_meta.bin"
        result = run(adapter.verify_checksum(uri, "abc123"))

        assert result is False

    def test_none_metadata_returns_false(self, adapter):
        """blob.metadata=None must not crash — returns False."""
        mock_blob = MagicMock()
        mock_blob.metadata = None
        adapter._bucket.blob.return_value = mock_blob

        uri = "gs://test-gcs-bucket/backups/backup_none_meta.bin"
        result = run(adapter.verify_checksum(uri, "abc123"))

        assert result is False
