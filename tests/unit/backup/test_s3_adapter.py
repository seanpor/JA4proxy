"""
Unit tests for S3StorageAdapter (Phase 57b).

Uses moto to mock AWS S3 — no real AWS credentials or network calls.

Covers:
- upload() returns correct StorageMetadata on success
- verify_checksum() returns True/False correctly
- upload() returns None on failure (fail-open), does NOT raise
- Prometheus counter incremented on success
- Prometheus counter incremented on failure
- list_backups() returns sorted StorageMetadata entries
- download() retrieves identical bytes
- delete() removes the object
- Retry on transient ClientError (patch put_object to fail twice then succeed)
"""

import asyncio
import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws
from prometheus_client import REGISTRY

from src.backup.storage_adapter import StorageMetadata

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def run(coro):
    """Run an async coroutine synchronously."""
    return asyncio.run(coro)


def _make_client_error(code: str = "InternalError") -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": "simulated error"}},
        "PutObject",
    )


def _make_adapter(bucket: str = "test-bucket", region: str = "us-east-1"):
    """Import and instantiate S3StorageAdapter (must exist before calling)."""
    from src.backup.cloud.s3_adapter import S3StorageAdapter

    return S3StorageAdapter(bucket=bucket, prefix="backups/", region=region)


def _get_counter_value(name: str, labels: dict) -> float:
    """Read current value of a prometheus Counter with given labels."""
    try:
        metric = REGISTRY._names_to_collectors[name]
        label_keys = sorted(labels.keys())
        label_values = tuple(str(labels[k]) for k in label_keys)
        for sample in metric.collect()[0].samples:
            if all(sample.labels.get(k) == str(labels[k]) for k in labels):
                return sample.value
    except (KeyError, IndexError):
        pass
    return 0.0


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def aws_credentials(monkeypatch):
    """Set fake AWS credentials so boto3 does not hit real AWS."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def s3_bucket(aws_credentials):
    """Start moto mock, create test bucket, yield bucket name."""
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="test-bucket")
        yield "test-bucket"


@pytest.fixture
def adapter(s3_bucket):
    """S3StorageAdapter pointed at the mocked bucket."""
    # Re-create inside mock_aws context — the fixture chain ensures we are inside it
    from src.backup.cloud.s3_adapter import S3StorageAdapter

    return S3StorageAdapter(bucket=s3_bucket, prefix="backups/", region="us-east-1")


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    """A small .bin file with known content."""
    f = tmp_path / "backup_20260406T000000Z.bin"
    f.write_bytes(b"phase-57b test payload")
    return f


# ---------------------------------------------------------------------------
# Test 1 — upload_success
# ---------------------------------------------------------------------------


class TestUploadSuccess:
    def test_upload_returns_storage_metadata(self, adapter, sample_file):
        manifest = {"created_at": "2026-04-06T00:00:00Z"}
        meta = run(adapter.upload(sample_file, manifest))

        assert meta is not None
        assert isinstance(meta, StorageMetadata)

    def test_upload_uri_has_s3_scheme(self, adapter, sample_file):
        meta = run(adapter.upload(sample_file, {}))
        assert meta.uri.startswith("s3://test-bucket/")

    def test_upload_uri_contains_key(self, adapter, sample_file):
        meta = run(adapter.upload(sample_file, {}))
        assert sample_file.name in meta.uri

    def test_upload_size_bytes_correct(self, adapter, sample_file):
        content = sample_file.read_bytes()
        meta = run(adapter.upload(sample_file, {}))
        assert meta.size_bytes == len(content)

    def test_upload_checksum_sha256_correct(self, adapter, sample_file):
        content = sample_file.read_bytes()
        expected = hashlib.sha256(content).hexdigest()
        meta = run(adapter.upload(sample_file, {}))
        assert meta.checksum_sha256 == expected

    def test_upload_provider_is_s3(self, adapter, sample_file):
        meta = run(adapter.upload(sample_file, {}))
        assert meta.provider == "s3"

    def test_upload_filename_correct(self, adapter, sample_file):
        meta = run(adapter.upload(sample_file, {}))
        assert meta.filename == sample_file.name

    def test_upload_created_at_from_manifest(self, adapter, sample_file):
        manifest = {"created_at": "2026-04-06T12:00:00Z"}
        meta = run(adapter.upload(sample_file, manifest))
        assert meta.created_at == "2026-04-06T12:00:00Z"

    def test_upload_extra_contains_bucket(self, adapter, sample_file):
        meta = run(adapter.upload(sample_file, {}))
        assert meta.extra.get("bucket") == "test-bucket"


# ---------------------------------------------------------------------------
# Test 2 — verify_checksum
# ---------------------------------------------------------------------------


class TestVerifyChecksum:
    def test_correct_hash_returns_true(self, adapter, sample_file):
        content = sample_file.read_bytes()
        correct_hash = hashlib.sha256(content).hexdigest()
        meta = run(adapter.upload(sample_file, {}))

        result = run(adapter.verify_checksum(meta.uri, correct_hash))
        assert result is True

    def test_wrong_hash_returns_false(self, adapter, sample_file):
        meta = run(adapter.upload(sample_file, {}))
        wrong_hash = "0" * 64

        result = run(adapter.verify_checksum(meta.uri, wrong_hash))
        assert result is False

    def test_nonexistent_uri_returns_false(self, adapter):
        result = run(
            adapter.verify_checksum("s3://test-bucket/backups/missing.bin", "abc")
        )
        assert result is False


# ---------------------------------------------------------------------------
# Test 3 — upload failure does NOT raise (fail-open)
# ---------------------------------------------------------------------------


class TestUploadFailure:
    def test_wrong_bucket_returns_none_not_raises(self, aws_credentials, tmp_path):
        """Uploading to a nonexistent bucket must return None, never raise."""
        with mock_aws():
            from src.backup.cloud.s3_adapter import S3StorageAdapter

            adapter = S3StorageAdapter(
                bucket="nonexistent-bucket", prefix="backups/", region="us-east-1"
            )
            f = tmp_path / "backup_fail.bin"
            f.write_bytes(b"data")

            # Override MAX_RETRIES to 1 to keep test fast
            adapter.MAX_RETRIES = 1

            result = run(adapter.upload(f, {}))

        assert result is None  # fail-open

    def test_upload_failure_does_not_raise(self, aws_credentials, tmp_path):
        """upload() must swallow ClientError and return None."""
        with mock_aws():
            from src.backup.cloud.s3_adapter import S3StorageAdapter

            adapter = S3StorageAdapter(
                bucket="no-such-bucket", prefix="backups/", region="us-east-1"
            )
            adapter.MAX_RETRIES = 1
            f = tmp_path / "backup_noraise.bin"
            f.write_bytes(b"x")

            # Must not raise — only return None
            result = run(adapter.upload(f, {}))

        assert result is None


# ---------------------------------------------------------------------------
# Test 4 — Prometheus counter on success
# ---------------------------------------------------------------------------


class TestPrometheusCounterSuccess:
    def test_success_increments_counter(self, adapter, sample_file):
        from src.backup.cloud.s3_adapter import CLOUD_UPLOAD_TOTAL

        before = CLOUD_UPLOAD_TOTAL.labels(provider="s3", result="success")._value.get()
        run(adapter.upload(sample_file, {}))
        after = CLOUD_UPLOAD_TOTAL.labels(provider="s3", result="success")._value.get()

        assert after == before + 1


# ---------------------------------------------------------------------------
# Test 5 — Prometheus counter on failure
# ---------------------------------------------------------------------------


class TestPrometheusCounterFailure:
    def test_failure_increments_failure_counter(self, aws_credentials, tmp_path):
        from src.backup.cloud.s3_adapter import CLOUD_UPLOAD_TOTAL

        with mock_aws():
            from src.backup.cloud.s3_adapter import S3StorageAdapter

            adapter = S3StorageAdapter(
                bucket="no-such-bucket", prefix="backups/", region="us-east-1"
            )
            adapter.MAX_RETRIES = 1
            f = tmp_path / "backup_ctr.bin"
            f.write_bytes(b"counter test")

            before = CLOUD_UPLOAD_TOTAL.labels(provider="s3", result="failure")._value.get()
            run(adapter.upload(f, {}))
            after = CLOUD_UPLOAD_TOTAL.labels(provider="s3", result="failure")._value.get()

        assert after == before + 1


# ---------------------------------------------------------------------------
# Test 6 — list_backups
# ---------------------------------------------------------------------------


class TestListBackups:
    def test_list_returns_three_entries(self, adapter, tmp_path):
        files = []
        for i in range(3):
            f = tmp_path / f"backup_file{i:02d}.bin"
            f.write_bytes(f"content-{i}".encode())
            files.append(f)
            run(adapter.upload(f, {}))

        results = run(adapter.list_backups())
        assert len(results) == 3

    def test_list_returns_storage_metadata(self, adapter, tmp_path):
        f = tmp_path / "backup_list.bin"
        f.write_bytes(b"list test")
        run(adapter.upload(f, {}))

        results = run(adapter.list_backups())
        for m in results:
            assert isinstance(m, StorageMetadata)

    def test_list_sorted_by_uri(self, adapter, tmp_path):
        names = ["backup_c.bin", "backup_a.bin", "backup_b.bin"]
        for name in names:
            f = tmp_path / name
            f.write_bytes(b"data")
            run(adapter.upload(f, {}))

        results = run(adapter.list_backups())
        uris = [m.uri for m in results]
        assert uris == sorted(uris)

    def test_list_with_prefix_filters(self, adapter, tmp_path):
        f1 = tmp_path / "backup_full_001.bin"
        f2 = tmp_path / "backup_incr_001.bin"
        f1.write_bytes(b"full")
        f2.write_bytes(b"incr")
        run(adapter.upload(f1, {}))
        run(adapter.upload(f2, {}))

        results = run(adapter.list_backups(prefix="backup_full"))
        filenames = [m.filename for m in results]
        assert "backup_full_001.bin" in filenames
        assert "backup_incr_001.bin" not in filenames

    def test_list_provider_is_s3(self, adapter, tmp_path):
        f = tmp_path / "backup_prov.bin"
        f.write_bytes(b"provider")
        run(adapter.upload(f, {}))

        results = run(adapter.list_backups())
        assert all(m.provider == "s3" for m in results)


# ---------------------------------------------------------------------------
# Test 7 — download
# ---------------------------------------------------------------------------


class TestDownload:
    def test_download_produces_identical_bytes(self, adapter, sample_file, tmp_path):
        original_content = sample_file.read_bytes()
        meta = run(adapter.upload(sample_file, {}))

        dest = tmp_path / "downloaded.bin"
        run(adapter.download(meta.uri, dest))

        assert dest.read_bytes() == original_content

    def test_download_returns_path(self, adapter, sample_file, tmp_path):
        meta = run(adapter.upload(sample_file, {}))
        dest = tmp_path / "dl.bin"
        result = run(adapter.download(meta.uri, dest))
        assert result == dest

    def test_download_creates_file(self, adapter, sample_file, tmp_path):
        meta = run(adapter.upload(sample_file, {}))
        dest = tmp_path / "created.bin"
        assert not dest.exists()
        run(adapter.download(meta.uri, dest))
        assert dest.exists()


# ---------------------------------------------------------------------------
# Test 8 — delete
# ---------------------------------------------------------------------------


class TestDelete:
    def test_delete_removes_object(self, adapter, sample_file):
        meta = run(adapter.upload(sample_file, {}))
        assert len(run(adapter.list_backups())) == 1

        run(adapter.delete(meta.uri))

        assert len(run(adapter.list_backups())) == 0

    def test_delete_nonexistent_does_not_raise(self, adapter):
        """Deleting a nonexistent object must not raise."""
        run(adapter.delete("s3://test-bucket/backups/ghost.bin"))  # no error


# ---------------------------------------------------------------------------
# Test 9 — retry on transient error
# ---------------------------------------------------------------------------


class TestRetryOnTransientError:
    def test_retry_succeeds_after_two_failures(self, adapter, sample_file):
        """put_object fails twice then succeeds; upload() returns StorageMetadata."""
        original_put = adapter._client.put_object
        call_count = 0

        def flaky_put(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise _make_client_error("InternalError")
            return original_put(**kwargs)

        with patch.object(adapter._client, "put_object", side_effect=flaky_put):
            meta = run(adapter.upload(sample_file, {}))

        assert meta is not None
        assert call_count == 3

    def test_retry_exhausted_returns_none(self, adapter, sample_file):
        """If all retries fail, upload() returns None (fail-open)."""
        adapter.MAX_RETRIES = 2

        def always_fail(**kwargs):
            raise _make_client_error("ServiceUnavailable")

        with patch.object(adapter._client, "put_object", side_effect=always_fail):
            result = run(adapter.upload(sample_file, {}))

        assert result is None
