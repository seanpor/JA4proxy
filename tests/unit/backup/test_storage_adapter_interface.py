"""
Unit tests for src/backup/storage_adapter.py.

Covers:
- StorageAdapter ABC enforces abstract methods (TypeError for incomplete subclasses)
- LocalStorageAdapter implements StorageAdapter (isinstance check passes)
- LocalStorageAdapter.upload() returns StorageMetadata with correct fields
- LocalStorageAdapter.list_backups() returns list of StorageMetadata
- LocalStorageAdapter.download() copies file to target path
- LocalStorageAdapter.delete() removes the file
- LocalStorageAdapter.verify_checksum() returns True for matching, False for mismatch

Uses pytest tmp_path fixture only — no Redis, no fakeredis needed.
"""

import asyncio
import hashlib
from pathlib import Path

import pytest

from src.backup.storage_adapter import (
    LocalStorageAdapter,
    StorageAdapter,
    StorageMetadata,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def run(coro):
    """Run a coroutine synchronously (avoids @pytest.mark.asyncio boilerplate)."""
    return asyncio.run(coro)


def _write_file(path: Path, content: bytes) -> Path:
    path.write_bytes(content)
    return path


# ---------------------------------------------------------------------------
# StorageAdapter ABC enforcement
# ---------------------------------------------------------------------------


class TestStorageAdapterABC:
    def test_cannot_instantiate_abc_directly(self) -> None:
        """StorageAdapter is abstract — direct instantiation must raise TypeError."""
        with pytest.raises(TypeError):
            StorageAdapter()  # type: ignore[abstract]

    def test_missing_upload_raises_type_error(self) -> None:
        """Subclass missing upload → TypeError on instantiation."""
        class BadAdapter(StorageAdapter):
            async def download(self, remote_uri, local_path): ...
            async def list_backups(self, prefix=""): ...
            async def delete(self, remote_uri): ...
            async def verify_checksum(self, remote_uri, expected_sha256): ...

        with pytest.raises(TypeError):
            BadAdapter()

    def test_missing_download_raises_type_error(self) -> None:
        class BadAdapter(StorageAdapter):
            async def upload(self, local_path, manifest): ...
            async def list_backups(self, prefix=""): ...
            async def delete(self, remote_uri): ...
            async def verify_checksum(self, remote_uri, expected_sha256): ...

        with pytest.raises(TypeError):
            BadAdapter()

    def test_missing_list_backups_raises_type_error(self) -> None:
        class BadAdapter(StorageAdapter):
            async def upload(self, local_path, manifest): ...
            async def download(self, remote_uri, local_path): ...
            async def delete(self, remote_uri): ...
            async def verify_checksum(self, remote_uri, expected_sha256): ...

        with pytest.raises(TypeError):
            BadAdapter()

    def test_missing_delete_raises_type_error(self) -> None:
        class BadAdapter(StorageAdapter):
            async def upload(self, local_path, manifest): ...
            async def download(self, remote_uri, local_path): ...
            async def list_backups(self, prefix=""): ...
            async def verify_checksum(self, remote_uri, expected_sha256): ...

        with pytest.raises(TypeError):
            BadAdapter()

    def test_missing_verify_checksum_raises_type_error(self) -> None:
        class BadAdapter(StorageAdapter):
            async def upload(self, local_path, manifest): ...
            async def download(self, remote_uri, local_path): ...
            async def list_backups(self, prefix=""): ...
            async def delete(self, remote_uri): ...

        with pytest.raises(TypeError):
            BadAdapter()

    def test_complete_subclass_instantiates_ok(self) -> None:
        """A class implementing all five methods must NOT raise TypeError."""
        class GoodAdapter(StorageAdapter):
            async def upload(self, local_path, manifest): ...
            async def download(self, remote_uri, local_path): ...
            async def list_backups(self, prefix=""): ...
            async def delete(self, remote_uri): ...
            async def verify_checksum(self, remote_uri, expected_sha256): ...

        adapter = GoodAdapter()  # must not raise
        assert adapter is not None


# ---------------------------------------------------------------------------
# LocalStorageAdapter isinstance check
# ---------------------------------------------------------------------------


class TestLocalStorageAdapterIsInstance:
    def test_is_instance_of_storage_adapter(self, tmp_path: Path) -> None:
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        assert isinstance(adapter, StorageAdapter)

    def test_is_instance_of_local_storage_adapter(self, tmp_path: Path) -> None:
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        assert isinstance(adapter, LocalStorageAdapter)


# ---------------------------------------------------------------------------
# StorageMetadata dataclass
# ---------------------------------------------------------------------------


class TestStorageMetadata:
    def test_can_create_metadata(self) -> None:
        meta = StorageMetadata(
            uri="/tmp/backup.bin",
            filename="backup.bin",
            size_bytes=1024,
            checksum_sha256="abc123",
            created_at="2026-04-06T00:00:00Z",
            provider="local",
        )
        assert meta.uri == "/tmp/backup.bin"
        assert meta.filename == "backup.bin"
        assert meta.size_bytes == 1024
        assert meta.checksum_sha256 == "abc123"
        assert meta.created_at == "2026-04-06T00:00:00Z"
        assert meta.provider == "local"
        assert meta.extra == {}  # default

    def test_extra_field_accepts_dict(self) -> None:
        meta = StorageMetadata(
            uri="s3://bucket/key",
            filename="backup.bin",
            size_bytes=0,
            checksum_sha256="",
            created_at="",
            provider="s3",
            extra={"bucket": "my-bucket", "region": "us-east-1"},
        )
        assert meta.extra["bucket"] == "my-bucket"


# ---------------------------------------------------------------------------
# LocalStorageAdapter.upload()
# ---------------------------------------------------------------------------


class TestLocalStorageAdapterUpload:
    def test_upload_returns_storage_metadata(self, tmp_path: Path) -> None:
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        content = b"backup payload"
        f = _write_file(tmp_path / "backup_20260406T000000Z.bin", content)
        manifest = {"created_at": "2026-04-06T00:00:00Z"}

        meta = run(adapter.upload(f, manifest))

        assert isinstance(meta, StorageMetadata)

    def test_upload_uri_is_file_path(self, tmp_path: Path) -> None:
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        content = b"hello world"
        f = _write_file(tmp_path / "backup_test.bin", content)

        meta = run(adapter.upload(f, {}))

        assert meta.uri == str(f)

    def test_upload_filename_correct(self, tmp_path: Path) -> None:
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        content = b"data"
        f = _write_file(tmp_path / "backup_20260406T120000Z.bin", content)

        meta = run(adapter.upload(f, {}))

        assert meta.filename == "backup_20260406T120000Z.bin"

    def test_upload_size_bytes_correct(self, tmp_path: Path) -> None:
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        content = b"A" * 512
        f = _write_file(tmp_path / "backup_size.bin", content)

        meta = run(adapter.upload(f, {}))

        assert meta.size_bytes == 512

    def test_upload_checksum_correct(self, tmp_path: Path) -> None:
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        content = b"checksum test"
        f = _write_file(tmp_path / "backup_cksum.bin", content)
        expected_sha256 = hashlib.sha256(content).hexdigest()

        meta = run(adapter.upload(f, {}))

        assert meta.checksum_sha256 == expected_sha256

    def test_upload_provider_is_local(self, tmp_path: Path) -> None:
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        f = _write_file(tmp_path / "backup_p.bin", b"x")

        meta = run(adapter.upload(f, {}))

        assert meta.provider == "local"

    def test_upload_created_at_from_manifest(self, tmp_path: Path) -> None:
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        f = _write_file(tmp_path / "backup_ts.bin", b"y")
        manifest = {"created_at": "2026-01-01T00:00:00Z"}

        meta = run(adapter.upload(f, manifest))

        assert meta.created_at == "2026-01-01T00:00:00Z"


# ---------------------------------------------------------------------------
# LocalStorageAdapter.list_backups()
# ---------------------------------------------------------------------------


class TestLocalStorageAdapterListBackups:
    def test_list_empty_directory(self, tmp_path: Path) -> None:
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        result = run(adapter.list_backups())
        assert result == []

    def test_list_returns_list(self, tmp_path: Path) -> None:
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        _write_file(tmp_path / "backup_a.bin", b"aaa")

        result = run(adapter.list_backups())

        assert isinstance(result, list)

    def test_list_returns_storage_metadata_items(self, tmp_path: Path) -> None:
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        _write_file(tmp_path / "backup_001.bin", b"data1")
        _write_file(tmp_path / "backup_002.bin", b"data2")

        result = run(adapter.list_backups())

        assert len(result) == 2
        for item in result:
            assert isinstance(item, StorageMetadata)

    def test_list_with_prefix_filters(self, tmp_path: Path) -> None:
        """list_backups(prefix) returns only files matching that prefix."""
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        _write_file(tmp_path / "backup_full_001.bin", b"full")
        _write_file(tmp_path / "backup_incr_001.bin", b"incr")

        result = run(adapter.list_backups(prefix="backup_full"))

        filenames = [m.filename for m in result]
        assert "backup_full_001.bin" in filenames
        assert "backup_incr_001.bin" not in filenames

    def test_list_non_bin_files_excluded(self, tmp_path: Path) -> None:
        """Only .bin files are listed."""
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        _write_file(tmp_path / "backup_001.bin", b"binary")
        _write_file(tmp_path / "backup_001.bin.manifest.json", b"manifest")

        result = run(adapter.list_backups())

        filenames = [m.filename for m in result]
        assert all(f.endswith(".bin") for f in filenames)


# ---------------------------------------------------------------------------
# LocalStorageAdapter.download()
# ---------------------------------------------------------------------------


class TestLocalStorageAdapterDownload:
    def test_download_copies_file_to_target(self, tmp_path: Path) -> None:
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        src = _write_file(tmp_path / "source.bin", b"source content")
        dest = tmp_path / "dest.bin"

        returned_path = run(adapter.download(str(src), dest))

        assert dest.exists()
        assert dest.read_bytes() == b"source content"

    def test_download_returns_path(self, tmp_path: Path) -> None:
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        src = _write_file(tmp_path / "src.bin", b"data")
        dest = tmp_path / "dst.bin"

        result = run(adapter.download(str(src), dest))

        assert isinstance(result, Path)
        assert result == dest

    def test_download_overwrites_existing_file(self, tmp_path: Path) -> None:
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        src = _write_file(tmp_path / "new.bin", b"new content")
        dest = _write_file(tmp_path / "old.bin", b"old content")

        run(adapter.download(str(src), dest))

        assert dest.read_bytes() == b"new content"


# ---------------------------------------------------------------------------
# LocalStorageAdapter.delete()
# ---------------------------------------------------------------------------


class TestLocalStorageAdapterDelete:
    def test_delete_removes_file(self, tmp_path: Path) -> None:
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        f = _write_file(tmp_path / "to_delete.bin", b"bye")

        run(adapter.delete(str(f)))

        assert not f.exists()

    def test_delete_nonexistent_file_does_not_raise(self, tmp_path: Path) -> None:
        """delete() on a nonexistent file must not raise (missing_ok)."""
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        ghost = tmp_path / "ghost.bin"

        # Must not raise
        run(adapter.delete(str(ghost)))


# ---------------------------------------------------------------------------
# LocalStorageAdapter.verify_checksum()
# ---------------------------------------------------------------------------


class TestLocalStorageAdapterVerifyChecksum:
    def test_matching_checksum_returns_true(self, tmp_path: Path) -> None:
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        content = b"verify me"
        f = _write_file(tmp_path / "backup.bin", content)
        expected = hashlib.sha256(content).hexdigest()

        result = run(adapter.verify_checksum(str(f), expected))

        assert result is True

    def test_mismatched_checksum_returns_false(self, tmp_path: Path) -> None:
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        content = b"verify me"
        f = _write_file(tmp_path / "backup2.bin", content)
        wrong_checksum = "0" * 64

        result = run(adapter.verify_checksum(str(f), wrong_checksum))

        assert result is False

    def test_empty_file_checksum(self, tmp_path: Path) -> None:
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        f = _write_file(tmp_path / "empty.bin", b"")
        expected = hashlib.sha256(b"").hexdigest()

        result = run(adapter.verify_checksum(str(f), expected))

        assert result is True


# ---------------------------------------------------------------------------
# Fixture for future phase 57b/57c inheritance
# ---------------------------------------------------------------------------


@pytest.fixture
def local_storage_adapter(tmp_path: Path) -> LocalStorageAdapter:
    """
    Reusable fixture for LocalStorageAdapter.

    Phase 57b (S3) and 57c (GCS) tests can import this fixture and compare
    behaviour of their adapters against the LocalStorageAdapter baseline.
    """
    return LocalStorageAdapter(base_dir=tmp_path)


class TestStorageAdapterFixture:
    """Smoke test confirming the local_storage_adapter fixture is importable."""

    def test_fixture_provides_local_adapter(
        self, local_storage_adapter: LocalStorageAdapter
    ) -> None:
        assert isinstance(local_storage_adapter, StorageAdapter)
        assert isinstance(local_storage_adapter, LocalStorageAdapter)
