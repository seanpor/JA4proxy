"""
Unit tests for BackupRedactor DSAR hardening (Phase 57e).

Tests cover:
- Value scanning: IPs embedded in JSON values are redacted
- Nested JSON structures
- Lists within JSON
- Key-name redaction still works (backward-compat)
- Non-JSON binary values: entry kept if key name doesn't match
- redact_entire_entry=True: entry excluded wholly when value matches
- DSARComplianceError raised when uploading un-scanned artifacts
- No error on scanned upload
"""

import asyncio
import json
from pathlib import Path

import pytest

from src.backup.format import encode_entry
from src.backup.redactor import BackupRedactor
from src.backup.storage_adapter import DSARComplianceError, LocalStorageAdapter

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def run(coro):
    """Run a coroutine synchronously."""
    return asyncio.run(coro)


def _make_artifact(entries: list[tuple[str, bytes]]) -> bytes:
    """Build a raw (legacy-format) backup artifact from (key, value) pairs."""
    data = b""
    for key, val in entries:
        data += encode_entry(key, val)
    return data


# ---------------------------------------------------------------------------
# Test 1: IP in JSON value — field redacted, entry kept
# ---------------------------------------------------------------------------


class TestRedactIPInJsonValue:
    def test_redact_ip_in_json_value(self):
        """IP appearing as a JSON value field is replaced with [REDACTED]."""
        payload = json.dumps(
            {"event": "login", "actor_ip": "192.0.2.1", "user": "admin"}
        ).encode("utf-8")
        data = _make_artifact([("management:audit_log", payload)])

        redactor = BackupRedactor()
        result_bytes, count = redactor.redact(data, ["192.0.2.1"])

        assert count == 1, "expected one redaction"
        # Entry must still be present — decode and inspect
        from src.backup.format import decode_entries

        entries = list(decode_entries(result_bytes))
        assert len(entries) == 1, "entry should be kept (field-redacted, not dropped)"
        key, val = entries[0]
        assert key == "management:audit_log"
        parsed = json.loads(val.decode("utf-8"))
        assert parsed["actor_ip"] == "[REDACTED]"
        assert parsed["user"] == "admin"  # unrelated fields untouched
        assert parsed["event"] == "login"

    def test_ip_not_in_target_list_is_not_redacted(self):
        """IPs absent from the target list are left intact."""
        payload = json.dumps({"actor_ip": "10.0.0.1"}).encode("utf-8")
        data = _make_artifact([("management:audit_log", payload)])

        redactor = BackupRedactor()
        result_bytes, count = redactor.redact(data, ["192.0.2.1"])

        assert count == 0
        from src.backup.format import decode_entries

        entries = list(decode_entries(result_bytes))
        assert len(entries) == 1
        parsed = json.loads(entries[0][1].decode("utf-8"))
        assert parsed["actor_ip"] == "10.0.0.1"


# ---------------------------------------------------------------------------
# Test 2: Nested JSON structure
# ---------------------------------------------------------------------------


class TestRedactNestedIPInJsonValue:
    def test_redact_nested_ip_in_json_value(self):
        """IP nested inside a sub-dict is redacted correctly."""
        payload = json.dumps({"outer": {"inner_ip": "10.0.0.1"}}).encode("utf-8")
        data = _make_artifact([("some:key", payload)])

        redactor = BackupRedactor()
        result_bytes, count = redactor.redact(data, ["10.0.0.1"])

        assert count == 1
        from src.backup.format import decode_entries

        entries = list(decode_entries(result_bytes))
        assert len(entries) == 1
        parsed = json.loads(entries[0][1].decode("utf-8"))
        assert parsed["outer"]["inner_ip"] == "[REDACTED]"


# ---------------------------------------------------------------------------
# Test 3: IP inside a list within JSON
# ---------------------------------------------------------------------------


class TestRedactIPInListWithinJson:
    def test_redact_ip_in_list_within_json(self):
        """Target IP inside a JSON list element is replaced; others untouched."""
        payload = json.dumps({"ips": ["192.0.2.1", "10.0.0.2"]}).encode("utf-8")
        data = _make_artifact([("some:list:key", payload)])

        redactor = BackupRedactor()
        result_bytes, count = redactor.redact(data, ["192.0.2.1"])

        assert count == 1
        from src.backup.format import decode_entries

        entries = list(decode_entries(result_bytes))
        assert len(entries) == 1
        parsed = json.loads(entries[0][1].decode("utf-8"))
        assert parsed["ips"][0] == "[REDACTED]"
        assert parsed["ips"][1] == "10.0.0.2"  # non-target intact


# ---------------------------------------------------------------------------
# Test 4: Key-name redaction still works (backward compat)
# ---------------------------------------------------------------------------


class TestKeyNameRedactionStillWorks:
    def test_key_name_redaction_excludes_entry(self):
        """Entry whose key name matches target IP is excluded entirely (old behavior)."""
        data = _make_artifact(
            [
                ("ban:192.0.2.1", b"somevalue"),
                ("visitor:192.0.2.1", b"othervalue"),
                ("ja4:whitelist", b"unrelated"),
            ]
        )

        redactor = BackupRedactor()
        result_bytes, count = redactor.redact(data, ["192.0.2.1"])

        assert count == 2
        from src.backup.format import decode_entries

        remaining_keys = [k for k, _ in decode_entries(result_bytes)]
        assert "ban:192.0.2.1" not in remaining_keys
        assert "visitor:192.0.2.1" not in remaining_keys
        assert "ja4:whitelist" in remaining_keys

    def test_key_name_redaction_coexists_with_value_redaction(self):
        """Both key-name and value redactions can happen in the same call."""
        value_with_ip = json.dumps({"actor_ip": "192.0.2.1"}).encode("utf-8")
        data = _make_artifact(
            [
                ("ban:192.0.2.1", b"val"),  # excluded by key name
                ("audit:log", value_with_ip),  # field-redacted by value scan
                ("unrelated", b"clean"),
            ]
        )

        redactor = BackupRedactor()
        result_bytes, count = redactor.redact(data, ["192.0.2.1"])

        assert count == 2  # one key exclusion + one value field-redaction
        from src.backup.format import decode_entries

        remaining = {k: v for k, v in decode_entries(result_bytes)}
        assert "ban:192.0.2.1" not in remaining
        assert "audit:log" in remaining
        parsed = json.loads(remaining["audit:log"].decode("utf-8"))
        assert parsed["actor_ip"] == "[REDACTED]"
        assert "unrelated" in remaining


# ---------------------------------------------------------------------------
# Test 5: Non-JSON binary value — entry kept when key doesn't match
# ---------------------------------------------------------------------------


class TestNonJsonValueNotAffected:
    def test_non_json_value_with_no_ip_is_kept(self):
        """Binary (non-JSON) value without target IP passes through untouched."""
        binary_value = b"\x80\x00\xff\xfe\xab\xcd"
        data = _make_artifact([("rdb:dump:somekey", binary_value)])

        redactor = BackupRedactor()
        result_bytes, count = redactor.redact(data, ["192.0.2.1"])

        assert count == 0
        from src.backup.format import decode_entries

        entries = list(decode_entries(result_bytes))
        assert len(entries) == 1
        assert entries[0][1] == binary_value

    def test_non_json_value_containing_ip_excluded_entirely(self):
        """Non-JSON value that happens to contain the target IP bytes → excluded (safe default)."""
        # Raw bytes that contain the IP string but aren't valid JSON
        raw_value = b"\x00\x01192.0.2.1\xff"
        data = _make_artifact(
            [
                ("rdb:dump:somekey", raw_value),
                ("clean:key", b"no-ip-here"),
            ]
        )

        redactor = BackupRedactor()
        result_bytes, count = redactor.redact(data, ["192.0.2.1"])

        assert count == 1, "non-JSON value containing IP should be excluded"
        from src.backup.format import decode_entries

        remaining_keys = [k for k, _ in decode_entries(result_bytes)]
        assert "rdb:dump:somekey" not in remaining_keys
        assert "clean:key" in remaining_keys

    def test_no_error_on_purely_binary_value(self):
        """Pure binary value with no embedded IP string does not cause any exception."""
        # Use null bytes — definitely not valid UTF-8 JSON
        binary_value = bytes(range(256))
        data = _make_artifact([("binary:key", binary_value)])

        redactor = BackupRedactor()
        # Must not raise
        result_bytes, count = redactor.redact(data, ["192.0.2.1"])
        assert count == 0


# ---------------------------------------------------------------------------
# Test 6: redact_entire_entry=True excludes entry when value matches
# ---------------------------------------------------------------------------


class TestRedactEntireEntryOption:
    def test_redact_entire_entry_excludes_when_value_matches(self):
        """When redact_entire_entry=True, entry with IP in value is excluded wholly."""
        payload = json.dumps({"actor_ip": "192.0.2.1", "event": "login"}).encode(
            "utf-8"
        )
        data = _make_artifact(
            [
                ("management:audit_log", payload),
                ("unrelated", b"clean"),
            ]
        )

        redactor = BackupRedactor(redact_entire_entry=True)
        result_bytes, count = redactor.redact(data, ["192.0.2.1"])

        assert count == 1
        from src.backup.format import decode_entries

        remaining_keys = [k for k, _ in decode_entries(result_bytes)]
        assert "management:audit_log" not in remaining_keys
        assert "unrelated" in remaining_keys

    def test_redact_entire_entry_does_not_affect_clean_entries(self):
        """Entries with no IP match are always kept."""
        data = _make_artifact([("clean:key", b"no-ip")])

        redactor = BackupRedactor(redact_entire_entry=True)
        result_bytes, count = redactor.redact(data, ["192.0.2.1"])

        assert count == 0
        from src.backup.format import decode_entries

        assert len(list(decode_entries(result_bytes))) == 1

    def test_default_redact_entire_entry_is_false(self):
        """Default BackupRedactor performs field-level redaction (not entry exclusion)."""
        payload = json.dumps({"actor_ip": "192.0.2.1"}).encode("utf-8")
        data = _make_artifact([("management:audit_log", payload)])

        redactor = BackupRedactor()  # default: redact_entire_entry=False
        result_bytes, count = redactor.redact(data, ["192.0.2.1"])

        from src.backup.format import decode_entries

        entries = list(decode_entries(result_bytes))
        assert len(entries) == 1, "entry should be kept with field-redacted value"


# ---------------------------------------------------------------------------
# Test 7: DSARComplianceError raised on unscanned upload
# ---------------------------------------------------------------------------


class TestDSARComplianceErrorOnUnscannedUpload:
    def test_dsar_compliance_error_on_unscanned_upload(self, tmp_path: Path):
        """Upload with dsar_scanned=False and dsar.redact_values=True raises DSARComplianceError."""
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        f = tmp_path / "backup_test.bin"
        f.write_bytes(b"some data")
        manifest = {
            "filename": "backup_test.bin",
            "created_at": "2026-04-06T00:00:00Z",
            "dsar_scanned": False,
            "dsar": {"redact_values": True},
        }

        with pytest.raises(DSARComplianceError, match="dsar_scanned=False"):
            run(adapter.upload(f, manifest))

    def test_dsar_compliance_error_message_contains_filename(self, tmp_path: Path):
        """Error message includes the artifact filename."""
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        f = tmp_path / "my_backup.bin"
        f.write_bytes(b"x")
        manifest = {
            "filename": "my_backup.bin",
            "dsar_scanned": False,
            "dsar": {"redact_values": True},
        }

        with pytest.raises(DSARComplianceError, match="my_backup.bin"):
            run(adapter.upload(f, manifest))


# ---------------------------------------------------------------------------
# Test 8: No error on scanned upload
# ---------------------------------------------------------------------------


class TestNoErrorOnScannedUpload:
    def test_no_error_when_dsar_scanned_true(self, tmp_path: Path):
        """Upload with dsar_scanned=True does not raise DSARComplianceError."""
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        f = tmp_path / "backup_scanned.bin"
        f.write_bytes(b"payload")
        manifest = {
            "filename": "backup_scanned.bin",
            "created_at": "2026-04-06T00:00:00Z",
            "dsar_scanned": True,
            "dsar": {"redact_values": True},
        }

        # Must not raise
        meta = run(adapter.upload(f, manifest))
        assert meta.filename == "backup_scanned.bin"

    def test_no_error_when_dsar_section_absent(self, tmp_path: Path):
        """Upload with no dsar config at all does not raise (backward-compatible default)."""
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        f = tmp_path / "backup_legacy.bin"
        f.write_bytes(b"legacy payload")
        manifest = {"created_at": "2026-04-06T00:00:00Z"}

        # Must not raise (existing tests pass manifests without dsar section)
        meta = run(adapter.upload(f, manifest))
        assert meta.filename == "backup_legacy.bin"

    def test_no_error_when_redact_values_false(self, tmp_path: Path):
        """No error when dsar.redact_values=False, even if dsar_scanned=False."""
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        f = tmp_path / "backup_noredact.bin"
        f.write_bytes(b"data")
        manifest = {
            "filename": "backup_noredact.bin",
            "dsar_scanned": False,
            "dsar": {"redact_values": False},
        }

        # Must not raise — redaction is disabled
        meta = run(adapter.upload(f, manifest))
        assert meta.provider == "local"

    def test_no_error_empty_manifest(self, tmp_path: Path):
        """Empty manifest dict does not raise (no dsar section = skip check)."""
        adapter = LocalStorageAdapter(base_dir=tmp_path)
        f = tmp_path / "backup_empty.bin"
        f.write_bytes(b"x")

        meta = run(adapter.upload(f, {}))
        assert meta is not None


# ---------------------------------------------------------------------------
# Test: redact_values=False constructor arg skips value scanning entirely
# ---------------------------------------------------------------------------


class TestRedactValuesFalseSkipsValueScanning:
    def test_redact_values_false_skips_json_value_scan(self):
        """When redact_values=False, IP in JSON value is not redacted."""
        payload = json.dumps({"actor_ip": "192.0.2.1"}).encode("utf-8")
        data = _make_artifact([("audit:log", payload)])

        redactor = BackupRedactor(redact_values=False)
        result_bytes, count = redactor.redact(data, ["192.0.2.1"])

        assert count == 0
        from src.backup.format import decode_entries

        entries = list(decode_entries(result_bytes))
        assert len(entries) == 1
        parsed = json.loads(entries[0][1].decode("utf-8"))
        assert parsed["actor_ip"] == "192.0.2.1"  # untouched

    def test_redact_values_false_still_redacts_key_names(self):
        """Key-name matching still happens even when value scanning is disabled."""
        data = _make_artifact(
            [
                ("ban:192.0.2.1", b"val"),
                ("clean:key", b"other"),
            ]
        )

        redactor = BackupRedactor(redact_values=False)
        result_bytes, count = redactor.redact(data, ["192.0.2.1"])

        assert count == 1
        from src.backup.format import decode_entries

        remaining_keys = [k for k, _ in decode_entries(result_bytes)]
        assert "ban:192.0.2.1" not in remaining_keys
        assert "clean:key" in remaining_keys
