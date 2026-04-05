"""Unit tests for Phase 35a — Supply Chain & Configuration Integrity.

Tests IntegrityMonitor from src/security/integrity_monitor.py:
- verify_config_signature: returns True for valid sig, False for missing/bad/wrong-key sig
- append_audit_log: creates file, appends JSON lines, maintains hash chain
- Hash chain tamper-evidence: mutating a middle entry invalidates subsequent hashes
- start_background_monitor: detects file modification, increments Prometheus counter
- Background monitor fails open: missing files log but don't crash

Key/sig format matches scripts/config-signer.py:
  - Keys: base64-encoded raw 32 bytes, one line + newline (no PEM wrapper)
  - Sig:  base64-encoded raw 64-byte Ed25519 signature, one line + newline

The implementation does NOT exist yet — these tests define the interface contract.
"""

import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


# ---------------------------------------------------------------------------
# Helpers — key format matches scripts/config-signer.py
# ---------------------------------------------------------------------------


def _run(coro):
    return asyncio.run(coro)


def _generate_keypair():
    """Return (private_key, public_key) as Ed25519 objects."""
    privkey = Ed25519PrivateKey.generate()
    pubkey = privkey.public_key()
    return privkey, pubkey


def _write_pubkey_raw(pubkey, path: Path) -> None:
    """Write public key as base64-encoded raw bytes (config-signer format)."""
    raw = pubkey.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    path.write_bytes(base64.b64encode(raw) + b"\n")


def _sign_file(privkey, file_path: Path, sig_path: Path) -> None:
    """Sign file_path with privkey, write base64-encoded signature to sig_path."""
    data = file_path.read_bytes()
    sig = privkey.sign(data)
    sig_path.write_bytes(base64.b64encode(sig) + b"\n")


# ---------------------------------------------------------------------------
# verify_config_signature
# ---------------------------------------------------------------------------


class TestVerifyConfigSignature:
    """Tests for IntegrityMonitor.verify_config_signature()."""

    def test_valid_signature_returns_true(self, tmp_path):
        """A correctly signed config file returns True."""
        from src.security.integrity_monitor import IntegrityMonitor

        privkey, pubkey = _generate_keypair()
        config_path = tmp_path / "proxy.yml"
        config_path.write_text("dial: 0\n")
        sig_path = tmp_path / "proxy.yml.sig"
        _sign_file(privkey, config_path, sig_path)

        pubkey_path = tmp_path / "pubkey.pem"
        _write_pubkey_raw(pubkey, pubkey_path)

        monitor = IntegrityMonitor()
        result = monitor.verify_config_signature(
            str(config_path), str(pubkey_path)
        )
        assert result is True

    def test_missing_sig_file_returns_false(self, tmp_path):
        """If .sig file is absent, returns False — does NOT raise."""
        from src.security.integrity_monitor import IntegrityMonitor

        _, pubkey = _generate_keypair()
        config_path = tmp_path / "proxy.yml"
        config_path.write_text("dial: 0\n")
        # No .sig file written

        pubkey_path = tmp_path / "pubkey.pem"
        _write_pubkey_raw(pubkey, pubkey_path)

        monitor = IntegrityMonitor()
        result = monitor.verify_config_signature(
            str(config_path), str(pubkey_path)
        )
        assert result is False

    def test_corrupted_sig_returns_false(self, tmp_path):
        """A .sig file with corrupted content returns False, not an exception.

        We replace the .sig file with all-0xFF bytes (clearly invalid) to ensure
        the corruption is always detected regardless of format auto-detection quirks.
        """
        from src.security.integrity_monitor import IntegrityMonitor

        privkey, pubkey = _generate_keypair()
        config_path = tmp_path / "proxy.yml"
        config_path.write_text("dial: 0\n")
        sig_path = tmp_path / "proxy.yml.sig"
        _sign_file(privkey, config_path, sig_path)

        # Replace the .sig file with a completely wrong signature (all 0xFF bytes).
        # A 64-byte raw Ed25519 signature is cryptographically invalid for this content.
        sig_path.write_bytes(bytes([0xFF] * 64))

        pubkey_path = tmp_path / "pubkey.pub"
        _write_pubkey_raw(pubkey, pubkey_path)

        monitor = IntegrityMonitor()
        result = monitor.verify_config_signature(
            str(config_path), str(pubkey_path)
        )
        assert result is False

    def test_wrong_key_returns_false(self, tmp_path):
        """Signature was made with one key but we verify with a different key → False."""
        from src.security.integrity_monitor import IntegrityMonitor

        privkey, _ = _generate_keypair()
        _, wrong_pubkey = _generate_keypair()  # Different keypair

        config_path = tmp_path / "proxy.yml"
        config_path.write_text("dial: 0\n")
        sig_path = tmp_path / "proxy.yml.sig"
        _sign_file(privkey, config_path, sig_path)

        # Write the wrong public key
        pubkey_path = tmp_path / "pubkey.pub"
        _write_pubkey_raw(wrong_pubkey, pubkey_path)

        monitor = IntegrityMonitor()
        result = monitor.verify_config_signature(
            str(config_path), str(pubkey_path)
        )
        assert result is False

    def test_config_modified_after_signing_returns_false(self, tmp_path):
        """If config file is modified after signing, verification returns False."""
        from src.security.integrity_monitor import IntegrityMonitor

        privkey, pubkey = _generate_keypair()
        config_path = tmp_path / "proxy.yml"
        config_path.write_text("dial: 0\n")
        sig_path = tmp_path / "proxy.yml.sig"
        _sign_file(privkey, config_path, sig_path)

        # Modify config after signing
        config_path.write_text("dial: 100\n")

        pubkey_path = tmp_path / "pubkey.pem"
        _write_pubkey_raw(pubkey, pubkey_path)

        monitor = IntegrityMonitor()
        result = monitor.verify_config_signature(
            str(config_path), str(pubkey_path)
        )
        assert result is False

    def test_missing_config_file_returns_false(self, tmp_path):
        """If the config file itself is missing, returns False without raising."""
        from src.security.integrity_monitor import IntegrityMonitor

        _, pubkey = _generate_keypair()
        config_path = tmp_path / "nonexistent.yml"
        pubkey_path = tmp_path / "pubkey.pem"
        _write_pubkey_raw(pubkey, pubkey_path)

        monitor = IntegrityMonitor()
        result = monitor.verify_config_signature(
            str(config_path), str(pubkey_path)
        )
        assert result is False

    def test_missing_pubkey_file_returns_false(self, tmp_path):
        """If the public key file is missing, returns False without raising."""
        from src.security.integrity_monitor import IntegrityMonitor

        privkey, _ = _generate_keypair()
        config_path = tmp_path / "proxy.yml"
        config_path.write_text("dial: 0\n")
        sig_path = tmp_path / "proxy.yml.sig"
        _sign_file(privkey, config_path, sig_path)

        monitor = IntegrityMonitor()
        result = monitor.verify_config_signature(
            str(config_path), str(tmp_path / "missing_pubkey.pem")
        )
        assert result is False


# ---------------------------------------------------------------------------
# append_audit_log
# ---------------------------------------------------------------------------


class TestAppendAuditLog:
    """Tests for IntegrityMonitor.append_audit_log()."""

    def test_creates_file_if_not_exists(self, tmp_path):
        """append_audit_log creates the log file if it doesn't exist."""
        from src.security.integrity_monitor import IntegrityMonitor

        log_path = tmp_path / "integrity.log"
        assert not log_path.exists()

        monitor = IntegrityMonitor()
        monitor.append_audit_log(str(log_path), status="OK", detail="startup check")

        assert log_path.exists()

    def test_appends_json_lines(self, tmp_path):
        """Each call appends a valid JSON line to the log file."""
        from src.security.integrity_monitor import IntegrityMonitor

        log_path = tmp_path / "integrity.log"
        monitor = IntegrityMonitor()

        monitor.append_audit_log(str(log_path), status="OK", detail="first check")
        monitor.append_audit_log(str(log_path), status="FAIL", detail="tampering")

        lines = log_path.read_text().strip().splitlines()
        assert len(lines) == 2

        entry1 = json.loads(lines[0])
        assert entry1["status"] == "OK"
        assert entry1["detail"] == "first check"

        entry2 = json.loads(lines[1])
        assert entry2["status"] == "FAIL"
        assert entry2["detail"] == "tampering"

    def test_entry_has_timestamp(self, tmp_path):
        """Each log entry includes a timestamp field."""
        from src.security.integrity_monitor import IntegrityMonitor

        log_path = tmp_path / "integrity.log"
        monitor = IntegrityMonitor()
        monitor.append_audit_log(str(log_path), status="OK", detail="ts check")

        entry = json.loads(log_path.read_text().strip())
        assert "timestamp" in entry
        # Timestamp should be a non-empty string or numeric
        assert entry["timestamp"]

    def test_first_entry_prev_hash_is_empty_string(self, tmp_path):
        """The first log entry has prev_hash == '' (no predecessor)."""
        from src.security.integrity_monitor import IntegrityMonitor

        log_path = tmp_path / "integrity.log"
        monitor = IntegrityMonitor()
        monitor.append_audit_log(str(log_path), status="OK", detail="genesis")

        entry = json.loads(log_path.read_text().strip())
        assert "prev_hash" in entry
        assert entry["prev_hash"] == ""

    def test_second_entry_prev_hash_is_sha256_of_first_raw_line(self, tmp_path):
        """The second entry's prev_hash is SHA-256 of the first raw log line."""
        from src.security.integrity_monitor import IntegrityMonitor

        log_path = tmp_path / "integrity.log"
        monitor = IntegrityMonitor()
        monitor.append_audit_log(str(log_path), status="OK", detail="first")
        monitor.append_audit_log(str(log_path), status="OK", detail="second")

        lines = log_path.read_text().strip().splitlines()
        first_raw = lines[0]
        expected_prev_hash = hashlib.sha256(first_raw.encode()).hexdigest()

        entry2 = json.loads(lines[1])
        assert entry2["prev_hash"] == expected_prev_hash

    def test_hash_chain_across_five_entries(self, tmp_path):
        """Five entries form a correct forward-linked hash chain."""
        from src.security.integrity_monitor import IntegrityMonitor

        log_path = tmp_path / "integrity.log"
        monitor = IntegrityMonitor()

        for i in range(5):
            monitor.append_audit_log(
                str(log_path), status="OK", detail=f"entry-{i}"
            )

        lines = log_path.read_text().strip().splitlines()
        assert len(lines) == 5

        # Verify the chain: each entry's prev_hash == sha256 of previous raw line
        for idx in range(1, 5):
            prev_raw = lines[idx - 1]
            expected = hashlib.sha256(prev_raw.encode()).hexdigest()
            entry = json.loads(lines[idx])
            assert entry["prev_hash"] == expected, (
                f"Hash chain broken at entry {idx}: "
                f"expected {expected!r}, got {entry['prev_hash']!r}"
            )

    def test_hash_chain_tamper_evident_middle_entry(self, tmp_path):
        """Mutating a middle entry causes subsequent prev_hash to be wrong."""
        from src.security.integrity_monitor import IntegrityMonitor

        log_path = tmp_path / "integrity.log"
        monitor = IntegrityMonitor()

        for i in range(4):
            monitor.append_audit_log(
                str(log_path), status="OK", detail=f"entry-{i}"
            )

        lines = log_path.read_text().strip().splitlines()

        # Tamper with entry at index 1
        entry1 = json.loads(lines[1])
        entry1["detail"] = "TAMPERED"
        tampered_line = json.dumps(entry1)
        lines[1] = tampered_line
        log_path.write_text("\n".join(lines) + "\n")

        # Now verify: entry 2's prev_hash should NOT match hash of tampered line 1
        lines_after = log_path.read_text().strip().splitlines()
        actual_hash_of_line1 = hashlib.sha256(lines_after[1].encode()).hexdigest()
        entry2 = json.loads(lines_after[2])

        # Entry 2's prev_hash was computed from the original line 1, not the tampered one
        assert entry2["prev_hash"] != actual_hash_of_line1, (
            "Hash chain should be broken after tampering a middle entry"
        )

    def test_creates_parent_directory_if_missing(self, tmp_path):
        """append_audit_log creates parent directories if they don't exist."""
        from src.security.integrity_monitor import IntegrityMonitor

        log_path = tmp_path / "var" / "log" / "ja4proxy" / "integrity.log"
        assert not log_path.parent.exists()

        monitor = IntegrityMonitor()
        monitor.append_audit_log(str(log_path), status="OK", detail="mkdir test")

        assert log_path.exists()


# ---------------------------------------------------------------------------
# start_background_monitor
# ---------------------------------------------------------------------------


class TestStartBackgroundMonitor:
    """Tests for IntegrityMonitor.start_background_monitor()."""

    def test_detects_file_modification_increments_counter(self, tmp_path):
        """Background monitor increments ja4proxy_integrity_violation_total on change."""
        from prometheus_client import REGISTRY

        # Pre-clean any existing integrity_violation counter from prior test runs
        for name, collector in list(REGISTRY._names_to_collectors.items()):
            if "integrity_violation" in name:
                try:
                    REGISTRY.unregister(collector)
                except Exception:
                    pass

        from src.security.integrity_monitor import IntegrityMonitor

        watched_file = tmp_path / "proxy.py"
        watched_file.write_text("# original content\n")

        monitor = IntegrityMonitor()

        async def run_test():
            # Start monitor with very short interval
            task = asyncio.create_task(
                monitor.start_background_monitor(
                    paths=[str(watched_file)], interval_s=0.05
                )
            )
            # Allow one poll cycle to establish baseline
            await asyncio.sleep(0.1)

            # Get counter value before modification
            violation_counter = monitor.violation_counter
            before = violation_counter._value.get()

            # Modify the file
            watched_file.write_text("# MODIFIED content\n")

            # Wait for next poll to detect the change
            await asyncio.sleep(0.15)

            after = violation_counter._value.get()
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

            return before, after

        before, after = _run(run_test())
        assert after > before, (
            "Prometheus counter should have incremented after file modification"
        )

    def test_monitors_multiple_files(self, tmp_path):
        """Monitor watches all specified paths, detects changes in any of them."""
        from src.security.integrity_monitor import IntegrityMonitor

        file_a = tmp_path / "proxy.py"
        file_b = tmp_path / "pipeline.py"
        file_a.write_text("# file A original\n")
        file_b.write_text("# file B original\n")

        monitor = IntegrityMonitor()

        async def run_test():
            task = asyncio.create_task(
                monitor.start_background_monitor(
                    paths=[str(file_a), str(file_b)], interval_s=0.05
                )
            )
            await asyncio.sleep(0.1)
            before = monitor.violation_counter._value.get()

            # Modify only file B
            file_b.write_text("# file B TAMPERED\n")
            await asyncio.sleep(0.15)

            after = monitor.violation_counter._value.get()
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            return before, after

        before, after = _run(run_test())
        assert after > before, "Violation counter must increment when any watched file changes"

    def test_no_violation_when_files_unchanged(self, tmp_path):
        """Monitor does NOT increment the counter when files remain identical."""
        from src.security.integrity_monitor import IntegrityMonitor

        watched_file = tmp_path / "proxy.py"
        watched_file.write_text("# stable content\n")

        monitor = IntegrityMonitor()

        async def run_test():
            task = asyncio.create_task(
                monitor.start_background_monitor(
                    paths=[str(watched_file)], interval_s=0.05
                )
            )
            # Let it poll several times without changes
            await asyncio.sleep(0.3)
            count = monitor.violation_counter._value.get()
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            return count

        count = _run(run_test())
        assert count == 0, "No violations should be reported for unchanged files"

    def test_missing_file_does_not_crash(self, tmp_path):
        """If a watched file disappears, the monitor logs but does not crash."""
        from src.security.integrity_monitor import IntegrityMonitor

        watched_file = tmp_path / "proxy.py"
        watched_file.write_text("# original\n")

        monitor = IntegrityMonitor()

        async def run_test():
            task = asyncio.create_task(
                monitor.start_background_monitor(
                    paths=[str(watched_file)], interval_s=0.05
                )
            )
            await asyncio.sleep(0.1)

            # Delete the file
            watched_file.unlink()

            # Monitor should survive the next poll without raising
            await asyncio.sleep(0.15)

            assert not task.done() or task.cancelled(), (
                "Task should still be running (or cleanly cancelled), not crashed"
            )
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                pytest.fail(
                    f"Background monitor raised an unexpected exception: {exc}"
                )

        _run(run_test())  # Test passes if no exception raised

    def test_violation_logs_at_error_level(self, tmp_path, caplog):
        """File modification is logged at ERROR level."""
        import logging

        from src.security.integrity_monitor import IntegrityMonitor

        watched_file = tmp_path / "proxy.py"
        watched_file.write_text("# original\n")
        monitor = IntegrityMonitor()

        async def run_test():
            task = asyncio.create_task(
                monitor.start_background_monitor(
                    paths=[str(watched_file)], interval_s=0.05
                )
            )
            await asyncio.sleep(0.1)
            watched_file.write_text("# tampered\n")
            await asyncio.sleep(0.15)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        with caplog.at_level(logging.ERROR):
            _run(run_test())

        error_messages = [r.message for r in caplog.records if r.levelno >= logging.ERROR]
        assert any(
            "integrity" in msg.lower() or "violation" in msg.lower() or str(watched_file) in msg
            for msg in error_messages
        ), f"Expected an ERROR log about integrity violation, got: {error_messages}"
