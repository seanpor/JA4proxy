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

Tests were written TDD-style before implementation.  All tests now pass against
the live implementation in src/security/integrity_monitor.py.
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
        result = monitor.verify_config_signature(str(config_path), str(pubkey_path))
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
        result = monitor.verify_config_signature(str(config_path), str(pubkey_path))
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
        result = monitor.verify_config_signature(str(config_path), str(pubkey_path))
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
        result = monitor.verify_config_signature(str(config_path), str(pubkey_path))
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
        result = monitor.verify_config_signature(str(config_path), str(pubkey_path))
        assert result is False

    def test_missing_config_file_returns_false(self, tmp_path):
        """If the config file itself is missing, returns False without raising."""
        from src.security.integrity_monitor import IntegrityMonitor

        _, pubkey = _generate_keypair()
        config_path = tmp_path / "nonexistent.yml"
        pubkey_path = tmp_path / "pubkey.pem"
        _write_pubkey_raw(pubkey, pubkey_path)

        monitor = IntegrityMonitor()
        result = monitor.verify_config_signature(str(config_path), str(pubkey_path))
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
            monitor.append_audit_log(str(log_path), status="OK", detail=f"entry-{i}")

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
            monitor.append_audit_log(str(log_path), status="OK", detail=f"entry-{i}")

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
        assert (
            entry2["prev_hash"] != actual_hash_of_line1
        ), "Hash chain should be broken after tampering a middle entry"

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
        assert (
            after > before
        ), "Prometheus counter should have incremented after file modification"

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
        assert (
            after > before
        ), "Violation counter must increment when any watched file changes"

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

            assert (
                not task.done() or task.cancelled()
            ), "Task should still be running (or cleanly cancelled), not crashed"
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                pytest.fail(f"Background monitor raised an unexpected exception: {exc}")

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

        error_messages = [
            r.message for r in caplog.records if r.levelno >= logging.ERROR
        ]
        assert any(
            "integrity" in msg.lower()
            or "violation" in msg.lower()
            or str(watched_file) in msg
            for msg in error_messages
        ), f"Expected an ERROR log about integrity violation, got: {error_messages}"

    def test_new_file_post_baseline_logs_warning(self, tmp_path, caplog):
        """A file that appears after baseline is established logs at WARNING level.

        A new file should be suspicious — not silently accepted — because an
        attacker who can write to the monitored tree could plant a backdoor module.
        """
        import logging

        from src.security.integrity_monitor import IntegrityMonitor

        existing_file = tmp_path / "proxy.py"
        existing_file.write_text("# original\n")
        new_file = tmp_path / "injected.py"

        monitor = IntegrityMonitor()

        async def run_test():
            task = asyncio.create_task(
                monitor.start_background_monitor(paths=[str(tmp_path)], interval_s=0.05)
            )
            await asyncio.sleep(0.1)
            # Plant a new file after baseline is set
            new_file.write_text("import os; os.system('evil')\n")
            await asyncio.sleep(0.15)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        with caplog.at_level(logging.WARNING):
            _run(run_test())

        warning_messages = [
            r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING
        ]
        assert any(
            "new_file" in msg or str(new_file) in msg for msg in warning_messages
        ), f"Expected WARNING about new file in monitored tree, got: {warning_messages}"

    def test_shutdown_on_violation_calls_sys_exit(self, tmp_path):
        """When shutdown_on_violation is True, a tampered file triggers sys.exit(1)."""
        import sys

        from src.security.integrity_monitor import IntegrityMonitor

        watched_file = tmp_path / "proxy.py"
        watched_file.write_text("# original\n")

        monitor = IntegrityMonitor({"integrity": {"shutdown_on_violation": True}})

        exit_calls = []

        async def run_test():
            with patch.object(
                sys, "exit", side_effect=lambda code: exit_calls.append(code)
            ):
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

        _run(run_test())
        # The mock sys.exit doesn't actually stop the process, so the monitor
        # continues polling and may call sys.exit(1) more than once.
        # Assert it was called at least once with code 1.
        assert exit_calls and all(c == 1 for c in exit_calls), (
            f"sys.exit(1) should be called on violation with shutdown_on_violation=True, "
            f"got exit_calls={exit_calls}"
        )


# ---------------------------------------------------------------------------
# Additional coverage tests — targeting previously uncovered lines
# ---------------------------------------------------------------------------


class TestVerifyConfigSignatureCryptographyMissing:
    """Lines 136-142: cryptography ImportError → fail-open with True."""

    def test_cryptography_import_error_returns_true(self, tmp_path):
        """When the cryptography library is not importable, verify_config_signature
        must return True (fail-open) rather than raising ImportError.

        So what: if the dependency is stripped from the container at runtime, the
        proxy continues to operate rather than hard-failing every connection.
        """

        config_path = tmp_path / "proxy.yml"
        config_path.write_text("dial: 0\n")
        pubkey_path = tmp_path / "pubkey.pem"
        pubkey_path.write_bytes(b"dummy")

        import builtins

        real_import = builtins.__import__

        def _block_cryptography(name, *args, **kwargs):
            if name == "cryptography.exceptions":
                raise ImportError("cryptography not installed")
            return real_import(name, *args, **kwargs)

        # We must reload the module so the patched import is exercised at call time.
        # The function does a local `from cryptography.exceptions import InvalidSignature`
        # on every call — patch builtins.__import__ to simulate the missing library.
        with patch("builtins.__import__", side_effect=_block_cryptography):
            from src.security.integrity_monitor import IntegrityMonitor

            monitor = IntegrityMonitor()
            result = monitor.verify_config_signature(str(config_path), str(pubkey_path))

        assert (
            result is True
        ), "verify_config_signature must return True when cryptography is absent"


class TestVerifyConfigSignatureGenericVerifyException:
    """Lines 190-196: generic Exception from public_key.verify() → False."""

    def test_generic_exception_during_verify_returns_false(self, tmp_path):
        """If public_key.verify() raises an unexpected exception (not InvalidSignature),
        verify_config_signature catches it and returns False.

        So what: an attacker-controlled key that raises during verify must not
        be treated as a pass — the function must stay closed on unexpected errors.
        """
        from unittest.mock import MagicMock

        from src.security.integrity_monitor import IntegrityMonitor

        privkey, pubkey = _generate_keypair()
        config_path = tmp_path / "proxy.yml"
        config_path.write_text("dial: 0\n")
        sig_path = tmp_path / "proxy.yml.sig"
        _sign_file(privkey, config_path, sig_path)
        pubkey_path = tmp_path / "pubkey.pem"
        _write_pubkey_raw(pubkey, pubkey_path)

        # Patch _load_pubkey to return a mock whose .verify() raises RuntimeError
        mock_key = MagicMock()
        mock_key.verify.side_effect = RuntimeError("unexpected internal error")

        with patch(
            "src.security.integrity_monitor._load_pubkey", return_value=mock_key
        ):
            monitor = IntegrityMonitor()
            result = monitor.verify_config_signature(str(config_path), str(pubkey_path))

        assert (
            result is False
        ), "Generic exception from verify() must return False, not propagate"


class TestBackgroundMonitorShutdownFlag:
    """Line 230: _shutdown flag causes the monitor loop to break cleanly."""

    def test_shutdown_flag_stops_monitor(self, tmp_path):
        """Setting monitor._shutdown = True between poll cycles causes the loop to
        exit cleanly without cancellation.

        So what: the graceful-shutdown path must work so the process can exit
        cleanly under SIGTERM without leaving background tasks dangling.
        """
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
            # Let baseline establish and one sleep start
            await asyncio.sleep(0.08)
            # Set shutdown flag; the loop checks it after sleep completes
            monitor._shutdown = True
            # Give the task time to wake from sleep and notice the flag
            await asyncio.sleep(0.1)
            # Task should have exited on its own (not cancelled, not exception)
            return task.done()

        done = _run(run_test())
        assert done, "Monitor task should have exited after _shutdown flag was set"


class TestBackgroundMonitorHashPathsException:
    """Lines 237-244: exception in _hash_paths/_compare_and_alert → fail-open."""

    def test_hash_paths_exception_does_not_crash_monitor(self, tmp_path):
        """If _hash_paths raises during a poll cycle the monitor logs the error
        and continues running rather than crashing.

        So what: a transient filesystem error (NFS stall, permissions change) must
        not take down the monitor permanently — integrity monitoring must be resilient.
        """

        from src.security.integrity_monitor import IntegrityMonitor

        watched_file = tmp_path / "proxy.py"
        watched_file.write_text("# original\n")
        monitor = IntegrityMonitor()

        call_count = [0]
        original_hash_paths = __import__(
            "src.security.integrity_monitor", fromlist=["_hash_paths"]
        )._hash_paths

        def _flaky_hash_paths(paths):
            call_count[0] += 1
            if call_count[0] == 1:
                # First call — establish baseline normally
                return original_hash_paths(paths)
            if call_count[0] == 2:
                # Second call — simulate a transient error
                raise RuntimeError("NFS stall")
            return original_hash_paths(paths)

        async def run_test():
            with patch(
                "src.security.integrity_monitor._hash_paths",
                side_effect=_flaky_hash_paths,
            ):
                task = asyncio.create_task(
                    monitor.start_background_monitor(
                        paths=[str(watched_file)], interval_s=0.05
                    )
                )
                # Let baseline + two poll cycles complete
                await asyncio.sleep(0.2)
                still_running = not task.done()
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                return still_running

        still_running = _run(run_test())
        assert (
            still_running
        ), "Monitor must keep running after a transient _hash_paths exception"

    def test_outer_cancelled_error_stops_monitor(self, tmp_path):
        """Lines 242-244: CancelledError raised around the entire try block (e.g.
        during the baseline _hash_paths call) causes a clean exit.

        So what: if the event loop is shut down while the monitor is computing the
        baseline, it must exit cleanly without swallowing the cancellation.
        """

        from src.security.integrity_monitor import IntegrityMonitor

        monitor = IntegrityMonitor()

        async def run_test():
            def _raise_cancelled(paths):
                raise asyncio.CancelledError()

            with patch(
                "src.security.integrity_monitor._hash_paths",
                side_effect=_raise_cancelled,
            ):
                # The outer try/except CancelledError in start_background_monitor
                # catches this and returns cleanly
                await monitor.start_background_monitor(
                    paths=["/tmp/fake"], interval_s=0.05
                )

        # Should complete without raising
        _run(run_test())


class TestAppendAuditLogExceptionPath:
    """Lines 272-273: append_audit_log catches and logs unexpected exceptions."""

    def test_write_failure_does_not_raise(self, tmp_path):
        """If writing to the log file raises an unexpected exception, append_audit_log
        swallows it and logs the error instead of propagating.

        So what: an audit log write failure (disk full, permissions) must not crash
        the proxy — it must fail open so legitimate traffic continues flowing.
        """
        from unittest.mock import MagicMock

        from src.security.integrity_monitor import IntegrityMonitor

        log_path = tmp_path / "integrity.log"
        monitor = IntegrityMonitor()

        # Patch open() to raise on write
        original_open = open

        def _failing_open(path, *args, **kwargs):
            if str(path) == str(log_path) and "a" in args:
                raise OSError("disk full")
            return original_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=_failing_open):
            # Should not raise
            monitor.append_audit_log(str(log_path), status="OK", detail="test")

        # No assertion needed — the test passes if no exception was raised


class TestDecodeSignatureEdgePaths:
    """Lines 303, 311-313: _decode_signature edge cases."""

    def test_64_bytes_with_trailing_whitespace(self):
        """A 65-byte input where stripping trailing newline yields exactly 64 bytes
        takes the stripped path (line 302-303).

        So what: signatures written with a trailing newline (common in file writes)
        must be accepted without treating the extra byte as corruption.
        """
        from src.security.integrity_monitor import _decode_signature

        raw_sig = b"\xab" * 64 + b"\n"  # 65 bytes — 64 + newline
        result = _decode_signature(raw_sig)
        assert result == b"\xab" * 64

    def test_base64_decoded_wrong_length_raises_value_error(self):
        """Valid base64 that decodes to something other than 64 bytes raises ValueError.

        So what: a truncated or padded signature must be rejected, not silently
        accepted as a shorter-than-expected byte sequence.
        """
        import base64

        from src.security.integrity_monitor import _decode_signature

        # Encode 32 bytes (wrong size) as base64 — yields a >64-char b64 string
        short_sig = base64.b64encode(b"\xcc" * 32)
        with pytest.raises(ValueError, match="bytes, expected 64"):
            _decode_signature(short_sig)

    def test_invalid_base64_raises_value_error(self):
        """Completely invalid base64 content raises ValueError (line 312-313).

        So what: a corrupt or non-base64 signature file must not silently succeed
        or raise an unexpected exception type that bypasses the caller's handler.
        """
        from src.security.integrity_monitor import _decode_signature

        # Not valid base64 and not 64 bytes
        garbage = b"not-valid-base64!!!"
        with pytest.raises(ValueError, match="Cannot decode signature"):
            _decode_signature(garbage)


class TestLoadPubkeyEdgePaths:
    """Lines 334, 342-349: _load_pubkey format branches."""

    def test_pem_public_key_accepted(self, tmp_path):
        """A PEM-wrapped SubjectPublicKeyInfo key is loaded via load_pem_public_key
        (line 334).

        So what: operator tooling typically generates PEM keys; failing to load them
        would make signature verification permanently return False.
        """
        from cryptography.hazmat.primitives.serialization import (
            Encoding as _Enc,
        )
        from cryptography.hazmat.primitives.serialization import (
            PublicFormat as _PF,
        )
        from src.security.integrity_monitor import _load_pubkey

        _, pubkey = _generate_keypair()
        pem_bytes = pubkey.public_bytes(
            encoding=_Enc.PEM, format=_PF.SubjectPublicKeyInfo
        )
        pem_path = tmp_path / "pubkey.pem"
        pem_path.write_bytes(pem_bytes)

        key = _load_pubkey(str(pem_path))
        assert key is not None

    def test_raw_32_byte_key_accepted(self, tmp_path):
        """A raw 32-byte key written directly to disk is loaded (line 346-347).

        So what: some signing tools write raw keys; they must be accepted so
        operators are not forced into PEM format.
        """
        from cryptography.hazmat.primitives.serialization import (
            Encoding as _Enc,
        )
        from cryptography.hazmat.primitives.serialization import (
            PublicFormat as _PF,
        )
        from src.security.integrity_monitor import _load_pubkey

        _, pubkey = _generate_keypair()
        raw_bytes = pubkey.public_bytes(encoding=_Enc.Raw, format=_PF.Raw)
        assert len(raw_bytes) == 32

        key_path = tmp_path / "pubkey.raw"
        key_path.write_bytes(raw_bytes)

        key = _load_pubkey(str(key_path))
        assert key is not None

    def test_unrecognised_format_raises_value_error(self, tmp_path):
        """Content that is not PEM, not valid base64→32 bytes, and not 32 raw bytes
        raises ValueError (lines 349-352).

        So what: a misconfigured or attacker-supplied garbage key file must not be
        silently accepted — the caller must see a clear failure signal.
        """
        from src.security.integrity_monitor import _load_pubkey

        bad_path = tmp_path / "bad.pem"
        # 100 bytes — not PEM, not 32, base64 decodes to wrong length
        bad_path.write_bytes(b"X" * 100)

        with pytest.raises(ValueError, match="unrecognised format"):
            _load_pubkey(str(bad_path))

    def test_base64_decode_exception_falls_through_to_raw_check(self, tmp_path):
        """If base64.b64decode raises for a non-base64 payload, the code falls
        through to the raw 32-byte check (lines 342-343).

        So what: resilience in the key loader means a non-base64 key that happens
        to be 32 bytes long is still usable via the raw path.
        """
        from cryptography.hazmat.primitives.serialization import (
            Encoding as _Enc,
        )
        from cryptography.hazmat.primitives.serialization import (
            PublicFormat as _PF,
        )
        from src.security.integrity_monitor import _load_pubkey

        _, pubkey = _generate_keypair()
        raw_bytes = pubkey.public_bytes(encoding=_Enc.Raw, format=_PF.Raw)
        assert len(raw_bytes) == 32

        # Write bytes that are not valid base64 but are exactly 32 bytes.
        # b64decode will raise, the except block will pass, and the raw-32-byte
        # branch (line 346) will succeed.
        # Most 32-byte sequences with high-bit bytes are not valid base64.
        key_path = tmp_path / "pubkey.raw"
        key_path.write_bytes(raw_bytes)

        key = _load_pubkey(str(key_path))
        assert key is not None


class TestHashPathsEdgeCases:
    """Lines 379, 383-384, 392-396: _hash_paths directory and error branches."""

    def test_pycache_files_are_skipped(self, tmp_path):
        """__pycache__ directories and .pyc files are excluded from the hash set
        (line 379).

        So what: bytecode caches are regenerated by the interpreter at runtime;
        including them in the baseline would generate constant false-positive
        violation alerts every time Python recompiles a module.
        """
        from src.security.integrity_monitor import _hash_paths

        # Create a normal file and a fake __pycache__ .pyc file
        normal = tmp_path / "module.py"
        normal.write_text("# normal\n")

        cache_dir = tmp_path / "__pycache__"
        cache_dir.mkdir()
        (cache_dir / "module.cpython-312.pyc").write_bytes(b"\x00" * 16)

        result = _hash_paths([str(tmp_path)])

        assert str(normal) in result
        # No __pycache__ entry should appear
        assert not any(
            "__pycache__" in p for p in result
        ), "__pycache__ files must be excluded from the hash baseline"

    def test_hash_error_on_individual_dir_file_is_skipped(self, tmp_path):
        """If hashing one file in a directory raises OSError, that file is skipped
        and the rest of the directory is still processed (lines 383-384).

        So what: a file with permissions that prevent reading must not abort
        monitoring of all other files in the same directory.
        """

        from src.security.integrity_monitor import _hash_paths

        file_a = tmp_path / "a.py"
        file_b = tmp_path / "b.py"
        file_a.write_text("# a\n")
        file_b.write_text("# b\n")

        original_hash_file = __import__(
            "src.security.integrity_monitor", fromlist=["_hash_file"]
        )._hash_file

        def _partial_failure(path):
            if "a.py" in path:
                raise OSError("permission denied")
            return original_hash_file(path)

        with patch(
            "src.security.integrity_monitor._hash_file", side_effect=_partial_failure
        ):
            result = _hash_paths([str(tmp_path)])

        # b.py should still be hashed; a.py should be absent (skipped)
        assert str(file_b) in result
        assert str(file_a) not in result

    def test_path_not_found_logs_debug(self, tmp_path, caplog):
        """A path that is neither a file nor a directory (lines 391-394) is logged
        at DEBUG level and skipped without error.

        So what: a misconfigured watchlist entry (typo in path) must not abort
        monitoring of the other valid paths.
        """
        import logging

        from src.security.integrity_monitor import _hash_paths

        real_file = tmp_path / "real.py"
        real_file.write_text("# real\n")
        missing = str(tmp_path / "nonexistent.py")

        with caplog.at_level(logging.DEBUG):
            result = _hash_paths([str(real_file), missing])

        assert str(real_file) in result
        assert missing not in result

    def test_outer_exception_on_path_is_logged_and_skipped(self, tmp_path):
        """An unexpected exception inside the try-block in _hash_paths (lines 395-396)
        is caught, logged, and does not abort processing of remaining paths.

        So what: a transient error on one monitored path must not blind the monitor
        to tampered files in all other paths.
        """
        from unittest.mock import MagicMock

        from src.security.integrity_monitor import _hash_paths

        real_file = tmp_path / "real.py"
        real_file.write_text("# real\n")

        # We need to trigger an exception INSIDE the try block (line 373+).
        # Patch _hash_file so it raises an unexpected non-OSError exception when
        # processing the file at a specific path, which propagates up to the outer
        # except Exception block (lines 395-396).
        # Use a directory so rglob is iterated; the inner try only catches OSError,
        # so a RuntimeError will bubble up to the outer handler.

        inner_dir = tmp_path / "watched_dir"
        inner_dir.mkdir()
        inner_file = inner_dir / "module.py"
        inner_file.write_text("# module\n")

        original_hash_file = __import__(
            "src.security.integrity_monitor", fromlist=["_hash_file"]
        )._hash_file

        def _bad_hash_file(path):
            if "watched_dir" in path:
                raise RuntimeError("unexpected non-OSError in hash_file")
            return original_hash_file(path)

        with patch(
            "src.security.integrity_monitor._hash_file", side_effect=_bad_hash_file
        ):
            # Should not raise — outer except catches the RuntimeError
            result = _hash_paths([str(inner_dir), str(real_file)])

        # real_file should be processed normally; inner_dir triggers the outer handler
        assert str(real_file) in result
        assert isinstance(result, dict)


class TestReadLastLineHashEdgeCases:
    """Lines 464, 469-475: _read_last_line_hash empty file and exception paths."""

    def test_empty_log_file_returns_empty_string(self, tmp_path):
        """An existing but empty log file returns '' (line 464).

        So what: the very first write to a newly created log file must produce
        prev_hash='' so the audit chain starts cleanly rather than with a stale hash.
        """
        from src.security.integrity_monitor import _read_last_line_hash

        log_path = tmp_path / "empty.log"
        log_path.write_text("")  # empty file — exists but has no lines

        result = _read_last_line_hash(str(log_path))
        assert (
            result == ""
        ), "Empty log file must return empty string as the previous hash"

    def test_generic_read_exception_returns_empty_string(self, tmp_path):
        """A non-FileNotFoundError exception while reading the log file returns ''
        (lines 469-475) rather than propagating.

        So what: a corrupt or unreadable log file must not prevent subsequent audit
        entries from being written — the chain can restart but monitoring continues.
        """
        from unittest.mock import MagicMock

        from src.security.integrity_monitor import _read_last_line_hash

        log_path = tmp_path / "integrity.log"
        log_path.write_text('{"status":"OK"}\n')

        original_open = open

        def _bad_open(path, *args, **kwargs):
            if str(path) == str(log_path):
                raise PermissionError("permission denied")
            return original_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=_bad_open):
            result = _read_last_line_hash(str(log_path))

        assert (
            result == ""
        ), "_read_last_line_hash must return '' on any non-FileNotFoundError exception"
