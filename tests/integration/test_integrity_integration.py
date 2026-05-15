"""Integration tests for Phase 35a — Supply Chain & Configuration Integrity.

Integration tests use real temporary files to exercise:
- Sign a real temp file, verify it, corrupt byte-by-byte, verify returns False
- Background monitor with a real temp file: start monitor, modify file, assert
  violation counter increments within poll interval
- Audit log integration: write 5 entries, read them back, verify full hash chain

Key/sig format matches scripts/config-signer.py:
  - Keys: base64-encoded raw 32 bytes, one line + newline
  - Sig:  base64-encoded raw 64-byte Ed25519 signature, one line + newline

These tests require real filesystem access.
"""

import asyncio
import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helpers
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
# Signature verification integration
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSignAndVerifyIntegration:
    """Sign a real temp file and exercise various corruption scenarios."""

    def test_sign_verify_roundtrip_real_file(self, tmp_path):
        """Full sign→verify roundtrip with a real file and keys."""
        from src.security.integrity_monitor import IntegrityMonitor

        privkey, pubkey = _generate_keypair()
        config_file = tmp_path / "proxy.yml"
        config_file.write_text(
            "dial: 0\nlog_level: INFO\nredis:\n  host: localhost\n  port: 6379\n"
        )
        sig_path = tmp_path / "proxy.yml.sig"
        _sign_file(privkey, config_file, sig_path)

        pubkey_path = tmp_path / "pubkey.pem"
        _write_pubkey_raw(pubkey, pubkey_path)

        monitor = IntegrityMonitor()
        assert (
            monitor.verify_config_signature(str(config_file), str(pubkey_path)) is True
        )

    def test_corrupt_single_byte_fails_verification(self, tmp_path):
        """Corrupting any single byte in the config makes verification return False."""
        from src.security.integrity_monitor import IntegrityMonitor

        privkey, pubkey = _generate_keypair()
        config_file = tmp_path / "proxy.yml"
        original_content = b"dial: 0\nlog_level: INFO\n"
        config_file.write_bytes(original_content)
        sig_path = tmp_path / "proxy.yml.sig"
        _sign_file(privkey, config_file, sig_path)

        pubkey_path = tmp_path / "pubkey.pem"
        _write_pubkey_raw(pubkey, pubkey_path)

        monitor = IntegrityMonitor()

        # Try corrupting each byte position in the content
        corruption_detected = True
        for byte_pos in range(len(original_content)):
            corrupted = bytearray(original_content)
            corrupted[byte_pos] ^= 0x01  # Flip one bit
            config_file.write_bytes(bytes(corrupted))

            result = monitor.verify_config_signature(str(config_file), str(pubkey_path))
            if result is not False:
                corruption_detected = False
                break

        assert (
            corruption_detected
        ), f"Corrupting byte at position {byte_pos} was not detected by verify_config_signature"

    def test_corrupt_sig_byte_by_byte_fails_verification(self, tmp_path):
        """Corrupting decoded signature bytes makes verification return False.

        We corrupt the raw Ed25519 signature bytes (before base64 encoding) so
        that the base64 in the .sig file is always valid — this isolates the
        Ed25519 verification failure from base64 decode errors and avoids the
        edge case where Python's b64decode silently discards a corrupted trailing
        byte and recovers the original valid signature.
        """
        import base64 as _base64

        from src.security.integrity_monitor import IntegrityMonitor

        privkey, pubkey = _generate_keypair()
        config_file = tmp_path / "proxy.yml"
        config_file.write_text("dial: 0\n")
        sig_path = tmp_path / "proxy.yml.sig"
        _sign_file(privkey, config_file, sig_path)

        # Decode the stored signature to get raw 64 bytes
        original_sig_bytes = _base64.b64decode(sig_path.read_bytes().strip())
        assert len(original_sig_bytes) == 64

        pubkey_path = tmp_path / "pubkey.pem"
        _write_pubkey_raw(pubkey, pubkey_path)

        monitor = IntegrityMonitor()

        # Corrupt first, middle, and last byte of the decoded 64-byte signature
        for byte_pos in [0, len(original_sig_bytes) // 2, len(original_sig_bytes) - 1]:
            corrupted = bytearray(original_sig_bytes)
            corrupted[byte_pos] ^= 0xFF
            # Re-encode so the .sig file has valid base64, wrong signature value
            sig_path.write_bytes(_base64.b64encode(bytes(corrupted)) + b"\n")

            result = monitor.verify_config_signature(str(config_file), str(pubkey_path))
            assert (
                result is False
            ), f"Expected False when decoded sig byte {byte_pos} is corrupted, got {result}"


# ---------------------------------------------------------------------------
# Background monitor integration
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestBackgroundMonitorIntegration:
    """Integration tests for the background integrity monitor."""

    def test_monitor_detects_change_within_poll_interval(self, tmp_path):
        """Monitor detects file modification and increments violation counter."""
        from prometheus_client import REGISTRY

        # Clean any pre-existing integrity counters
        for name, collector in list(REGISTRY._names_to_collectors.items()):
            if "integrity_violation" in name:
                try:
                    REGISTRY.unregister(collector)
                except Exception:
                    pass

        from src.security.integrity_monitor import IntegrityMonitor

        watched_file = tmp_path / "proxy.py"
        watched_file.write_text("# stable proxy code\n")

        monitor = IntegrityMonitor()

        async def run_monitor_test():
            task = asyncio.create_task(
                monitor.start_background_monitor(
                    paths=[str(watched_file)],
                    interval_s=0.05,  # Very fast polling for tests
                )
            )

            # Let it establish baseline checksum
            await asyncio.sleep(0.12)
            before = monitor.violation_counter._value.get()

            # Modify the watched file
            watched_file.write_text("# TAMPERED proxy code\nimport evil_module\n")

            # Wait for next poll cycle
            await asyncio.sleep(0.15)
            after = monitor.violation_counter._value.get()

            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

            return before, after

        before, after = _run(run_monitor_test())
        assert after > before, (
            f"Violation counter should increment after file modification. "
            f"Before: {before}, After: {after}"
        )

    def test_monitor_watches_directory_tree(self, tmp_path):
        """Monitor can watch a list of paths including paths in subdirectories."""
        from src.security.integrity_monitor import IntegrityMonitor

        src_dir = tmp_path / "src" / "security"
        src_dir.mkdir(parents=True)

        files = [
            tmp_path / "proxy.py",
            src_dir / "pipeline.py",
            src_dir / "risk_scorer.py",
        ]
        for f in files:
            f.write_text(f"# original content of {f.name}\n")

        monitor = IntegrityMonitor()

        async def run_test():
            task = asyncio.create_task(
                monitor.start_background_monitor(
                    paths=[str(f) for f in files],
                    interval_s=0.05,
                )
            )
            await asyncio.sleep(0.12)
            before = monitor.violation_counter._value.get()

            # Modify the deepest file
            files[-1].write_text("# risk_scorer.py COMPROMISED\n")
            await asyncio.sleep(0.15)
            after = monitor.violation_counter._value.get()

            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

            return before, after

        before, after = _run(run_test())
        assert after > before, "Modification in nested file must be detected"

    def test_monitor_survives_file_deletion_and_recreation(self, tmp_path):
        """Monitor does not crash when a watched file is deleted then recreated."""
        from src.security.integrity_monitor import IntegrityMonitor

        watched_file = tmp_path / "proxy.py"
        watched_file.write_text("# original\n")

        monitor = IntegrityMonitor()
        exceptions_raised = []

        async def run_test():
            task = asyncio.create_task(
                monitor.start_background_monitor(
                    paths=[str(watched_file)],
                    interval_s=0.05,
                )
            )
            await asyncio.sleep(0.1)

            # Delete the file
            watched_file.unlink()
            await asyncio.sleep(0.1)

            # Recreate with different content
            watched_file.write_text("# recreated with different content\n")
            await asyncio.sleep(0.1)

            # Check the task is still alive
            if task.done() and not task.cancelled():
                try:
                    task.result()  # Re-raise exception if any
                except Exception as exc:
                    exceptions_raised.append(exc)

            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        _run(run_test())

        assert (
            not exceptions_raised
        ), f"Background monitor raised an exception: {exceptions_raised[0]}"


# ---------------------------------------------------------------------------
# Audit log integration
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAuditLogIntegration:
    """Integration tests for the cryptographic audit log."""

    def test_five_entries_full_hash_chain_valid(self, tmp_path):
        """Write 5 audit log entries and verify the entire hash chain is valid."""
        from src.security.integrity_monitor import IntegrityMonitor

        log_path = tmp_path / "integrity.log"
        monitor = IntegrityMonitor()

        entries = [
            {"status": "OK", "detail": "startup signature check passed"},
            {"status": "OK", "detail": "scheduled integrity check passed"},
            {"status": "FAIL", "detail": "proxy.py checksum mismatch"},
            {"status": "OK", "detail": "recovery: file restored to known-good hash"},
            {"status": "OK", "detail": "scheduled integrity check passed"},
        ]

        for entry in entries:
            monitor.append_audit_log(str(log_path), **entry)

        lines = log_path.read_text().strip().splitlines()
        assert len(lines) == 5, f"Expected 5 log lines, got {len(lines)}"

        # Validate chain integrity from genesis to end
        first_entry = json.loads(lines[0])
        assert first_entry["prev_hash"] == "", "First entry must have prev_hash=''"

        for i in range(1, 5):
            prev_raw = lines[i - 1]
            expected_prev_hash = hashlib.sha256(prev_raw.encode()).hexdigest()
            current_entry = json.loads(lines[i])
            assert current_entry["prev_hash"] == expected_prev_hash, (
                f"Hash chain broken at entry {i}: "
                f"expected prev_hash={expected_prev_hash!r}, "
                f"got {current_entry['prev_hash']!r}"
            )

    def test_all_entries_contain_required_fields(self, tmp_path):
        """Every audit log entry has timestamp, status, detail, and prev_hash."""
        from src.security.integrity_monitor import IntegrityMonitor

        log_path = tmp_path / "integrity.log"
        monitor = IntegrityMonitor()

        for i in range(3):
            monitor.append_audit_log(str(log_path), status="OK", detail=f"check-{i}")

        lines = log_path.read_text().strip().splitlines()
        for i, line in enumerate(lines):
            entry = json.loads(line)
            assert "timestamp" in entry, f"Entry {i} missing 'timestamp'"
            assert "status" in entry, f"Entry {i} missing 'status'"
            assert "detail" in entry, f"Entry {i} missing 'detail'"
            assert "prev_hash" in entry, f"Entry {i} missing 'prev_hash'"

    def test_audit_log_entries_are_append_only(self, tmp_path):
        """Writing entries in batches produces identical results as one session."""
        from src.security.integrity_monitor import IntegrityMonitor

        log_path = tmp_path / "integrity.log"
        monitor = IntegrityMonitor()

        # Write 2 entries in first session
        monitor.append_audit_log(str(log_path), status="OK", detail="entry-0")
        monitor.append_audit_log(str(log_path), status="OK", detail="entry-1")

        # Write 2 more entries (simulating a new monitor instance)
        monitor2 = IntegrityMonitor()
        monitor2.append_audit_log(str(log_path), status="OK", detail="entry-2")
        monitor2.append_audit_log(str(log_path), status="FAIL", detail="entry-3")

        lines = log_path.read_text().strip().splitlines()
        assert len(lines) == 4, f"Expected 4 entries total, got {len(lines)}"

        # Verify all 4 entries are correct
        for i, (line, expected_detail) in enumerate(
            zip(lines, ["entry-0", "entry-1", "entry-2", "entry-3"])
        ):
            entry = json.loads(line)
            assert (
                entry["detail"] == expected_detail
            ), f"Entry {i}: expected detail={expected_detail!r}, got {entry['detail']!r}"

    def test_audit_log_chain_tamper_detection(self, tmp_path):
        """Demonstrates tamper detection: changing entry N breaks chain from N+1 onwards."""
        from src.security.integrity_monitor import IntegrityMonitor

        log_path = tmp_path / "integrity.log"
        monitor = IntegrityMonitor()

        for i in range(4):
            monitor.append_audit_log(str(log_path), status="OK", detail=f"check-{i}")

        lines = log_path.read_text().strip().splitlines()

        # Tamper entry at index 1
        entry1 = json.loads(lines[1])
        original_detail = entry1["detail"]
        entry1["detail"] = "TAMPERED by attacker"
        entry1["status"] = "OK"  # Attacker tries to hide the change
        lines[1] = json.dumps(entry1)
        log_path.write_text("\n".join(lines) + "\n")

        # Re-read and check chain validity
        lines = log_path.read_text().strip().splitlines()

        # Entry 2's prev_hash was computed from the ORIGINAL line 1
        actual_hash_of_tampered_line1 = hashlib.sha256(lines[1].encode()).hexdigest()
        entry2 = json.loads(lines[2])

        # The stored prev_hash should NOT match the hash of the tampered entry
        assert entry2["prev_hash"] != actual_hash_of_tampered_line1, (
            "Hash chain did not detect tampering: "
            "entry 2's prev_hash matches tampered entry 1's hash"
        )

    def test_status_field_preserved_accurately(self, tmp_path):
        """The status field accurately reflects what was passed to append_audit_log."""
        from src.security.integrity_monitor import IntegrityMonitor

        log_path = tmp_path / "integrity.log"
        monitor = IntegrityMonitor()

        statuses = ["OK", "FAIL", "WARNING", "OK"]
        for i, status in enumerate(statuses):
            monitor.append_audit_log(str(log_path), status=status, detail=f"test-{i}")

        lines = log_path.read_text().strip().splitlines()
        for i, (line, expected_status) in enumerate(zip(lines, statuses)):
            entry = json.loads(line)
            assert (
                entry["status"] == expected_status
            ), f"Entry {i}: expected status={expected_status!r}, got {entry['status']!r}"
