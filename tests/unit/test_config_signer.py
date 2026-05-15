"""Unit tests for Phase 35a — scripts/config-signer.py CLI.

The config-signer.py script already exists with a known interface:
    config-signer.py [--privkey PATH] [--pubkey PATH] {genkey,sign,verify} FILE

Key format: base64-encoded raw 32 bytes (not PEM).
Sig format: base64-encoded raw 64-byte Ed25519 signature + newline.

Tests exercise:
- Running 'sign <file>' creates <file>.sig
- The .sig file decodes to a 64-byte valid Ed25519 signature
- Signed file can be verified by IntegrityMonitor.verify_config_signature
- Running sign twice overwrites the .sig file
- Signing a non-existent file exits with code 1
- Signing with missing key exits non-zero
- verify exits 0 for valid sig, non-zero for corrupted/missing sig
"""

import base64
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SCRIPTS_DIR = Path(__file__).parent.parent.parent / "scripts"
CONFIG_SIGNER = SCRIPTS_DIR / "config-signer.py"
REPO_ROOT = Path(__file__).parent.parent.parent


# ---------------------------------------------------------------------------
# Helpers — key format matches config-signer.py expectations
# ---------------------------------------------------------------------------


def _generate_keypair_files(directory: Path) -> tuple[Path, Path]:
    """Generate Ed25519 keypair in the format config-signer.py expects.

    Keys stored as base64-encoded raw 32 bytes (one line + newline), which is
    what config-signer.py writes with genkey and reads with _load_private_key /
    _load_public_key.
    """
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    privkey = Ed25519PrivateKey.generate()
    pubkey = privkey.public_key()

    privkey_path = directory / "signing.key"
    pubkey_path = directory / "signing.pub"

    priv_raw = privkey.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    pub_raw = pubkey.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )

    privkey_path.write_bytes(base64.b64encode(priv_raw) + b"\n")
    os.chmod(privkey_path, 0o600)
    pubkey_path.write_bytes(base64.b64encode(pub_raw) + b"\n")

    return privkey_path, pubkey_path


def _run_signer(*args, cwd=None) -> subprocess.CompletedProcess:
    """Run config-signer.py with the given args, return CompletedProcess."""
    return subprocess.run(
        [sys.executable, str(CONFIG_SIGNER)] + list(args),
        capture_output=True,
        text=True,
        cwd=str(cwd or REPO_ROOT),
    )


def _signer_sign(config_file: Path, privkey_path: Path) -> subprocess.CompletedProcess:
    """Run: config-signer.py --privkey <path> sign <file>"""
    return _run_signer("--privkey", str(privkey_path), "sign", str(config_file))


def _signer_verify(config_file: Path, pubkey_path: Path) -> subprocess.CompletedProcess:
    """Run: config-signer.py --pubkey <path> verify <file>"""
    return _run_signer("--pubkey", str(pubkey_path), "verify", str(config_file))


# ---------------------------------------------------------------------------
# sign subcommand
# ---------------------------------------------------------------------------


class TestConfigSignerSign:
    """Tests for: config-signer.py [--privkey PATH] sign FILE"""

    def test_sign_creates_sig_file(self, tmp_path):
        """Signing a file creates a corresponding .sig file in the same directory."""
        privkey_path, _ = _generate_keypair_files(tmp_path)
        config_file = tmp_path / "proxy.yml"
        config_file.write_text("dial: 0\n")

        result = _signer_sign(config_file, privkey_path)

        assert (
            result.returncode == 0
        ), f"config-signer.py exited {result.returncode}; stderr: {result.stderr}"
        sig_file = tmp_path / "proxy.yml.sig"
        assert sig_file.exists(), ".sig file was not created alongside config file"

    def test_sig_file_decodes_to_64_byte_signature(self, tmp_path):
        """The .sig file base64-decodes to 64 bytes — the Ed25519 signature size."""
        privkey_path, _ = _generate_keypair_files(tmp_path)
        config_file = tmp_path / "proxy.yml"
        config_file.write_text("dial: 0\n")

        result = _signer_sign(config_file, privkey_path)
        assert result.returncode == 0, f"Sign failed: {result.stderr}"

        sig_file = tmp_path / "proxy.yml.sig"
        sig_bytes = base64.b64decode(sig_file.read_bytes().strip())
        assert (
            len(sig_bytes) == 64
        ), f"Ed25519 signature should be 64 bytes after base64 decode, got {len(sig_bytes)}"

    def test_signed_file_verifiable_by_integrity_monitor(self, tmp_path):
        """A file signed by config-signer.py can be verified by IntegrityMonitor."""
        from src.security.integrity_monitor import IntegrityMonitor

        privkey_path, pubkey_path = _generate_keypair_files(tmp_path)
        config_file = tmp_path / "proxy.yml"
        config_file.write_text("dial: 0\nlog_level: INFO\n")

        result = _signer_sign(config_file, privkey_path)
        assert result.returncode == 0, f"Signing failed: {result.stderr}"

        monitor = IntegrityMonitor()
        verified = monitor.verify_config_signature(str(config_file), str(pubkey_path))
        assert (
            verified is True
        ), "IntegrityMonitor should verify a file signed by config-signer.py"

    def test_sign_twice_overwrites_sig_file(self, tmp_path):
        """Running sign twice with different file contents produces a different .sig."""
        privkey_path, pubkey_path = _generate_keypair_files(tmp_path)
        config_file = tmp_path / "proxy.yml"
        config_file.write_text("dial: 0\n")

        result1 = _signer_sign(config_file, privkey_path)
        assert result1.returncode == 0, f"First sign failed: {result1.stderr}"

        sig_file = tmp_path / "proxy.yml.sig"
        first_sig = sig_file.read_bytes()

        # Modify the file so the signature will differ
        config_file.write_text("dial: 50\n")

        result2 = _signer_sign(config_file, privkey_path)
        assert result2.returncode == 0, f"Second sign failed: {result2.stderr}"

        second_sig = sig_file.read_bytes()
        assert (
            second_sig != first_sig
        ), "Signing a modified file should produce a different .sig"

        # Verify the new sig is valid
        from src.security.integrity_monitor import IntegrityMonitor

        monitor = IntegrityMonitor()
        assert (
            monitor.verify_config_signature(str(config_file), str(pubkey_path)) is True
        )

    def test_sign_nonexistent_file_exits_code_1(self, tmp_path):
        """Signing a file that does not exist exits with return code 1."""
        privkey_path, _ = _generate_keypair_files(tmp_path)
        nonexistent = tmp_path / "doesnotexist.yml"

        result = _signer_sign(nonexistent, privkey_path)

        assert (
            result.returncode == 1
        ), f"Expected exit code 1 for missing file, got {result.returncode}"

    def test_sign_missing_key_exits_nonzero(self, tmp_path):
        """Signing with a missing private key file exits non-zero."""
        config_file = tmp_path / "proxy.yml"
        config_file.write_text("dial: 0\n")
        missing_key = tmp_path / "nosuchkey.key"

        result = _signer_sign(config_file, missing_key)

        assert (
            result.returncode != 0
        ), "Should fail with non-zero exit when key file is missing"

    def test_sign_produces_no_traceback_on_success(self, tmp_path):
        """Successful signing does not produce a Python traceback."""
        privkey_path, _ = _generate_keypair_files(tmp_path)
        config_file = tmp_path / "proxy.yml"
        config_file.write_text("dial: 0\n")

        result = _signer_sign(config_file, privkey_path)

        assert result.returncode == 0, f"Sign failed: {result.stderr}"
        assert "Traceback" not in result.stdout
        assert "Traceback" not in result.stderr

    def test_sig_file_is_cryptographically_valid(self, tmp_path):
        """The .sig file can be manually verified using the cryptography library."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        privkey_path, pubkey_path = _generate_keypair_files(tmp_path)
        config_file = tmp_path / "proxy.yml"
        original_content = b"dial: 0\nredis:\n  host: localhost\n"
        config_file.write_bytes(original_content)

        result = _signer_sign(config_file, privkey_path)
        assert result.returncode == 0, f"Sign failed: {result.stderr}"

        sig_file = tmp_path / "proxy.yml.sig"
        signature = base64.b64decode(sig_file.read_bytes().strip())

        # Load the public key in the same raw-base64 format
        pub_raw = base64.b64decode(pubkey_path.read_bytes().strip())
        public_key = Ed25519PublicKey.from_public_bytes(pub_raw)

        # This should not raise — meaning the signature is cryptographically valid
        try:
            public_key.verify(signature, original_content)
        except Exception as exc:
            pytest.fail(f"Signature did not verify: {exc}")


# ---------------------------------------------------------------------------
# verify subcommand
# ---------------------------------------------------------------------------


class TestConfigSignerVerify:
    """Tests for: config-signer.py [--pubkey PATH] verify FILE"""

    def test_verify_valid_sig_exits_zero(self, tmp_path):
        """Verifying a correctly signed file exits with code 0."""
        privkey_path, pubkey_path = _generate_keypair_files(tmp_path)
        config_file = tmp_path / "proxy.yml"
        config_file.write_text("dial: 0\n")

        sign_result = _signer_sign(config_file, privkey_path)
        assert sign_result.returncode == 0, f"Sign failed: {sign_result.stderr}"

        verify_result = _signer_verify(config_file, pubkey_path)
        assert verify_result.returncode == 0, (
            f"Verify of valid sig failed with code {verify_result.returncode}; "
            f"stderr: {verify_result.stderr}"
        )

    def test_verify_corrupted_sig_exits_nonzero(self, tmp_path):
        """Verifying a corrupted .sig file exits with non-zero code."""
        privkey_path, pubkey_path = _generate_keypair_files(tmp_path)
        config_file = tmp_path / "proxy.yml"
        config_file.write_text("dial: 0\n")

        sign_result = _signer_sign(config_file, privkey_path)
        assert sign_result.returncode == 0, f"Sign failed: {sign_result.stderr}"

        # Overwrite the .sig with garbage (not a valid base64 Ed25519 signature)
        sig_file = tmp_path / "proxy.yml.sig"
        sig_file.write_bytes(base64.b64encode(bytes([0xFF] * 64)) + b"\n")

        verify_result = _signer_verify(config_file, pubkey_path)
        assert (
            verify_result.returncode != 0
        ), "Verify of corrupted sig should exit non-zero"

    def test_verify_missing_sig_exits_nonzero(self, tmp_path):
        """Verifying when .sig file is absent exits with non-zero code."""
        _, pubkey_path = _generate_keypair_files(tmp_path)
        config_file = tmp_path / "proxy.yml"
        config_file.write_text("dial: 0\n")
        # No .sig file written

        verify_result = _signer_verify(config_file, pubkey_path)
        assert (
            verify_result.returncode != 0
        ), "Verify with absent .sig file should exit non-zero"

    def test_verify_modified_content_exits_nonzero(self, tmp_path):
        """Verify exits non-zero if the file was modified after signing."""
        privkey_path, pubkey_path = _generate_keypair_files(tmp_path)
        config_file = tmp_path / "proxy.yml"
        config_file.write_text("dial: 0\n")

        sign_result = _signer_sign(config_file, privkey_path)
        assert sign_result.returncode == 0

        # Modify file content after signing
        config_file.write_text("dial: 100\n")  # Changed!

        verify_result = _signer_verify(config_file, pubkey_path)
        assert (
            verify_result.returncode != 0
        ), "Verify should fail when file content was modified after signing"

    def test_verify_wrong_pubkey_exits_nonzero(self, tmp_path):
        """Verify exits non-zero when using a different public key than what signed."""
        privkey_path, _ = _generate_keypair_files(tmp_path)
        config_file = tmp_path / "proxy.yml"
        config_file.write_text("dial: 0\n")

        sign_result = _signer_sign(config_file, privkey_path)
        assert sign_result.returncode == 0

        # Generate a different keypair and use its public key for verification
        other_dir = tmp_path / "other"
        other_dir.mkdir(exist_ok=True)
        _, wrong_pubkey_path = _generate_keypair_files(other_dir)

        verify_result = _signer_verify(config_file, wrong_pubkey_path)
        assert (
            verify_result.returncode != 0
        ), "Verify should fail when the wrong public key is used"


# ---------------------------------------------------------------------------
# genkey subcommand
# ---------------------------------------------------------------------------


class TestConfigSignerGenkey:
    """Tests for: config-signer.py genkey"""

    def test_genkey_creates_key_files(self, tmp_path):
        """genkey creates config/keys/integrity.key and integrity.pub in cwd."""
        result = _run_signer("genkey", cwd=tmp_path)

        assert (
            result.returncode == 0
        ), f"genkey failed with code {result.returncode}; stderr: {result.stderr}"
        privkey_path = tmp_path / "config" / "keys" / "integrity.key"
        pubkey_path = tmp_path / "config" / "keys" / "integrity.pub"
        assert privkey_path.exists(), f"Private key not created at {privkey_path}"
        assert pubkey_path.exists(), f"Public key not created at {pubkey_path}"

    def test_genkey_key_is_valid_base64(self, tmp_path):
        """Generated key files contain valid base64 that decodes to 32 bytes."""
        result = _run_signer("genkey", cwd=tmp_path)
        assert result.returncode == 0, f"genkey failed: {result.stderr}"

        pubkey_path = tmp_path / "config" / "keys" / "integrity.pub"
        pub_raw = base64.b64decode(pubkey_path.read_bytes().strip())
        assert (
            len(pub_raw) == 32
        ), f"Ed25519 public key should be 32 bytes, got {len(pub_raw)}"

    def test_genkey_sets_correct_permissions_on_privkey(self, tmp_path):
        """genkey sets 0o600 permissions on the private key file."""
        result = _run_signer("genkey", cwd=tmp_path)
        assert result.returncode == 0

        privkey_path = tmp_path / "config" / "keys" / "integrity.key"
        mode = oct(privkey_path.stat().st_mode)[-3:]
        assert mode == "600", f"Private key should have mode 600, got {mode}"

    def test_genkey_does_not_overwrite_existing_keys(self, tmp_path):
        """Running genkey twice does not overwrite existing key files."""
        result1 = _run_signer("genkey", cwd=tmp_path)
        assert result1.returncode == 0

        privkey_path = tmp_path / "config" / "keys" / "integrity.key"
        original_content = privkey_path.read_bytes()

        result2 = _run_signer("genkey", cwd=tmp_path)
        # Should exit 0 with a "keys already exist" message, NOT overwrite
        assert result2.returncode == 0, f"Second genkey failed: {result2.stderr}"

        final_content = privkey_path.read_bytes()
        assert (
            final_content == original_content
        ), "genkey should not overwrite existing key files"

    def test_genkey_produces_no_traceback(self, tmp_path):
        """genkey does not produce a Python traceback."""
        result = _run_signer("genkey", cwd=tmp_path)
        assert "Traceback" not in result.stdout
        assert "Traceback" not in result.stderr
