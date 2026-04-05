#!/usr/bin/env python3
"""config-signer.py — Ed25519 signing utility for JA4proxy configuration files.

Usage
-----
  # Generate keypair (once):
  python3 scripts/config-signer.py genkey

  # Sign a file:
  python3 scripts/config-signer.py sign config/proxy.yml

  # Verify a file's signature:
  python3 scripts/config-signer.py verify config/proxy.yml

  # Override default key paths:
  python3 scripts/config-signer.py sign config/proxy.yml \\
      --privkey /path/to/private.key --pubkey /path/to/public.pub

Key storage
-----------
  Private key : config/keys/integrity.key  (permissions: 0o600)
  Public key  : config/keys/integrity.pub  (permissions: 0o644)

Both files store the raw 32-byte key encoded as base64 (one line, no PEM
wrapper) so they are portable and easy to inspect.

Signature format
----------------
Signatures are written to ``<target_file>.sig`` as a single base64-encoded
line (no newline inside the encoding) followed by a newline.  The signature
is over the raw bytes of the target file.
"""

import argparse
import base64
import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_PRIVKEY = Path("config/keys/integrity.key")
DEFAULT_PUBKEY = Path("config/keys/integrity.pub")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_cryptography() -> None:
    """Exit with an informative message if cryptography is not installed."""
    try:
        import cryptography  # noqa: F401
    except ImportError:
        print(
            "ERROR: The 'cryptography' package is required.\n"
            "  pip install cryptography",
            file=sys.stderr,
        )
        sys.exit(2)


def _generate_keypair(privkey_path: Path, pubkey_path: Path) -> None:
    """Generate a new Ed25519 keypair and save to disk."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    privkey_path.parent.mkdir(parents=True, exist_ok=True)
    pubkey_path.parent.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Export raw 32-byte keys and store as base64
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    priv_raw = private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    pub_raw = public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )

    _write_key(privkey_path, base64.b64encode(priv_raw), mode=0o600)
    _write_key(pubkey_path, base64.b64encode(pub_raw), mode=0o644)

    print("Generated keypair:")
    print(f"  Private key : {privkey_path}")
    print(f"  Public key  : {pubkey_path}")


def _write_key(path: Path, data: bytes, mode: int) -> None:
    """Write *data* to *path* atomically with the correct permissions.

    Uses ``os.open`` with ``O_CREAT|O_EXCL`` so that the file is created
    with *mode* in a single syscall — eliminating the TOCTOU window that
    would exist between ``write_bytes`` and a subsequent ``os.chmod``.
    Raises ``FileExistsError`` if *path* already exists (caller must check).
    """
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.write(fd, data + b"\n")
    finally:
        os.close(fd)


def _load_private_key(privkey_path: Path):
    """Load an Ed25519 private key from a base64-encoded file."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    raw_b64 = privkey_path.read_bytes().strip()
    raw = base64.b64decode(raw_b64)
    if len(raw) != 32:
        print(
            f"ERROR: Private key in {privkey_path} must be exactly 32 bytes "
            f"(got {len(raw)})",
            file=sys.stderr,
        )
        sys.exit(1)
    return Ed25519PrivateKey.from_private_bytes(raw)


def _load_public_key(pubkey_path: Path):
    """Load an Ed25519 public key from a base64-encoded file."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    raw_b64 = pubkey_path.read_bytes().strip()
    raw = base64.b64decode(raw_b64)
    if len(raw) != 32:
        print(
            f"ERROR: Public key in {pubkey_path} must be exactly 32 bytes "
            f"(got {len(raw)})",
            file=sys.stderr,
        )
        sys.exit(1)
    return Ed25519PublicKey.from_public_bytes(raw)


def _sign_file(target: Path, privkey_path: Path, pubkey_path: Path) -> None:
    """Sign *target* with the private key at *privkey_path*."""
    if not privkey_path.exists():
        print(
            f"ERROR: Private key not found: {privkey_path}\n"
            "  Run: python3 scripts/config-signer.py genkey",
            file=sys.stderr,
        )
        sys.exit(1)

    data = target.read_bytes()
    private_key = _load_private_key(privkey_path)
    signature = private_key.sign(data)
    sig_path = Path(str(target) + ".sig")
    sig_path.write_bytes(base64.b64encode(signature) + b"\n")
    print(f"Signed {target} -> {sig_path}")


def _verify_file(target: Path, pubkey_path: Path) -> bool:
    """Verify the signature for *target*.

    Returns True on success, False on failure.  Exits 0 or 1 accordingly.
    """
    from cryptography.exceptions import InvalidSignature

    sig_path = Path(str(target) + ".sig")
    if not sig_path.exists():
        print(f"ERROR: Signature file not found: {sig_path}", file=sys.stderr)
        return False

    if not pubkey_path.exists():
        print(f"ERROR: Public key not found: {pubkey_path}", file=sys.stderr)
        return False

    try:
        data = target.read_bytes()
        sig_b64 = sig_path.read_bytes().strip()
        signature = base64.b64decode(sig_b64)
        public_key = _load_public_key(pubkey_path)
        public_key.verify(signature, data)
        print(f"OK: {target} — signature valid")
        return True
    except InvalidSignature:
        print(f"FAIL: {target} — signature INVALID", file=sys.stderr)
        return False
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="config-signer",
        description="Ed25519 signing utility for JA4proxy configuration files.",
    )
    parser.add_argument(
        "--privkey",
        type=Path,
        default=DEFAULT_PRIVKEY,
        metavar="PATH",
        help=f"Private key path (default: {DEFAULT_PRIVKEY})",
    )
    parser.add_argument(
        "--pubkey",
        type=Path,
        default=DEFAULT_PUBKEY,
        metavar="PATH",
        help=f"Public key path (default: {DEFAULT_PUBKEY})",
    )

    subs = parser.add_subparsers(dest="command", required=True)

    # genkey
    subs.add_parser(
        "genkey",
        help="Generate a new Ed25519 keypair (skips if files already exist).",
    )

    # sign
    sign_p = subs.add_parser("sign", help="Sign a file.")
    sign_p.add_argument("file", type=Path, metavar="FILE", help="File to sign.")

    # verify
    verify_p = subs.add_parser("verify", help="Verify a file's signature.")
    verify_p.add_argument(
        "file", type=Path, metavar="FILE", help="File to verify."
    )

    return parser


def main() -> None:
    _require_cryptography()
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "genkey":
        if args.privkey.exists() or args.pubkey.exists():
            print(
                f"Keys already exist ({args.privkey}, {args.pubkey}). "
                "Delete them first to regenerate.",
            )
            sys.exit(0)
        _generate_keypair(args.privkey, args.pubkey)

    elif args.command == "sign":
        if not args.file.exists():
            print(f"ERROR: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        _sign_file(args.file, args.privkey, args.pubkey)

    elif args.command == "verify":
        if not args.file.exists():
            print(f"ERROR: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        ok = _verify_file(args.file, args.pubkey)
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
