"""
Atomic file swapping utilities for zero-downtime upgrades (Phase 42).
"""

import os
import shutil
import tempfile
from pathlib import Path


def atomic_write(data: bytes, target_path: Path):
    """
    Write data to a temporary file and rename it to the target path.
    On Unix, os.rename is atomic.
    """
    target_path = Path(target_path)
    temp_dir = target_path.parent
    with tempfile.NamedTemporaryFile(dir=temp_dir, delete=False) as tf:
        tf.write(data)
        temp_name = tf.name

    try:
        os.chmod(temp_name, 0o644)
        os.rename(temp_name, target_path)
    except Exception:
        if os.path.exists(temp_name):
            os.remove(temp_name)
        raise


def atomic_symlink_swap(target_symlink: Path, new_target_dir: Path):
    """
    Atomically swap a symlink to point to a new directory.
    Uses a temporary symlink and os.rename().
    """
    target_symlink = Path(target_symlink)
    new_target_dir = Path(new_target_dir)

    temp_symlink = target_symlink.parent / f"{target_symlink.name}.tmp"

    if temp_symlink.exists():
        temp_symlink.unlink()

    os.symlink(new_target_dir, temp_symlink)

    try:
        os.rename(temp_symlink, target_symlink)
    except Exception:
        if temp_symlink.exists():
            temp_symlink.unlink()
        raise
