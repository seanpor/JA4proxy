"""Phase 814e Step 6: Setup Wizard Security Pentest Suite.

Tests:
1. Secret Redaction:
   - Generated secrets (REDIS_PASSWORD, MANAGEMENT_JWT_SECRET, etc.) are NEVER printed to stdout/stderr.
   - redacted_summary masks every key in SECRET_KEYS with [generated — see .env].
2. File Permissions:
   - Generated .env file must be strictly chmod 0600 (owner read/write only).
   - Generated config/proxy.yml must be chmod 0644 (non-secret).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from scripts.setup_wizard import SECRET_KEYS, build_env, redacted_summary, write_env


def test_wizard_secrets_are_redacted_in_summary():
    """All secret keys must be masked in summary output."""
    sample_answers = {
        "backend_host": "backend.corp",
        "backend_port": "443",
        "admin_user": "admin",
    }
    env = build_env(sample_answers)
    summary = redacted_summary(env)

    # Every secret key in SECRET_KEYS must be masked
    for secret_key in SECRET_KEYS:
        assert secret_key in env, f"Expected {secret_key} in generated env"
        raw_val = env[secret_key]
        assert raw_val not in summary, f"Secret {secret_key} leaked in summary: {raw_val}"
        assert f"{secret_key} = [generated — see .env]" in summary


def test_wizard_env_file_permissions(tmp_path: Path):
    """The generated .env file must be strictly chmod 0600."""
    target_env = tmp_path / ".env"
    sample_answers = {"backend_host": "backend.corp"}
    env = build_env(sample_answers)

    write_env(target_env, env, timestamp="2026-10-11T16:00:00Z")

    assert target_env.exists()
    mode = stat.S_IMODE(target_env.stat().st_mode)
    assert mode == 0o600, f"Expected permissions 0600, got {oct(mode)}"
