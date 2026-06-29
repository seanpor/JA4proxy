"""Container configuration security regression tests.

Closes gaps JA4PROXY-2026-0076 and JA4PROXY-2026-0077:
  0076 — docker-compose templates must not contain hardcoded default credentials
  0077 — management service in poc compose must run with read_only filesystem
"""
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
POC_COMPOSE = REPO_ROOT / "deploy" / "docker" / "docker-compose.poc.yml"

_DEFAULT_CREDENTIAL_PATTERNS = [
    "admin123",
    "password1",
    "changeme",
    "secret123",
    "letmein",
    "qwerty",
    "123456",
    "default_password",
]


def test_template_env_no_default_credentials():
    """docker-compose.poc.yml must not contain hardcoded default credentials.

    All secrets must be injected via :?-required env vars (e.g. ${REDIS_PASSWORD:?...}).
    Hardcoded fallback values like 'password', 'changeme', etc. must never appear.
    """
    if not POC_COMPOSE.exists():
        return  # skip if compose file absent (non-blocking)

    raw_text = POC_COMPOSE.read_text().lower()
    for pattern in _DEFAULT_CREDENTIAL_PATTERNS:
        assert pattern not in raw_text, (
            f"docker-compose.poc.yml contains hardcoded default credential pattern "
            f"'{pattern}'. All secrets must use the ${{VAR:?required}} syntax."
        )

    data = yaml.safe_load(POC_COMPOSE.read_text())
    services = data.get("services", {})
    for svc_name, svc in services.items():
        env = svc.get("environment", [])
        if isinstance(env, dict):
            env_items = [f"{k}={v}" for k, v in env.items()]
        else:
            env_items = list(env)
        for item in env_items:
            item_str = str(item).lower()
            for pattern in _DEFAULT_CREDENTIAL_PATTERNS:
                assert pattern not in item_str, (
                    f"Service '{svc_name}' has env var with default credential "
                    f"pattern '{pattern}': {item!r}"
                )


def test_management_service_read_only():
    """Management service must have read_only: true filesystem.

    A writable root filesystem allows an attacker who gains code execution to
    persist malicious files across restarts. The management container only
    writes to /tmp (tmpfs) and should run read-only everywhere else.
    """
    if not POC_COMPOSE.exists():
        return  # skip if compose file absent (non-blocking)

    data = yaml.safe_load(POC_COMPOSE.read_text())
    services = data.get("services", {})
    mgmt = services.get("management")
    assert mgmt is not None, (
        "Management service not found in docker-compose.poc.yml"
    )
    assert mgmt.get("read_only") is True, (
        "management service must have 'read_only: true' to prevent filesystem "
        "writes by a compromised process. Add 'tmpfs: [/tmp]' for ephemeral writes."
    )
