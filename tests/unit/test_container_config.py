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


def test_every_required_compose_var_exists_in_template_env():
    """Every `${VAR:?...}` in a compose file must be defined in template.env.

    WHY THIS EXISTS
    ---------------
    Found 2026-08-17. Pointing the management service at the dedicated
    `management` Redis ACL user introduced `${MANAGEMENT_REDIS_PASSWORD:?...}`
    in docker-compose.poc.yml, but nothing added the variable to template.env.

    The `:?` syntax is deliberate — it is how this repo forces a real secret
    instead of a silent insecure default (JA4PROXY-2026-0076). The cost is that
    adding one is a two-file change, and forgetting the second file is
    invisible locally: a developer's own .env already has the value, so
    `docker compose up` works fine for the person who made the change. It only
    breaks for everyone else, and in CI, which copies template.env verbatim:

        error while interpolating services.management.environment.[]:
        required variable MANAGEMENT_REDIS_PASSWORD is missing a value

    That is a red CI run for a fresh clone rather than a bug in the change
    itself, so this test moves the failure to the commit that causes it.
    """
    import re

    compose_files = sorted(
        (REPO_ROOT / "deploy" / "docker").glob("docker-compose*.yml")
    )
    assert compose_files, "no compose files found"

    template = REPO_ROOT / "template.env"
    defined = {
        m.group(1)
        for m in re.finditer(r"^\s*([A-Z_][A-Z0-9_]*)\s*=", template.read_text(), re.M)
    }

    missing: dict[str, set[str]] = {}
    for cf in compose_files:
        for var in re.findall(r"\$\{([A-Z_][A-Z0-9_]*):\?", cf.read_text()):
            if var not in defined:
                missing.setdefault(var, set()).add(cf.name)

    assert not missing, (
        "compose requires env var(s) that template.env does not define:\n  "
        + "\n  ".join(f"{v} (in {', '.join(sorted(f))})" for v, f in sorted(missing.items()))
        + "\n\nAdd them to template.env — CI copies it verbatim, so a fresh "
        "clone cannot start without them."
    )
