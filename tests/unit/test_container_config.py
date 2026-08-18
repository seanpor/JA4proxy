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


def test_lint_docker_injects_every_required_var_it_validates():
    """`make lint`'s compose validation must supply every `${VAR:?}` it hits.

    WHY THIS EXISTS
    ---------------
    Sibling of the template.env guard above, and the second half of the same
    2026-08-17 break. `lint-docker` runs `docker compose config` with an inline
    list of `VAR=lint-placeholder` assignments per compose file, because the
    `:?` syntax would otherwise refuse to validate without real secrets.

    That list is a THIRD place a new required variable has to be registered
    (compose file, template.env, here). Missing it fails only in CI: the Full
    Lint job never creates a .env, whereas any developer running `make lint`
    locally has a real .env that docker compose picks up automatically — so the
    target passes for the author and fails for everyone else.
    """
    import re

    makefile = (REPO_ROOT / "Makefile").read_text()
    body = re.search(r"^lint-docker:.*?(?=^\w[\w-]*:)", makefile, re.M | re.S)
    assert body, "lint-docker target not found in Makefile"
    recipe = body.group(0)

    injected = set(re.findall(r"([A-Z_][A-Z0-9_]*)=lint-placeholder", recipe))

    missing: dict[str, set[str]] = {}
    for line in recipe.splitlines():
        for cf_name in re.findall(r"deploy/docker/(docker-compose[\w.]*\.yml)", line):
            cf = REPO_ROOT / "deploy" / "docker" / cf_name
            if not cf.is_file():
                continue
            for var in re.findall(r"\$\{([A-Z_][A-Z0-9_]*):\?", cf.read_text()):
                if var not in injected:
                    missing.setdefault(var, set()).add(cf_name)

    assert not missing, (
        "lint-docker validates compose file(s) requiring var(s) it does not "
        "inject:\n  "
        + "\n  ".join(f"{v} (needed by {', '.join(sorted(f))})" for v, f in sorted(missing.items()))
        + "\n\nAdd `VAR=lint-placeholder` to the matching line in the Makefile's "
        "lint-docker recipe, or CI's Full Lint job fails while local passes."
    )


def test_start_poc_generates_every_required_env_var():
    """`start-poc.sh` writes a fresh .env — it must cover every `${VAR:?}`.

    WHY THIS EXISTS
    ---------------
    The third sibling of the same 2026-08-17 break, and the one that got
    furthest: a required variable has to be registered in FIVE places (the
    compose file, template.env, the Makefile's lint-docker recipe, the compose
    validation test, and here). Adding ANALYTICS_HMAC_SECRET missed this one,
    and the failure surfaced first in the cold-start CI job — the only place
    without a pre-existing .env.

    NOTE: an earlier version of this docstring concluded from that symptom that
    "a brand-new clone cannot start the stack at all, while every existing
    checkout works fine". That is backwards, and the wrong half got the guard.
    A fresh clone is fine — start-poc.sh generates a complete .env. It is every
    EXISTING checkout that breaks, because that generator only runs when the
    file is absent, so a `git pull` adds a required variable that nothing ever
    writes into the .env already on disk. See
    tests/unit/test_env_upgrade_path.py, which guards that path; this test
    still guards the from-scratch one.
    """
    import re

    script = (REPO_ROOT / "scripts" / "start-poc.sh").read_text()
    # Only the generated heredoc counts; a mention in a comment is not a value.
    heredoc = re.search(r"cat > \.env << ?ENV_EOF\n(.*?)\nENV_EOF", script, re.S)
    assert heredoc, "could not find the .env heredoc in start-poc.sh"
    generated = set(re.findall(r"^([A-Z_][A-Z0-9_]*)=", heredoc.group(1), re.M))

    poc = REPO_ROOT / "deploy" / "docker" / "docker-compose.poc.yml"
    required = set(re.findall(r"\$\{([A-Z_][A-Z0-9_]*):\?", poc.read_text()))

    missing = required - generated
    assert not missing, (
        "start-poc.sh generates a .env that is missing required var(s): "
        f"{sorted(missing)}\n\nA fresh clone cannot start the stack — compose "
        "fails on the :? requirement. Add them to the heredoc in start-poc.sh."
    )
