"""
tests/integration/test_container_config.py — Phase 202 TDD (red)

Structural invariants for docker-compose files, workflow pinning, and
credential handling. These tests purposely fail on the current tree — they
encode the acceptance criteria in `docs/phases/PHASE_202.md`.

Design notes:
  * We parse the compose files as raw text (not via `docker compose config`)
    because `config` subst-expands env vars, which obscures whether the compose
    author wrote `${VAR:-default}` (bad) or `${VAR:?required}` (good).
  * For YAML-level structural checks (ports, command) we use `yaml.safe_load`.
  * Action-pinning test walks every `uses:` line under .github/workflows/ and
    enforces `<name>@<40-hex-SHA>` for ordinary actions. Reusable workflows
    from the `slsa-framework` org are explicitly allowlisted because GitHub's
    supply-chain docs permit tag-pinning trusted reusable workflows (see
    `docs/phases/PHASE_202.md` sub-phase 202a route (b)).
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEPLOY_DOCKER = REPO_ROOT / "deploy" / "docker"
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

POC_COMPOSE = DEPLOY_DOCKER / "docker-compose.poc.yml"
PROD_COMPOSE = DEPLOY_DOCKER / "docker-compose.prod.yml"
MONITORING_COMPOSE = DEPLOY_DOCKER / "docker-compose.monitoring.yml"
TEST_COMPOSE = DEPLOY_DOCKER / "docker-compose.test.yml"


# ── Credential fallback tests ────────────────────────────────────────────────


@pytest.mark.parametrize(
    "var_name",
    [
        "MANAGEMENT_JWT_SECRET",
        "MANAGEMENT_ADMIN_USER",
        "MANAGEMENT_ADMIN_PASSWORD",
    ],
)
def test_compose_poc_requires_management_secrets(var_name: str) -> None:
    """Every ${VAR...} reference to a management secret in poc compose must
    use the `:?` required syntax — never `:-` default-fallback, and never a
    bare `${VAR}` (which silently expands to the empty string)."""
    text = POC_COMPOSE.read_text()

    # Find every ${VAR...} reference for this var.
    pattern = re.compile(r"\$\{" + re.escape(var_name) + r"(:[^}]*)?\}")
    matches = pattern.findall(text)
    assert matches, (
        f"{var_name} not referenced at all in {POC_COMPOSE.name} — "
        f"expected at least one ${{ {var_name}:? }} reference"
    )

    bad_default = re.compile(r"\$\{" + re.escape(var_name) + r":-[^}]*\}")
    bad = bad_default.findall(text)
    assert not bad, (
        f"{var_name} uses default-fallback syntax `${{VAR:-default}}` in "
        f"{POC_COMPOSE.name}: {bad!r}. Must use `${{VAR:?message}}` to force "
        f"operators to set it explicitly."
    )

    # Every reference must use `:?` required-syntax (not `:-`, not bare).
    # `matches` contains the group-1 capture (the `:...` suffix or empty).
    # A bare `${VAR}` yields suffix == "" — reject it.
    non_required = [m for m in matches if not m.startswith(":?")]
    assert not non_required, (
        f"{var_name} has {len(non_required)} reference(s) in {POC_COMPOSE.name} "
        f"that are NOT `${{VAR:?message}}` required-syntax (suffixes={non_required!r}). "
        f"A bare `${{VAR}}` silently expands to empty — use `${{VAR:?required}}`."
    )


@pytest.mark.parametrize(
    "var_name",
    [
        "GRAFANA_PASSWORD",
        "HAPROXY_STATS_USER",
        "HAPROXY_STATS_PASSWORD",
    ],
)
def test_compose_monitoring_requires_credentials(var_name: str) -> None:
    """Monitoring stack must not ship with default admin/admin123 creds and
    must not use bare `${VAR}` (silently expands to empty)."""
    text = MONITORING_COMPOSE.read_text()

    pattern = re.compile(r"\$\{" + re.escape(var_name) + r"(:[^}]*)?\}")
    matches = pattern.findall(text)
    assert matches, f"{var_name} not referenced at all in {MONITORING_COMPOSE.name}"

    bad_default = re.compile(r"\$\{" + re.escape(var_name) + r":-[^}]*\}")
    bad = bad_default.findall(text)
    assert not bad, (
        f"{var_name} uses default-fallback syntax in "
        f"{MONITORING_COMPOSE.name}: {bad!r}. Must use `${{VAR:?message}}`."
    )

    non_required = [m for m in matches if not m.startswith(":?")]
    assert not non_required, (
        f"{var_name} has {len(non_required)} reference(s) in "
        f"{MONITORING_COMPOSE.name} that are not `${{VAR:?message}}` required-"
        f"syntax (suffixes={non_required!r}). A bare `${{VAR}}` silently "
        f"expands to empty — use `${{VAR:?required}}`."
    )


def test_no_default_admin_fallbacks_anywhere() -> None:
    """Across all deploy/docker/ files, the well-known weak defaults
    (`admin`, `admin123`, `change-me`) must not appear as compose
    ${VAR:-default} fallbacks."""
    forbidden = re.compile(r":-(admin|admin123|change-me[-\w]*)")
    offenders: list[tuple[str, int, str]] = []
    for path in sorted(DEPLOY_DOCKER.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix not in {".yml", ".yaml"}:
            continue
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            if forbidden.search(line):
                offenders.append(
                    (str(path.relative_to(REPO_ROOT)), lineno, line.strip())
                )
    assert (
        not offenders
    ), "Weak default credential fallbacks found in deploy/docker/:\n" + "\n".join(
        f"  {p}:{n}: {ln}" for p, n, ln in offenders
    )


# ── Test-Redis hardening ─────────────────────────────────────────────────────


def _find_redis_test_service(compose: dict) -> tuple[str, dict]:
    """Locate the Redis service in the test compose file.

    The service is conventionally called `redis` or `redis-test`. We identify
    it by (a) a well-known name or (b) the image starting with `redis:`.
    """
    services = compose.get("services", {}) or {}
    for name, svc in services.items():
        if name in {"redis", "redis-test"}:
            return name, svc
        image = (svc or {}).get("image", "") or ""
        if image.startswith("redis:"):
            return name, svc
    raise AssertionError(
        f"No redis service found in {TEST_COMPOSE.name}; "
        f"services present: {list(services)}"
    )


def test_test_redis_bound_to_loopback() -> None:
    """Test Redis must only bind to 127.0.0.1 — never 0.0.0.0 / all-interfaces.

    Exposing an unauthenticated Redis on an all-interfaces host port on a
    laptop or CI runner is a well-known attack surface.
    """
    compose = yaml.safe_load(TEST_COMPOSE.read_text()) or {}
    _, svc = _find_redis_test_service(compose)
    ports = svc.get("ports") or []
    assert ports, (
        "redis service in test compose has no `ports:` block; "
        "expected an explicit 127.0.0.1-bound mapping."
    )
    for entry in ports:
        # Short-form string mapping: "HOST_IP:HOST_PORT:CONTAINER_PORT" or
        # "HOST_PORT:CONTAINER_PORT". Long-form dict: {published, host_ip, ...}.
        if isinstance(entry, str):
            assert entry.startswith("127.0.0.1:"), (
                f"redis ports entry {entry!r} is not bound to loopback. "
                f"Use `127.0.0.1:HOST:CONTAINER` format."
            )
        elif isinstance(entry, dict):
            host_ip = entry.get("host_ip")
            assert (
                host_ip == "127.0.0.1"
            ), f"redis ports entry {entry!r} lacks host_ip=127.0.0.1."
        else:
            raise AssertionError(
                f"Unexpected ports entry type {type(entry)}: {entry!r}"
            )


def test_test_redis_has_password() -> None:
    """Test Redis must set REDIS_PASSWORD to a non-empty value AND pass
    `--requirepass` to `redis-server` so auth is actually enforced."""
    compose = yaml.safe_load(TEST_COMPOSE.read_text()) or {}
    name, svc = _find_redis_test_service(compose)

    # 1. Password is set (env block, list or dict form).
    env = svc.get("environment") or {}
    if isinstance(env, list):
        env_dict = {}
        for item in env:
            if "=" in item:
                k, _, v = item.partition("=")
                env_dict[k] = v
        env = env_dict
    password = env.get("REDIS_PASSWORD")
    assert password, (
        f"redis service {name!r} in {TEST_COMPOSE.name} has no REDIS_PASSWORD "
        f"environment variable (or it is empty). Set it to "
        f"`${{REDIS_TEST_PASSWORD:-test-fixtures-pw}}` or similar."
    )
    assert password.strip() not in {
        '""',
        "''",
    }, f"redis service {name!r} REDIS_PASSWORD is literally empty: {password!r}"

    # 2. `--requirepass` is passed to redis-server via `command:`.
    command = svc.get("command")
    if isinstance(command, list):
        cmd_str = " ".join(str(c) for c in command)
    else:
        cmd_str = str(command or "")
    assert "--requirepass" in cmd_str, (
        f"redis service {name!r} command does not include `--requirepass`; "
        f"command={command!r}. REDIS_PASSWORD env var alone does NOT enable "
        f"auth — redis-server must be started with `--requirepass`."
    )

    # The password the server *requires* must be derived from the same source
    # as the password the env block *advertises* — otherwise clients and
    # server silently drift. We enforce this by requiring both to reference
    # the same `${REDIS_TEST_PASSWORD...}` token.
    env_refs = re.findall(r"\$\{REDIS_TEST_PASSWORD[^}]*\}", password)
    cmd_refs = re.findall(r"\$\{REDIS_TEST_PASSWORD[^}]*\}", cmd_str)
    assert env_refs and cmd_refs, (
        f"redis service {name!r} does not reference `${{REDIS_TEST_PASSWORD...}}` "
        f"in both env and command (env_refs={env_refs!r} cmd_refs={cmd_refs!r}). "
        f"They must share a single source-of-truth token."
    )
    assert env_refs == cmd_refs, (
        f"redis service {name!r} REDIS_PASSWORD env and --requirepass command "
        f"reference different tokens: env={env_refs!r} cmd={cmd_refs!r}. "
        f"They must be identical — otherwise clients will fail to authenticate."
    )


# ── Network topology & host-port exposure (phase-232c) ───────────────────────


def _service_networks(svc: dict | None) -> list[str]:
    """Return the list of networks a compose service is attached to.

    The `networks:` key may be a list (`[a, b]`) or a mapping
    (`{a: {...}, b: {...}}`); normalise both to a list of names.
    """
    nets = (svc or {}).get("networks") or []
    if isinstance(nets, dict):
        return list(nets.keys())
    return list(nets)


def test_poc_analytics_shares_redis_data_network() -> None:
    """The POC `analytics` service must share a network with `redis`.

    Redis is attached only to the internal `ja4proxy-data` network. If the
    analytics container is not also on that network, the `redis` hostname does
    not resolve and the analytics node cannot read the events stream or write
    findings. The `management` and `admin-api` services are correctly on both
    `ja4proxy-mgmt` and `ja4proxy-data` — analytics must match (phase-232c).
    """
    compose = yaml.safe_load(POC_COMPOSE.read_text()) or {}
    services = compose.get("services", {}) or {}

    redis_nets = set(_service_networks(services.get("redis")))
    analytics_nets = set(_service_networks(services.get("analytics")))

    assert redis_nets, "poc redis service declares no networks"
    assert analytics_nets, "poc analytics service declares no networks"

    shared = redis_nets & analytics_nets
    assert shared, (
        f"poc analytics (networks={sorted(analytics_nets)}) shares NO network "
        f"with redis (networks={sorted(redis_nets)}); the `redis` hostname will "
        f"not resolve. Attach analytics to the shared data network "
        f"(ja4proxy-data)."
    )


# Internal services whose host ports were removed in Phase 0046 (proxy
# metrics/health, analytics HTTP, tarpit metrics). Prometheus and the proxy
# reach them over the compose network, so they need no host publishing at all
# and must never be republished on a wildcard / public interface. (haproxy's
# 443/80 are intentionally public and are deliberately excluded.)
_PROD_INTERNAL_SERVICES = ("proxy", "analytics", "tarpit")


def _leading_host_ip(port_str: str) -> str:
    """Host-IP field of a compose ``HOST_IP:PUBLISHED:TARGET`` short-form string.

    Returns ``""`` when the entry has no host-IP field (``PUBLISHED:TARGET``),
    which means Docker binds it on all interfaces (0.0.0.0). Brace-aware so a
    ``${VAR:-127.0.0.1}:80:80`` default is not split on its inner colon.
    """
    fields: list[str] = []
    depth = 0
    cur = ""
    for ch in port_str:
        if ch == "{":
            depth += 1
            cur += ch
        elif ch == "}":
            depth -= 1
            cur += ch
        elif ch == ":" and depth == 0:
            fields.append(cur)
            cur = ""
        else:
            cur += ch
    fields.append(cur)
    return fields[0] if len(fields) == 3 else ""


def _host_ip_is_safe(host_ip: str) -> bool:
    """True when a published host-IP is loopback/private and never wildcard.

    Resolves a ``${VAR:-default}`` to its default. A bare ``${VAR}`` (no
    default) or an empty field is treated as unsafe — it can resolve to
    0.0.0.0 at deploy time.
    """
    host_ip = host_ip.strip()
    if host_ip.startswith("${"):
        inner = host_ip[2:].rstrip("}")
        if ":-" in inner:
            host_ip = inner.split(":-", 1)[1]
        else:
            return False  # bare ${VAR} — unknown default, assume unsafe
    if not host_ip:
        return False
    if host_ip == "localhost":
        return True
    try:
        addr = ipaddress.ip_address(host_ip)
    except ValueError:
        return False
    if addr.is_unspecified:  # 0.0.0.0 / ::
        return False
    return addr.is_loopback or addr.is_private


def test_prod_internal_services_not_published_on_wildcard() -> None:
    """Regression guard for Phase 0046: the internal prod services must not
    publish host ports on a wildcard / public interface.

    Today they publish no host ports at all (this test passes trivially); the
    guard's job is to fail loudly if someone re-adds a bare ``- "8082"``-style
    mapping that would expose an internal service on 0.0.0.0.
    """
    compose = yaml.safe_load(PROD_COMPOSE.read_text()) or {}
    services = compose.get("services", {}) or {}

    offenders: list[str] = []
    for name in _PROD_INTERNAL_SERVICES:
        svc = services.get(name)
        assert svc is not None, (
            f"prod compose is missing expected service {name!r}; "
            f"services present: {sorted(services)}"
        )
        for entry in svc.get("ports") or []:
            if isinstance(entry, dict):
                host_ip = entry.get("host_ip", "") or ""
            else:
                host_ip = _leading_host_ip(str(entry))
            if not _host_ip_is_safe(host_ip):
                offenders.append(f"{name}: {entry!r}")

    assert not offenders, (
        "Internal prod services must not publish host ports on a wildcard/"
        "public interface (Phase 0046 removed these — Prometheus and the proxy "
        "reach them over the compose network):\n"
        + "\n".join(f"  {o}" for o in offenders)
    )


# ── Workflow action SHA pinning ──────────────────────────────────────────────


# Allowlist: reusable workflows that GitHub's supply-chain docs permit to be
# tag-pinned (rather than SHA-pinned). Keep this list TIGHT — add entries only
# with an accompanying ADR.
REUSABLE_WORKFLOW_TAG_ALLOWLIST = {
    # SLSA Level 3 generator — trusted reusable workflow from slsa-framework.
    # Rationale tracked in docs/decisions/ADR-202a.md (or will be when 202a
    # chooses route (b)). Pinning this one by tag is industry-standard.
    "slsa-framework/slsa-github-generator",
}

_USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)")
_SHA_PIN_RE = re.compile(r"^[^@]+@[0-9a-f]{40}$")


def _collect_uses_lines() -> list[tuple[Path, int, str]]:
    results: list[tuple[Path, int, str]] = []
    for wf in sorted(WORKFLOWS_DIR.glob("*.yml")):
        for lineno, line in enumerate(wf.read_text().splitlines(), start=1):
            m = _USES_RE.match(line)
            if not m:
                continue
            ref = m.group(1).strip().strip("'\"")
            results.append((wf, lineno, ref))
    return results


def test_all_workflow_actions_sha_pinned() -> None:
    """Every `uses:` reference in .github/workflows/*.yml must be SHA-pinned
    to a 40-char hex commit SHA. Reusable workflows in the
    REUSABLE_WORKFLOW_TAG_ALLOWLIST may be tag-pinned (documented exception).
    """
    unpinned: list[str] = []
    for path, lineno, ref in _collect_uses_lines():
        # Is this an allowlisted reusable workflow?
        # Format: owner/repo/.github/workflows/foo.yml@ref
        owner_repo = ref.split("/.github/")[0] if "/.github/" in ref else None
        if owner_repo in REUSABLE_WORKFLOW_TAG_ALLOWLIST:
            continue
        if _SHA_PIN_RE.match(ref):
            continue
        unpinned.append(
            f"{path.relative_to(REPO_ROOT)}:{lineno}: {ref!r} is not SHA-pinned"
        )
    assert not unpinned, (
        "Unpinned GitHub Action references found (supply-chain risk):\n"
        + "\n".join(f"  {u}" for u in unpinned)
        + "\n\nPin to a 40-char commit SHA, e.g. `owner/action@<sha>  # vX.Y.Z`."
    )


# ── Behavioural `docker compose config` tests (docker-gated) ─────────────────


_DOCKER_AVAILABLE = shutil.which("docker") is not None


def _clean_env() -> dict[str, str]:
    """An env with every phase-202 secret variable removed, so we can test
    that `docker compose config` correctly refuses to interpolate."""
    env = {
        k: v
        for k, v in os.environ.items()
        if k
        not in {
            "MANAGEMENT_JWT_SECRET",
            "MANAGEMENT_ADMIN_USER",
            "MANAGEMENT_ADMIN_PASSWORD",
            "GRAFANA_PASSWORD",
            "HAPROXY_STATS_USER",
            "HAPROXY_STATS_PASSWORD",
            "REDIS_PASSWORD",
            "BACKEND_HOST",
        }
    }
    # Ensure docker compose doesn't pick up a local .env file.
    env["COMPOSE_DISABLE_ENV_FILE"] = "1"
    return env


@pytest.mark.integration
@pytest.mark.skipif(not _DOCKER_AVAILABLE, reason="docker CLI not on PATH")
@pytest.mark.parametrize(
    "compose_file,required_var",
    [
        (POC_COMPOSE, "MANAGEMENT_JWT_SECRET"),
        (MONITORING_COMPOSE, "GRAFANA_PASSWORD"),
    ],
)
def test_compose_config_fails_without_required_secrets(
    compose_file: Path, required_var: str
) -> None:
    """Runtime invariant: `docker compose config` MUST fail (non-zero) and
    emit a clear error when required secrets are unset.

    This is the behavioural counterpart to the regex tests above — it
    proves that the `${VAR:?...}` syntax actually translates into a hard
    failure at interpolation time, not just that the syntax *looks* right.
    """
    proc = subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "config"],
        capture_output=True,
        text=True,
        env=_clean_env(),
        timeout=30,
    )
    assert proc.returncode != 0, (
        f"docker compose config for {compose_file.name} SUCCEEDED with no "
        f"env vars set — phase-202 `${{VAR:?...}}` required-syntax is not "
        f"being enforced at the compose level.\nSTDOUT:\n{proc.stdout}"
    )
    combined = (proc.stderr + proc.stdout).lower()
    # Compose error: "required variable X is missing a value: <message>"
    assert "required" in combined and "missing" in combined, (
        f"docker compose config for {compose_file.name} failed but the error "
        f"did not mention 'required' / 'missing':\n{proc.stderr}\n{proc.stdout}"
    )


@pytest.mark.integration
@pytest.mark.skipif(not _DOCKER_AVAILABLE, reason="docker CLI not on PATH")
def test_compose_poc_succeeds_with_all_env_vars() -> None:
    """Negative control: when every required env var IS set, `docker compose
    config` must succeed. Proves we haven't over-constrained the file so
    badly that legitimate operators can't use it."""
    env = _clean_env()
    env.update(
        {
            "MANAGEMENT_JWT_SECRET": "qa-placeholder-jwt-secret",
            "MANAGEMENT_ADMIN_USER": "qa-admin",
            "MANAGEMENT_ADMIN_PASSWORD": "qa-placeholder-admin-pw",
            "REDIS_PASSWORD": "qa-placeholder-redis-pw",
            "BACKEND_HOST": "qa-placeholder-backend",
        }
    )
    proc = subprocess.run(
        ["docker", "compose", "-f", str(POC_COMPOSE), "config", "--quiet"],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    assert proc.returncode == 0, (
        f"docker compose config for poc.yml FAILED even with all env vars set:\n"
        f"STDERR:\n{proc.stderr}\nSTDOUT:\n{proc.stdout}"
    )
