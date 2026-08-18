"""An EXISTING .env must survive a newly-required compose variable.

WHY THIS EXISTS
---------------
`docker-compose.poc.yml` declares its secrets as `${VAR:?...}` — required, hard
fail. `start-poc.sh` generates a complete .env, but only inside
`if [ ! -f .env ]`. Nothing ever edited an .env that already existed.

So when ANALYTICS_HMAC_SECRET landed on main (phase-826), every existing
checkout broke on `make build` with

    required variable ANALYTICS_HMAC_SECRET is missing a value

while a brand-new clone worked perfectly.

`tests/unit/test_container_config.py::test_start_poc_generates_every_required_env_var`
already guards the fresh-clone path, and its docstring states the failure mode
as "a brand-new clone cannot start the stack at all, while every existing
checkout works fine". That is exactly backwards, which is why the real breakage
went unguarded: the test was written from the one CI job that had no .env, and
generalised from it in the wrong direction.

These tests guard the upgrade path — the one every human actually takes.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE = REPO_ROOT / "deploy" / "docker" / "docker-compose.poc.yml"
ENV_SYNC = REPO_ROOT / "scripts" / "env-sync.sh"
TEMPLATE = REPO_ROOT / "template.env"


def required_vars() -> set[str]:
    """Every `${VAR:?}` in the compose file — the single source of truth."""
    return set(re.findall(r"\$\{([A-Z_][A-Z0-9_]*):\?", COMPOSE.read_text()))


def run_sync(env_file: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(ENV_SYNC), str(env_file)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )


@pytest.fixture
def stale_env(tmp_path: Path) -> Path:
    """A complete .env with one required variable removed — the real situation."""
    env = tmp_path / ".env"
    lines = [f"{v}=preexisting-value-{v.lower()}" for v in sorted(required_vars())]
    lines.append("COMPOSE_PROJECT_NAME=ja4proxy-test")
    env.write_text("\n".join(lines) + "\n")
    return env


def test_the_gap_is_real_start_poc_only_generates_when_env_is_absent():
    """Anchor the root cause, so a fix that removes the guard is visible.

    If start-poc.sh is ever restructured so the generator runs unconditionally,
    this test should be revisited — but it must never silently go back to
    having no upgrade path at all.
    """
    script = (REPO_ROOT / "scripts" / "start-poc.sh").read_text()
    assert 'if [ ! -f .env ]; then' in script, "generator guard changed shape"
    assert "env-sync.sh" in script, (
        "start-poc.sh no longer tops up an existing .env — an existing "
        "checkout will break the next time a required variable is added"
    )


def test_missing_required_var_is_added(stale_env: Path):
    for var in sorted(required_vars()):
        text = stale_env.read_text()
        stale_env.write_text(re.sub(rf"^{var}=.*\n", "", text, flags=re.M))

        result = run_sync(stale_env)
        assert result.returncode == 0, (
            f"env-sync could not supply {var}:\n{result.stdout}\n{result.stderr}"
        )
        assert re.search(rf"^{var}=.+", stale_env.read_text(), re.M), (
            f"{var} still missing after env-sync — `make build` stays broken"
        )


def test_every_required_var_is_classifiable(stale_env: Path):
    """No required variable may fall through to 'I cannot generate this'.

    This is the forward-looking guard: a NEW required variable that env-sync
    cannot classify fails here, in CI, rather than at a colleague's `make
    build` after a pull.
    """
    stale_env.write_text("COMPOSE_PROJECT_NAME=ja4proxy-test\n")
    result = run_sync(stale_env)
    assert result.returncode == 0, (
        "env-sync cannot supply every required variable from an empty .env.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}\n\n"
        "Either give the new variable a name env-sync recognises "
        "(*_PASSWORD / *_SECRET / *_KEY / *_TOKEN), or add an explicit "
        "non-secret default to the case statement in scripts/env-sync.sh."
    )
    produced = set(re.findall(r"^([A-Z_][A-Z0-9_]*)=.+", stale_env.read_text(), re.M))
    assert required_vars() <= produced, f"not produced: {sorted(required_vars() - produced)}"


def test_existing_values_are_never_overwritten(stale_env: Path):
    """The whole point: this runs on live deployments with real secrets."""
    before = stale_env.read_text()
    assert run_sync(stale_env).returncode == 0
    assert stale_env.read_text() == before, (
        "env-sync rewrote an .env that was already complete — it must be a "
        "no-op, or it would rotate live credentials on every `make build`"
    )


def test_empty_value_counts_as_missing_and_is_not_duplicated(stale_env: Path):
    """`VAR=` passes a naive grep but compose's `:?` rejects it."""
    var = sorted(required_vars())[0]
    stale_env.write_text(
        re.sub(rf"^{var}=.*$", f"{var}=", stale_env.read_text(), flags=re.M)
    )
    assert run_sync(stale_env).returncode == 0

    content = stale_env.read_text()
    assert len(re.findall(rf"^{var}=", content, re.M)) == 1, "duplicate assignment"
    assert re.search(rf"^{var}=.+", content, re.M), "empty value not replaced"


def test_secrets_are_never_printed(stale_env: Path):
    """A CI log is not a place to publish generated credentials."""
    stale_env.write_text("COMPOSE_PROJECT_NAME=ja4proxy-test\n")
    result = run_sync(stale_env)

    values = re.findall(r"^[A-Z_][A-Z0-9_]*=(.+)$", stale_env.read_text(), re.M)
    generated = [v for v in values if len(v) >= 16]
    assert generated, "fixture produced no generated secrets to check"
    for value in generated:
        assert value not in result.stdout and value not in result.stderr, (
            "env-sync printed a generated secret to its output"
        )


def test_env_file_stays_owner_only(stale_env: Path):
    stale_env.chmod(0o644)
    assert run_sync(stale_env).returncode == 0
    mode = stat.S_IMODE(os.stat(stale_env).st_mode)
    assert mode == 0o600, f"env file left world-readable: {oct(mode)}"


def test_template_env_documents_every_required_var():
    """template.env is the manual path — it must not drift either."""
    documented = set(re.findall(r"^([A-Z_][A-Z0-9_]*)=", TEMPLATE.read_text(), re.M))
    missing = required_vars() - documented
    assert not missing, (
        f"template.env does not mention required var(s): {sorted(missing)} — "
        "anyone following the 'cp template.env .env' path gets a broken stack"
    )


def test_missing_env_file_gives_actionable_advice(tmp_path: Path):
    """Failing is fine. Failing without saying what to run is not."""
    result = run_sync(tmp_path / "nonexistent.env")
    assert result.returncode != 0
    assert "make start-poc" in result.stdout or "make init" in result.stdout
