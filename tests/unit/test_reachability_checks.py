"""
tests/unit/test_reachability_checks.py

Phase 847f — every waiver's `reachability:` claim is bound to a check, and the
check runs against the live compose/source tree.

Two things are tested here:

1. **The mechanism works.** Each registered check actually fails when its
   premise stops being true. A check that can never fail is not a check; it is
   a comment with a green tick next to it. The tests below edit a scratch copy
   of the deployment (a scratch compose file with a published port, a scratch
   requirements file with the package added, a scratch module importing it)
   and assert the check reports the broken premise.

2. **A broken premise produces a re-justification, never a removal.** The
   failure message must name the waiver, name the premise and its evidence,
   and tell the reader to re-justify. Deleting the waiver would remove the
   *record* of the exposure, not the exposure.

The live registry is also checked, so a waiver whose premise has genuinely
broken fails CI here rather than being discovered by hand months later.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from scripts import reachability_checks as rc
from scripts import render_waivers

REPO_ROOT = Path(__file__).resolve().parents[2]


# ── helpers ─────────────────────────────────────────────────────────────────

def _waiver(**overrides) -> dict:
    waiver = {
        "id": "CVE-2026-99999",
        "scope": "third-party",
        "severity": "HIGH",
        "source": "trivy",
        "carriers": ["grafana/grafana:13.2.4-ubuntu"],
        "rationale": "a test waiver",
        "reachability": "internal-monitoring-only",
        "created": "2026-01-01",
        "expires": "2026-03-01",
    }
    waiver.update(overrides)
    return waiver


def _scratch_repo(tmp_path: Path, prod_compose: str, monitoring_compose: str = "services: {}\n") -> Path:
    """A minimal repo root with the compose files the checks scan.

    Every file in ``DEPLOYED_COMPOSE_FILES`` must exist: a missing one is an
    unreadable input, and the checks fail closed on those rather than quietly
    examining a smaller deployment than they claim to.
    """
    compose_dir = tmp_path / "deploy" / "docker"
    compose_dir.mkdir(parents=True)
    (compose_dir / "docker-compose.prod.yml").write_text(prod_compose, encoding="utf-8")
    (compose_dir / "docker-compose.monitoring.yml").write_text(
        monitoring_compose, encoding="utf-8"
    )
    for name in rc.DEPLOYED_COMPOSE_FILES:
        if name in {"docker-compose.prod.yml", "docker-compose.monitoring.yml"}:
            continue
        (compose_dir / name).write_text("services: {}\n", encoding="utf-8")
    return tmp_path


# ── the live registry ───────────────────────────────────────────────────────

def test_every_waiver_has_a_registered_reachability_check() -> None:
    registry = render_waivers.load_registry()
    for waiver in registry["waivers"]:
        assert waiver.get("reachability") in rc.REACHABILITY_VALUES, (
            f"{waiver['id']}: reachability {waiver.get('reachability')!r} names no "
            f"registered check"
        )


def test_the_live_registry_passes_every_check() -> None:
    """The CI gate: a waiver whose premise has broken fails here."""
    registry = render_waivers.load_registry()
    results = rc.check_all(registry, REPO_ROOT)
    failures = [r for r in results if not r.ok]
    assert failures == [], "\n".join(
        f"{r.waiver_id} ({r.check}): {r.message}\n  " + "\n  ".join(r.evidence)
        for r in failures
    )


def test_check_all_covers_every_waiver() -> None:
    registry = render_waivers.load_registry()
    results = rc.check_all(registry, REPO_ROOT)
    assert len(results) == len(registry["waivers"])


def test_the_live_registry_reports_both_check_kinds() -> None:
    """A silently-empty attested set would read as 'everything is machine-checked'."""
    registry = render_waivers.load_registry()
    results = rc.check_all(registry, REPO_ROOT)
    kinds = {r.kind for r in results}
    assert kinds == {"machine", "attested"}


def test_cli_exits_zero_on_the_live_registry() -> None:
    assert rc.main([]) == 0


# ── internal-monitoring-only ────────────────────────────────────────────────

def test_internal_monitoring_only_passes_for_a_loopback_bound_service(tmp_path: Path) -> None:
    repo = _scratch_repo(
        tmp_path,
        textwrap.dedent(
            """
            services:
              grafana:
                image: grafana/grafana:13.2.4-ubuntu
                ports:
                  - "${AGENT_BIND_IP:-127.0.0.1}:3000:3000"
            """
        ),
    )
    result = rc.check_internal_monitoring_only(_waiver(), repo)
    assert result.ok, result.message


def test_internal_monitoring_only_fails_when_a_port_is_published(tmp_path: Path) -> None:
    """The negative test the phase's acceptance criteria require."""
    repo = _scratch_repo(
        tmp_path,
        textwrap.dedent(
            """
            services:
              grafana:
                image: grafana/grafana:13.2.4-ubuntu
                ports:
                  - "3000:3000"
            """
        ),
    )
    result = rc.check_internal_monitoring_only(_waiver(), repo)
    assert not result.ok
    assert "BROKEN" in result.message
    assert "CVE-2026-99999" in result.message
    # The instruction is re-justification, never removal.
    assert "Re-justify" in result.message
    assert any("3000:3000" in line for line in result.evidence)


def test_a_broken_premise_never_deletes_the_waiver() -> None:
    """The check is read-only: it reports, it does not mutate the registry."""
    registry = {"waivers": [_waiver(reachability="internal-monitoring-only")]}
    before = repr(registry)
    rc.check_all(registry, REPO_ROOT)
    assert repr(registry) == before


# ── local-socket-only ───────────────────────────────────────────────────────

def test_local_socket_only_passes_without_a_published_port(tmp_path: Path) -> None:
    repo = _scratch_repo(
        tmp_path,
        textwrap.dedent(
            """
            services:
              socket-proxy:
                image: tecnativa/docker-socket-proxy:v0.5.0
                volumes:
                  - /var/run/docker.sock:/var/run/docker.sock:ro
            """
        ),
    )
    result = rc.check_local_socket_only(
        _waiver(carriers=["tecnativa/docker-socket-proxy:v0.5.0"]), repo
    )
    assert result.ok, result.message
    assert any("/var/run/docker.sock" in line for line in result.evidence)


def test_local_socket_only_fails_when_a_port_is_published(tmp_path: Path) -> None:
    repo = _scratch_repo(
        tmp_path,
        textwrap.dedent(
            """
            services:
              socket-proxy:
                image: tecnativa/docker-socket-proxy:v0.5.0
                ports:
                  - "2375:2375"
                volumes:
                  - /var/run/docker.sock:/var/run/docker.sock:ro
            """
        ),
    )
    result = rc.check_local_socket_only(
        _waiver(carriers=["tecnativa/docker-socket-proxy:v0.5.0"]), repo
    )
    assert not result.ok
    assert "Re-justify" in result.message


def test_local_socket_only_treats_a_loopback_port_as_published(tmp_path: Path) -> None:
    """A loopback port is still a network route; local-socket-only is stronger."""
    repo = _scratch_repo(
        tmp_path,
        textwrap.dedent(
            """
            services:
              socket-proxy:
                image: tecnativa/docker-socket-proxy:v0.5.0
                ports:
                  - "127.0.0.1:2375:2375"
            """
        ),
    )
    result = rc.check_local_socket_only(
        _waiver(carriers=["tecnativa/docker-socket-proxy:v0.5.0"]), repo
    )
    assert not result.ok


# ── dev-tooling-only ────────────────────────────────────────────────────────

def _repo_with_deployed_requirements(tmp_path: Path, requirements: str) -> Path:
    repo = tmp_path
    compose_dir = repo / "deploy" / "docker"
    compose_dir.mkdir(parents=True)
    (compose_dir / "docker-compose.prod.yml").write_text(
        textwrap.dedent(
            """
            services:
              management:
                image: ja4proxy-management:1.0.0
                build:
                  context: ../..
                  dockerfile: deploy/docker/Dockerfile.management
              ci-only:
                image: ja4proxy-test:1.0.0
                profiles: ["test"]
                build:
                  context: ../..
                  dockerfile: deploy/docker/Dockerfile.test
            """
        ),
        encoding="utf-8",
    )
    for name in rc.DEPLOYED_COMPOSE_FILES:
        if name == "docker-compose.prod.yml":
            continue
        (compose_dir / name).write_text("services: {}\n", encoding="utf-8")
    (repo / "management").mkdir()
    (repo / "management" / "requirements.txt").write_text(requirements, encoding="utf-8")
    (repo / "requirements.txt").write_text("urllib3>=2.7.0\n", encoding="utf-8")
    (compose_dir / "Dockerfile.management").write_text(
        "FROM python:3.14\nCOPY management/requirements.txt .\n", encoding="utf-8"
    )
    (compose_dir / "Dockerfile.test").write_text(
        "FROM python:3.14\nCOPY requirements.txt .\n", encoding="utf-8"
    )
    return repo


def test_dev_tooling_only_passes_when_the_package_is_not_deployed(tmp_path: Path) -> None:
    repo = _repo_with_deployed_requirements(tmp_path, "fastapi==0.141.1\n")
    result = rc.check_dev_tooling_only(_waiver(carriers=["urllib3"]), repo)
    assert result.ok, result.message


def test_dev_tooling_only_fails_when_the_package_reaches_a_deployed_image(tmp_path: Path) -> None:
    repo = _repo_with_deployed_requirements(tmp_path, "fastapi==0.141.1\nurllib3>=2.7.0\n")
    result = rc.check_dev_tooling_only(_waiver(carriers=["urllib3"]), repo)
    assert not result.ok
    assert "urllib3" in result.message or any("urllib3" in e for e in result.evidence)
    assert "Re-justify" in result.message


def test_dev_tooling_only_ignores_a_profiled_ci_only_image(tmp_path: Path) -> None:
    """`profiles:` is how this repo marks CI-only images; they are not deployed.

    The fixture's `ci-only` service copies a requirements file that declares
    urllib3, but sits behind `profiles: ["test"]`. Counting it would make every
    dev-tooling waiver fail, because requirements.txt is where dev tooling
    legitimately lives.
    """
    repo = _repo_with_deployed_requirements(tmp_path, "fastapi==0.141.1\n")
    result = rc.check_dev_tooling_only(_waiver(carriers=["urllib3"]), repo)
    assert result.ok, result.message


# ── not-imported ────────────────────────────────────────────────────────────

def test_not_imported_passes_when_nothing_imports_the_package(tmp_path: Path) -> None:
    repo = _scratch_repo(tmp_path, "services: {}\n")
    (repo / "src").mkdir()
    (repo / "src" / "module.py").write_text("import json\n", encoding="utf-8")
    result = rc.check_not_imported(_waiver(carriers=["mcp"]), repo)
    assert result.ok, result.message


def test_not_imported_fails_when_first_party_code_imports_the_package(tmp_path: Path) -> None:
    repo = _scratch_repo(tmp_path, "services: {}\n")
    (repo / "src").mkdir()
    (repo / "src" / "module.py").write_text("from mcp.server import thing\n", encoding="utf-8")
    result = rc.check_not_imported(_waiver(carriers=["mcp"]), repo)
    assert not result.ok
    assert any("module.py" in line for line in result.evidence)
    assert "Re-justify" in result.message


def test_not_imported_matches_a_submodule_of_an_alias(tmp_path: Path) -> None:
    """`from google.protobuf import x` imports the distribution `protobuf`."""
    repo = _scratch_repo(tmp_path, "services: {}\n")
    (repo / "src").mkdir()
    (repo / "src" / "module.py").write_text(
        "from google.protobuf import descriptor\n", encoding="utf-8"
    )
    result = rc.check_not_imported(_waiver(carriers=["protobuf"]), repo)
    assert not result.ok


# ── input-path-unreachable (attested) ───────────────────────────────────────

def test_attested_claim_passes_with_substantive_evidence() -> None:
    waiver = _waiver(
        reachability="input-path-unreachable",
        reachability_evidence="the regex is compiled only from a bind-mounted static file",
    )
    result = rc.check_input_path_unreachable(waiver, REPO_ROOT)
    assert result.ok, result.message
    assert result.kind == "attested"


def test_attested_claim_fails_without_evidence() -> None:
    result = rc.check_input_path_unreachable(
        _waiver(reachability="input-path-unreachable"), REPO_ROOT
    )
    assert not result.ok
    assert "reachability_evidence" in result.message


def test_attested_claim_fails_with_placeholder_evidence() -> None:
    result = rc.check_input_path_unreachable(
        _waiver(reachability="input-path-unreachable", reachability_evidence="n/a"),
        REPO_ROOT,
    )
    assert not result.ok
    assert "too short" in result.message


# ── unknown values ──────────────────────────────────────────────────────────

def test_an_unregistered_reachability_value_is_an_error() -> None:
    result = rc.check_waiver(_waiver(reachability="vibes"), REPO_ROOT)
    assert result is not None and not result.ok
    assert "not a registered check" in result.message or "unknown reachability" in result.message


def test_a_waiver_with_no_reachability_claim_is_skipped_by_the_runner() -> None:
    assert rc.check_waiver(_waiver(reachability=None), REPO_ROOT) is None


# ── schema: the renderer rejects an unbound waiver at authoring time ────────

def _registry_with(waiver: dict) -> dict:
    return {
        "version": 1,
        "policy": {"max_window_days": 90, "default_owner": "security-oncall"},
        "waivers": [waiver],
    }


def test_schema_rejects_a_missing_reachability_field() -> None:
    waiver = _waiver()
    waiver.pop("reachability")
    errors = render_waivers.validate(_registry_with(waiver))
    assert any("reachability" in e for e in errors), errors


def test_schema_rejects_an_unregistered_reachability_value() -> None:
    errors = render_waivers.validate(_registry_with(_waiver(reachability="vibes")))
    assert any("not a registered check" in e for e in errors), errors


def test_schema_rejects_an_attested_claim_without_evidence() -> None:
    errors = render_waivers.validate(
        _registry_with(_waiver(reachability="input-path-unreachable"))
    )
    assert any("reachability_evidence" in e for e in errors), errors


def test_schema_accepts_an_attested_claim_with_evidence() -> None:
    errors = render_waivers.validate(
        _registry_with(
            _waiver(
                reachability="input-path-unreachable",
                reachability_evidence="the regex is compiled only from a static file",
            )
        )
    )
    assert errors == []


@pytest.mark.parametrize("value", sorted(rc.REACHABILITY_VALUES))
def test_schema_accepts_every_registered_value(value: str) -> None:
    waiver = _waiver(reachability=value)
    if value in rc.ATTESTED_VALUES:
        waiver["reachability_evidence"] = "a substantive statement of the unreachable path"
    assert render_waivers.validate(_registry_with(waiver)) == []


def test_every_registered_check_is_described_and_callable() -> None:
    for name, spec in rc.CHECKS.items():
        assert spec.name == name
        assert spec.summary
        assert spec.kind in {"machine", "attested"}
        assert callable(spec.run)
