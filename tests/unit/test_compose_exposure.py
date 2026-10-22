"""
tests/unit/test_compose_exposure.py

Phase 847f — `scripts/compose_exposure.py` is the ONE implementation of "is
this compose service published?", shared by the MEDIUM inventory (847e) and
the waiver reachability checks (847f).

It exists because the first implementation of that rule was wrong in a way
that mattered: it split a port mapping on the first `:`, which mangles the
interpolated form the monitoring stack actually ships —

    "${AGENT_BIND_IP:-127.0.0.1}:${HOST_PORT_GRAFANA:-3000}:3000"

— and therefore reported every default-bound monitoring service (grafana,
prometheus, alertmanager) as published. The bug was fail-safe in direction
(it over-reported exposure) but it made the inventory's numbers wrong and
would have made 847f's `internal-monitoring-only` check fail on 21 waivers
whose premise is true.

These tests pin the parsing rules so the same class of bug cannot come back.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from scripts import compose_exposure

# ── port_fields: the split that used to be wrong ────────────────────────────

@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("80", ["80"]),
        ("8080:80", ["8080", "80"]),
        ("127.0.0.1:3001:3000", ["127.0.0.1", "3001", "3000"]),
        ("443:443/tcp", ["443", "443/tcp"]),
        ("${AGENT_BIND_IP:-127.0.0.1}:${HOST_PORT_GRAFANA:-3000}:3000",
         ["${AGENT_BIND_IP:-127.0.0.1}", "${HOST_PORT_GRAFANA:-3000}", "3000"]),
    ],
)
def test_port_fields_splits_respecting_interpolation(spec: str, expected: list[str]) -> None:
    assert compose_exposure.port_fields(spec) == expected


# ── host_binding ────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("80", None),                 # container port only → every interface
        ("8080:80", None),            # no host IP → every interface
        ("127.0.0.1:3001:3000", "127.0.0.1"),
        ("0.0.0.0:3001:3000", "0.0.0.0"),
        ("${AGENT_BIND_IP:-127.0.0.1}:3000:3000", "${AGENT_BIND_IP:-127.0.0.1}"),
    ],
)
def test_host_binding(spec: str, expected: str | None) -> None:
    assert compose_exposure.host_binding(spec) == expected


# ── is_loopback ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", True),
        ("localhost", True),
        ("::1", True),
        ("[::1]", True),
        ("0.0.0.0", False),
        ("10.0.0.5", False),
        # The form the monitoring stack ships: judged by its DEFAULT, because
        # the committed configuration is what the repository ships.
        ("${AGENT_BIND_IP:-127.0.0.1}", True),
        ("${AGENT_BIND_IP:-0.0.0.0}", False),
        ("${AGENT_BIND_IP}", False),      # no default → cannot be read → fail closed
        ("${AGENT_BIND_IP-127.0.0.1}", True),
    ],
)
def test_is_loopback(host: str, expected: bool) -> None:
    assert compose_exposure.is_loopback(host) is expected


# ── published_ports / service_publishes_host_port ───────────────────────────

def test_no_ports_means_not_published() -> None:
    service = {"image": "grafana/loki:3.7.7"}
    assert compose_exposure.published_ports(service) == []
    assert compose_exposure.service_publishes_host_port(service) is False


def test_loopback_binding_is_not_published() -> None:
    service = {"ports": ["127.0.0.1:3001:3000"]}
    assert compose_exposure.published_ports(service) == []
    assert compose_exposure.service_publishes_host_port(service) is False


def test_default_bound_interpolation_is_not_published() -> None:
    """The regression: this used to be reported as published."""
    service = {"ports": ["${AGENT_BIND_IP:-127.0.0.1}:${HOST_PORT_GRAFANA:-3000}:3000"]}
    assert compose_exposure.published_ports(service) == []
    assert compose_exposure.service_publishes_host_port(service) is False


def test_bare_host_port_is_published_on_every_interface() -> None:
    service = {"ports": ["443:443"]}
    published = compose_exposure.published_ports(service)
    assert published == [("443:443", "*")]
    assert compose_exposure.service_publishes_host_port(service) is True


def test_long_syntax_published_port_without_host_ip_is_published() -> None:
    service = {"ports": [{"target": 80, "published": "8080"}]}
    assert compose_exposure.service_publishes_host_port(service) is True


def test_long_syntax_without_published_is_not_published() -> None:
    service = {"ports": [{"target": 80, "host_ip": "127.0.0.1"}]}
    assert compose_exposure.service_publishes_host_port(service) is False


def test_long_syntax_on_a_public_address_is_published() -> None:
    service = {"ports": [{"target": 80, "published": "8080", "host_ip": "0.0.0.0"}]}
    assert compose_exposure.service_publishes_host_port(service) is True


# ── socket_mounts ───────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("/var/run/docker.sock", True),
        ("/run/docker.sock", True),
        ("/var/run", True),
        ("/var/lib/docker", False),
        ("/etc/alloy/config.alloy", False),
        ("alloy-data", False),          # a named volume, not a host path
    ],
)
def test_socket_mounts(source: str, expected: bool) -> None:
    service = {"volumes": [f"{source}:{source}:ro"]}
    assert bool(compose_exposure.socket_mounts(service)) is expected


# ── image_base ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("ref", "expected"),
    [
        ("grafana/grafana:13.2.4-ubuntu", "grafana/grafana"),
        ("redis:7.4.11-alpine@sha256:520775a41a63", "redis"),
        ("grafana/alloy:v1.19.2@sha256:b8ec653c4423", "grafana/alloy"),
        ("registry.example.com:5000/team/app:v1", "registry.example.com:5000/team/app"),
        ("nginx", "nginx"),
    ],
)
def test_image_base(ref: str, expected: str) -> None:
    assert compose_exposure.image_base(ref) == expected


# ── requirement_names ───────────────────────────────────────────────────────

def test_requirement_names_normalises_and_ignores_comments(tmp_path: Path) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "\n".join(
            [
                "# a comment",
                "",
                "urllib3>=2.7.0  # trailing comment",
                "redis[asyncio]==8.1.0",
                "zope.interface>=5.0",
                "PyYAML==6.0.3",
                "-r other.txt",
            ]
        ),
        encoding="utf-8",
    )
    names = compose_exposure.requirement_names(requirements)
    assert names == {"urllib3", "redis", "zope-interface", "pyyaml"}


# ── The 847e inventory now uses the shared rule ─────────────────────────────

def test_inventory_agrees_with_the_shared_parser() -> None:
    """The MEDIUM inventory must not keep its own, subtly different rule."""
    from scripts import medium_inventory

    service = {"ports": ["${AGENT_BIND_IP:-127.0.0.1}:${HOST_PORT_GRAFANA:-3000}:3000"]}
    assert medium_inventory._service_is_internal_only(service) is True
    assert medium_inventory._service_is_internal_only({"ports": ["443:443"]}) is False
