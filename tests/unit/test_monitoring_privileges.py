"""Phase 829c, outcome O12 — the privilege trade must stay bounded.

Moving container metrics into Alloy concentrates privilege: the process that
reads every container's logs gains the host visibility cadvisor needed. That was
accepted knowingly, in exchange for removing an unrebuildable image carrying 49
HIGH/CRITICAL findings.

"Accepted knowingly" only means anything if the boundary is enforced. Two prior
findings tightened exactly these services:

* ``JA4PROXY-2026-0016`` cut cadvisor from ``privileged: true`` to
  ``SYS_PTRACE`` + ``DAC_READ_SEARCH`` with read-only mounts.
* ``JA4PROXY-2026-0017`` removed Alloy's Docker socket, routing discovery
  through ``docker-socket-proxy`` instead.

These tests assert Alloy gained *cadvisor's* capabilities and nothing more, and
that the Docker socket does not return by the back door.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

COMPOSE = (
    Path(__file__).resolve().parents[2]
    / "deploy"
    / "docker"
    / "docker-compose.monitoring.yml"
)

# Exactly what JA4PROXY-2026-0016 left cadvisor with.
CADVISOR_CAPS = {"SYS_PTRACE", "DAC_READ_SEARCH"}


@pytest.fixture(scope="module")
def services() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]


def test_cadvisor_sidecar_is_gone(services: dict) -> None:
    """The whole point: 49 HIGH/CRITICAL and 24 exclusive waivers removed."""
    assert "cadvisor" not in services


def test_no_service_still_pulls_the_cadvisor_image(services: dict) -> None:
    """A renamed service would keep the image and the CVEs."""
    images = [s.get("image", "") for s in services.values()]
    assert not [i for i in images if "cadvisor/cadvisor" in i]


def test_alloy_gains_only_the_capabilities_cadvisor_needed(services: dict) -> None:
    alloy = services["alloy"]
    assert alloy.get("cap_drop") == ["ALL"], "the blanket drop must stay"

    added = set(alloy.get("cap_add") or [])
    assert added == CADVISOR_CAPS, (
        f"Alloy has {sorted(added)}; cadvisor needed {sorted(CADVISOR_CAPS)}. "
        "Anything extra is scope creep in a privilege change."
    )


def test_alloy_is_not_privileged(services: dict) -> None:
    """JA4PROXY-2026-0016 removed `privileged: true` once already."""
    assert services["alloy"].get("privileged") in (None, False)


def test_alloy_does_not_gain_the_docker_socket(services: dict) -> None:
    """JA4PROXY-2026-0017 removed it deliberately.

    A compromise of Alloy with a writable Docker socket is a direct path to host
    root. Discovery goes through docker-socket-proxy, which whitelists only the
    CONTAINERS endpoint — that must not be quietly bypassed while adding
    cadvisor's other mounts.
    """
    mounts = services["alloy"].get("volumes") or []
    offending = [m for m in mounts if "docker.sock" in str(m)]
    assert not offending, f"Alloy must not mount the Docker socket: {offending}"


def test_alloy_host_mounts_are_read_only(services: dict) -> None:
    """Every host path cadvisor read, it read read-only. Same here."""
    host_paths = ("/rootfs", "/sys", "/var/lib/docker", "/dev/disk", "/var/run")
    writable = []
    for mount in services["alloy"].get("volumes") or []:
        m = str(mount)
        if any(f":{p}:" in m or m.startswith(f"{p}:") for p in host_paths) or any(
            m.split(":")[0] == p.rstrip("/") or m.split(":")[0] == "/" for p in host_paths
        ):
            if not m.endswith(":ro"):
                writable.append(m)
    assert not writable, f"host mounts must be read-only: {writable}"


def test_sys_ptrace_is_held_only_by_alloy(services: dict) -> None:
    """Vacuity guard.

    SYS_PTRACE is the capability this phase actually moves — it is what reading
    other containers' /proc requires. (DAC_READ_SEARCH is not a useful marker:
    docker-socket-proxy has legitimately held it since before this phase.)

    If a refactor moved it onto another service, every assertion above could
    still pass while the privilege sat somewhere nobody reviewed.
    """
    holders = {
        name for name, svc in services.items() if "SYS_PTRACE" in (svc.get("cap_add") or [])
    }
    assert holders == {"alloy"}, f"unexpected SYS_PTRACE holders: {sorted(holders)}"


def test_compose_has_no_duplicate_keys_within_a_service() -> None:
    """A duplicate mapping key is silently resolved to the LAST one.

    Hit for real while writing this phase: a `cap_add` block was added near the
    top of the alloy service, which already had one further down. PyYAML did not
    complain, Docker did not complain, and SYS_PTRACE was silently discarded —
    the capability the whole change depends on. The compose file looked correct
    in the diff.

    PyYAML has no duplicate-key check, so this walks the raw text per service.
    """
    import re
    from collections import Counter

    text = COMPOSE.read_text(encoding="utf-8")
    lines = text.split("\n")

    service_starts = [
        i
        for i, l in enumerate(lines)
        if re.match(r"^  [a-z0-9_-]+:\s*$", l) and not l.startswith("    ")
    ]
    failures = []
    for n, start in enumerate(service_starts):
        end = service_starts[n + 1] if n + 1 < len(service_starts) else len(lines)
        keys = [
            m.group(1)
            for m in (re.match(r"^    ([a-z0-9_]+):", l) for l in lines[start:end])
            if m
        ]
        dupes = [k for k, c in Counter(keys).items() if c > 1]
        if dupes:
            failures.append(f"{lines[start].strip()} duplicates {dupes}")

    assert not failures, "duplicate keys silently drop the earlier block: " + "; ".join(
        failures
    )
