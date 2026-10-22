#!/usr/bin/env python3
"""scripts/compose_exposure.py — one implementation of "is this surface published?".

Two consumers need the same answer and must never disagree about it:

* the MEDIUM inventory (`scripts/medium_inventory.py`, Phase 847e), which
  classifies every scanned surface as published / not-published, and
* the waiver reachability checks (`scripts/reachability_checks.py`, Phase
  847f), which assert that a waiver's premise ("this service is
  internal-monitoring-only") still holds in the compose files.

Two independent implementations of a port-parsing rule is a divergence
waiting to happen — and the first version of this logic (in
`medium_inventory.py`) had one: it split a port mapping on the first `:`,
which mangles the interpolated form the monitoring stack actually uses::

    "${AGENT_BIND_IP:-127.0.0.1}:${HOST_PORT_GRAFANA:-3000}:3000"

`partition(":")` cut that at the colon inside `${AGENT_BIND_IP:-…}`, leaving
the host field reading `${AGENT_BIND_IP` — which is not a loopback address,
so every default-bound monitoring service was reported as published. The
inventory's own docstring says the *default* is what decides; the code did
not implement that. This module implements it, once.

The rules, in one place:

* A port mapping is ``[HOST_IP:][HOST_PORT:]CONTAINER_PORT[/PROTOCOL]``.
  A mapping with no ``HOST_IP`` — ``8080:80`` or a bare ``80`` — publishes on
  **every** interface, whatever the host port happens to be.
* ``HOST_IP`` may be an interpolation. ``${VAR:-default}`` is judged by its
  **default**: the committed configuration is what the repository ships and
  what the check judges. An operator can widen the binding at deploy time;
  that is their call, not a fact about the repository.
* An interpolation with no default (``${VAR}``) cannot be read, so it is
  judged **not** loopback. The checks fail closed on what they cannot read.
* Only a literal loopback address (``127.0.0.1``, ``localhost``, ``::1``,
  ``[::1]``) counts as loopback.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

#: Host expressions that bind loopback only.
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})

#: Host paths under which a Unix socket is mounted. A service that reaches
#: the host only through one of these is "local socket only".
SOCKET_PATH_PREFIXES = ("/var/run", "/run")

_COPY_LINE = re.compile(r"^\s*COPY\s+(.+)$", re.IGNORECASE | re.MULTILINE)
_REQUIREMENT_NAME = re.compile(r"^[A-Za-z0-9._-]+")


@dataclass(frozen=True)
class ServiceRef:
    """One compose service, with the file it came from."""

    image: str
    name: str
    path: Path
    service: dict

    @property
    def location(self) -> str:
        try:
            rel = self.path.as_posix()
        except (OSError, ValueError):  # pragma: no cover - defensive
            rel = str(self.path)
        return f"{rel} :: {self.name}"


def port_fields(spec: str) -> list[str]:
    """Split a compose port mapping into its fields.

    The split respects ``${…}`` interpolation, so the colon inside
    ``${AGENT_BIND_IP:-127.0.0.1}`` does not end a field.
    """
    fields: list[str] = []
    current: list[str] = []
    index = 0
    length = len(spec)
    while index < length:
        char = spec[index]
        if char == "$" and spec.startswith("${", index):
            depth = 0
            cursor = index
            while cursor < length:
                if spec[cursor] == "{":
                    depth += 1
                elif spec[cursor] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                cursor += 1
            current.append(spec[index : cursor + 1])
            index = cursor + 1
            continue
        if char == ":":
            fields.append("".join(current).strip())
            current = []
            index += 1
            continue
        current.append(char)
        index += 1
    fields.append("".join(current).strip())
    return fields


def host_binding(spec: str) -> str | None:
    """The host address a port mapping binds to, or ``None`` for every interface.

    ``8080:80`` and a bare ``80`` publish on every interface, whatever the
    host port happens to be. ``127.0.0.1:3000:80`` binds loopback only.
    """
    fields = port_fields(spec)
    if len(fields) >= 3:
        return fields[0]
    return None


def is_loopback(host: str) -> bool:
    """Is this host expression a loopback-only binding?

    ``${VAR:-default}`` is judged by its default — the committed
    configuration is what the repository ships and what the check judges.
    An interpolation with no default cannot be read, so it is judged *not*
    loopback: the checks fail closed on what they cannot read.
    """
    expr = host.strip()
    if expr.startswith("${") and expr.endswith("}"):
        body = expr[2:-1]
        # `:-` takes the default when the variable is unset *or* empty; the
        # plainer `-` form only when it is unset. Both resolve to a readable
        # default. Any other operator (`:+`, `:?`, a bare name) resolves to
        # nothing we can read, so it fails closed.
        if ":-" in body:
            expr = body.split(":-", 1)[1]
        elif "-" in body:
            expr = body.split("-", 1)[1]
        else:
            return False
    return expr in LOOPBACK_HOSTS


def published_ports(service: dict) -> list[tuple[str, str]]:
    """The port mappings a service publishes on a non-loopback address.

    Each entry is ``(spec, host)`` where ``host`` is ``"*"`` for "every
    interface". Long syntax (``target``/``published``/``host_ip``) is
    understood as well as the short string form.
    """
    published: list[tuple[str, str]] = []
    for entry in service.get("ports") or []:
        if isinstance(entry, str):
            host = host_binding(entry)
            if host is None or not is_loopback(host):
                published.append((entry, host or "*"))
        elif isinstance(entry, dict):
            if entry.get("published") in (None, "", 0):
                continue
            host = entry.get("host_ip")
            if not host or not is_loopback(str(host)):
                published.append((str(entry), str(host or "*")))
    return published


def service_publishes_host_port(service: dict) -> bool:
    """Does this service publish any host port on a non-loopback address?"""
    return bool(published_ports(service))


def socket_mounts(service: dict) -> list[str]:
    """The host paths this service mounts that carry a local Unix socket."""
    mounts: list[str] = []
    for entry in service.get("volumes") or []:
        if isinstance(entry, str):
            source = entry.split(":")[0].strip()
        elif isinstance(entry, dict):
            source = str(entry.get("source") or "").strip()
        else:
            continue
        if not source.startswith("/"):
            continue
        if source.endswith(".sock") or any(
            source == prefix or source.startswith(prefix + "/")
            for prefix in SOCKET_PATH_PREFIXES
        ):
            mounts.append(source)
    return mounts


def image_base(ref: str) -> str:
    """The repository part of an image reference — no tag, no digest.

    ``grafana/grafana:13.2.4-ubuntu`` → ``grafana/grafana``
    ``redis:7.4.11-alpine@sha256:…``  → ``redis``
    """
    ref = ref.split("@", 1)[0].strip()
    name, sep, tail = ref.rpartition(":")
    if sep and "/" not in tail:
        return name
    return ref


def load_compose(path: Path) -> dict:
    """Parse one compose file. Raises on unreadable or invalid YAML."""
    if yaml is None:  # pragma: no cover - PyYAML is a hard dependency in practice
        raise RuntimeError("PyYAML is required to read compose files")
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def compose_services(paths: Iterable[Path]) -> list[ServiceRef]:
    """Every service declared in the given compose files."""
    found: list[ServiceRef] = []
    for path in paths:
        document = load_compose(path)
        services = document.get("services") or {}
        if not isinstance(services, dict):
            continue
        for name, service in services.items():
            if not isinstance(service, dict):
                continue
            image = service.get("image")
            if not isinstance(image, str) or not image:
                continue
            found.append(ServiceRef(image=image, name=name, path=path, service=service))
    return found


def services_for_image(
    image_ref: str, paths: Iterable[Path]
) -> list[ServiceRef]:
    """The services that run the given image, across the given compose files."""
    wanted = image_base(image_ref)
    return [ref for ref in compose_services(paths) if image_base(ref.image) == wanted]


def requirement_names(path: Path) -> set[str]:
    """The distribution names declared in a requirements file.

    Names are normalised the way PyPI normalises them — lower case, with
    ``.`` and ``_`` folded to ``-`` — so ``zope.interface`` and
    ``zope_interface`` compare equal.
    """
    names: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = _REQUIREMENT_NAME.match(line)
        if match:
            names.add(normalise_distribution(match.group(0)))
    return names


def normalise_distribution(name: str) -> str:
    """Fold a distribution name to its PyPI-normalised form."""
    return name.strip().lower().replace("_", "-").replace(".", "-")


def dockerfile_requirements(dockerfile: Path, context: Path) -> list[Path]:
    """The requirement files a Dockerfile installs, as repository paths.

    Only ``COPY`` lines are consulted. A ``pip install -r requirements.txt``
    names the file *as copied into the image*, which is not necessarily the
    repository path — the COPY line is the one that carries the path.
    """
    if not dockerfile.is_file():
        return []
    text = dockerfile.read_text(encoding="utf-8")
    found: list[Path] = []
    for line in _COPY_LINE.findall(text):
        for token in line.split():
            if token.startswith("--"):
                continue
            # A COPY source may carry a directory prefix —
            # `COPY management/requirements.txt .` is how the management image
            # gets its dependencies. Keying on the bare basename is what makes
            # the *deployed* dependency set complete: miss this and the
            # `dev-tooling-only` check silently examines a smaller set of
            # deployed images than it claims to.
            basename = token.rsplit("/", 1)[-1]
            if not basename.startswith("requirements") or not basename.endswith(".txt"):
                continue
            candidate = (context / token).resolve()
            if candidate.is_file():
                found.append(candidate)
    return found


def compose_build_targets(
    path: Path, include_profiled: bool = True
) -> list[tuple[Path, Path]]:
    """The ``(dockerfile, build context)`` pairs the services in a compose file build.

    The context is the compose-declared ``build.context``, resolved — **not**
    the Dockerfile's own directory. A ``COPY`` path is relative to the build
    context, so using the Dockerfile's directory silently resolves
    ``COPY management/requirements.txt`` to a path that does not exist and
    skips the file. That is how a "which packages are deployed?" check ends up
    examining no deployed images at all while reporting success.

    ``include_profiled=False`` drops services behind a ``profiles:`` gate.
    Such a service only starts when the profile is named explicitly, which is
    how the repository marks its CI-only images (``test``, ``traffic``). They
    still build and still run, so callers asking "is this reachable?" want
    them included; callers asking "is this *deployed*?" do not.
    """
    document = load_compose(path)
    services = document.get("services") or {}
    if not isinstance(services, dict):
        return []
    targets: list[tuple[Path, Path]] = []
    for service in services.values():
        if not isinstance(service, dict):
            continue
        if not include_profiled and service.get("profiles"):
            continue
        build = service.get("build")
        if not isinstance(build, dict):
            continue
        dockerfile = build.get("dockerfile")
        if not isinstance(dockerfile, str) or not dockerfile:
            continue
        context = build.get("context") or "."
        context_dir = (path.parent / str(context)).resolve()
        resolved = (context_dir / dockerfile).resolve()
        if resolved.is_file():
            targets.append((resolved, context_dir))
    return targets


def any_dependency(*values: Any) -> bool:  # pragma: no cover - tiny helper
    return any(values)
