#!/usr/bin/env python3
"""scripts/reachability_checks.py — machine-checked reachability assertions for waivers.

Phase 847f. Every waiver in `security/waivers.yaml` carries a `reachability:`
claim: a statement about *why* the finding behind the waiver is not reachable
from an attacker who can talk to this deployment. Until now that statement was
prose. It is now an **enum naming a registered check**, and the check is
executed against the live compose files and source tree. When the premise
stops being true, CI says so — it does not silently delete the waiver.

THE POINT OF THE PHASE
----------------------
An evidenced waiver is one whose premise is *checked*. A hand-wave is one
whose premise is *asserted* and then quietly outlives its justification. The
failure mode this module exists to prevent:

    a service that was internal-only gets a published host port
    → the waiver's justification is now false
    → the finding is now reachable
    → nothing in the pipeline notices, because nobody re-read the prose

What a broken premise produces
-------------------------------
A failure that names the waiver, names the broken premise, shows the
evidence (file, service, port), and instructs re-justification. Never a
silent removal: deleting the waiver would remove the *record* of the
exposure, not the exposure.

THE ENUM
--------
Each value names one registered check, and each check asserts one specific,
mechanically-observable fact:

``internal-monitoring-only``
    The carrier's service publishes no host port on a non-loopback address.
    *Machine.* — read from the compose files.

``local-socket-only``
    The carrier's service publishes no host port at all, so the only route
    to it is a local Unix socket.
    *Machine.* — read from the compose files.

``dev-tooling-only``
    The carrier package is not a declared dependency of any deployed image.
    *Machine.* — read from the compose files and the Dockerfiles they build.

``not-imported``
    No first-party module imports the carrier package, and it is not a
    declared dependency of any deployed image.
    *Machine.* — read from the source tree and the compose files.

``input-path-unreachable``
    The vulnerable code path is not reachable by untrusted input. There is no
    static signal for this, so the claim is a **documented attestation**: the
    waiver must carry a `reachability_evidence:` field saying what the
    unreachable path is. The check asserts the attestation exists and is
    substantive — it does not pretend to verify a premise it cannot read.

A claim nothing checks is exactly what this programme is against, so the
attested value is deliberately the only escape hatch: it is more expensive to
use (it needs written evidence) and it is visible in the summary.

SCOPE
-----
The compose files that define the **deployed** stack — the same set the CVE
gate scans (`scripts/check_image_versions.py:SCAN_GATE_COMPOSE_FILES`) and
the same set the MEDIUM inventory measures. One scope, so the gate, the
inventory and these checks cannot describe three different deployments.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

try:  # works as `python3 scripts/x.py` and as `from scripts.x import ...`
    from scripts.check_image_versions import COMPOSE_DIR
    from scripts.compose_exposure import (
        ServiceRef,
        compose_build_targets,
        compose_services,
        dockerfile_requirements,
        normalise_distribution,
        published_ports,
        requirement_names,
        services_for_image,
        socket_mounts,
    )
except ImportError:  # invoked directly, scripts/ on sys.path
    from check_image_versions import COMPOSE_DIR  # type: ignore[no-redef]
    from compose_exposure import (  # type: ignore[no-redef]
        ServiceRef,
        compose_build_targets,
        compose_services,
        dockerfile_requirements,
        normalise_distribution,
        published_ports,
        requirement_names,
        services_for_image,
        socket_mounts,
    )

REPO_ROOT = Path(__file__).resolve().parents[1]

#: The compose files that define a stack this repository actually deploys.
#:
#: The CVE gate scans `prod` + `monitoring` — the production stack. These
#: checks ask a related but different question: "is the premise true of *any*
#: deployment we ship?" — so they also cover the POC and scale stacks, where
#: the management image (absent from the production compose file) and the
#: multi-worker layout live. Deliberately excluded:
#:
#: * `docker-compose.test.yml` — a CI harness, not a deployment;
#: * `docker-compose.pentest.yml` — a deliberately hostile range that overrides
#:   `poc` and is not meant to ship;
#: * `docker-compose.override.yml` — a developer tweak applied on top of
#:   another stack;
#: * `docker-compose.redis-tls.yml`, `docker-compose.logtide-eval.yml` —
#:   variant overlays and evaluation harnesses.
#:
#: Every listed file is required to exist: a missing one is an unreadable
#: input, and these checks fail closed on those.
DEPLOYED_COMPOSE_FILES = (
    "docker-compose.prod.yml",
    "docker-compose.monitoring.yml",
    "docker-compose.poc.yml",
    "docker-compose.scale.yml",
)

#: Directories whose Python modules count as first-party code.
FIRST_PARTY_PY_DIRS = ("src", "management", "scripts", "tools", "tests")

#: Minimum length of a `reachability_evidence:` attestation.
MIN_EVIDENCE_CHARS = 20

#: Distribution name → the import name(s) it is known to provide. A PyPI
#: distribution is not always importable under its own name.
IMPORT_ALIASES: dict[str, set[str]] = {
    "pyyaml": {"yaml"},
    "pillow": {"pil"},
    "beautifulsoup4": {"bs4"},
    "scikit-learn": {"sklearn"},
    "python-dateutil": {"dateutil"},
    "opencv-python": {"cv2"},
    "attrs": {"attr", "attrs"},
    "protobuf": {"protobuf"},
    "python-multipart": {"multipart"},
    "setuptools": {"setuptools", "pkg_resources"},
}


@dataclass
class CheckResult:
    """The outcome of one reachability check."""

    ok: bool
    message: str
    waiver_id: str = ""
    check: str = ""
    kind: str = "machine"
    evidence: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "waiver_id": self.waiver_id,
            "check": self.check,
            "kind": self.kind,
            "message": self.message,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class CheckSpec:
    """A registered check: what it asserts, and how it is evaluated."""

    name: str
    kind: str
    summary: str
    run: Callable[["dict", Path], CheckResult]


def _load_yaml(path: Path) -> dict:
    if yaml is None:  # pragma: no cover
        raise RuntimeError("PyYAML is required")
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def _compose_paths(repo_root: Path) -> list[Path]:
    """The compose files that define a deployment this repository ships."""
    return [repo_root / COMPOSE_DIR / name for name in DEPLOYED_COMPOSE_FILES]


# --------------------------------------------------------------------------
# Check: internal-monitoring-only
# --------------------------------------------------------------------------


def check_internal_monitoring_only(waiver: dict, repo_root: Path) -> CheckResult:
    """The carrier's service publishes no host port on a non-loopback address."""
    wid = waiver.get("id", "?")
    offenders: list[str] = []
    for carrier in waiver.get("carriers") or []:
        for ref in services_for_image(carrier, _compose_paths(repo_root)):
            for spec, host in published_ports(ref.service):
                offenders.append(
                    f"{ref.location} publishes {spec!r} on {host} "
                    f"(carrier {carrier!r})"
                )
    if offenders:
        return CheckResult(
            ok=False,
            message=(
                f"waiver {wid}: the internal-monitoring-only premise is BROKEN — "
                f"the carrier is published on a non-loopback address. "
                f"Re-justify this waiver or remove the exposure; do not delete "
                f"the waiver to silence CI."
            ),
            waiver_id=wid,
            check="internal-monitoring-only",
            evidence=offenders,
        )
    return CheckResult(
        ok=True,
        message=f"waiver {wid}: internal-monitoring-only — OK (no non-loopback port)",
        waiver_id=wid,
        check="internal-monitoring-only",
    )


# --------------------------------------------------------------------------
# Check: local-socket-only
# --------------------------------------------------------------------------


def check_local_socket_only(waiver: dict, repo_root: Path) -> CheckResult:
    """The carrier's service publishes no host port at all.

    "Local socket only" means there is no *network* route to the service:
    whatever reaches it, reaches it over a local Unix socket. The check
    therefore asserts that no host port is published — not even a loopback
    one, which is still a network route.

    A service that mounts no socket at all is *more* isolated than the
    premise requires, not less, so a missing socket mount is reported as
    supporting evidence and never as a failure.
    """
    wid = waiver.get("id", "?")
    offenders: list[str] = []
    evidence: list[str] = []
    for carrier in waiver.get("carriers") or []:
        for ref in services_for_image(carrier, _compose_paths(repo_root)):
            for entry in ref.service.get("ports") or []:
                offenders.append(
                    f"{ref.location} publishes {entry!r} (carrier {carrier!r}) — "
                    f"a local socket is not the only route"
                )
            for mount in socket_mounts(ref.service):
                evidence.append(f"{ref.location} mounts local socket {mount!r}")
    if offenders:
        return CheckResult(
            ok=False,
            message=(
                f"waiver {wid}: the local-socket-only premise is BROKEN — the "
                f"carrier is reachable by more than a local socket. "
                f"Re-justify this waiver or remove the exposure; do not delete "
                f"the waiver to silence CI."
            ),
            waiver_id=wid,
            check="local-socket-only",
            evidence=offenders,
        )
    return CheckResult(
        ok=True,
        message=f"waiver {wid}: local-socket-only — OK (no published port)",
        waiver_id=wid,
        check="local-socket-only",
        evidence=evidence,
    )


# --------------------------------------------------------------------------
# Check: dev-tooling-only
# --------------------------------------------------------------------------


def deployed_distributions(repo_root: Path) -> tuple[set[str], list[str]]:
    """The distributions installed into any deployed image, and where they come from.

    A service is *deployed* when a deployed compose file declares it and it is
    not behind a ``profiles:`` gate — a profiled service only starts when the
    profile is named explicitly, which is how this repository marks the
    CI-only images (``test``, ``traffic``). Its Python dependencies are the
    requirement files its Dockerfile copies in; third-party images contribute
    nothing here, because they bring packages this repository never declares.
    """
    names: set[str] = set()
    sources: list[str] = []
    for path in _compose_paths(repo_root):
        for dockerfile, context in compose_build_targets(path, include_profiled=False):
            for requirements in dockerfile_requirements(dockerfile, context):
                found = requirement_names(requirements)
                if not found:
                    continue
                rel = requirements
                try:
                    rel = requirements.relative_to(repo_root)
                except ValueError:  # pragma: no cover - defensive
                    pass
                label = f"{rel} ({dockerfile.name})"
                if label not in sources:  # a stack may build the same image twice
                    sources.append(label)
                names |= found
    return names, sources


def check_dev_tooling_only(waiver: dict, repo_root: Path) -> CheckResult:
    """The carrier package is not a declared dependency of any deployed image."""
    wid = waiver.get("id", "?")
    deployed, sources = deployed_distributions(repo_root)
    offenders: list[str] = []
    for carrier in waiver.get("carriers") or []:
        wanted = normalise_distribution(carrier)
        if wanted in deployed:
            offenders.append(
                f"{carrier!r} is a declared dependency of a deployed image "
                f"({', '.join(sources)})"
            )
    if offenders:
        return CheckResult(
            ok=False,
            message=(
                f"waiver {wid}: the dev-tooling-only premise is BROKEN — the "
                f"carrier is installed into a deployed image, so it is on a "
                f"production path. Re-justify this waiver or remove the "
                f"dependency; do not delete the waiver to silence CI."
            ),
            waiver_id=wid,
            check="dev-tooling-only",
            evidence=offenders,
        )
    return CheckResult(
        ok=True,
        message=f"waiver {wid}: dev-tooling-only — OK (not a deployed dependency)",
        waiver_id=wid,
        check="dev-tooling-only",
    )


# --------------------------------------------------------------------------
# Check: not-imported
# --------------------------------------------------------------------------


def _first_party_python_files(repo_root: Path) -> list[Path]:
    files: list[Path] = []
    for name in FIRST_PARTY_PY_DIRS:
        root = repo_root / name
        if not root.is_dir():
            continue
        for path in root.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            files.append(path)
    return sorted(files)


def imported_modules(repo_root: Path) -> dict[str, list[str]]:
    """Every dotted module path imported by first-party code.

    The key is the module path, the value is the files that import it. Only
    *static* imports are seen — a dynamic ``importlib.import_module("x")``
    is invisible to a source scan, and the docstring says so.
    """
    found: dict[str, list[str]] = {}
    for path in _first_party_python_files(repo_root):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, ValueError):
            continue
        try:
            rel = str(path.relative_to(repo_root))
        except ValueError:  # pragma: no cover - defensive
            rel = str(path)
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    continue  # a relative import: same package, not a dependency
                if node.module:
                    names = [node.module]
            for name in names:
                parts = name.split(".")
                for index in range(1, len(parts) + 1):
                    found.setdefault(".".join(parts[:index]), []).append(rel)
    return found


def _candidate_import_names(carrier: str) -> set[str]:
    wanted = normalise_distribution(carrier)
    return {wanted} | IMPORT_ALIASES.get(wanted, set())


def check_not_imported(waiver: dict, repo_root: Path) -> CheckResult:
    """The carrier package is imported by no first-party module.

    "Not imported" is the operational sense of "not in the code path of
    anything we ship": the package is not imported by first-party code, and
    it is not a declared dependency of any deployed image. The second half
    matters because a package can enter a deployed image without anyone
    importing it — as a transitive dependency, declared one line away from
    the code that would have imported it.
    """
    wid = waiver.get("id", "?")
    imported = imported_modules(repo_root)
    deployed, sources = deployed_distributions(repo_root)
    offenders: list[str] = []
    for carrier in waiver.get("carriers") or []:
        candidates = _candidate_import_names(carrier)
        for module, files in sorted(imported.items()):
            components = {part.lower() for part in module.split(".")}
            if components & candidates:
                for filename in sorted(set(files)):
                    offenders.append(
                        f"{filename} imports {module!r} (carrier {carrier!r})"
                    )
        wanted = normalise_distribution(carrier)
        if wanted in deployed:
            offenders.append(
                f"{carrier!r} is a declared dependency of a deployed image "
                f"({', '.join(sources)})"
            )
    if offenders:
        return CheckResult(
            ok=False,
            message=(
                f"waiver {wid}: the not-imported premise is BROKEN — the "
                f"carrier is imported by first-party code or installed into a "
                f"deployed image. Re-justify this waiver or remove the "
                f"usage; do not delete the waiver to silence CI."
            ),
            waiver_id=wid,
            check="not-imported",
            evidence=offenders,
        )
    return CheckResult(
        ok=True,
        message=f"waiver {wid}: not-imported — OK (no first-party import)",
        waiver_id=wid,
        check="not-imported",
    )


# --------------------------------------------------------------------------
# Check: input-path-unreachable (attested)
# --------------------------------------------------------------------------


def check_input_path_unreachable(waiver: dict, repo_root: Path) -> CheckResult:
    """The unreachable path is documented in the waiver, not merely asserted."""
    wid = waiver.get("id", "?")
    evidence = waiver.get("reachability_evidence")
    if not isinstance(evidence, str) or not evidence.strip():
        return CheckResult(
            ok=False,
            message=(
                f"waiver {wid}: reachability 'input-path-unreachable' requires a "
                f"'reachability_evidence:' field naming the path that is not "
                f"reachable. Write down what the unreachable path is."
            ),
            waiver_id=wid,
            check="input-path-unreachable",
            kind="attested",
        )
    if len(evidence.strip()) < MIN_EVIDENCE_CHARS:
        return CheckResult(
            ok=False,
            message=(
                f"waiver {wid}: 'reachability_evidence' is too short "
                f"({len(evidence.strip())} chars, need {MIN_EVIDENCE_CHARS}) — "
                f"name the specific path that is not reachable."
            ),
            waiver_id=wid,
            check="input-path-unreachable",
            kind="attested",
            evidence=[evidence.strip()],
        )
    return CheckResult(
        ok=True,
        message=f"waiver {wid}: input-path-unreachable — attested",
        waiver_id=wid,
        check="input-path-unreachable",
        kind="attested",
        evidence=[evidence.strip()],
    )


# --------------------------------------------------------------------------
# The registry of checks
# --------------------------------------------------------------------------

CHECKS: dict[str, CheckSpec] = {
    spec.name: spec
    for spec in (
        CheckSpec(
            "internal-monitoring-only",
            "machine",
            "the carrier's service publishes no host port on a non-loopback address",
            check_internal_monitoring_only,
        ),
        CheckSpec(
            "local-socket-only",
            "machine",
            "the carrier's service publishes no host port at all",
            check_local_socket_only,
        ),
        CheckSpec(
            "dev-tooling-only",
            "machine",
            "the carrier package is not a declared dependency of any deployed image",
            check_dev_tooling_only,
        ),
        CheckSpec(
            "not-imported",
            "machine",
            "the carrier package is imported by no first-party module and is "
            "not a declared dependency of any deployed image",
            check_not_imported,
        ),
        CheckSpec(
            "input-path-unreachable",
            "attested",
            "the unreachable path is documented in 'reachability_evidence'",
            check_input_path_unreachable,
        ),
    )
}

#: The values a waiver may use for `reachability:`.
REACHABILITY_VALUES = frozenset(CHECKS)

#: The values whose premise is a documented human attestation rather than a
#: machine-checked fact.
ATTESTED_VALUES = frozenset(
    name for name, spec in CHECKS.items() if spec.kind == "attested"
)


def check_waiver(waiver: dict, repo_root: Path = REPO_ROOT) -> CheckResult | None:
    """Check one waiver. ``None`` when the waiver makes no reachability claim."""
    reachability = waiver.get("reachability")
    if not reachability:
        return None
    spec = CHECKS.get(str(reachability))
    if spec is None:
        return CheckResult(
            ok=False,
            message=(
                f"waiver {waiver.get('id')}: unknown reachability value "
                f"{reachability!r}. It must name a registered check: "
                f"{sorted(REACHABILITY_VALUES)}."
            ),
            waiver_id=str(waiver.get("id", "?")),
            check=str(reachability),
        )
    result = spec.run(waiver, repo_root)
    result.kind = spec.kind
    return result


def check_all(registry: dict, repo_root: Path = REPO_ROOT) -> list[CheckResult]:
    """Run every bound check in the registry."""
    results: list[CheckResult] = []
    for waiver in (registry or {}).get("waivers") or []:
        if not isinstance(waiver, dict):
            continue
        result = check_waiver(waiver, repo_root)
        if result is not None:
            results.append(result)
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check every waiver's reachability premise.")
    parser.add_argument(
        "--registry",
        type=Path,
        default=REPO_ROOT / "security" / "waivers.yaml",
        help="the waiver registry to check (default: security/waivers.yaml)",
    )
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--json", action="store_true", help="emit machine-readable output")
    args = parser.parse_args(argv)

    try:
        registry = _load_yaml(args.registry)
    except (OSError, yaml.YAMLError if yaml else ValueError) as exc:  # type: ignore[misc]
        print(f"✗ cannot read the waiver registry: {exc}", file=sys.stderr)
        return 2

    try:
        results = check_all(registry, args.repo_root)
    except (OSError, yaml.YAMLError if yaml else ValueError) as exc:  # type: ignore[misc]
        print(f"✗ cannot evaluate the reachability checks: {exc}", file=sys.stderr)
        return 2

    failures = [r for r in results if not r.ok]
    machine = sum(1 for r in results if r.kind == "machine")
    attested = sum(1 for r in results if r.kind == "attested")

    if args.json:
        print(
            json.dumps(
                {
                    "checked": len(results),
                    "machine": machine,
                    "attested": attested,
                    "failures": [r.as_dict() for r in failures],
                    "results": [r.as_dict() for r in results],
                },
                indent=2,
            )
        )
        return 1 if failures else 0

    for result in results:
        if result.ok:
            print(f"✓ {result.message}")
            for line in result.evidence:
                print(f"    {line}")
        else:
            print(f"✗ {result.message}", file=sys.stderr)
            for line in result.evidence:
                print(f"    {line}", file=sys.stderr)

    print(
        f"\n{len(results)} bound check(s): {machine} machine-checked, "
        f"{attested} attested, {len(failures)} broken"
    )
    if failures:
        print(
            "✗ a broken premise is a re-justification, not a deletion — "
            "fix the exposure or re-write the justification.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
