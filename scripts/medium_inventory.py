#!/usr/bin/env python3
"""scripts/medium_inventory.py — measure the MEDIUM vulnerability surface.

Phase 847e is "measure, then extend": the HIGH/CRITICAL gate exists, the
programme's stated aim reaches MEDIUM as well, and nobody may guess at how big
the MEDIUM surface is before deciding how to gate it. This script is the
measurement, and its output is the evidence the decision is made from.

WHAT IT MEASURES
----------------
For every surface the repository actually deploys — the third-party images
pinned in the compose files, the first-party images the Makefile builds, and
the Python dependency surface — it reports:

* how many **unwaived** MEDIUM findings that surface carries;
* how many of them have a **fixed version published** for the package that
  carries them (the cheapest class of fix: same package, newer version);
* which packages contribute the most findings;
* the surface's **reachability claim** — whether the service is reachable from
  outside our network at all — because a finding on an internal-only surface
  is a different proposition from one on a published port.

THE SEVERITY DIMENSION
----------------------
MEDIUM findings are invisible to the current gate: the scanner is told to
report `HIGH,CRITICAL`, so a MEDIUM row never exists in the report. Measuring
MEDIUM therefore needs the severity to become a parameter, which is why
`scripts/trivy_image_report.py` takes `severities=` and keeps
`GATING_SEVERITIES` as the default for every other caller.

THE PYTHON SURFACE HAS NO SEVERITY
----------------------------------
`pip-audit` reports no severity at all — its JSON carries `id`, `aliases`,
`fix_versions` and `description`, and nothing else. The existing gate therefore
treats every pip-audit finding as gating, at `HIGH`. This script does not
invent a MEDIUM band for it: the Python surface is reported as *no severity
dimension*, and is excluded from the MEDIUM baseline with a note, rather than
being silently counted as "clean at MEDIUM".

NEVER FAIL OPEN
---------------
A surface that could not be scanned is an error, not an empty result. This
script exits 2 and writes nothing: a partial inventory that reads as "the
MEDIUM surface is small" is worse than no inventory, because the decision would
be made on it.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

try:  # works as `python3 scripts/x.py` and as `from scripts.x import ...`
    from scripts.check_image_versions import (
        FIRST_PARTY_IMAGES,
        scan_gate_compose_paths,
        third_party_image_refs,
    )
    from scripts.compose_exposure import service_publishes_host_port
    from scripts.scan_baseline import (
        PYPI_SURFACE,
        build_baseline,
        image_name,
        record_findings,
        render_baseline,
        scan_image,
        surface_for_image,
    )
except ImportError:  # invoked directly, scripts/ on sys.path
    from check_image_versions import (  # type: ignore[no-redef]
        FIRST_PARTY_IMAGES,
        scan_gate_compose_paths,
        third_party_image_refs,
    )
    from compose_exposure import service_publishes_host_port  # type: ignore[no-redef]
    from scan_baseline import (  # type: ignore[no-redef]
        PYPI_SURFACE,
        build_baseline,
        image_name,
        record_findings,
        render_baseline,
        scan_image,
        surface_for_image,
    )

MEDIUM_SEVERITIES = "MEDIUM"
DEFAULT_OUT = Path("security/baseline-medium.json")
DEFAULT_MARKDOWN = Path("security/medium-inventory.md")
MAKEFILE = "Makefile"


class InventoryError(RuntimeError):
    """The inventory could not be completed.

    Callers must treat this as a FAILURE. An inventory that is missing a
    surface reads as "the MEDIUM surface is smaller than it is", and a decision
    made on that is a decision made on a lie.
    """


def first_party_refs() -> list[str]:
    """The first-party images, read from the Makefile — the same authority.

    The Makefile's `FIRST_PARTY_IMAGES` is what the gate scans and what the
    monitor scans. Reading it here means the inventory cannot describe a
    different set of surfaces than the gate judges, which is the failure mode
    a second, independent list would introduce.
    """
    text = Path(MAKEFILE).read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("FIRST_PARTY_IMAGES"):
            _, _, values = line.partition(":=")
            return [v.strip() for v in values.split() if v.strip()]
    raise InventoryError(
        f"{MAKEFILE} has no FIRST_PARTY_IMAGES assignment — cannot enumerate the "
        f"first-party surfaces"
    )


def _service_is_internal_only(service: dict) -> bool:
    """True when a compose service publishes no host port.

    This is 847f's `internal-monitoring-only` claim, computed from the compose
    files. A finding on such a surface is not reachable from outside our
    network, which is a materially different proposition from a finding on a
    published port — and it is the reachability signal that exists today,
    without any new analysis.

    Fail-safe by design: anything this cannot read as loopback-only is
    reported as *published*, so the inventory never understates a surface's
    exposure.

    The port parsing itself lives in `scripts/compose_exposure.py`, shared with
    the 847f reachability checks: two implementations of "is this published?"
    is exactly the divergence that made the first version of this function
    mis-report every default-bound monitoring service as published.
    """
    return not service_publishes_host_port(service)


def exposure_by_surface() -> dict[str, str]:
    """Classify every surface that appears in a compose file.

    Three states, all structural facts read from the compose files:

    ``published``
        The service binds a host port that is not loopback-only.
    ``no published host port``
        The service binds no host port, or only loopback ones.
    ``not deployed in compose``
        The image is not in any compose file at all (CI-only build artefacts).

    A surface is *published* if **any** compose file publishes it — the union,
    not the intersection, because a service that is loopback-only in the
    monitoring file but published in the production file is published.

    This is deliberately a statement about the compose file, not a claim about
    the internet: a service with no published host port can still be reachable
    through a front door that does publish one. The report says so.
    """
    exposure: dict[str, str] = {}
    for path in scan_gate_compose_paths():
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            continue
        services = (doc or {}).get("services") or {}
        if not isinstance(services, dict):
            continue
        for service in services.values():
            if not isinstance(service, dict):
                continue
            image = service.get("image")
            if not isinstance(image, str) or not image:
                continue
            surface = surface_for_image(image_name(image))
            state = "no published host port" if _service_is_internal_only(service) else "published"
            # The union is the fail-safe direction: once any file publishes a
            # surface, it stays published.
            if exposure.get(surface) != "published":
                exposure[surface] = state
    return exposure


def python_package_names() -> set[str]:
    """The Python distributions this repository installs, from the requirements files.

    Read from the files rather than hard-coded, so the answer cannot drift away
    from what we actually ship. A distribution whose name differs from its
    import name is a known wrinkle; the classification below only needs to
    recognise "this is one of ours", and every name in the requirements files
    is one of ours.

    The three names the images install themselves are added explicitly: they
    are Python distributions we ship, but no requirements file lists them, and
    a fix for them arrives when *we* rebuild the image.
    """
    names: set[str] = {"pip", "setuptools", "wheel"}
    for path in sorted(Path(".").glob("requirements*.txt")) + sorted(
        Path("management").glob("requirements*.txt")
    ):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            name = re.split(r"[<>=!~\[]", line, maxsplit=1)[0].strip()
            if name:
                names.add(name.lower().replace("_", "-"))
    return names


def classify_package(package: str, python_packages: set[str]) -> str:
    """What a finding is in — and therefore how a fix for it could arrive.

    * ``go`` — the Go standard library (Trivy names it ``stdlib``) or a Go
      module path. A fix arrives when the upstream project rebuilds its image
      with a newer Go toolchain.
    * ``python`` — one of the Python distributions we install ourselves. A fix
      arrives when we rebuild our own image.
    * ``os`` — an operating-system package. A fix arrives when the upstream
      project rebuilds its image on a newer base.

    The Go test is the *shape* of a module path rather than a list of names: a
    Go module path always contains a "/" and a dot in its first segment
    (``golang.org/x/net``, ``github.com/foo/bar``). Operating-system packages
    contain no "/" at all, and Python distributions contain none either, so the
    three kinds cannot overlap.
    """
    name = str(package or "")
    if name == "stdlib":
        return "go"
    if "/" in name:
        head = name.split("/", 1)[0]
        return "go" if "." in head else "os"
    if name.lower().replace("_", "-") in python_packages:
        return "python"
    return "os"


def measure_image(
    ref: str,
    first_party: bool,
    cache: str,
    severities: str,
    python_packages: set[str] | None = None,
) -> dict:
    """Scan one image surface and summarise it (plus the raw findings)."""
    rows, digest = scan_image(ref, first_party, cache, severities=severities)
    entry = record_findings(rows, ref, digest, severities=severities)
    findings: dict[str, dict] = entry["findings"]
    with_fix = sorted(cid for cid, e in findings.items() if e.get("fixed"))
    packages = Counter(str(e.get("package")) for e in findings.values())
    kinds = Counter(
        classify_package(str(e.get("package")), python_packages or set())
        for e in findings.values()
    )
    return {
        "ref": ref,
        "digest": entry.get("digest", ""),
        "count": len(findings),
        "with_fix": len(with_fix),
        "packages": packages.most_common(8),
        "kinds": dict(kinds),
        "findings": findings,
    }


def measure(
    severities: str,
    cache: str,
    include_pypi: bool,
) -> tuple[dict[str, dict], list[str]]:
    """Measure every surface. Returns (surfaces, failures)."""
    refs: list[tuple[str, bool]] = []
    for ref in third_party_image_refs(scan_gate_compose_paths()):
        refs.append((ref, False))
    for ref in first_party_refs():
        refs.append((ref, True))
    # Stable order, no duplicates: the same image must not be measured twice
    # under two keys.
    seen: set[str] = set()
    ordered: list[tuple[str, bool]] = []
    for ref, first_party in refs:
        if ref in seen:
            continue
        seen.add(ref)
        ordered.append((ref, first_party))

    exposure = exposure_by_surface()
    python_packages = python_package_names()
    surfaces: dict[str, dict] = {}
    failures: list[str] = []
    for ref, first_party in ordered:
        surface = surface_for_image(image_name(ref))
        try:
            measured = measure_image(ref, first_party, cache, severities, python_packages)
        except (RuntimeError, OSError, ValueError) as exc:
            print(f"✗ could not scan {ref}: {exc}", file=sys.stderr)
            failures.append(surface)
            continue
        measured["scope"] = "first-party" if first_party else "third-party"
        measured["exposure"] = exposure.get(surface, "not deployed in compose")
        surfaces[surface] = measured
        print(
            f"  {surface}: {measured['count']} {severities} finding(s), "
            f"{measured['with_fix']} with a published fix"
        )

    if include_pypi:
        # pip-audit reports no severity, so there is no MEDIUM band to measure
        # here. It is recorded as a surface with no severity dimension rather
        # than counted as zero.
        surfaces[PYPI_SURFACE] = {
            "ref": "requirements.txt",
            "digest": "",
            "count": 0,
            "with_fix": 0,
            "packages": [],
            "kinds": {},
            "findings": {},
            "scope": "python",
            "exposure": "n/a",
            "severity_dimension": False,
            "note": (
                "pip-audit reports no severity — its JSON carries id, aliases, "
                "fix_versions and description only. The existing gate therefore "
                "treats every pip-audit finding as gating (HIGH). There is no "
                "MEDIUM band to measure on this surface, and none is invented "
                "here."
            ),
        }
    return surfaces, failures


def ratchet(baseline: dict) -> dict:
    """The ratchet's state: what is recorded, what is allowed, whether it holds.

    The ratchet is measured against the **committed record**, never against a
    live scan. The Trivy database churns daily, so a live comparison would make
    the ratchet a coin-flip — and a coin-flip is not a ratchet. The record is
    the thing a reviewer can argue with.

    `holds` is false when the recorded count has grown past the ceiling: the
    record may only shrink, so accretion has to be paid for deliberately (by
    lowering the ceiling in a reviewed edit), not absorbed by a file that grows
    on its own.
    """
    recorded = sum(
        len(entry.get("findings", {})) for entry in (baseline.get("surfaces") or {}).values()
    )
    ceiling = int(baseline.get("ceiling", 0))
    return {
        "recorded": recorded,
        "ceiling": ceiling,
        "holds": recorded <= ceiling,
    }


def summarise(surfaces: dict[str, dict]) -> dict:
    """The headline numbers the decision is made from."""
    total = sum(int(s.get("count", 0)) for s in surfaces.values())
    with_fix = sum(int(s.get("with_fix", 0)) for s in surfaces.values())
    published = sum(
        int(s.get("count", 0))
        for s in surfaces.values()
        if s.get("exposure") == "published"
    )
    first_party = sum(
        int(s.get("count", 0)) for s in surfaces.values() if s.get("scope") == "first-party"
    )
    third_party = sum(
        int(s.get("count", 0)) for s in surfaces.values() if s.get("scope") == "third-party"
    )
    kinds: Counter = Counter()
    for data in surfaces.values():
        for kind, count in (data.get("kinds") or {}).items():
            kinds[kind] += int(count)
    return {
        "total": total,
        "with_fix": with_fix,
        "without_fix": total - with_fix,
        "published": published,
        "no_published_port": total - published,
        "first_party": first_party,
        "third_party": third_party,
        "surfaces": len(surfaces),
        "kinds": dict(kinds),
    }


def render_markdown(surfaces: dict[str, dict], severities: str) -> str:
    """The human-readable report — the artefact the decision is argued from."""
    s = summarise(surfaces)
    lines = [
        f"# MEDIUM vulnerability inventory ({severities})",
        "",
        f"Recorded: {datetime.date.today().isoformat()} — produced by "
        "`scripts/medium_inventory.py`. The numbers below are the script's "
        "output, not a hand-written summary.",
        "",
        "## Headline",
        "",
        f"- **{s['total']}** unwaived {severities} finding(s) across "
        f"**{s['surfaces']}** surface(s)",
        f"- **{s['with_fix']}** of them have a **published fix** for the same "
        f"package ({s['without_fix']} have none published)",
        f"- **{s['published']}** are on a surface that publishes a host port; "
        f"**{s['no_published_port']}** are on a surface that does not",
        f"- **{s['first_party']}** on images this repository builds, "
        f"**{s['third_party']}** on third-party images",
        "",
        "The decision this measurement informed, and the reasoning behind it, are "
        "recorded in `docs/phases/complete/PHASE_847e.md`.",
        "",
        "## By kind — how a fix could arrive",
        "",
        "| Kind | Findings | A fix arrives when… |",
        "|------|----------|---------------------|",
        f"| Go (standard library or module) | {s['kinds'].get('go', 0)} | the upstream project "
        "rebuilds its image with a newer Go toolchain |",
        f"| Python (a distribution we install) | {s['kinds'].get('python', 0)} | we rebuild our "
        "own image |",
        f"| OS or base-image package | {s['kinds'].get('os', 0)} | the upstream project "
        "rebuilds its image on a newer base |",
        "",
        "## Reachability",
        "",
        f"- **{s['third_party']}** of the {s['total']} findings are inside third-party "
        "images, whose binaries and packages have **no static reachability signal "
        "available to us** — their source is not ours to analyse, and the operating-system "
        "packages in them are not linked against anything we can call.",
        f"- **{s['first_party']}** are in images this repository builds.",
        "- Nothing here is recorded as *unreachable*. A reachability claim without a "
        "check behind it is the one thing this programme is not allowed to make: Phase "
        "847f is what turns a claim into an assertion, and until then the honest "
        "answer for every one of these findings is **unknown**.",
        "",
        "## Per surface",
        "",
        "| Surface | Scope | Exposure | Findings | With a published fix | Top packages |",
        "|---------|-------|----------|----------|----------------------|--------------|",
    ]
    for surface, data in sorted(surfaces.items()):
        packages = ", ".join(f"{name}×{n}" for name, n in (data.get("packages") or [])[:3])
        lines.append(
            f"| `{surface}` | {data.get('scope', '?')} | {data.get('exposure', '?')} | "
            f"{data.get('count', 0)} | {data.get('with_fix', 0)} | {packages} |"
        )
    notes = [d for d in surfaces.values() if d.get("note")]
    if notes:
        lines += ["", "## Notes", ""]
        for data in notes:
            lines += [f"- **{data.get('ref')}**: {data['note']}"]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--severities", default=MEDIUM_SEVERITIES,
        help=f"severity band to measure (default: {MEDIUM_SEVERITIES})",
    )
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="baseline path to write")
    parser.add_argument("--markdown", default=str(DEFAULT_MARKDOWN), help="markdown report path")
    parser.add_argument(
        "--no-record", action="store_true",
        help="measure and print only; write no baseline and no report",
    )
    parser.add_argument("--no-pypi", action="store_true", help="skip the Python dependency surface")
    args = parser.parse_args(argv)

    cache = os.environ.get("TRIVY_CACHE", os.path.expanduser("~/.cache/trivy"))
    print(f"=== measuring the {args.severities} surface ===")
    surfaces, failures = measure(args.severities, cache, not args.no_pypi)
    if failures:
        print(
            f"✗ {len(failures)} surface(s) could not be measured — inventory NOT written",
            file=sys.stderr,
        )
        return 2

    s = summarise(surfaces)
    print(
        f"\n{s['total']} {args.severities} finding(s) across {s['surfaces']} surface(s); "
        f"{s['with_fix']} with a published fix; {s['published']} on a published surface"
    )

    if args.no_record:
        print(json.dumps(s, indent=2, sort_keys=True))
        return 0

    # The recorded baseline carries the *image* surfaces only: the Python
    # surface has no severity dimension, so it has no MEDIUM entry to record.
    entries = {
        surface: {
            "findings": data["findings"],
            **({"ref": data["ref"]} if data.get("ref") else {}),
            **({"digest": data["digest"]} if data.get("digest") else {}),
        }
        for surface, data in surfaces.items()
        if data.get("scope") in {"first-party", "third-party"}
    }
    recorded = sum(len(entry["findings"]) for entry in entries.values())
    baseline = build_baseline(entries, datetime.date.today().isoformat())
    # The ratchet ceiling: the recorded count at the moment of the decision.
    # It may only go down, and a unit test holds it there.
    baseline["ceiling"] = recorded
    Path(args.out).write_text(render_baseline(baseline), encoding="utf-8")
    print(f"✓ wrote {args.out} ({recorded} finding(s), ceiling {recorded})")

    Path(args.markdown).write_text(
        render_markdown(surfaces, args.severities), encoding="utf-8"
    )
    print(f"✓ wrote {args.markdown}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
