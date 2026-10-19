#!/usr/bin/env python3
"""scripts/trivy_image_report.py — the `make scan-images` per-image gate (Phase 847b).

WHY THIS EXISTS
---------------
`make scan-images` used to decide pass/fail by counting severity *tokens* in
Trivy's human-readable table:

    high=$$(echo "$$result" | grep -v "Total:" | grep -c "HIGH" || true);

That number is wrong in both directions, and it is the number a person triaging
under pressure reads and reasons from:

  UNDERCOUNT — Trivy's table groups by library and prints the severity **once
  per group**; the continuation rows for the other CVEs in that group leave the
  Severity column blank. Measured on a live capture of **14 real Trivy tables**
  (Phase 847b): the old expression returned **1 for all 14**, while Trivy's own
  line reported 4, 5 or 6. The worst case is pinned in
  tests/fixtures/trivy-grafana-kin-openapi.table.txt — an image carrying 5
  kin-openapi HIGHs (CVE-2026-100349, -100351..-100354) counts as 1, which
  invites exactly the wrong conclusion: "a single CVE, easy to waive".

  NOT A COUNT AT ALL — the expression counts *lines containing a word*, with
  nothing tying a hit back to a distinct CVE id, and a severity cell left blank
  on a continuation row is simply invisible to it. Across the capture above it
  returned the same number (1) for tables whose true counts were 4, 5 and 6: it
  does not track the number of findings in either direction.

  SILENT PASS — `grep -c` on a *failed* scan (image unpullable, Trivy error)
  finds no "HIGH" and counts 0, so a scanner that never ran was indistinguish-
  able from a clean image. That is the worst failure mode of the three.

Finally, the one line that carries Trivy's own correct count —
`Total: 5 (HIGH: 5, CRITICAL: 0)` — was explicitly discarded by the
`grep -v "Total:"` above.

So the count now comes from Trivy JSON (`.Results[].Vulnerabilities[]`) via the
single parser in `scripts/check_trivyignore_drift.py`, and a scan that cannot be
parsed is a FAILURE, not a pass.

Modes
-----
    trivy_image_report.py IMAGE [IMAGE ...]      # run Trivy (JSON) per image
    trivy_image_report.py --json-file REPORT     # read an already-captured
                                                 # report (offline, unit tests)

Exit status (this IS a gate, unlike scan_summary.py which only reports):
    0  no HIGH/CRITICAL findings
    1  HIGH/CRITICAL findings present
    2  a scan or report could not be run/parsed — treat as failure, never a pass
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess  # nosec B404 -- invokes the pinned trivy container by fixed argv
import sys
from pathlib import Path

try:  # works as `python3 scripts/x.py` and as `from scripts.x import ...`
    from scripts.check_trivyignore_drift import VulnRow, load_report, vuln_rows
except ImportError:  # invoked directly, scripts/ on sys.path
    # Same names from an equivalent module path (scripts/ has no __init__.py, so
    # this file is importable either way) — not a real redefinition.
    from check_trivyignore_drift import VulnRow, load_report, vuln_rows  # type: ignore[no-redef]

TRIVY_IMAGE = "aquasec/trivy:0.71.0"
GATING_SEVERITIES = "HIGH,CRITICAL"
DEFAULT_IGNOREFILE = ".trivyignore.third-party"
# The repo is mounted read-only into the Trivy container here (see run_trivy),
# so this is the prefix on every path Trivy itself reads.
SCAN_MOUNT = "/scan"

# CRITICAL first: the gate fails on both, but a human reads the top of the list.
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1}


def resolve_ignorefile(ignorefile: str, cwd: str | os.PathLike[str] | None = None) -> str:
    """Validate `--ignorefile` and return the exact path Trivy will read.

    Exactly two spellings are accepted:

        .trivyignore.third-party           repo-relative — how humans write it
        /scan/.trivyignore.third-party     the container path it is mounted at,
                                           which is what `make scan-*` and the
                                           Phase 822 guard tests speak

    Anything else is *rejected*, not silently re-homed. This matters: taking a
    plain `basename()` of whatever was passed would turn `/etc/hosts` into
    `/scan/hosts` — a typo in a security gate quietly resolving to some other
    file, which is exactly the class of silent wrongness this phase exists to
    remove.

    FileNotFoundError if the file is not in the repo root: an ignore file we
    cannot see must fail here, with a message, rather than becoming a Trivy
    FATAL inside a container the operator has to decode.

    Idempotent, so a caller may pass the result straight back in.
    """
    prefix = f"{SCAN_MOUNT}/"
    name = ignorefile[len(prefix):] if ignorefile.startswith(prefix) else ignorefile
    if not name or name in {".", ".."} or "/" in name or os.sep in name:
        raise ValueError(
            f"--ignorefile must be a file in the repo root, e.g. {DEFAULT_IGNOREFILE!r} "
            f"or {prefix + DEFAULT_IGNOREFILE!r} (got {ignorefile!r})"
        )
    base = Path(cwd) if cwd is not None else Path.cwd()
    if not (base / name).is_file():
        raise FileNotFoundError(
            f"ignore file {name!r} does not exist in {base} — it is generated from "
            f"security/waivers.yaml by scripts/render_waivers.py"
        )
    return f"{prefix}{name}"


def counts(rows: list[VulnRow]) -> dict[str, int]:
    """Tally rows by severity, always reporting both keys so the output is stable."""
    out = {"HIGH": 0, "CRITICAL": 0}
    for row in rows:
        out[row.severity] += 1
    return out


def sort_rows(rows: list[VulnRow]) -> list[VulnRow]:
    """CRITICAL first, then by CVE id — deterministic output for humans and diffs."""
    return sorted(rows, key=lambda r: (_SEVERITY_RANK.get(r.severity, 9), r.cve))


def render_table(rows: list[VulnRow]) -> str:
    """A compact per-CVE table, built from the JSON rows rather than re-parsed text."""
    if not rows:
        return ""
    headers = ("PACKAGE", "CVE", "INSTALLED", "SEVERITY")
    cols = [
        [headers[0], *(r.package for r in rows)],
        [headers[1], *(r.cve for r in rows)],
        [headers[2], *(r.installed for r in rows)],
        [headers[3], *(r.severity for r in rows)],
    ]
    widths = [max(len(c) for c in col) for col in cols]
    lines = []
    for i in range(len(rows) + 1):
        # Package/CVE/Installed are left-aligned; severity right-aligned so the
        # single most important column reads straight down.
        cells = [
            cols[0][i].ljust(widths[0]),
            cols[1][i].ljust(widths[1]),
            cols[2][i].ljust(widths[2]),
            cols[3][i].rjust(widths[3]),
        ]
        lines.append("    " + "  ".join(cells).rstrip())
    return "\n".join(lines)


def trivy_cmd(image: str, ignorefile: str, cache: str, docker_socket: bool = False) -> list[str]:
    """The exact argv Trivy receives, built without running anything.

    Split out of :func:`run_trivy` so the gate's *policy* — which severities it
    scans for, which ignorefile it applies, and that it reads JSON rather than a
    human table — is assertable without docker or network (Phase 847b).

    `docker_socket` is required for locally-built images: they exist only in the
    local daemon, not in any registry, so without the mount Trivy cannot find
    them. It is deliberately opt-in — third-party images come from registries and
    need no host socket at all.
    """
    os.makedirs(cache, exist_ok=True)
    mounts = ["-v", f"{os.getcwd()}:/scan:ro", "-v", f"{cache}:/root/.cache/trivy"]
    if docker_socket:
        mounts += ["-v", "/var/run/docker.sock:/var/run/docker.sock"]
    return [
        "docker", "run", "--rm",
        *mounts,
        TRIVY_IMAGE, "image",
        "--severity", GATING_SEVERITIES,
        "--exit-code", "0",
        "--no-progress", "--scanners", "vuln",
        "--ignorefile", resolve_ignorefile(ignorefile),
        "--skip-version-check",
        "--format", "json", image,
    ]


def run_trivy(image: str, ignorefile: str, cache: str, docker_socket: bool = False) -> dict:
    """Run the pinned Trivy container against `image` and return the parsed JSON.

    Raises RuntimeError if Trivy produced no usable JSON — a scan we could not
    read must never be mistaken for a scan that found nothing (Phase 847b).
    """
    cmd = trivy_cmd(image, ignorefile, cache, docker_socket)
    proc = subprocess.run(cmd, capture_output=True, text=True)  # nosec B603 -- fixed argv, no shell
    if not proc.stdout.strip():
        raise RuntimeError(f"trivy produced no output: {proc.stderr.strip()[:300]}")
    try:
        return json.loads(proc.stdout)
    except ValueError as exc:
        raise RuntimeError(f"trivy output was not JSON ({exc}): {proc.stdout[:200]!r}") from exc


def report(rows: list[VulnRow], label: str, stream=None) -> int:
    """Print the per-image table + summary, returning this image's exit code.

    `stream` defaults to the *current* `sys.stdout` (not a def-time binding), so
    callers can capture the output and unit tests see it.
    """
    if stream is None:
        stream = sys.stdout
    c = counts(rows)
    if not rows:
        print("    \u2713 no HIGH/CRITICAL findings", file=stream)
        return 0
    print(render_table(sort_rows(rows)), file=stream)
    print(
        f"    \u2717 {c['HIGH']} HIGH + {c['CRITICAL']} CRITICAL CVE(s) in {label}",
        file=stream,
    )
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("images", nargs="*", help="image references to scan with Trivy")
    parser.add_argument(
        "--ignorefile", default=DEFAULT_IGNOREFILE,
        help="the ignore file Trivy applies, as a repo-relative name "
             f"({DEFAULT_IGNOREFILE}) or as the path it is mounted at "
             f"({SCAN_MOUNT}/{DEFAULT_IGNOREFILE})",
    )
    parser.add_argument(
        "--docker-socket", action="store_true",
        help="mount the host docker socket — required for locally-built images "
             "that exist in no registry",
    )
    parser.add_argument(
        "--json-file", action="append", default=[], metavar="PATH",
        help="read an already-captured Trivy report instead of scanning (repeatable)",
    )
    args = parser.parse_args(argv)

    if not args.images and not args.json_file:
        parser.error("give at least one IMAGE, or --json-file PATH")

    failures = 0
    for path in args.json_file:
        report_path = Path(path)
        try:
            rows = vuln_rows(load_report(report_path))
        except ValueError as exc:  # unreadable/!json report
            print(f"    \u2717 {exc}", file=sys.stderr)
            failures += 1
            continue
        failures += report(rows, report_path.stem)

    cache = os.environ.get("TRIVY_CACHE", os.path.expanduser("~/.cache/trivy"))
    ignorefile = args.ignorefile
    if args.images:
        try:
            ignorefile = resolve_ignorefile(args.ignorefile)
        except (ValueError, FileNotFoundError) as exc:
            # A gate pointed at an ignore file it cannot read must not scan.
            print(f"    \u2717 {exc}", file=sys.stderr)
            return 2
    for image in args.images:
        try:
            rows = vuln_rows(run_trivy(image, ignorefile, cache, args.docker_socket))
        except RuntimeError as exc:
            # A scan we could not read is a FAILURE, not a clean image.
            print(f"    \u2717 could not scan {image}: {exc}", file=sys.stderr)
            failures += 1
            continue
        failures += report(rows, image)

    return 1 if failures else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
