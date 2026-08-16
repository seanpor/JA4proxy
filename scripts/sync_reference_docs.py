#!/usr/bin/env python3
"""
sync_reference_docs.py — generate the reference lists from the things they
describe, instead of hand-maintaining them (Phase 815).

    ┌───────────────────────────────────────────────────────────────────────┐
    │ STATUS: UNWIRED WIP for Phase 815 — rescued 2026-08-15, NOT ACTIVE.   │
    │                                                                       │
    │ No Makefile target and no workflow invokes this. It has never been    │
    │ run against the real docs beyond a smoke test, and the docs it        │
    │ targets do not yet carry the BEGIN/END GENERATED markers it needs     │
    │ (running --check today reports exactly that).                         │
    │                                                                       │
    │ It was written 2026-08-06 and survived only on the                    │
    │ `handoff-to-deepseek` branch, which was about to be deleted. It is    │
    │ preserved here so Phase 815 (PROPOSED) can pick it up rather than     │
    │ rewrite it — HANDOFF-2026-08-06.md records that it also BLOCKS 814b,  │
    │ which needs the same derive-doc-from-reality + --check drift gate.    │
    │                                                                       │
    │ Do not wire this into `make lint` or CI until Phase 815 is approved   │
    │ and it has real tests. tests/unit/test_sync_reference_docs_smoke.py   │
    │ only guards against bit-rot; it does not validate the output.         │
    └───────────────────────────────────────────────────────────────────────┘

Three documents under ``docs/reference/`` enumerate artefacts that already
exist elsewhere in the repo. All three had drifted before this script existed:

    MAKEFILE_TARGETS.md   187 targets, 167 documented, 56 missing -- AND 36
                          documented that no longer exist (go-parity,
                          go-rollback, go-start: Phase 15 leftovers). Wrong in
                          both directions.
    SCRIPTS.md            119 scripts, 45 documented. 63% missing.
    DOCKER_IMAGES.md      4 of 10 Dockerfiles unlisted -- including
                          Dockerfile.go-proxy, which builds the PRODUCTION
                          PROXY, in a file docs/README.md calls "the canonical
                          registry of all images".

Nothing caught it: ``make lint-meta``'s documentation-sync check is
one-directional. It verifies that commands *mentioned in docs* exist in the
Makefile, not that Makefile targets are documented.

This is the third time this project has been bitten by a hand-maintained list
(Phase 810's TRIVY_IMAGES drift hid 113 findings across three never-scanned
images; Phase 812 killed the KNOWN_ACTION_SHAS table), so this follows the
pattern Phase 332 already established for TODO.md / PROJECT_STATUS.md: derive
it, and gate on drift.

Hand-written prose is preserved. Only content between markers is replaced:

    <!-- BEGIN GENERATED: make-targets -->
    ...regenerated table...
    <!-- END GENERATED: make-targets -->

Usage:
    python3 scripts/sync_reference_docs.py            # regenerate in place
    python3 scripts/sync_reference_docs.py --check    # CI gate: fail on drift
    python3 scripts/sync_reference_docs.py --migrate  # one-time, see below

``--migrate`` lifts descriptions that currently live only in
MAKEFILE_TARGETS.md into the Makefile as ``## `` comments, so the migration to
generated docs does not throw away work someone already did. Run once.
"""

from __future__ import annotations

import argparse
import difflib
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

MAKEFILE = ROOT / "Makefile"
SCRIPTS_DIR = ROOT / "scripts"
TARGETS_DOC = ROOT / "docs" / "reference" / "MAKEFILE_TARGETS.md"
SCRIPTS_DOC = ROOT / "docs" / "reference" / "SCRIPTS.md"
IMAGES_DOC = ROOT / "docs" / "reference" / "DOCKER_IMAGES.md"

BEGIN = "<!-- BEGIN GENERATED: {key} -->"
END = "<!-- END GENERATED: {key} -->"

# Targets that exist for `make` plumbing rather than for humans to invoke.
# Listing them adds noise without adding information.
INTERNAL_TARGETS = frozenset({"all", "default", ".PHONY"})


# ---------------------------------------------------------------------------
# Parsing — the Makefile
# ---------------------------------------------------------------------------

TARGET_RE = re.compile(
    r"^(?P<name>[a-z][a-z0-9_-]*)\s*:(?!=)(?P<deps>[^=#\n]*?)(?:##\s*(?P<desc>.*))?$",
    re.MULTILINE,
)
SECTION_RE = re.compile(r"^#\s*──+\s*(?P<title>.+?)\s*──+\s*$", re.MULTILINE)


@dataclass(frozen=True)
class Target:
    """One `make` target as declared in the Makefile."""

    name: str
    description: str
    deps: str
    section: str


def parse_makefile(text: str) -> list[Target]:
    """Extract every human-invocable target, tagged with its section heading.

    Sections come from the Makefile's own ``# ── Heading ──`` comments, so the
    generated document inherits the grouping the Makefile author intended
    rather than a second, drifting classification.
    """
    sections: list[tuple[int, str]] = [
        (m.start(), m.group("title")) for m in SECTION_RE.finditer(text)
    ]

    def section_for(pos: int) -> str:
        current = "General"
        for start, title in sections:
            if start < pos:
                current = title
            else:
                break
        return current

    targets: list[Target] = []
    seen: set[str] = set()
    for match in TARGET_RE.finditer(text):
        name = match.group("name")
        if name in INTERNAL_TARGETS or name in seen:
            continue
        seen.add(name)
        targets.append(
            Target(
                name=name,
                description=(match.group("desc") or "").strip(),
                deps=(match.group("deps") or "").strip(),
                section=section_for(match.start()),
            )
        )
    return targets


# ---------------------------------------------------------------------------
# Parsing — scripts
# ---------------------------------------------------------------------------


def _script_description(path: Path) -> str:
    """First meaningful line of a script's header comment or docstring."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""

    for i, raw in enumerate(lines[:40]):
        line = raw.strip()
        if not line or line.startswith("#!"):
            continue
        # Python docstring
        if line.startswith(('"""', "'''")):
            body = line.strip("\"'").strip()
            if body:
                return body
            if i + 1 < len(lines):
                return lines[i + 1].strip()
            return ""
        # Shell header comment
        if line.startswith("#"):
            body = line.lstrip("#").strip()
            # Skip decoration and the filename-only first line
            if not body or set(body) <= {"-", "=", "─"}:
                continue
            body = re.sub(rf"^{re.escape(path.name)}\s*[-—:]\s*", "", body)
            if body:
                return body
    return ""


def parse_scripts(makefile_text: str) -> list[tuple[str, str, str]]:
    """Return (script, invoking make target or '', description)."""
    rows: list[tuple[str, str, str]] = []
    for path in sorted(SCRIPTS_DIR.iterdir()):
        if not path.is_file() or path.suffix not in (".sh", ".py"):
            continue
        # Which target calls it? First match wins; '' when nothing does.
        caller = ""
        pattern = re.compile(
            rf"^([a-z][a-z0-9_-]*)\s*:[^\n]*\n(?:\t[^\n]*\n)*?\t[^\n]*{re.escape(path.name)}",
            re.MULTILINE,
        )
        found = pattern.search(makefile_text)
        if found:
            caller = found.group(1)
        rows.append((path.name, caller, _script_description(path)))
    return rows


# ---------------------------------------------------------------------------
# Parsing — images
# ---------------------------------------------------------------------------


def parse_first_party_images() -> list[tuple[str, str, str]]:
    """Return (image, dockerfile, base) for every first-party Dockerfile."""
    dockerfiles = sorted(ROOT.glob("deploy/docker/Dockerfile*")) + sorted(
        ROOT.glob("src/*/Dockerfile")
    )
    dockerfiles += [p for p in (ROOT / "Dockerfile.tools", ROOT / "Dockerfile.bandit") if p.exists()]

    # image: tag  <- from compose files, keyed by dockerfile path
    image_for: dict[str, str] = {}
    for compose in list(ROOT.glob("deploy/docker/docker-compose*.yml")) + [
        ROOT / "docker-compose.yml"
    ]:
        if not compose.exists():
            continue
        text = compose.read_text(encoding="utf-8", errors="replace")
        for block in re.finditer(
            r"dockerfile:\s*(?P<df>\S+)(?P<rest>(?:.|\n){0,400})", text
        ):
            image = re.search(r"^\s{4}image:\s*(?P<img>\S+)", block.group("rest"), re.MULTILINE)
            if image:
                image_for.setdefault(block.group("df"), image.group("img"))

    rows: list[tuple[str, str, str]] = []
    for path in dockerfiles:
        rel = str(path.relative_to(ROOT))
        text = path.read_text(encoding="utf-8", errors="replace")
        bases = re.findall(r"^FROM\s+(\S+)", text, re.MULTILINE)
        base = bases[-1] if bases else "—"
        rows.append((image_for.get(rel, "—"), rel, base))
    return sorted(rows, key=lambda r: r[1])


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_targets(targets: list[Target]) -> str:
    described = [t for t in targets if t.description]
    bare = [t for t in targets if not t.description]

    out: list[str] = [
        f"_{len(targets)} targets. Generated from the Makefile's own `##` help "
        "comments by `make sync` — do not edit this table by hand._",
        "",
    ]
    by_section: dict[str, list[Target]] = {}
    for t in described:
        by_section.setdefault(t.section, []).append(t)

    for section in sorted(by_section):
        out.append(f"### {section}")
        out.append("")
        out.append("| Target | Description |")
        out.append("|--------|-------------|")
        for t in sorted(by_section[section], key=lambda x: x.name):
            out.append(f"| `{t.name}` | {t.description} |")
        out.append("")

    if bare:
        out.append("### Undocumented")
        out.append("")
        out.append(
            f"_{len(bare)} targets carry no `##` description. They are listed "
            "here rather than omitted, so the gap stays visible instead of "
            "becoming invisible again. Fix one by adding `## <description>` to "
            "its rule in the Makefile._"
        )
        out.append("")
        out.append("| Target |")
        out.append("|--------|")
        for t in sorted(bare, key=lambda x: x.name):
            out.append(f"| `{t.name}` |")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def render_scripts(rows: list[tuple[str, str, str]]) -> str:
    out = [
        f"_{len(rows)} scripts. Generated from each script's header comment by "
        "`make sync` — do not edit this table by hand._",
        "",
        "| Script | Called by | What it does |",
        "|--------|-----------|--------------|",
    ]
    for name, caller, desc in rows:
        called = f"`make {caller}`" if caller else "—"
        out.append(f"| `{name}` | {called} | {desc or '—'} |")
    return "\n".join(out) + "\n"


def render_images(rows: list[tuple[str, str, str]]) -> str:
    out = [
        f"_{len(rows)} first-party images. Generated from the Dockerfiles and "
        "compose files by `make sync` — do not edit this table by hand._",
        "",
        "| Image | Dockerfile | Base |",
        "|-------|------------|------|",
    ]
    for image, dockerfile, base in rows:
        img = f"`{image}`" if image != "—" else "—"
        out.append(f"| {img} | `{dockerfile}` | `{base}` |")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Marker splicing
# ---------------------------------------------------------------------------


def splice(document: str, key: str, generated: str) -> str:
    """Replace the marked block, leaving every other byte untouched."""
    begin, end = BEGIN.format(key=key), END.format(key=key)
    if begin not in document or end not in document:
        raise SystemExit(
            f"missing markers for {key!r}. Add:\n  {begin}\n  {end}\n"
            "around the table this script owns."
        )
    head, rest = document.split(begin, 1)
    _, tail = rest.split(end, 1)
    return f"{head}{begin}\n\n{generated}\n{end}{tail}"


def build() -> dict[Path, str]:
    """Return {path: new content} for every generated document."""
    makefile_text = MAKEFILE.read_text(encoding="utf-8")
    return {
        TARGETS_DOC: splice(
            TARGETS_DOC.read_text(encoding="utf-8"),
            "make-targets",
            render_targets(parse_makefile(makefile_text)),
        ),
        SCRIPTS_DOC: splice(
            SCRIPTS_DOC.read_text(encoding="utf-8"),
            "scripts",
            render_scripts(parse_scripts(makefile_text)),
        ),
        IMAGES_DOC: splice(
            IMAGES_DOC.read_text(encoding="utf-8"),
            "first-party-images",
            render_images(parse_first_party_images()),
        ),
    }


# ---------------------------------------------------------------------------
# One-time migration
# ---------------------------------------------------------------------------


def migrate(dry_run: bool = False) -> int:
    """Lift descriptions that live only in the doc into the Makefile.

    With ``dry_run`` it prints a unified diff and writes nothing — the default
    from the CLI unless ``--yes`` is given, because this edits the Makefile.

    Without this, switching to generated docs would silently discard the
    hand-written descriptions for the ~88 targets that have a doc row but no
    ``##`` comment — replacing real drift with real data loss.
    """
    doc = TARGETS_DOC.read_text(encoding="utf-8")
    documented: dict[str, str] = {}
    for m in re.finditer(r"^\|\s*`([a-z][a-z0-9_-]*)`\s*\|\s*([^|]+?)\s*\|", doc, re.MULTILINE):
        documented[m.group(1)] = m.group(2).strip()

    makefile_text = MAKEFILE.read_text(encoding="utf-8")
    targets = {t.name: t for t in parse_makefile(makefile_text)}

    lifted = 0
    lines = makefile_text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        m = TARGET_RE.match(line.rstrip("\n"))
        if not m:
            continue
        name = m.group("name")
        if name not in targets or targets[name].description:
            continue
        desc = documented.get(name)
        if not desc or desc in ("—", "-"):
            continue
        lines[i] = f"{line.rstrip()}  ## {desc}\n"
        lifted += 1

    new_text = "".join(lines)
    if dry_run:
        import difflib

        diff = list(difflib.unified_diff(
            makefile_text.splitlines(keepends=True), new_text.splitlines(keepends=True),
            fromfile="Makefile", tofile="Makefile (after --migrate)",
        ))
        sys.stdout.writelines(diff)
        print(f"\nmigrate --dry-run: would lift {lifted} description(s). Nothing written.")
        return 0

    MAKEFILE.write_text(new_text, encoding="utf-8")
    print(f"migrate: lifted {lifted} description(s) from the doc into the Makefile")
    print("  Review the diff — some doc descriptions may need rewording as help text.")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the reference lists.")
    # --check and --migrate are mutually exclusive. --migrate rewrites the
    # Makefile IN PLACE, and it used to be handled first — so `--check
    # --migrate` silently mutated the build's front door despite the caller
    # asking for a read-only check. A CI gate that edits the Makefile is the
    # worst possible failure mode for this script.
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="fail on drift (CI gate); never writes")
    mode.add_argument("--migrate", action="store_true", help="one-time description lift INTO the Makefile")
    parser.add_argument(
        "--yes", action="store_true",
        help="required by --migrate to actually write; without it, print a diff and exit",
    )
    args = parser.parse_args(argv)

    if args.migrate:
        if not args.yes:
            print(
                "--migrate rewrites the Makefile in place. Re-run with --yes to "
                "apply. Showing what would change:\n"
            )
            return migrate(dry_run=True)
        return migrate()

    drifted = False
    for path, new in build().items():
        current = path.read_text(encoding="utf-8")
        if current == new:
            continue
        drifted = True
        if args.check:
            print(f"\n✗ {path.relative_to(ROOT)} is out of date:")
            diff = difflib.unified_diff(
                current.splitlines(keepends=True),
                new.splitlines(keepends=True),
                fromfile="committed",
                tofile="generated",
                n=1,
            )
            sys.stdout.writelines(list(diff)[:60])
        else:
            path.write_text(new, encoding="utf-8")
            print(f"  ✓ regenerated {path.relative_to(ROOT)}")

    if args.check:
        if drifted:
            print("\nsync_reference_docs: drift detected — run `make sync` and commit.")
            return 1
        print("sync_reference_docs: all reference documents are in sync")
    elif not drifted:
        print("  ✓ reference documents already in sync")
    return 0


if __name__ == "__main__":
    sys.exit(main())
