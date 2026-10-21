#!/usr/bin/env python3
"""Render the CVE-waiver derived artifacts from security/waivers.yaml.

Phase 847a.

WHY THIS EXISTS
---------------
CVE waivers used to be authored in two hand-maintained places that had already
diverged: the `Makefile` listed 6 pip-audit `--ignore-vuln` flags while
`.github/workflows/ci.yml` listed 2, and `.trivyignore.*` was hand-edited with a
date-rewriting script racing a justification-rewriting script on the same file.
Nothing made the two pip-audit lists agree, and nothing made the ignorefiles
agree with any external claim.

`security/waivers.yaml` is now the single source of truth. This script renders
three derived artifacts from it:

    .trivyignore.third-party   scope: third-party, source: trivy
    .trivyignore.first-party   scope: first-party, source: trivy
    .pip-audit-ignores         source: pip-audit (consumed by Makefile AND ci.yml)

The derived files stay COMMITTED (the scans read them at runtime and reviewers
should see waiver changes in a diff). What stops them going stale is
`--check` / `tests/unit/test_waivers_registry.py`, which fail when a derived file
does not match a fresh render.

USAGE
-----
    python3 scripts/render_waivers.py                 # write the derived files
    python3 scripts/render_waivers.py --check         # exit 1 if any is stale
    python3 scripts/render_waivers.py --refresh-carriers --scan-dir DIR
                                                      # rewrite `carriers:` from scan data

Renewal is NOT here. Phase 847d removed the auto-renew: moving an expiry is a
decision with evidence (`scripts/renew_trivyignore.py` classifies each expiring
entry dead / fixable / escalate) rather than a date bump this module performs.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import textwrap
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:  # invoked directly (scripts/ on sys.path) or as a package member
    from scripts.check_trivyignore_drift import scan_dir_findings
except ImportError:  # pragma: no cover - direct invocation
    from check_trivyignore_drift import scan_dir_findings

_ROOT = Path(__file__).resolve().parents[1]
REGISTRY = _ROOT / "security" / "waivers.yaml"
THIRD_PARTY_IGNORE = _ROOT / ".trivyignore.third-party"
FIRST_PARTY_IGNORE = _ROOT / ".trivyignore.first-party"
PIP_AUDIT_IGNORES = _ROOT / ".pip-audit-ignores"

SEVERITIES = ("HIGH", "CRITICAL", "MEDIUM")
SCOPES = ("third-party", "first-party")
SOURCES = ("trivy", "pip-audit")

_ID_RE = re.compile(r"^(CVE-\d{4}-\d+|GHSA-[\w-]{4,}|PYSEC-\d{4}-\d+)$")
_WRAP = 78

THIRD_PARTY_HEADER = """\
# =============================================================================
# Trivy scan exceptions — PINNED UPSTREAM IMAGES. (policy: 226/822/847)
# Consumed by `make scan-images` ONLY.               *** GENERATED FILE ***
# =============================================================================
#
# DO NOT EDIT. This file is rendered from `security/waivers.yaml` by
# `scripts/render_waivers.py`. Hand edits are reverted by the drift test
# (`tests/unit/test_waivers_registry.py`). To change a waiver, edit the
# registry and re-run the renderer.
#
# SPLIT FROM `.trivyignore` IN PHASE 822 — see .trivyignore.first-party for the
# full rationale. Short version: one shared ignorefile meant a waiver for a
# monitoring sidecar silently covered the same CVE in our own proxy image.
#
# THE RULE HERE
#   An entry is valid only when **no fix is reachable without replacing the
#   image**. That is deliberately weaker than the first-party rule, and it is
#   the honest criterion: these are third-party tags we cannot rebuild, so a
#   fixed version existing upstream in Go or a Go module does NOT help us until
#   the image publisher ships a new tag.
#
# ENTRY FORMAT
#   One `CVE-… exp:YYYY-MM-DD` line per waiver, preceded by its justification
#   comment block. Trivy suppresses the finding while `today < exp`, so an entry
#   whose exp: is today is ALREADY expired (Phase 812 fix). Since Phase 847d a
#   re-check pass (`scripts/renew_trivyignore.py`) classifies each expiring
#   entry and either deletes a dead waiver, proposes the real fix, or
#   escalates it with the dates UNCHANGED — the window is never extended
#   without evidence.
# =============================================================================
"""

FIRST_PARTY_HEADER = """\
# =============================================================================
# Trivy scan exceptions — IMAGES WE BUILD.        (policy: 226/822/847)
# Consumed by `make scan-first-party` ONLY.          *** GENERATED FILE ***
# =============================================================================
#
# DO NOT EDIT. Rendered from `security/waivers.yaml` by
# `scripts/render_waivers.py`; hand edits are reverted by the drift test.
#
# WHY THIS FILE IS SEPARATE (Phase 822)
#   Until Phase 822 there was one `.trivyignore`, and the Makefile passed it to
#   BOTH scans. Trivy's ignorefile has no per-image scoping, so every waiver
#   granted to an abandoned third-party sidecar ALSO suppressed the same finding
#   in the proxy we ship. CVE-2026-39821 and CVE-2026-46600 were waived with
#   justifications written entirely about Grafana/Promtail/Alertmanager/cAdvisor
#   while both were live in ja4proxy:2.0.0, an internet-facing TLS proxy. Both
#   were fixed with a one-line Go bump instead.
#
# THE RULE HERE IS STRICTER
#   We control these images. If a fix exists ANYWHERE upstream — a base-image
#   bump, a dependency bump, a Go toolchain bump — it is not a waiver, it is a
#   fix we owe. This file is expected to stay EMPTY.
# =============================================================================
"""


class RegistryError(Exception):
    """A registry that violates the schema."""


def _wrap_comment(text: str, prefix: str = "# ") -> List[str]:
    """Hard-wrap `text` into comment lines, preserving explicit paragraphs."""
    out: List[str] = []
    for para in str(text).split("\n\n"):
        para = " ".join(para.split())
        if not para:
            continue
        out.extend(
            textwrap.wrap(
                para,
                width=_WRAP,
                initial_indent=prefix,
                subsequent_indent=prefix,
                break_long_words=False,
                break_on_hyphens=False,
            )
        )
        out.append("#")
    if out and out[-1] == "#":
        out.pop()
    return out


def load_registry(path: Path = REGISTRY) -> Dict[str, Any]:
    import yaml

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:  # pragma: no cover - guarded by callers
        raise RegistryError(f"registry not found: {path}") from exc
    if not isinstance(data, dict):
        raise RegistryError(f"{path}: top level must be a mapping")
    _normalise_dates(data)
    # `waivers:` with no entries loads as None, but every consumer (validate,
    # renderers, remove_entries) reasons about a *list*. An empty registry is a
    # legitimate end state (Phase 847d), so give it the type it means.
    #
    # A MISSING key is a different thing and stays an error: it means the file
    # is not a registry (a truncated edit, a bad merge). Coercing it to `[]`
    # would read as "zero waivers", and the derived ignorefiles would then be
    # regenerated EMPTY — every live exemption dropped, silently. This is the
    # one failure the whole programme exists to prevent, so it is refused at
    # load time rather than caught later by validate().
    if "waivers" not in data:
        raise RegistryError(
            f"{path}: missing `waivers:` key — this file is not a registry "
            "(an empty registry still has the key, with no entries)"
        )
    if data["waivers"] is None:
        data["waivers"] = []
    return data


def _normalise_dates(registry: Dict[str, Any]) -> None:
    """Unquoted YYYY-MM-DD is a YAML timestamp, which PyYAML loads as datetime.date.

    Normalise those back to ISO strings so every downstream consumer sees the
    same type, and so `--check` compares strings rather than date objects.
    """
    for w in registry.get("waivers") or []:
        if not isinstance(w, dict):
            continue
        for key in ("created", "expires"):
            value = w.get(key)
            if isinstance(value, date):
                w[key] = value.isoformat()


def validate(registry: Dict[str, Any]) -> List[str]:
    """Return a list of schema violations (empty means valid)."""
    errors: List[str] = []
    policy = registry.get("policy") or {}
    max_days = int(policy.get("max_window_days", 90))
    waivers = registry.get("waivers")
    # An EMPTY registry is the goal state of Phase 847d's "zero CVEs" programme —
    # every waiver deleted because every finding is genuinely gone is success,
    # not a schema error. A missing key is still a violation: that means the
    # registry is not a registry.
    if not isinstance(waivers, list):
        return ["`waivers:` must be a list"]

    seen: Dict[str, int] = {}
    for i, w in enumerate(waivers):
        where = f"waivers[{i}]"
        if not isinstance(w, dict):
            errors.append(f"{where}: must be a mapping")
            continue
        wid = w.get("id")
        where = f"{where} ({wid!r})"
        if not isinstance(wid, str) or not _ID_RE.match(wid):
            errors.append(f"{where}: missing or malformed id")
        elif wid in seen:
            errors.append(f"{where}: duplicate id (first at waivers[{seen[wid]}])")
        else:
            seen[wid] = i

        for key in ("scope", "severity", "source", "rationale", "created", "expires"):
            if not w.get(key) and w.get(key) != 0:
                errors.append(f"{where}: missing required field {key!r}")

        if w.get("scope") not in SCOPES:
            errors.append(f"{where}: scope must be one of {SCOPES}")
        if w.get("severity") not in SEVERITIES:
            errors.append(f"{where}: severity must be one of {SEVERITIES}")
        if w.get("source") not in SOURCES:
            errors.append(f"{where}: source must be one of {SOURCES}")

        carriers = w.get("carriers")
        if not isinstance(carriers, list) or not carriers or not all(
            isinstance(c, str) and c for c in carriers
        ):
            errors.append(f"{where}: carriers must be a non-empty list of strings")

        if w.get("fix_available") is False and not w.get("recheck_trigger"):
            errors.append(
                f"{where}: fix_available: false requires a recheck_trigger "
                "(state the upstream change that would obsolete this waiver)"
            )

        created, expires = w.get("created"), w.get("expires")
        for label, value in (("created", created), ("expires", expires)):
            if value and not _is_iso_date(value):
                errors.append(f"{where}: {label} must be YYYY-MM-DD, got {value!r}")
        if _is_iso_date(created) and _is_iso_date(expires):
            span = (_as_date(expires) - _as_date(created)).days
            if span < 0:
                errors.append(f"{where}: expires ({expires}) is before created ({created})")
            elif span > max_days:
                errors.append(
                    f"{where}: window is {span}d, exceeds policy max {max_days}d "
                    f"(created {created}, expires {expires})"
                )
    return errors


def _is_iso_date(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", value))


def _as_date(value: str) -> date:
    return date.fromisoformat(value)


def _sorted(waivers: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(waivers, key=lambda w: str(w.get("id", "")))


def render_trivy(registry: Dict[str, Any], scope: str) -> str:
    header = THIRD_PARTY_HEADER if scope == "third-party" else FIRST_PARTY_HEADER
    rows = [
        w
        for w in _sorted(registry.get("waivers") or [])
        if w.get("source") == "trivy" and w.get("scope") == scope
    ]
    parts = [header.rstrip("\n"), ""]
    if not rows:
        parts.append("# (No waivers for this scope.)")
        return "\n".join(parts) + "\n"

    for w in rows:
        carriers = w.get("carriers") or []
        # Rationale first so `make scan-exceptions`' JUSTIFICATION column shows
        # the reasoning, not the id/severity restated.
        parts.extend(_wrap_comment(w["rationale"]))
        parts.append("#")
        parts.append("# Carriers:")
        parts.extend(f"#   - {c}" for c in carriers)
        if w.get("reachability"):
            parts.append(f"# Reachability: {w['reachability']}")
        parts.append(f"# Severity: {w.get('severity', 'HIGH')}")
        if w.get("fix_available") is False and w.get("recheck_trigger"):
            parts.extend(_wrap_comment(f"Re-check when: {w['recheck_trigger']}"))
        parts.append(f"{w['id']} exp:{w['expires']}")
        parts.append("")
    return "\n".join(parts) + "\n"


def render_pip_audit(registry: Dict[str, Any]) -> str:
    rows = _sorted(
        [w for w in (registry.get("waivers") or []) if w.get("source") == "pip-audit"]
    )
    lines = [
        "# GENERATED by scripts/render_waivers.py from security/waivers.yaml — DO NOT EDIT.",
        "# Consumed by the Makefile `lint-static` gate AND .github/workflows/ci.yml,",
        "# so the two pip-audit ignore lists can no longer diverge (Phase 847a).",
        "# Word-split by the shell at the point of use (one flag pair per line).",
        "",
    ]
    lines.extend(f"--ignore-vuln {w['id']}" for w in rows)
    return "\n".join(lines) + "\n"


def render_all(registry: Dict[str, Any]) -> Dict[Path, str]:
    return {
        THIRD_PARTY_IGNORE: render_trivy(registry, "third-party"),
        FIRST_PARTY_IGNORE: render_trivy(registry, "first-party"),
        PIP_AUDIT_IGNORES: render_pip_audit(registry),
    }


def write_derived(rendered: Dict[Path, str]) -> List[Path]:
    changed: List[Path] = []
    for path, text in rendered.items():
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            path.write_text(text, encoding="utf-8")
            changed.append(path)
    return changed


# The fields the date/carrier mutators change. Everything else in an entry
# (rationale prose, severity…) is hand-authored and must survive a rewrite
# byte-for-byte.
_MUTABLE_KEYS = ("created", "expires", "carriers")
# Phase 847d: the fix-forward bot records fix-availability facts on existing
# entries (`fix_available`, plus the schema-required `recheck_trigger` when it
# records `false`). These are only ever rewritten by mutators that explicitly
# pass BOT_MUTABLE_KEYS — the default splice path above still preserves them
# byte-for-byte, exactly as it preserves rationale prose.
FIX_META_KEYS = ("fix_available", "recheck_trigger")
BOT_MUTABLE_KEYS = (*_MUTABLE_KEYS, *FIX_META_KEYS)

_ENTRY_RE = re.compile(r"^(\s*)- id:\s*(\S+)\s*$")


def _entry_starts(lines: Sequence[str]) -> List[int]:
    """Indices of the lines that BEGIN a registry entry.

    Only the first match's indent counts. Every entry is a sibling under
    `waivers:` and shares one indent, while a deeper-indented `- id:` line is
    prose inside a rationale's folded block scalar (`rationale: >-` followed by
    indented lines). Treating that prose as an entry boundary made
    `remove_entries` delete only the HEAD of an entry and leave its tail
    behind — the surviving `created:`/`expires:` lines then parsed as a
    top-level mapping and the registry stopped being valid YAML. Found by
    constructing exactly that registry; Phase 847d.

    `_ENTRY_RE` alone cannot tell the two apart: both lines match it.
    """
    starts: List[int] = []
    indent: Optional[str] = None
    for i, line in enumerate(lines):
        matched = _ENTRY_RE.match(line)
        if matched is None:
            continue
        if indent is None:
            indent = matched.group(1)
        elif matched.group(1) != indent:
            continue  # prose inside a block scalar, not an entry
        starts.append(i)
    return starts
_KEY_RE = re.compile(r"^(\s*)([A-Za-z_][\w-]*):")


def _format_carriers(carriers: Sequence[str]) -> str:
    return "[" + ", ".join('"%s"' % c for c in carriers) + "]"


def _format_mutable_value(key: str, value: Any) -> str:
    """Single-line YAML for a mutable key. Booleans must be lowercase
    (`False` would round-trip as the *string* "False"), and the free-text
    recheck_trigger is JSON-quoted so embedded `: `/`#`/quotes stay safe —
    for values already written in the file's double-quoted style this is
    byte-identical, so an unrelated save never churns the line."""
    if key == "carriers":
        return _format_carriers(value or [])
    if isinstance(value, bool):
        return "true" if value else "false"
    if key == "recheck_trigger":
        return json.dumps(str(value))
    return str(value)


def _is_list_continuation(line: str, key_indent: int) -> bool:
    """True for a `- item` line that belongs to a key at `key_indent`.

    PyYAML emits *indentless* block sequences (`carriers:` with `- x` at the same
    indent as the key), while hand-authored files often indent one further, so
    anything at or beyond the key's indent counts. Entry-start lines (`- id:`) are
    never continuations, so a following entry can't be swallowed.
    """
    stripped = line.rstrip("\n")
    if stripped.strip() == "" or _ENTRY_RE.match(line):
        return False
    indent = len(stripped) - len(stripped.lstrip())
    return indent >= key_indent and stripped.lstrip().startswith("- ")


def _last_field_end(block: List[str], key_indent: str) -> int:
    """Index just past the entry's last field — deliberately overshooting any
    trailing blank/comment lines (overshoot is harmless: a line inserted at key
    indent before the next `- id:` still belongs to this entry; undershoot would
    split a multi-line scalar and corrupt the YAML)."""
    key_len = len(key_indent)
    last = 0
    for i, line in enumerate(block):
        match = _KEY_RE.match(line)
        if match is not None and match.group(1) == key_indent:
            last = i + 1
    j = last
    while j < len(block):
        stripped = block[j].rstrip("\n")
        if (
            stripped.strip() == ""
            or _is_list_continuation(block[j], key_len)
            or (len(stripped) - len(stripped.lstrip(" ")) > key_len)
        ):
            j += 1
            continue
        break
    return j


def _splice_entry_block(
    block: List[str],
    waiver: Dict[str, Any],
    mutable_keys: Sequence[str] = _MUTABLE_KEYS,
) -> List[str]:
    """Rewrite one entry's mutable scalars in place, keeping all comments.

    Emits single-line values only (`created: 2026-10-19`,
    `carriers: ["a", "b"]`). Any block-form continuation an old value owned is
    consumed, so an existing block list collapses cleanly. Keys are matched at the
    entry's own key indent (derived from the `- id:` line) so prose inside a
    multi-line `rationale:` can never be mistaken for a field.

    Phase 847d adds two moves for the fix-forward bot's keys: a mutable key the
    waiver no longer carries has its line DROPPED (so `fix_available: true`
    supersedes a stale `recheck_trigger`), and a mutable key the waiver carries
    but the text lacks is APPENDED after the last field — a registry record the
    splice silently dropped must not be possible.
    """
    first = block[0]
    key_indent = " " * ((len(first) - len(first.lstrip(" "))) + 2)
    out: List[str] = []
    written: set = set()
    i = 0
    while i < len(block):
        line = block[i]
        match = _KEY_RE.match(line)
        if (
            match is not None
            and match.group(1) == key_indent
            and match.group(2) in mutable_keys
        ):
            key = match.group(2)
            i += 1
            while i < len(block) and _is_list_continuation(block[i], len(key_indent)):
                i += 1
            if key in waiver:
                out.append(f"{key_indent}{key}: {_format_mutable_value(key, waiver[key])}\n")
                written.add(key)
            continue
        out.append(line)
        i += 1

    missing = [k for k in mutable_keys if k in waiver and k not in written]
    if missing:
        at = _last_field_end(out, key_indent)
        out[at:at] = [
            f"{key_indent}{k}: {_format_mutable_value(k, waiver[k])}\n" for k in missing
        ]
    return out


def save_registry(
    registry: Dict[str, Any],
    path: Path = REGISTRY,
    mutable_keys: Sequence[str] | None = None,
) -> None:
    """Persist registry mutations while preserving the file's comments.

    `yaml.safe_dump` strips every comment — the whole header and schema
    documentation — and reflows the hand-authored `>-` rationale blocks into
    quoted strings. A single `--refresh-carriers` run produced a 1346-line diff of
    pure destruction, and the same would happen on every renewal. So splice only
    the fields the mutators touch into the existing text rather than
    re-serialising the document. New entries are authored by hand, not here.

    `mutable_keys` widens which scalars may be rewritten (Phase 847d: the
    fix-forward bot passes BOT_MUTABLE_KEYS to record fix availability); the
    default keeps every other field — including fix metadata — byte-for-byte.
    """
    mutable = tuple(mutable_keys) if mutable_keys is not None else _MUTABLE_KEYS
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    by_id = {str(w.get("id")): w for w in registry.get("waivers") or []}

    starts = _entry_starts(lines)
    found = {
        matched.group(2).strip("\"'")
        for matched in (_ENTRY_RE.match(lines[s]) for s in starts)
        if matched is not None
    }
    missing = sorted(set(by_id) - found)
    if missing:
        # Never write a partial registry: an entry we cannot locate in the text
        # (e.g. a quoted id the entry regex misses) would be silently skipped, so
        # its dates/carriers would go stale without anyone noticing.
        raise ValueError(
            f"refusing to write: registry entries absent from {path.name}: {missing}"
        )

    bounds = [
        (start, starts[i + 1] if i + 1 < len(starts) else len(lines))
        for i, start in enumerate(starts)
    ]
    for start, end in reversed(bounds):
        matched = _ENTRY_RE.match(lines[start])
        if matched is None:  # pragma: no cover - guaranteed by `starts`
            continue
        waiver = by_id.get(matched.group(2).strip("\"'"))
        if waiver is None:
            continue
        lines[start:end] = _splice_entry_block(lines[start:end], waiver, mutable)

    path.write_text("".join(lines), encoding="utf-8")


def remove_entries(
    registry: Dict[str, Any], ids: Sequence[str], path: Path = REGISTRY
) -> List[str]:
    """Delete whole entries from the registry's text, keeping every comment.

    Trims each entry's block (its `- id:` line through the last line before the
    next entry) out of the document rather than re-serialising, so hand-authored
    prose and comments survive. Refuses — with no partial write — when an entry
    is unknown, or when another *surviving* waiver still claims one of its
    carriers: silently dropping that carrier would narrow a live exemption.
    Returns the ids actually removed.
    """
    wanted = [str(i) for i in ids]
    if not wanted:
        return []
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)

    spans: Dict[str, Tuple[int, int]] = {}
    starts = _entry_starts(lines)
    for n, start in enumerate(starts):
        end = starts[n + 1] if n + 1 < len(starts) else len(lines)
        cid = _ENTRY_RE.match(lines[start]).group(2).strip("\"'")  # type: ignore[union-attr]
        spans[cid] = (start, end)

    missing = [i for i in wanted if i not in spans]
    if missing:
        raise ValueError(f"no registry entry for: {', '.join(sorted(missing))}")

    survivors: set = set()
    for cid, w in {str(w.get("id")): w for w in registry.get("waivers") or []}.items():
        if cid in wanted:
            continue
        survivors.update(w.get("carriers") or [])

    for cid in wanted:
        entry: Dict[str, Any] = next(
            (w for w in registry.get("waivers") or [] if str(w.get("id")) == cid), {}
        )
        lost = sorted(set(entry.get("carriers") or []) & survivors)
        if lost:
            raise ValueError(
                f"refusing to remove {cid}: carrier(s) {', '.join(lost)} are still "
                "claimed by a surviving waiver (removing it would narrow that exemption)"
            )

    for cid in sorted(wanted, key=lambda i: spans[i][0], reverse=True):
        start, end = spans[cid]
        del lines[start:end]

    # Fail closed. The text is spliced, not re-serialised, so a wrong span
    # would write a file that no longer parses — and the registry is the
    # single source of truth, so an unparseable one breaks every downstream
    # consumer. Verify BEFORE writing: the result must parse, and must hold
    # exactly the entries we expect.
    text = "".join(lines)
    try:
        import yaml

        parsed = yaml.safe_load(text) or {}
    except Exception as exc:  # noqa: BLE001 -- any parse failure is a refusal
        raise ValueError(
            f"refusing to write {path.name}: the result does not parse ({exc})"
        ) from exc
    kept = {str(w.get("id")) for w in parsed.get("waivers") or []}
    expected = {str(w.get("id")) for w in registry.get("waivers") or []} - set(wanted)
    if kept != expected:
        raise ValueError(
            f"refusing to write {path.name}: entries would be {sorted(kept)}, "
            f"expected {sorted(expected)}"
        )

    path.write_text(text, encoding="utf-8")
    for w in list(registry.get("waivers") or []):
        if str(w.get("id")) in wanted:
            registry["waivers"].remove(w)
    return wanted


def refresh_carriers(
    registry: Dict[str, Any], scan_dir: Path, today: date
) -> int:
    """Rewrite each trivy entry's `carriers:` from measured scan data (Phase 829b)."""
    _severity, carriers_by_cve = scan_dir_findings(scan_dir)
    updated = 0
    for w in registry.get("waivers") or []:
        if w.get("source") != "trivy":
            continue
        measured = carriers_by_cve.get(str(w.get("id")))
        if measured and sorted(measured) != sorted(w.get("carriers") or []):
            w["carriers"] = list(measured)
            updated += 1
    return updated


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="exit 1 if a derived file is stale")
    parser.add_argument("--refresh-carriers", action="store_true")
    parser.add_argument("--scan-dir", type=Path)
    parser.add_argument("--today", default="", help="override today (YYYY-MM-DD)")
    parser.add_argument("--registry", type=Path, default=REGISTRY)
    args = parser.parse_args(argv)

    today = _as_date(args.today) if args.today else date.today()

    try:
        registry = load_registry(args.registry)
    except RegistryError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 2

    errors = validate(registry)
    if errors:
        for e in errors:
            print(f"✗ {e}", file=sys.stderr)
        return 2

    mutated = False
    if args.refresh_carriers:
        if not args.scan_dir:
            print("✗ --refresh-carriers requires --scan-dir", file=sys.stderr)
            return 2
        try:
            n = refresh_carriers(registry, args.scan_dir, today)
        except ValueError as exc:
            print(f"✗ {exc}", file=sys.stderr)
            return 2
        print(f"Refreshed carrier claims on {n} entr{'y' if n == 1 else 'ies'}.")
        mutated = mutated or n > 0

    if mutated:
        save_registry(registry, args.registry)

    rendered = render_all(registry)

    if args.check:
        stale = [
            p
            for p, text in rendered.items()
            if not p.exists() or p.read_text(encoding="utf-8") != text
        ]
        if stale:
            for p in stale:
                print(f"✗ stale (does not match security/waivers.yaml): {p.name}", file=sys.stderr)
            print(
                "  Run `python3 scripts/render_waivers.py` to regenerate from the registry.",
                file=sys.stderr,
            )
            return 1
        print("✓ derived files match security/waivers.yaml")
        return 0

    changed = write_derived(rendered)
    if changed:
        for p in changed:
            print(f"  wrote {p.name}")
    else:
        print("  derived files already up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
