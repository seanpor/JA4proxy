#!/usr/bin/env python3
"""scripts/fix_forward.py — fix-availability engine + proposal authoring (Phase 847d).

WHY THIS EXISTS
---------------
Waiving is a one-line YAML edit; fixing is a PR. Under schedule pressure the
cheap option always wins, so waivers accrete — and the `fix_available: false`
claims that justify them were never actually *verified*, because the
authoritative check ("does ANY published version clear this?") was expensive and
manual. The kin-openapi "no fixed version exists" fact got got wrong by hand for
exactly that reason.

Phase 847d.1 inverts the cost. For every unwaived finding with a published fix
(the baseline monitor's fixable queue) and for every expiring waiver
(re-affirmation, `scripts/renew_trivyignore.py`), this module decides — with
evidence — whether a clearing version actually exists WITHIN THIS REPO'S
CONSTRAINTS:

  image surface   newer tags from the registry; candidate tags are scanned;
                  the fix is real only if the candidate clears the finding AND
                  introduces no new unwaived HIGH/CRITICAL (a bump the
                  `scan-regression` gate would reject just wastes a human's
                  review).
  pypi surface    is the fixed version published (PyPI), does requirements.txt
                  permit it, and does any *direct* requirement's `requires_dist`
                  hard-pin it away — the `mcp`/semgrep case, where the answer is
                  "semgrep 1.181.0 still pins `mcp==1.29.0`".

THREE OUTCOMES — never a guess:
  fixable   a clearing version exists   -> author a proposal: a `bot/*` branch
                                           carrying the bump + the before/after
                                           table, plus an informational issue
                                           with a one-click compare link.
  blocked   no adoptable clearing       -> record `fix_available: false` with the
            version exists without       evidence on the registry entry
            an upstream/external change  (batched into one reviewable branch),
                                          or comment the evidence on the
                                          finding's monitor issue when no
                                          registry entry exists yet.
  unknown   the check cannot decide      -> report only. Never guess.
            (non-semver tag, digest pin, first-party image, unreachable
            registry, unparseable or deliberately-bounded constraint).

REPO POLICY, deliberately: GITHUB_TOKEN may not open PRs — the repo setting
"Allow GitHub Actions to create and approve pull requests" is DISABLED (Phase
818, #396) — so a proposal is a branch + an informational issue carrying a
one-click compare link, the same pattern Phase 812-B's renewal workflow settled
on. The bot NEVER auto-merges anything: its branches are `bot/*`, deliberately
not `phase-*`, because maintainer-automerge.yml auto-squashes `phase-*` PRs.

COST: nothing is scanned when the fixable queue is empty (the steady state).
Candidate scans are bounded by `--max-candidates` and memoised in a small
scan cache keyed by (ref, ignorefile hash), so a daily run re-scans a candidate
only when a new tag is published or the waiver set moved. Cached candidate
findings are advisory: the PR's own `scan-regression` gate re-scans for real
before anything merges.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import date
from hashlib import sha1
from pathlib import Path
from typing import Any, Callable, Sequence

try:  # works as `python3 scripts/x.py` and as `from scripts.x import ...`
    from scripts.check_upstream_image_updates import (
        fetch_docker_hub_tags,
        find_newer_tags,
        parse_image_ref,
    )
    from scripts.render_waivers import (
        BOT_MUTABLE_KEYS,
        FIX_META_KEYS,
        load_registry,
        render_all,
        save_registry,
        validate,
        write_derived,
    )
    from scripts.render_waivers import REGISTRY as REGISTRY_PATH
    from scripts.scan_baseline import PYPI_SURFACE, is_first_party, scan_image
    from scripts.scan_baseline_monitor import create_issue, issue_title, issues_by_title
except ImportError:  # invoked directly, scripts/ on sys.path
    from check_upstream_image_updates import (  # type: ignore[no-redef]
        fetch_docker_hub_tags,
        find_newer_tags,
        parse_image_ref,
    )
    from render_waivers import (  # type: ignore[no-redef]  # type: ignore[no-redef]
        BOT_MUTABLE_KEYS,
        FIX_META_KEYS,
        load_registry,
        render_all,
        save_registry,
        validate,
        write_derived,
    )
    from render_waivers import REGISTRY as REGISTRY_PATH  # type: ignore[no-redef]
    from scan_baseline import PYPI_SURFACE, is_first_party, scan_image  # type: ignore[no-redef]
    from scan_baseline_monitor import (  # type: ignore[no-redef]
        create_issue,
        issue_title,
        issues_by_title,
    )

#: HTTP responses are capped (AGENTS.md): external APIs answer in well under
#: a default cap, and an oversized body is an error, never something to buffer
#: whole. PyPI project metadata is the exception that must be measured, not
#: guessed: `aiohttp`'s JSON carries historical release data and is already
#: >256 KiB, so the *metadata* fetches pass an explicit larger cap while the
#: default stays small. Live end-to-end check (2026-10-21) that caught this:
#: the mcp/semgrep block was unreachable because the sweep died on aiohttp.
HTTP_LIMIT = 256 * 1024
#: PyPI `/pypi/<project>/json` is the documented, stable metadata envelope for a
#: project, but its size grows with release history: measured 2026-10-21,
#: aiohttp 9.5 MB (314 releases), semgrep 1.4 MB (301), mcp 120 KB. The cap
#: must clear the largest project on this dependency surface, so it is set with
#: margin and the recorded high-water mark is asserted in tests and reported by
#: the workflow — a project outgrowing it must surface as a real failure, not as
#: a silent `unknown` that hides the whole sweep.
PYPI_METADATA_LIMIT = 32 * 1024 * 1024
#: Newest-first candidate scan budget per image surface.
DEFAULT_MAX_CANDIDATES = 3
#: Reverse-dep (`requires_dist`) sweep budget — requirements.txt has ~60 direct
#: requirements; past this cap the sweep reports `unknown` rather than claiming
#: a fix it did not fully prove.
DEFAULT_MAX_REVERSE_DEPS = 100
#: Candidate-scan cache entries older than this are re-scanned (advisory cache;
#: see module docstring).
DEFAULT_SCAN_CACHE_MAX_AGE_DAYS = 7
#: Marker for evidence comments on monitor issues — dedup across daily runs.
ISSUE_MARKER = "<!-- fix-forward:847d -->"
#: Titles the bot creates issues under; also the dedup key.
PROPOSAL_PREFIX = "Fix-forward: "
#: Opt-in per-run meter of observed response sizes (`main --bytes-out`), so the
#: HTTP caps are justified by data from the environment they run in.
_BYTES_SEEN: list[tuple[str, int]] | None = None


class Indeterminate(Exception):
    """The check cannot decide (network failure, unparseable spec, ...).

    Carries a human-readable reason that becomes an `unknown` decision's
    evidence. It is NEVER converted into either `fixable` or `blocked`: an
    undecidable check must not claim a fix exists, nor that one does not.
    """


class ProposeError(Exception):
    """A proposal could not be authored. Reported per-unit; never fatal."""


# ---------------------------------------------------------------------------
# PEP 503 / PEP 440-lite constraint engine (stdlib only, deliberately narrow)
# ---------------------------------------------------------------------------


def normalize_name(name: str) -> str:
    """PEP 503 normalisation: lowercase, runs of `-_.` collapse to `-`."""
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


_CLAUSE_RE = re.compile(r"^(===|==|!=|~=|<=|>=|<|>)\s*([A-Za-z0-9][\w.*+!-]*)$")
#: Operators this bot may re-write when raising a package's own pin/floor to
#: the fixed version. `~=`, `<`, `<=`, `!=` are deliberately excluded: those
#: encode an upper bound or an explicit exclusion a human chose, and silently
#: relaxing them is a policy decision, not a fix.
BUMPABLE_OPS = ("==", ">=")


def _cmp_versions(a: str, b: str) -> int | None:
    """Compare two numeric dotted versions; None when either is non-numeric.

    Deliberately not a PEP 440 implementation: pre/post-releases and local
    versions are decided as `Indeterminate` (see `spec_excludes`) rather than
    risk a subtly wrong ordering that could justify a broken bump.
    """
    try:
        left = [int(p) for p in a.strip().split(".")]
        right = [int(p) for p in b.strip().split(".")]
    except ValueError:
        return None
    width = max(len(left), len(right))
    left += [0] * (width - len(left))
    right += [0] * (width - len(right))
    return (left > right) - (left < right)


def _prefix_matches(version: str, prefix: str) -> bool:
    """`==1.29.*`-style prefix match, or plain equality when no `.*`."""
    if prefix.endswith(".*"):
        v_parts, p_parts = version.split("."), prefix[:-2].split(".")
        return v_parts[: len(p_parts)] == p_parts
    return _cmp_versions(version, prefix) == 0


def spec_excludes(version: str, spec: str) -> tuple[bool, str]:
    """Does `spec` (e.g. `>=1.0,<2`, `~=8.1.8`, `==1.29.0`) exclude `version`?

    Returns `(excluded, evidence)`. Raises `Indeterminate` when any clause
    cannot be decided with certainty — the caller must treat that as "cannot
    prove a fix", never as "fix exists".
    """
    for raw in spec.split(","):
        clause = raw.strip()
        if not clause:
            continue
        m = _CLAUSE_RE.match(clause)
        if m is None:
            raise Indeterminate(f"unparseable version specifier {clause!r}")
        op, value = m.group(1), m.group(2)
        if op == "===":  # arbitrary equality: only exact string equality decides
            if version.strip() != value:
                return True, f"{clause} excludes {version} (arbitrary equality)"
            continue
        if op in ("==", "!="):
            excluded = not _prefix_matches(version, value) if op == "==" else _prefix_matches(version, value)
        elif op == "~=":
            cmp = _cmp_versions(version, value)
            if cmp is None:
                raise Indeterminate(f"non-numeric version in specifier {clause!r}")
            # ~=X.Y.Z  ==  >=X.Y.Z, ==X.Y.* — compatible release.
            prefix = ".".join(value.split(".")[:-1]) + ".*" if "." in value else value
            if cmp < 0 or not _prefix_matches(version, prefix):
                return True, f"{clause} excludes {version}"
            continue
        else:  # >=, <=, >, <
            cmp = _cmp_versions(version, value)
            if cmp is None:
                raise Indeterminate(f"non-numeric version in specifier {clause!r}")
            excluded = {"<=": cmp > 0, "<": cmp >= 0, ">": cmp <= 0}[op] if op != ">=" else cmp < 0
        if excluded:
            return True, f"{clause} excludes {version}"
    return False, ""


def parse_req_line(line: str) -> tuple[str, str, str] | None:
    """Parse one requirements-style line → `(norm_name, spec, name_as_written)`.

    Markers (`; sys_platform == ...`) and trailing comments are stripped; a
    bare name with no specifier yields no spec (nothing to decide or bump).
    """
    stripped = line.split("#", 1)[0].split(";", 1)[0].strip()
    if not stripped or stripped.startswith("-"):
        return None
    m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\s*\[[^\]]*\])?\s*(.*)", stripped)
    if m is None:
        return None
    written, spec = m.group(1), m.group(2).strip()
    if spec.startswith("(") and spec.endswith(")"):  # legacy `name (>=1.0)` form
        spec = spec[1:-1].strip()
    if not spec:
        return None
    return normalize_name(written), spec, written


def requirements_specs(text: str, package: str) -> list[str]:
    """Every specifier this file places on `package` (normalised name)."""
    target = normalize_name(package)
    specs: list[str] = []
    for line in text.splitlines():
        parsed = parse_req_line(line)
        if parsed is not None and parsed[0] == target:
            specs.append(parsed[1])
    return specs


def direct_requirement_names(text: str) -> list[str]:
    """Ordered, de-duplicated normalised names of direct requirements."""
    names: list[str] = []
    for line in text.splitlines():
        parsed = parse_req_line(line)
        if parsed is not None and parsed[0] not in names:
            names.append(parsed[0])
    return names


def _rebuild_spec(spec: str, fixed: str) -> str:
    """Raise every bumpable clause in `spec` to `fixed`; other clauses survive."""
    rebuilt: list[str] = []
    for clause in spec.split(","):
        m = _CLAUSE_RE.match(clause.strip())
        if m is not None and m.group(1) in BUMPABLE_OPS:
            rebuilt.append(f"{m.group(1)}{fixed}")
        else:
            rebuilt.append(clause.strip())
    return ",".join(rebuilt)


def bump_requirements(text: str, package: str, fixed: str) -> str:
    """Raise `package`'s specifier(s) in `text` to `fixed`; comments survive.

    The same function decides *and* edits (check_pypi_fix proves the rewritten
    spec admits `fixed` before ever calling this a fix), so the claim and the
    edit can never disagree. Raises `ValueError` when nothing is editable — an
    edit that would silently change nothing must never be proposed.
    """
    target = normalize_name(package)
    lines = text.splitlines(keepends=True)
    changed = False
    for i, line in enumerate(lines):
        parsed = parse_req_line(line)
        if parsed is None or parsed[0] != target:
            continue
        _norm, spec, _written = parsed
        rebuilt = _rebuild_spec(spec, fixed)
        if rebuilt != spec:
            lines[i] = line.replace(spec, rebuilt, 1)
            changed = True
    if not changed:
        raise ValueError(f"{package}: no bumpable specifier found in requirements.txt")
    return "".join(lines)


# ---------------------------------------------------------------------------
# HTTP (stdlib, HTTPS-only, capped, injectable for tests)
# ---------------------------------------------------------------------------


def http_get_json(url: str, *, timeout: float = 15.0, limit: int = HTTP_LIMIT) -> Any:
    """GET `url` (HTTPS only) and JSON-decode; capped at `limit` bytes."""
    if not url.startswith("https://"):
        raise Indeterminate(f"refusing non-HTTPS fetch: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "JA4proxy-FixForward/1.0"})  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            data = resp.read(limit + 1)
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise Indeterminate(f"unreachable: {url} ({exc})") from exc
    if _BYTES_SEEN is not None:  # opt-in per-run meter (set by `main`)
        _BYTES_SEEN.append((url, len(data)))
    if len(data) > limit:
        raise Indeterminate(f"response over {limit} bytes: {url}")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise Indeterminate(f"non-JSON response from {url}: {exc}") from exc


def pypi_fetch(url: str) -> Any:
    """`http_get_json` with the PyPI metadata cap (see PYPI_METADATA_LIMIT)."""
    if "/pypi/" in url and url.endswith("/json"):
        return http_get_json(url, limit=PYPI_METADATA_LIMIT)
    return http_get_json(url)


def memoized_json_fetch(
    fetch_json: Callable[[str], Any] = pypi_fetch,
) -> Callable[[str], Any]:
    """One HTTP layer per run: repeated lookups hit a dict, not the network."""
    cache: dict[str, Any] = {}

    def wrapped(url: str) -> Any:
        if url not in cache:
            cache[url] = fetch_json(url)
        return cache[url]

    return wrapped


# ---------------------------------------------------------------------------
# pypi-surface fix checks
# ---------------------------------------------------------------------------


def pypi_release_exists(
    package: str, version: str, *, fetch_json: Callable[[str], Any]
) -> tuple[bool, str]:
    """Is `version` actually published (and not yanked) on PyPI?"""
    doc = fetch_json(f"https://pypi.org/pypi/{package}/json")
    releases = doc.get("releases") or {}
    if version in releases:
        if releases[version]:
            return True, f"{package} {version} is published on PyPI"
        return False, f"{package} {version} exists on PyPI but is yanked"
    latest = (doc.get("info") or {}).get("version", "?")
    return False, f"{package} {version} is not published on PyPI (latest {latest})"


def osv_fixed_version(
    cve: str, package: str, *, fetch_json: Callable[[str], Any]
) -> tuple[str, str]:
    """Fixed version for `package` under `cve` per OSV — `""` when none is published."""
    doc = fetch_json(f"https://api.osv.dev/v1/vulns/{cve}")
    target = normalize_name(package)
    fixed_versions: list[str] = []
    for affected in doc.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("ecosystem") != "PyPI" or normalize_name(str(pkg.get("name", ""))) != target:
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if "fixed" in event:
                    fixed_versions.append(str(event["fixed"]))
    if not fixed_versions:
        return "", f"OSV publishes no fixed version for {package} under {cve}"
    # Events are chronological; the last `fixed` is the current fix line.
    chosen = fixed_versions[-1]
    return chosen, f"{package} {cve} is fixed in {chosen} (OSV)"


def external_constraint_block(
    package: str,
    fixed: str,
    requirements_text: str,
    *,
    fetch_json: Callable[[str], Any],
    max_reverse_deps: int = DEFAULT_MAX_REVERSE_DEPS,
) -> tuple[bool, str, str]:
    """Sweep `requires_dist` of every direct requirement for a pin on `package`.

    Returns `(blocked, evidence, dep)`. This is the `mcp`/semgrep check: our
    own floor can allow the fix while a transitive hard-pin makes it
    unresolvable — the finding is only genuinely blocked when the *external*
    graph says so.
    """
    direct = [n for n in direct_requirement_names(requirements_text) if n != package]
    if len(direct) > max_reverse_deps:
        raise Indeterminate(
            f"{len(direct)} direct requirements exceed the sweep cap "
            f"({max_reverse_deps}); a complete constraint check was not possible"
        )
    for name in direct:
        doc = fetch_json(f"https://pypi.org/pypi/{name}/json")
        info = doc.get("info") or {}
        version = info.get("version", "?")
        for item in info.get("requires_dist") or []:
            parsed = parse_req_line(str(item))
            if parsed is None or parsed[0] != package or not parsed[1]:
                continue
            raw = str(item).split(";")[0].strip()
            excluded, _ = spec_excludes(fixed, parsed[1])
            if excluded:
                return True, f"latest {name} ({version}) still pins {raw}", name
    return False, "", ""


def check_pypi_fix(
    cve: str,
    info: dict,
    *,
    requirements_text: str,
    fetch_json: Callable[[str], Any],
) -> dict:
    """Decide whether an unwaived pypi-surface finding has an adoptable fix.

    `info` is the monitor's finding dict (`package`, `installed`, `fixed`).
    Precedence: proven `blocked` > `unknown` > proven `fixable`.
    """
    package = normalize_name(str(info.get("package") or "?"))
    installed = str(info.get("installed") or "?")
    base = {"surface": PYPI_SURFACE, "cve": cve, "table": None, "bump": None}

    fixed = str(info.get("fixed") or "")
    fixed_evidence = ""
    if not fixed:
        try:
            fixed, fixed_evidence = osv_fixed_version(cve, package, fetch_json=fetch_json)
        except Indeterminate as exc:
            return {**base, "decision": "unknown", "evidence": str(exc), "recheck": ""}
    if not fixed:
        return {
            **base,
            "decision": "blocked",
            "evidence": fixed_evidence or f"no fixed version published for {package} under {cve}",
            "recheck": f"{package} publishes a fixed version for {cve}",
        }

    try:
        published, pub_evidence = pypi_release_exists(package, fixed, fetch_json=fetch_json)
        if not published:
            return {
                **base,
                "decision": "blocked",
                "evidence": pub_evidence,
                "recheck": f"{package} {fixed} is published to PyPI",
            }
        blocked, block_evidence, dep = external_constraint_block(
            package, fixed, requirements_text, fetch_json=fetch_json
        )
        if blocked:
            return {
                **base,
                "decision": "blocked",
                "evidence": block_evidence,
                "recheck": f"{dep} publishes a release allowing {package} >= {fixed}",
            }
    except Indeterminate as exc:
        return {**base, "decision": "unknown", "evidence": str(exc), "recheck": ""}

    specs = requirements_specs(requirements_text, package)
    if not specs:
        return {
            **base,
            "decision": "unknown",
            "evidence": (
                f"{package} is not a direct requirement in requirements.txt; "
                "fixing it means adding a floor by hand"
            ),
            "recheck": "",
        }

    # Our own line decides fixable (an editable pin/floor) vs unknown (a
    # deliberate upper bound or exclusion — a human's call, not the bot's).
    excluded_by: list[str] = []
    try:
        for spec in specs:
            excluded, evidence = spec_excludes(fixed, spec)
            if excluded:
                excluded_by.append(f"`{spec}` — {evidence}")
        if excluded_by:
            # Only claim fixable if rewriting our own clauses actually yields a
            # spec that admits `fixed`; anything else is a deliberate bound.
            for spec in specs:
                if spec_excludes(fixed, _rebuild_spec(spec, fixed))[0]:
                    return {
                        **base,
                        "decision": "unknown",
                        "evidence": (
                            f"requirements.txt bounds {package} with `{spec}`; "
                            f"raising to {fixed} would require relaxing that bound — a human decision"
                        ),
                        "recheck": "",
                    }
        new_text = bump_requirements(requirements_text, package, fixed)
        for spec_new in requirements_specs(new_text, package):
            if spec_excludes(fixed, spec_new)[0]:
                return {
                    **base,
                    "decision": "unknown",
                    "evidence": f"rewritten specifier `{spec_new}` still excludes {fixed}",
                    "recheck": "",
                }
    except (Indeterminate, ValueError) as exc:
        return {
            **base,
            "decision": "unknown",
            "evidence": f"{package}: {exc}",
            "recheck": "",
        }

    spec_note = f"; requirements.txt specifier: `{specs[0]}`" if specs else ""
    table = [
        {
            "cve": cve,
            "severity": info.get("severity", "?"),
            "before": f"{package} {installed}",
            "after": f"{package} {fixed}",
        }
    ]
    if excluded_by:
        reason = f"pin {excluded_by[0]} forces {installed}; raising it to {fixed} resolves"
    else:
        reason = f"{package} {installed} → {fixed}: specifier raised to force the fix (external graph admits it)"
    return {
        **base,
        "decision": "fixable",
        "evidence": (
            f"checked requirements.txt + {len(direct_requirement_names(requirements_text))} "
            f"direct requires_dist for pins{spec_note}: {reason}"
        ),
        "recheck": "",
        "bump": {"kind": "pypi", "package": package, "from": installed, "to": fixed},
        "table": table,
    }


# ---------------------------------------------------------------------------
# image-surface fix checks
# ---------------------------------------------------------------------------


def default_scanner(cache: str | None = None) -> Callable[[str], dict]:
    """Scan via the shared Trivy path (`scripts/scan_baseline.scan_image`)."""

    def scan(ref: str) -> dict:
        rows, _digest = scan_image(ref, first_party=False, cache=cache)
        return {
            r.cve: {
                "severity": r.severity,
                "package": r.package,
                "installed": r.installed,
                "fixed": r.fixed,
            }
            for r in rows
        }

    return scan


def _fresh(at: str, today: str, max_age_days: int) -> bool:
    try:
        return (date.fromisoformat(today) - date.fromisoformat(at)).days <= max_age_days
    except ValueError:
        return False


def cached_scanner(
    scanner: Callable[[str], dict],
    *,
    cache_path: Path,
    ignore_sha: str,
    today: str,
    max_age_days: int = DEFAULT_SCAN_CACHE_MAX_AGE_DAYS,
) -> tuple[Callable[[str], dict], Callable[[], None]]:
    """Wrap `scanner` with an on-disk cache keyed by (ref, ignorefile hash).

    Returns `(scanner, save)`. Entries older than `max_age_days` are ignored
    and re-scanned; `save` persists what was actually scanned this run.
    """
    data: dict[str, Any] = {}
    if cache_path.exists():
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}

    def wrapped(ref: str) -> dict:
        key = f"{ref}|{ignore_sha}"
        entry = data.get(key)
        if isinstance(entry, dict) and _fresh(str(entry.get("at", "")), today, max_age_days):
            return dict(entry.get("findings") or {})
        findings = scanner(ref)
        data[key] = {"at": today, "findings": findings}
        return findings

    def save() -> None:
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        except OSError:  # a cache write failure must never fail the check
            pass

    return wrapped, save


def _ref_name_and_tag(ref: str) -> tuple[str, str]:
    """`grafana/grafana:13.2.4` → (`grafana/grafana`, `13.2.4`); digest-stripped."""
    bare = ref.split("@", 1)[0]
    name, tag = bare.rsplit(":", 1)
    return name, tag


def _undecidable(surface: str, cves: set[str], reason: str) -> list[dict]:
    return [
        {
            "surface": surface,
            "cve": cve,
            "decision": "unknown",
            "evidence": reason,
            "recheck": "",
            "bump": None,
            "table": None,
        }
        for cve in sorted(cves)
    ]


def check_image_fix(
    ref: str,
    surface: str,
    target_cves: set[str],
    current_findings: dict,
    *,
    scanner: Callable[[str], dict],
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
    fetch_tags: Callable[[str], list[str]] = fetch_docker_hub_tags,
    today: str,
) -> list[dict]:
    """Decide, for each target CVE on one image, whether a clearing tag exists.

    One *decider* candidate is chosen — the newest published tag that introduces
    no new unwaived finding — so a surface can only ever produce one bump target
    and the before/after table describes exactly what that bump would do.
    """
    base = {"surface": surface, "bump": None}

    if is_first_party(ref):
        return _undecidable(
            surface,
            target_cves,
            "first-party image: the fix is a repo build (Dockerfile/dependency), "
            "not an upstream tag — not automated",
        )
    if "@" in ref:
        return _undecidable(
            surface,
            target_cves,
            f"{ref} is digest-pinned (@sha256); an automatic bump would rewrite the digest — manual proposal required",
        )
    parsed = parse_image_ref(ref)
    if parsed is None:
        return _undecidable(surface, target_cves, f"{ref}: non-semver tag — cannot reason about newer tags")

    fetch_error = ""
    try:
        tags = fetch_tags(parsed.repository)
    except Exception as exc:  # noqa: BLE001 -- any fetch failure is "cannot decide"
        fetch_error = str(exc)
        tags = []
    if not tags:
        reason = f"no tags visible for {parsed.repository} (registry unreachable or rate-limited)"
        if fetch_error:
            reason = f"{reason}: {fetch_error}"
        return _undecidable(surface, target_cves, reason)

    newer = find_newer_tags(parsed, tags)[:max_candidates]
    if not newer:
        reason = f"no published tag newer than {parsed.tag} (checked {today})"
        recheck = (
            f"{parsed.repository} publishes a tag newer than {parsed.tag} "
            f"that clears {', '.join(sorted(target_cves))}"
        )
        return [
            {**base, "cve": cve, "decision": "blocked", "evidence": reason, "recheck": recheck, "table": None}
            for cve in sorted(target_cves)
        ]

    name, _old_tag = _ref_name_and_tag(ref)
    skipped: list[str] = []
    decider_findings: dict | None = None
    decider_ref = ""
    scanned_ok = 0
    for tag in newer:
        candidate = f"{name}:{tag}"
        try:
            findings = scanner(candidate)
        except Exception as exc:  # noqa: BLE001 -- a failed scan proves nothing
            skipped.append(f"{tag} (scan failed: {exc})")
            continue
        scanned_ok += 1
        introduced = sorted(set(findings) - set(current_findings))
        if introduced:
            skipped.append(f"{tag} (introduces {', '.join(introduced)})")
            continue
        decider_ref, decider_findings = candidate, findings
        break

    if decider_findings is None:
        if scanned_ok == 0:
            # No candidate produced a readable scan: nothing was proven either
            # way, so this must not become a `blocked` claim.
            return _undecidable(
                surface,
                target_cves,
                f"checked {len(newer)} newer tag(s) ({', '.join(newer)}); none could be scanned — "
                + "; ".join(skipped),
            )
        reason = (
            f"checked {len(newer)} newer tag(s) ({', '.join(newer)}); none usable — "
            + ("; ".join(skipped) or "no candidate produced a readable scan")
        )
        recheck = (
            f"{parsed.repository} publishes a tag beyond {parsed.tag} "
            "that introduces no new unwaived finding"
        )
        return [
            {**base, "cve": cve, "decision": "blocked", "evidence": reason, "recheck": recheck, "table": None}
            for cve in sorted(target_cves)
        ]

    skip_note = f" (skipped: {'; '.join(skipped)})" if skipped else ""
    table = _image_table(current_findings, decider_findings)
    decisions: list[dict] = []
    for cve in sorted(target_cves):
        if cve not in decider_findings:
            decisions.append(
                {
                    **base,
                    "cve": cve,
                    "decision": "fixable",
                    "evidence": (
                        f"checked {today}: {decider_ref} clears {cve} "
                        f"({len(newer)} newer tag(s) considered){skip_note}"
                    ),
                    "recheck": "",
                    "bump": {"kind": "image", "ref": ref, "name": name, "from": _old_tag, "to": decider_ref.split(":", 1)[1]},
                    "table": table,
                }
            )
        else:
            decisions.append(
                {
                    **base,
                    "cve": cve,
                    "decision": "blocked",
                    "evidence": f"checked {today}: {decider_ref} still carries {cve}{skip_note}",
                    "recheck": f"{parsed.repository} publishes a tag newer than {decider_ref.split(':', 1)[1]} that clears {cve}",
                    "table": table,
                }
            )
    return decisions


def _image_table(before: dict, after: dict) -> list[dict]:
    """Rows proving the bump's effect: every unwaived finding, present before/after."""
    rows = []
    for cve in sorted(set(before) | set(after)):
        b, a = before.get(cve) or {}, after.get(cve) or {}
        rows.append(
            {
                "cve": cve,
                "severity": b.get("severity") or a.get("severity") or "?",
                "before": "present" if cve in before else "—",
                "after": "present" if cve in after else "**cleared**",
            }
        )
    return rows


# ---------------------------------------------------------------------------
# Evaluation over a monitor state file
# ---------------------------------------------------------------------------


def evaluate(
    current: dict,
    *,
    requirements_text: str,
    fetch_json: Callable[[str], Any],
    scanner: Callable[[str], dict],
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
    fetch_tags: Callable[[str], list[str]] = fetch_docker_hub_tags,
    today: str,
) -> list[dict]:
    """Evaluate every unwaived finding with a published fix → decisions.

    Grouped per surface so one image scan pass serves all of its target CVEs
    and each surface yields at most one bump target.
    """
    decisions: list[dict] = []
    per_surface: dict[str, list[str]] = {}
    for surface in sorted(current):
        for cve, info in sorted(current[surface].get("findings", {}).items()):
            if info.get("fixed"):
                per_surface.setdefault(surface, []).append(cve)

    for surface, cves in per_surface.items():
        entry = current[surface]
        if surface == PYPI_SURFACE:
            for cve in cves:
                decisions.append(
                    check_pypi_fix(
                        cve,
                        entry.get("findings", {}).get(cve, {}),
                        requirements_text=requirements_text,
                        fetch_json=fetch_json,
                    )
                )
        else:
            decisions.extend(
                check_image_fix(
                    str(entry.get("ref", "")),
                    surface,
                    set(cves),
                    entry.get("findings", {}),
                    scanner=scanner,
                    max_candidates=max_candidates,
                    fetch_tags=fetch_tags,
                    today=today,
                )
            )
    return decisions


def group_fixable(decisions: Sequence[dict]) -> list[dict]:
    """Collapse fixable decisions into one proposal unit per bump target."""
    units: dict[tuple[str, str], dict] = {}
    for d in decisions:
        if d.get("decision") != "fixable" or not d.get("bump"):
            continue
        bump = d["bump"]
        target = bump.get("ref") or bump.get("package") or "?"
        key = (d["surface"], f"{bump['kind']}:{target}:{bump['to']}")
        unit = units.get(key)
        if unit is None:
            slug_src = bump.get("name") or bump.get("package") or target
            slug = re.sub(r"[^a-z0-9]+", "-", f"{slug_src}-{bump['to']}".lower()).strip("-")
            unit = {
                "title_base": f"bump {target} to {bump['to']}",
                "branch": f"bot/fix-forward-{slug}",
                "bump": bump,
                "cves": [],
                "table": d.get("table") or [],
                "surface": d["surface"],
                "evidence": [],
            }
            units[key] = unit
        unit["cves"].append(d["cve"])
        if d.get("table") and not unit["table"]:
            unit["table"] = d["table"]
        if d.get("evidence") and d["evidence"] not in unit["evidence"]:
            unit["evidence"].append(d["evidence"])
    for unit in units.values():
        unit["cves"].sort()
        suffix = f"+{len(unit['cves']) - 1} more" if len(unit["cves"]) > 1 else ""
        unit["title"] = f"{unit['title_base']} ({unit['cves'][0]}{suffix})"
    return sorted(units.values(), key=lambda u: u["title"])


# ---------------------------------------------------------------------------
# Registry recording
# ---------------------------------------------------------------------------


def registry_entry(registry: dict, cve: str) -> dict | None:
    for w in registry.get("waivers") or []:
        if w.get("id") == cve:
            return w
    return None


def record_fix_availability(registry: dict, cve: str, decision: dict, today: str) -> str | None:
    """Mutate the entry's fix metadata from a decision. `None` = nothing to do.

    `blocked` records `fix_available: false` + a `recheck_trigger` naming the
    concrete upstream change (schema-required by render_waivers.validate).
    `fixable` records `fix_available: true` and drops a now-stale trigger.
    `unknown` records nothing — an undecidable check must not claim either way.
    Registry *creation* is never done here: rationale/reachability are a
    human's authorship.
    """
    entry = registry_entry(registry, cve)
    if entry is None:
        return None
    kind = decision.get("decision")
    if kind == "blocked":
        if entry.get("fix_available") is False and entry.get("recheck_trigger"):
            return None
        evidence = decision.get("evidence") or "?"
        recheck = decision.get("recheck") or evidence
        entry["fix_available"] = False
        entry["recheck_trigger"] = f"{recheck} (checked {today}: {evidence})"
        return f"{cve}: fix_available: false"
    if kind == "fixable":
        if entry.get("fix_available") is True:
            return None
        entry["fix_available"] = True
        entry.pop("recheck_trigger", None)
        return f"{cve}: fix_available: true"
    return None


# ---------------------------------------------------------------------------
# Proposal authoring (git + issue — never `gh pr create`, see module docstring)
# ---------------------------------------------------------------------------


def sh(argv: Sequence[str]) -> tuple[int, str, str]:
    """Run a fixed argv (no shell); return `(returncode, stdout, stderr)`."""
    proc = subprocess.run(list(argv), capture_output=True, text=True)  # nosec B603 -- fixed argv, no shell
    return proc.returncode, proc.stdout, proc.stderr


def _github_remote(root: Path, sh_runner: Callable[[Sequence[str]], tuple[int, str, str]]) -> tuple[str, str] | None:
    rc, out, _ = sh_runner(["git", "-C", str(root), "remote", "get-url", "origin"])
    if rc != 0:
        return None
    m = re.search(r"github\.com[:/](?P<org>[^/]+)/(?P<repo>[^/.]+)", out.strip())
    if m is None:
        return None
    return m.group("org"), m.group("repo")


def propose(
    *,
    branch: str,
    title: str,
    body: str,
    edit_builder: Callable[[Path], list[Path]],
    repo_root: Path,
    sh_runner: Callable[[Sequence[str]], tuple[int, str, str]] | None = None,
    issue_creator: Callable[[str, str], str] | None = None,
) -> dict:
    """Author one proposal: `bot/*` branch from freshly-fetched origin/main + issue.

    Raises `ProposeError` on any git/issue failure — the caller reports it per
    unit and keeps going. Returns `{"branch", "issue"}`. Defaults resolve at
    call time (not def time) so tests can inject.
    """
    sh_runner = sh_runner or sh
    issue_creator = issue_creator or create_issue

    def run(argv: Sequence[str], what: str) -> tuple[int, str, str]:
        rc, out, err = sh_runner(list(argv))
        if rc != 0:
            raise ProposeError(f"{what} failed (rc={rc}): {(err or out).strip()[:300]}")
        return rc, out, err

    rc, out, _ = sh_runner(["git", "-C", str(repo_root), "status", "--porcelain"])
    if rc != 0:
        raise ProposeError(f"git status failed: {out.strip()[:200]}")
    if out.strip():
        raise ProposeError("working tree not clean — commit or stash before --apply")
    run(["git", "-C", str(repo_root), "fetch", "origin", "main"], "git fetch")
    # -B: idempotent for a same-day re-run after a partial failure; the push
    # uses --force-with-lease, mirroring the renewal workflow's proven pattern.
    run(["git", "-C", str(repo_root), "checkout", "-B", branch, "origin/main"], "git checkout")
    try:
        paths = edit_builder(repo_root)
    except Exception as exc:
        sh_runner(["git", "-C", str(repo_root), "checkout", "-B", branch, "HEAD"])
        raise ProposeError(f"edits failed: {exc}") from exc
    if not paths:
        raise ProposeError("edit builder produced no files")
    rel = [str(p.resolve().relative_to(repo_root.resolve())) for p in paths]
    run(["git", "-C", str(repo_root), "add", "--", *rel], "git add")
    rc, _out, _err = sh_runner(["git", "-C", str(repo_root), "diff", "--cached", "--quiet"])
    if rc == 0:
        raise ProposeError("no staged changes — nothing to propose (already recorded?)")
    run(
        [
            "git",
            "-C",
            str(repo_root),
            "-c",
            "user.name=github-actions[bot]",
            "-c",
            "user.email=41898282+github-actions[bot]@users.noreply.github.com",
            "commit",
            "-m",
            f"{PROPOSAL_PREFIX}{title}",
        ],
        "git commit",
    )
    run(["git", "-C", str(repo_root), "push", "--force-with-lease", "-u", "origin", branch], "git push")

    compare = ""
    remote = _github_remote(repo_root, sh_runner)
    if remote:
        org, repo = remote
        compare = (
            "\n**Open the PR here (one click, pre-filled):** "
            f"https://github.com/{org}/{repo}/compare/main...{branch}?expand=1\n"
        )
    issue = issue_creator(f"{PROPOSAL_PREFIX}{title}", f"{body}\n{compare}")
    return {"branch": branch, "issue": issue}


def issue_has_marker(number: int, marker: str = ISSUE_MARKER, sh_runner=None) -> bool:
    sh_runner = sh_runner or sh
    rc, out, err = sh_runner(["gh", "issue", "view", str(number), "--json", "comments"])
    if rc != 0:
        raise RuntimeError(f"gh issue view #{number} failed: {err.strip()[:300]}")
    comments = json.loads(out).get("comments") or []
    return any(marker in (c.get("body") or "") for c in comments)


def comment_issue(number: int, body: str, sh_runner=None) -> None:
    sh_runner = sh_runner or sh
    rc, _out, err = sh_runner(["gh", "issue", "comment", str(number), "--body", body])
    if rc != 0:
        raise RuntimeError(f"gh issue comment #{number} failed: {err.strip()[:300]}")


# ---------------------------------------------------------------------------
# Bodies and report
# ---------------------------------------------------------------------------


def _table_md(rows: list[dict], headers: tuple[str, str, str, str]) -> list[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    for r in rows:
        lines.append(f"| {r['cve']} | {r['severity']} | {r['before']} | {r['after']} |")
    return lines


def proposal_body(unit: dict, today: str) -> str:
    bump = unit["bump"]
    lines = [
        "Phase 847d fix-forward proposal — a clearing version exists; this branch carries the bump.",
        "",
    ]
    if unit["table"]:
        if bump["kind"] == "image":
            lines += _table_md(
                unit["table"],
                (
                    "CVE",
                    "Severity",
                    f"before `{bump.get('ref', '')}`",
                    f"after `{bump.get('name', '')}:{bump['to']}`",
                ),
            )
        else:
            lines += _table_md(unit["table"], ("CVE", "Severity", "before", "after"))
        lines.append("")
    lines.append("**Evidence:**")
    lines += [f"- {e}" for e in unit["evidence"]]
    lines += [
        "",
        "**Validation:** the PR opened from this branch carries compose/requirements",
        "validation, `Scan Regression (surfaces touched)` (required) and the smoke tests.",
        "",
        "> 🤖 Authored by the fix-forward bot (Phase 847d). It never merges its own",
        "> proposals — a human reviews the table and opens the PR from the compare link.",
    ]
    return "\n".join(lines)


def registry_proposal_body(records: Sequence[str], today: str) -> str:
    lines = [
        "Phase 847d fix-forward — fix-availability **negative** results recorded on the registry.",
        "",
        "Each entry below was checked against PyPI, requirements.txt and the",
        f"external constraint graph today ({today}):",
        "",
    ]
    lines += [f"- {r}" for r in records]
    lines += [
        "",
        "Every `fix_available: false` carries its evidence and the concrete upstream",
        "change that would obsolete it (`recheck_trigger`), so the waiver's premise",
        "stays machine-verifiable.",
        "",
        "> 🤖 Authored by the fix-forward bot (Phase 847d) — reviewable, never auto-merged.",
    ]
    return "\n".join(lines)


def evidence_comment_body(decision: dict, today: str) -> str:
    cve = decision["cve"]
    lines = [
        ISSUE_MARKER,
        f"**Fix-forward check ({today}): no adoptable fix — `fix_available: false`.**",
        "",
        f"- Evidence: {decision.get('evidence', '?')}",
    ]
    if decision.get("recheck"):
        lines.append(f"- Re-check when: {decision['recheck']}")
    lines += [
        "",
        "When waiving this finding, the registry entry can record that fact directly:",
        "",
        "```yaml",
        f"  - id: {cve}",
        "    # ...schema fields (rationale, reachability, dates)...",
        "    fix_available: false",
    ]
    if decision.get("recheck"):
        lines.append(f'    recheck_trigger: "{decision["recheck"]}"')
    lines += [
        "```",
        "",
        "_Evidence recorded automatically so the waiver's premise need not be_",
        "_re-derived by hand._",
    ]
    return "\n".join(lines)


def render_report(decisions: Sequence[dict], records: Sequence[str], proposed: Sequence[dict]) -> str:
    counts: dict[str, int] = {"fixable": 0, "blocked": 0, "unknown": 0}
    for d in decisions:
        counts[d["decision"]] = counts.get(d["decision"], 0) + 1
    lines = [
        "# Fix-forward report (Phase 847d)",
        "",
        f"- Fixable queue evaluated: **{len(decisions)}**",
        f"- fixable: **{counts['fixable']}** · blocked: **{counts['blocked']}** · unknown: **{counts['unknown']}**",
        f"- registry records changed: **{len(records)}**",
        f"- proposals authored: **{len(proposed)}**",
        "",
    ]
    for d in decisions:
        lines.append(f"- `[{d['decision']}]` {d['surface']} {d['cve']} — {d['evidence']}")
    if not decisions:
        lines.append("Steady state: nothing to fix, nothing to record.")
    lines.append("")
    lines.append(
        f"FIXABLE_QUEUE evaluated={len(decisions)} fixable={counts['fixable']} "
        f"blocked={counts['blocked']} unknown={counts['unknown']} proposed={len(proposed)}"
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Edit builders (recomputed inside propose, after the branch checkout)
# ---------------------------------------------------------------------------


def _image_builder(bump: dict) -> Callable[[Path], list[Path]]:
    def apply(root: Path) -> list[Path]:
        compose = root / "deploy" / "docker"
        old_ref = f"{bump['name']}:{bump['from']}"
        new_ref = f"{bump['name']}:{bump['to']}"
        written: list[Path] = []
        for path in sorted(compose.glob("docker-compose*.yml")):
            text = path.read_text(encoding="utf-8")
            if old_ref not in text:
                continue
            path.write_text(text.replace(old_ref, new_ref), encoding="utf-8")
            written.append(path)
        if not written:
            raise ProposeError(f"{old_ref} not found under {compose}")
        return written

    return apply


def _requirements_builder(bump: dict, requirements_path: Path) -> Callable[[Path], list[Path]]:
    def apply(root: Path) -> list[Path]:
        path = requirements_path if requirements_path.is_absolute() else root / requirements_path
        text = path.read_text(encoding="utf-8")
        new_text = bump_requirements(text, bump["package"], bump["to"])
        if new_text == text:
            raise ProposeError(f"{bump['package']}: requirements unchanged")
        path.write_text(new_text, encoding="utf-8")
        return [path]

    return apply


def _with_registry(
    inner: Callable[[Path], list[Path]] | None, registry: dict, registry_path: Path
) -> Callable[[Path], list[Path]]:
    """Append the registry save + derived re-render to another edit builder."""

    def apply(root: Path) -> list[Path]:
        paths = list(inner(root)) if inner else []
        save_registry(registry, registry_path, mutable_keys=BOT_MUTABLE_KEYS)
        rendered = write_derived(render_all(registry))
        registry_abs = registry_path if registry_path.is_absolute() else root / registry_path
        if registry_abs not in paths:
            paths.append(registry_abs)
        paths.extend(p for p in rendered if p not in paths)
        return paths

    return apply


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _registry_errors(registry: dict) -> list[str]:
    return validate(registry)


def _write_bytes_report(path: Path) -> None:
    """Persist what this run actually downloaded, largest first.

    The HTTP caps exist to fail loudly on a pathological body, not to hide a
    legitimate one: recording observed sizes keeps that boundary empirical.
    """
    rows = sorted(_BYTES_SEEN or [], key=lambda r: r[1], reverse=True)
    try:
        path.write_text(
            json.dumps(
                {"largest": [{"url": u, "bytes": n} for u, n in rows[:10]], "count": len(rows)},
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    except OSError as exc:  # never fail the check over a report write
        print(f"· bytes report not written: {exc}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--state", required=True, help="monitor state file (scan_baseline_monitor --state-out)")
    parser.add_argument("--apply", action="store_true", help="author proposals (default: report only)")
    parser.add_argument("--registry", type=Path, default=REGISTRY_PATH)
    parser.add_argument(
        "--requirements",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "requirements.txt",
    )
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--max-candidates", type=int, default=DEFAULT_MAX_CANDIDATES)
    parser.add_argument("--scan-cache", type=Path, default=None, help="candidate scan cache file")
    parser.add_argument("--today", default="", help="override today (YYYY-MM-DD)")
    parser.add_argument(
        "--bytes-out",
        type=Path,
        default=None,
        help="record observed HTTP response sizes (justifies the caps)",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable decisions")
    args = parser.parse_args(argv)

    today = args.today or date.today().isoformat()
    global _BYTES_SEEN
    if args.bytes_out is not None:
        _BYTES_SEEN = []
        globals()["_BYTES_SEEN"] = _BYTES_SEEN
    try:
        state = json.loads(Path(args.state).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"✗ unreadable state file {args.state}: {exc}", file=sys.stderr)
        return 2
    current = state.get("current") or {}

    try:
        registry = load_registry(args.registry)
    except Exception as exc:  # noqa: BLE001 -- registry load errors are reported
        print(f"✗ {exc}", file=sys.stderr)
        return 2
    requirements_text = (
        args.requirements.read_text(encoding="utf-8") if args.requirements.exists() else ""
    )

    save_cache: Callable[[], None] | None = None
    if args.scan_cache is None:
        scanner: Callable[[str], dict] = default_scanner()
    else:
        ignore_path = args.repo_root / ".trivyignore.third-party"
        ignore_sha = sha1(ignore_path.read_bytes()).hexdigest()[:16] if ignore_path.exists() else "none"
        scanner, save_cache = cached_scanner(
            default_scanner(), cache_path=args.scan_cache, ignore_sha=ignore_sha, today=today
        )

    fetch_json = memoized_json_fetch(pypi_fetch)
    try:
        decisions = evaluate(
            current,
            requirements_text=requirements_text,
            fetch_json=fetch_json,
            scanner=scanner,
            max_candidates=args.max_candidates,
            today=today,
        )
    finally:
        if save_cache:
            save_cache()
        if args.bytes_out is not None:
            _write_bytes_report(args.bytes_out)

    if args.json:
        print(json.dumps({"today": today, "decisions": decisions}, indent=2, sort_keys=True))
        return 0

    if not args.apply:
        print(render_report(decisions, [], []))
        return 0

    # --apply: guard the working tree and reach GitHub before anything moves.
    rc, out, _ = sh(["git", "-C", str(args.repo_root), "status", "--porcelain"])
    if rc != 0:
        print("✗ not a git repository (pass --repo-root)", file=sys.stderr)
        return 2
    if out.strip():
        print("✗ working tree not clean — commit or stash before --apply", file=sys.stderr)
        return 2
    try:
        known_issues = issues_by_title()
    except (RuntimeError, json.JSONDecodeError) as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 2

    rc, start_ref, _ = sh(["git", "-C", str(args.repo_root), "rev-parse", "--abbrev-ref", "HEAD"])
    start_ref = start_ref.strip() if rc == 0 and start_ref.strip() != "HEAD" else None

    proposed: list[dict] = []
    records: list[str] = []
    failures = 0

    try:
        # 1. Fixable units -> bump proposals (one branch per bump target).
        for unit in group_fixable(decisions):
            title = unit["title"]
            if f"{PROPOSAL_PREFIX}{title}" in known_issues:
                print(f"· already proposed: {PROPOSAL_PREFIX}{title}")
                continue
            bump = unit["bump"]
            unit_records = [
                change
                for cve in unit["cves"]
                if (change := record_fix_availability(registry, cve, {"decision": "fixable"}, today))
            ]
            if unit_records:
                errors = _registry_errors(registry)
                if errors:
                    print(f"✗ registry invalid after fixable records: {errors[0]}", file=sys.stderr)
                    failures += 1
                    continue
            builder: Callable[[Path], list[Path]]
            if bump["kind"] == "image":
                builder = _image_builder(bump)
            else:
                builder = _requirements_builder(bump, args.requirements)
            if unit_records:
                builder = _with_registry(builder, registry, args.registry)
            try:
                result = propose(
                    branch=unit["branch"],
                    title=title,
                    body=proposal_body(unit, today),
                    edit_builder=builder,
                    repo_root=args.repo_root,
                )
            except ProposeError as exc:
                print(f"✗ {title}: {exc}", file=sys.stderr)
                failures += 1
                continue
            records.extend(unit_records)
            proposed.append(result)
            print(f"✓ {title} → {result['issue']} ({result['branch']})")

        # 2. Blocked findings with an existing entry (e.g. an expired waiver
        #    whose premise the monitor just re-raised) -> one batched branch.
        no_fix_records = [
            change
            for d in decisions
            if d["decision"] == "blocked"
            and (change := record_fix_availability(registry, d["cve"], d, today))
        ]
        if no_fix_records:
            errors = _registry_errors(registry)
            if errors:
                print(f"✗ registry invalid after no-fix records: {errors[0]}", file=sys.stderr)
                failures += 1
            else:
                title = f"record fix_available: false evidence ({today})"
                if f"{PROPOSAL_PREFIX}{title}" in known_issues:
                    print(f"· already proposed: {PROPOSAL_PREFIX}{title}")
                else:
                    try:
                        result = propose(
                            branch=f"bot/fix-forward-no-fix-{today.replace('-', '')}",
                            title=title,
                            body=registry_proposal_body(no_fix_records, today),
                            edit_builder=_with_registry(None, registry, args.registry),
                            repo_root=args.repo_root,
                        )
                    except ProposeError as exc:
                        print(f"✗ {title}: {exc}", file=sys.stderr)
                        failures += 1
                    else:
                        proposed.append(result)
                        records.extend(no_fix_records)
                        print(f"✓ {title} → {result['issue']} ({result['branch']})")

        # 3. Blocked findings with NO entry -> evidence comment on the monitor
        #    issue, so the human waiver author gets the authoritative fact.
        for d in decisions:
            if d["decision"] != "blocked" or registry_entry(registry, d["cve"]):
                continue
            number = (known_issues.get(issue_title(d["surface"], d["cve"])) or {}).get("number")
            if not number:
                print(f"· no open monitor issue for {d['cve']} — evidence reported only")
                continue
            try:
                if issue_has_marker(number):
                    print(f"· evidence already recorded on #{number}")
                    continue
                comment_issue(number, evidence_comment_body(d, today))
            except (RuntimeError, json.JSONDecodeError) as exc:
                print(f"✗ {d['cve']}: {exc}", file=sys.stderr)
                failures += 1
                continue
            print(f"✓ evidence comment on #{number} ({d['cve']})")
    finally:
        if start_ref:
            sh(["git", "-C", str(args.repo_root), "checkout", start_ref])

    print(render_report(decisions, records, proposed))
    return 1 if failures else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
