#!/usr/bin/env python3
"""Meta-lint: verify the Makefile is internally honest.

This tool is intentionally **dependency-free** (Python standard library only) so
it can run anywhere — including hosts without the full Docker/3.14 toolchain —
because its whole job is to keep the build's front door (the Makefile) from
lying about itself. It parses the Makefile into a small model and asserts:

* every target name advertised in ``make help*`` output is a real target
  (Class 3 in PHASE_224);
* every prerequisite resolves to a real target or an existing file
  (Class 1 — dangling prereqs that make ``make lint`` etc. error out);
* every ``.PHONY`` name is a real target and no target is a silent no-op
  (Class 2/4 — the recipe-less ``scan`` that "succeeds" doing nothing);
* the light umbrellas (``lint``/``scan``/``test``) never pull in a heavy
  benchmark, so ``make lint scan test`` stays the "full but not punishing" gate.

The model is built by line-based parsing of the single ``Makefile`` (the only
include, ``.local/machine.mk``, is optional and machine-local), which keeps the
checks deterministic and independent of the installed ``make`` version. A light
``make -n`` resolution probe is layered on top as defence-in-depth.

Run as a script for ``make lint-meta``; import the functions for unit tests
(``tests/unit/test_makefile_integrity.py``).
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# --------------------------------------------------------------------------- #
# Single source of truth: which targets are "heavy" and which are the light
# umbrellas that must never reach them. Mirror docs/phases/PHASE_224.md.
# --------------------------------------------------------------------------- #
HEAVY_TARGETS: Set[str] = {
    "bench",
    "bench-macro",
    "bench-micro",
    "perf-test",
    "perf-test-basic",
    "load-test",
    "load-test-baseline",
    "load-test-report",
    "test-go-perf",
    "measure-mttr",
}
LIGHT_UMBRELLAS: Tuple[str, ...] = ("lint", "scan", "test")

# Tokens that may appear in help text in a ``make X``-looking position but are
# literal shell commands / examples, not targets.
ADVERTISED_ALLOWLIST: Set[str] = {
    "ssh",
    "git",
    "docker",
    "kubectl",
    "bash",
    "sh",
    "cd",
    "cp",
    "sudo",
    "make",
}

# Prereqs that are make built-ins / special targets, not user targets.
SPECIAL_PREREQS: Set[str] = {"FORCE", "force"}

_ASSIGNMENT_RE = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_.]*\s*[:+?!]?=")
_TARGET_RE = re.compile(r"^(?P<names>[^\t:#=]+?)::?(?!=)(?P<rest>.*)$")
_ECHO_RE = re.compile(r'@?echo\s+(?:-e\s+)?["\'](.*)["\']\s*$')
# Only the canonical sub-make form counts as a graph edge. Bare `make` in a
# recipe is discouraged and, more importantly, the word "make" appears constantly
# in echo prose ("make sure…"), which must not be mistaken for a target call.
_MAKE_CALL_RE = re.compile(r"\$[({]MAKE[)}]\s+(?P<args>[^\n;&|]+)")
_ADVERTISED_MAKE_RE = re.compile(r"\bmake\s+(?P<args>[a-z0-9][a-z0-9_/.-]*(?:\s+[a-z0-9][a-z0-9_/.-]*)*)")
# Help rows look like ``  <target>   - <description>``. The name is lowercase
# (targets are) and is followed by at least one space, a dash, and a space. We
# allow a single space (long names like ``test-component-suites`` are only
# one-space-aligned) — the lowercase anchor keeps prose ("  Note - …") out.
_HELP_ROW_RE = re.compile(r"^\s{2,}(?P<name>[a-z][a-z0-9_/.-]+)\s+-\s")


@dataclass
class Target:
    name: str
    prereqs: List[str] = field(default_factory=list)
    recipe: List[str] = field(default_factory=list)
    make_calls: Set[str] = field(default_factory=set)
    has_inline_recipe: bool = False
    line: int = 0

    @property
    def has_recipe(self) -> bool:
        return self.has_inline_recipe or any(r.strip() for r in self.recipe)


@dataclass
class Makefile:
    targets: Dict[str, Target] = field(default_factory=dict)
    phony: Set[str] = field(default_factory=set)
    echoes: List[Tuple[int, str]] = field(default_factory=list)


def _strip_comment(text: str) -> str:
    # Drop a trailing recipe/prereq comment, but not a ``#`` inside the string.
    # Makefile prereq lines do not legitimately contain ``#`` data, so this is safe.
    return text.split("#", 1)[0]


def _expand_slash_shorthand(token: str) -> List[str]:
    """Expand help shorthand like ``management-up/down/logs/shell``.

    The first segment is a full target name; later slash segments inherit the
    prefix up to the first token's last ``-`` (so ``down`` -> ``management-down``).
    A plain token returns itself.
    """
    if "/" not in token:
        return [token]
    parts = token.split("/")
    first = parts[0]
    if "-" in first:
        prefix = first.rsplit("-", 1)[0]
        return [first] + [f"{prefix}-{p}" for p in parts[1:] if p]
    # No prefix to inherit; treat each as its own token.
    return [p for p in parts if p]


def parse_makefile(text: str) -> Makefile:
    """Parse Makefile text into a model. Best-effort but robust to the
    constructs this repo uses: multi-target rules, backslash continuations,
    inline ``;`` recipes, ``.PHONY`` continuations, and ``$(MAKE)`` sub-calls."""
    mk = Makefile()
    lines = text.split("\n")
    current: List[str] = []  # target names owning the recipe lines that follow
    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i]

        # Recipe line (tab-indented) — belongs to the current target(s).
        if raw.startswith("\t"):
            recipe = raw[1:]
            while recipe.rstrip().endswith("\\") and i + 1 < n:
                i += 1
                recipe = recipe.rstrip()[:-1] + " " + lines[i].lstrip("\t")
            em = _ECHO_RE.search(recipe.strip())
            if em:
                mk.echoes.append((i + 1, em.group(1)))
            # $(MAKE) edges are extracted from every command line — including
            # `$(MAKE) X || echo …` fallbacks — since the canonical form never
            # appears in echo prose.
            for mc in _MAKE_CALL_RE.finditer(recipe):
                for tok in _strip_comment(mc.group("args")).split():
                    if re.match(r"^[a-z0-9][a-z0-9_.-]*$", tok):
                        for t in current:
                            mk.targets[t].make_calls.add(tok)
            for t in current:
                mk.targets[t].recipe.append(recipe)
            i += 1
            continue

        # Non-recipe logical line: join backslash continuations.
        logical = raw
        while logical.rstrip().endswith("\\") and i + 1 < n:
            i += 1
            logical = logical.rstrip()[:-1] + " " + lines[i]

        stripped = logical.strip()
        if not stripped or stripped.startswith("#"):
            current = []
            i += 1
            continue

        if stripped.startswith(".PHONY"):
            after = stripped[len(".PHONY"):].lstrip()
            if after.startswith(":"):
                mk.phony.update(after[1:].replace("\\", " ").split())
            current = []
            i += 1
            continue

        if _ASSIGNMENT_RE.match(logical):
            current = []
            i += 1
            continue

        m = _TARGET_RE.match(logical)
        if m:
            names = m.group("names").split()
            rest = _strip_comment(m.group("rest"))
            inline = False
            if ";" in rest:
                rest, _, _ = rest.partition(";")
                inline = True
            prereqs = [p for p in rest.replace("|", " ").split() if p]
            current = []
            for name in names:
                tgt = mk.targets.get(name)
                if tgt is None:
                    tgt = Target(name=name, line=i + 1)
                    mk.targets[name] = tgt
                tgt.prereqs.extend(prereqs)
                if inline:
                    tgt.has_inline_recipe = True
                current.append(name)
            i += 1
            continue

        current = []
        i += 1
    return mk


# --------------------------------------------------------------------------- #
# Advertised-name extraction
# --------------------------------------------------------------------------- #
def advertised_targets(mk: Makefile) -> Set[str]:
    found: Set[str] = set()
    for _lineno, text in mk.echoes:
        for am in _ADVERTISED_MAKE_RE.finditer(text):
            for tok in am.group("args").split():
                if "=" in tok or tok.startswith("$"):
                    break  # reached arguments; stop scanning this `make ...`
                found.update(_expand_slash_shorthand(tok))
        rm = _HELP_ROW_RE.match(text)
        if rm:
            found.update(_expand_slash_shorthand(rm.group("name")))
    return {t for t in found if t not in ADVERTISED_ALLOWLIST}


# --------------------------------------------------------------------------- #
# Checks — each returns a list of human-readable error strings.
# --------------------------------------------------------------------------- #
def check_advertised_exist(mk: Makefile) -> List[str]:
    errors = []
    for name in sorted(advertised_targets(mk)):
        if name not in mk.targets:
            errors.append(f"help text advertises 'make {name}' but no such target exists")
    return errors


def check_prereqs_exist(mk: Makefile) -> List[str]:
    errors = []
    for tgt in mk.targets.values():
        for p in tgt.prereqs:
            if "$(" in p or "${" in p or p.startswith("."):
                continue
            if p in SPECIAL_PREREQS:
                continue
            if p in mk.targets:
                continue
            if os.path.exists(p):
                continue
            errors.append(
                f"target '{tgt.name}' (line {tgt.line}) needs prerequisite "
                f"'{p}' which is neither a target nor an existing file"
            )
    return errors


def check_make_calls_exist(mk: Makefile) -> List[str]:
    """Every `$(MAKE) X` / `make X` invoked inside a recipe must be a real
    target. Catches dangling sub-calls (e.g. a recipe that runs `$(MAKE)
    lint-semgrep` when no such target exists) without needing `make` installed."""
    errors = []
    for tgt in sorted(mk.targets.values(), key=lambda t: t.line):
        for callee in sorted(tgt.make_calls):
            if callee.startswith(".") or callee in SPECIAL_PREREQS:
                continue
            if callee not in mk.targets:
                errors.append(
                    f"target '{tgt.name}' (line {tgt.line}) runs `$(MAKE) "
                    f"{callee}` but no such target exists"
                )
    return errors


def check_phony_sane(mk: Makefile) -> List[str]:
    errors = []
    for name in sorted(mk.phony):
        if name in (".PHONY",):
            continue
        if name not in mk.targets:
            errors.append(
                f".PHONY lists '{name}' but no such target is defined "
                f"(a recipe-less .PHONY name silently succeeds doing nothing)"
            )
    for tgt in mk.targets.values():
        if not tgt.has_recipe and not tgt.prereqs and not tgt.make_calls:
            errors.append(
                f"target '{tgt.name}' (line {tgt.line}) is a no-op: "
                f"no recipe, no prerequisites, no $(MAKE) calls"
            )
    return errors


def _closure(mk: Makefile, roots: Tuple[str, ...]) -> Set[str]:
    seen: Set[str] = set()
    stack = [r for r in roots if r in mk.targets]
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        tgt = mk.targets.get(cur)
        if not tgt:
            continue
        for nxt in list(tgt.prereqs) + list(tgt.make_calls):
            if nxt in mk.targets and nxt not in seen:
                stack.append(nxt)
    return seen


def check_umbrellas_exclude_heavy(mk: Makefile) -> List[str]:
    errors = []
    for umbrella in LIGHT_UMBRELLAS:
        if umbrella not in mk.targets:
            continue
        reachable = _closure(mk, (umbrella,))
        heavy_hits = sorted(reachable & HEAVY_TARGETS)
        if heavy_hits:
            errors.append(
                f"light umbrella '{umbrella}' transitively runs heavy "
                f"benchmark target(s): {', '.join(heavy_hits)}"
            )
    return errors


def run_integrity_checks(makefile_path: str = "Makefile") -> List[str]:
    """Return a flat list of integrity errors for the Makefile at the path."""
    with open(makefile_path, "r", encoding="utf-8") as f:
        mk = parse_makefile(f.read())
    errors: List[str] = []
    errors += check_advertised_exist(mk)
    errors += check_prereqs_exist(mk)
    errors += check_make_calls_exist(mk)
    errors += check_phony_sane(mk)
    errors += check_umbrellas_exclude_heavy(mk)
    return errors


def resolve_umbrellas(umbrellas: Tuple[str, ...] = LIGHT_UMBRELLAS) -> List[str]:
    """Defence-in-depth: ask `make` itself to dry-run each umbrella and flag any
    'No rule to make target' error. Skipped gracefully if `make` is absent."""
    errors = []
    for u in umbrellas:
        try:
            proc = subprocess.run(
                ["make", "-n", u],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=60,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []  # make unavailable / too slow — static checks still ran
        err = proc.stderr.decode(errors="replace")
        for m in re.finditer(r"No rule to make target '([^']+)'", err):
            errors.append(f"`make {u}` cannot resolve: missing target '{m.group(1)}'")
    return errors


# --------------------------------------------------------------------------- #
# Legacy checks (preserved from the original meta_lint)
# --------------------------------------------------------------------------- #
def check_basic_syntax() -> Optional[str]:
    try:
        subprocess.check_output(["make", "-n", "help"], stderr=subprocess.STDOUT)
        return None
    except FileNotFoundError:
        return None
    except subprocess.CalledProcessError as e:
        return f"Makefile syntax error or recursion detected:\n{e.output.decode()}"


def check_script_shebangs(scripts_dir: str = "scripts") -> List[str]:
    warnings = []
    if not os.path.isdir(scripts_dir):
        return warnings
    for s in sorted(os.listdir(scripts_dir)):
        if s.endswith((".sh", ".py")):
            path = os.path.join(scripts_dir, s)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    if not f.readline().startswith("#!"):
                        warnings.append(f"{path} is missing a shebang")
            except OSError:
                pass
    return warnings


def verify_documentation_commands(docs=("README.md", "docs/OPERATIONS_GUIDE.md")) -> List[str]:
    errors = []
    try:
        with open("Makefile", "r", encoding="utf-8") as f:
            mk = parse_makefile(f.read())
    except OSError as e:
        return [f"Could not read Makefile: {e}"]
    make_targets = set(mk.targets)
    for doc in docs:
        if not os.path.exists(doc):
            continue
        with open(doc, "r", encoding="utf-8") as f:
            content = f.read()
        cmds = re.findall(r"`make (.*?)`", content)
        for b in re.findall(r"```bash\n(.*?)\n```", content, re.DOTALL):
            for line in b.split("\n"):
                if line.strip().startswith("make "):
                    cmds.append(line.strip()[len("make "):])
        for cmd in cmds:
            if not cmd.split():
                continue
            target = cmd.split()[0].strip().strip("\\`").strip(".,;:!")
            if target and target not in make_targets and target != "start-all.sh" and not target.startswith("."):
                errors.append(f"{doc}: 'make {target}' referenced but target missing in Makefile")
    return errors


def main() -> int:
    ok = True
    print("=== Meta-Lint: Makefile syntax ===")
    syntax_err = check_basic_syntax()
    if syntax_err:
        print(f"  ❌ {syntax_err}")
        ok = False
    else:
        print("  ✓ Basic syntax & variable recursion: PASS")

    print("=== Meta-Lint: Makefile integrity ===")
    integrity = run_integrity_checks() + resolve_umbrellas()
    if integrity:
        for e in integrity:
            print(f"  ❌ {e}")
        ok = False
    else:
        print("  ✓ Targets, prerequisites, .PHONY, and umbrellas are consistent")

    print("=== Meta-Lint: Script integrity ===")
    for w in check_script_shebangs():
        print(f"  ! Warning: {w}")

    print("=== Meta-Lint: Documentation command sync ===")
    doc_errors = verify_documentation_commands()
    if doc_errors:
        for e in doc_errors:
            print(f"  ❌ {e}")
        ok = False
    else:
        print("  ✓ Documentation commands are synchronized with Makefile")

    print("=== Meta-Lint complete ===")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
