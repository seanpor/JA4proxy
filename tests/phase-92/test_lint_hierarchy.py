"""
Phase 92: Structural tests for the lint target hierarchy.

These tests verify:
- All 11 individual lint targets exist and are .PHONY-declared
- All 8 aggregate lint targets exist and reference the correct leaves
- lint-all aggregates every sub-aggregate
- make help exits 0 (regression test for lint-toml heredoc bug)
- lint-toml recipe does NOT contain a shell heredoc (the bug pattern)
- test-phase-92 target exists and is .PHONY-declared
"""

import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent

# ── Individual linters added in Phase 92 ──────────────────────────────────────

PHASE92_INDIVIDUAL_TARGETS = [
    "lint-pylint",
    "lint-semgrep",
    "lint-checkov",
    "lint-haproxy",
    "lint-helm",
    "lint-ansible",
    "lint-markdown",
    "lint-spelling",
    "lint-toml",
    "lint-makefiles",
    "lint-go-mod",
]

# ── Aggregate targets ─────────────────────────────────────────────────────────

PHASE92_AGGREGATE_TARGETS = [
    "lint-python",
    "lint-go",
    "lint-sast",
    "lint-infra",
    "lint-observability",
    "lint-supply-chain",
    "lint-docs-all",
    "lint-all",
]

# ── Expected dependency mappings ──────────────────────────────────────────────

AGGREGATE_REQUIRED_DEPS = {
    "lint-python": ["lint-static", "lint-security", "lint-pylint"],
    "lint-go": ["go-lint", "lint-go-full", "lint-go-mod"],
    "lint-sast": ["lint-semgrep", "lint-checkov"],
    "lint-infra": [
        "lint-docker", "lint-shell", "lint-yaml", "lint-lua", "lint-json",
        "lint-haproxy", "lint-makefiles", "lint-toml", "lint-ansible", "lint-helm",
    ],
    "lint-observability": ["lint-prom", "lint-alertmanager"],
    "lint-supply-chain": ["lint-secrets", "lint-deps"],
    "lint-docs-all": ["lint-docs", "lint-phases", "link-check", "lint-markdown", "lint-spelling"],
}

LINT_ALL_REQUIRED_SUBS = [
    "lint-python",
    "lint-go",
    "lint-sast",
    "lint-infra",
    "lint-observability",
    "lint-supply-chain",
    "lint-docs-all",
]

# ── Help section strings that must be present ─────────────────────────────────

HELP_STRINGS = [
    "lint-all",
    "lint-go",
    "lint-static",
    "lint-shell",
    "lint-yaml",
    "lint-docker",
    "lint-prom",
    "lint-alertmanager",
    "lint-secrets",
    "lint-deps",
    "go-lint",
    "lint-docs",
]


# =============================================================================
# Fixtures (local — supplement conftest.py)
# =============================================================================


def _makefile_text():
    return (REPO_ROOT / "Makefile").read_text()


def _targets_from_makefile(text):
    targets = set()
    for line in text.splitlines():
        m = re.match(r'^([a-zA-Z0-9_][a-zA-Z0-9_\-]*):', line)
        if m:
            targets.add(m.group(1))
    return targets


def _phony_from_makefile(text):
    """Parse all .PHONY-declared targets, including backslash-continued declarations."""
    phony = set()
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith(".PHONY:"):
            # Accumulate continuation lines
            content = line[len(".PHONY:"):]
            while content.rstrip().endswith("\\"):
                content = content.rstrip()[:-1]  # strip trailing backslash
                i += 1
                if i < len(lines):
                    content += " " + lines[i]
            phony.update(content.split())
        i += 1
    return phony


def _deps_for_target(text, target):
    """Return the list of prerequisites for a named target (first occurrence)."""
    for line in text.splitlines():
        m = re.match(rf'^{re.escape(target)}:\s*(.*)$', line)
        if m:
            return m.group(1).split()
    return []


# =============================================================================
# Group 1: Individual lint targets exist
# =============================================================================


@pytest.mark.parametrize("target", PHASE92_INDIVIDUAL_TARGETS)
def test_individual_lint_target_exists(target):
    """Each new individual lint target must be defined in the Makefile."""
    text = _makefile_text()
    targets = _targets_from_makefile(text)
    assert target in targets, f"Target '{target}' not found in Makefile"


@pytest.mark.parametrize("target", PHASE92_INDIVIDUAL_TARGETS)
def test_individual_lint_target_is_phony(target):
    """Each new individual lint target must be declared in .PHONY."""
    text = _makefile_text()
    phony = _phony_from_makefile(text)
    assert target in phony, f"Target '{target}' not in .PHONY declaration"


@pytest.mark.parametrize("target", PHASE92_INDIVIDUAL_TARGETS)
def test_individual_lint_target_has_recipe(target):
    """Each lint target must have at least one recipe line (starts with tab)."""
    text = _makefile_text()
    lines = text.splitlines()
    in_target = False
    has_recipe = False
    for line in lines:
        if re.match(rf'^{re.escape(target)}:', line):
            in_target = True
            continue
        if in_target:
            if line.startswith('\t'):
                has_recipe = True
                break
            # New target or blank line — stop looking
            if re.match(r'^[a-zA-Z0-9_][a-zA-Z0-9_\-]*:', line):
                break
    assert has_recipe, f"Target '{target}' has no recipe lines (tab-indented)"


# =============================================================================
# Group 2: Aggregate targets exist and are .PHONY
# =============================================================================


@pytest.mark.parametrize("target", PHASE92_AGGREGATE_TARGETS)
def test_aggregate_target_exists(target):
    text = _makefile_text()
    targets = _targets_from_makefile(text)
    assert target in targets, f"Aggregate target '{target}' not found in Makefile"


@pytest.mark.parametrize("target", PHASE92_AGGREGATE_TARGETS)
def test_aggregate_target_is_phony(target):
    text = _makefile_text()
    phony = _phony_from_makefile(text)
    assert target in phony, f"Aggregate target '{target}' not in .PHONY"


# =============================================================================
# Group 3: Aggregate dependency correctness
# =============================================================================


@pytest.mark.parametrize("aggregate,required_deps", list(AGGREGATE_REQUIRED_DEPS.items()))
def test_aggregate_deps_are_correct(aggregate, required_deps):
    """Each aggregate must list all its required leaf/sub-aggregate deps."""
    text = _makefile_text()
    # Collect all deps across multi-line continuations for this target
    all_deps = set()
    lines = text.splitlines()
    in_target = False
    for i, line in enumerate(lines):
        if re.match(rf'^{re.escape(aggregate)}:', line):
            in_target = True
            # Deps on the same line
            m = re.match(rf'^{re.escape(aggregate)}:\s*(.*)', line)
            if m:
                all_deps.update(m.group(1).replace('\\', '').split())
            continue
        if in_target:
            stripped = line.strip()
            if stripped.endswith('\\'):
                all_deps.update(stripped[:-1].split())
            elif stripped and not line.startswith('\t') and not stripped.startswith('#'):
                # Another target definition or blank — stop
                if re.match(r'^[a-zA-Z0-9_]', line):
                    break
                all_deps.update(stripped.split())
            elif line.startswith('\t'):
                # Recipe line — stop collecting deps
                break

    missing = [d for d in required_deps if d not in all_deps]
    assert not missing, (
        f"Aggregate '{aggregate}' is missing deps: {missing}\n"
        f"  Found deps: {sorted(all_deps)}"
    )


# =============================================================================
# Group 4: lint-all covers every sub-aggregate
# =============================================================================


@pytest.mark.parametrize("sub", LINT_ALL_REQUIRED_SUBS)
def test_lint_all_includes_sub_aggregate(sub):
    """lint-all must reference every sub-aggregate."""
    text = _makefile_text()
    # Collect deps for lint-all (may span continuation lines)
    all_deps = set()
    lines = text.splitlines()
    in_target = False
    for line in lines:
        if re.match(r'^lint-all:', line):
            in_target = True
            m = re.match(r'^lint-all:\s*(.*)', line)
            if m:
                all_deps.update(m.group(1).replace('\\', '').split())
            continue
        if in_target:
            stripped = line.strip()
            if stripped.endswith('\\'):
                all_deps.update(stripped[:-1].split())
            elif stripped and not line.startswith('\t') and not stripped.startswith('#'):
                if re.match(r'^[a-zA-Z0-9_]', line):
                    break
                all_deps.update(stripped.split())
            elif line.startswith('\t'):
                break
    assert sub in all_deps, (
        f"lint-all does not include sub-aggregate '{sub}'\n"
        f"  Found: {sorted(all_deps)}"
    )


# =============================================================================
# Group 5: make help correctness (regression for lint-toml heredoc bug)
# =============================================================================


@pytest.fixture(scope="module")
def make_help_result():
    """Run `make help` once per module and cache the result."""
    return subprocess.run(
        ["make", "help"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_make_help_exits_zero(make_help_result):
    """make help must exit with status 0 — catches parser errors in Makefile."""
    assert make_help_result.returncode == 0, (
        f"make help exited {make_help_result.returncode}\n"
        f"STDOUT:\n{make_help_result.stdout[:2000]}\n"
        f"STDERR:\n{make_help_result.stderr[:2000]}"
    )


@pytest.mark.parametrize("expected_string", HELP_STRINGS)
def test_make_help_mentions_lint_target(make_help_result, expected_string):
    """make help output must mention each lint target."""
    assert make_help_result.returncode == 0, f"make help failed: {make_help_result.stderr[:500]}"
    assert expected_string in make_help_result.stdout, (
        f"make help output does not mention '{expected_string}'"
    )


# =============================================================================
# Group 6: lint-toml heredoc bug is fixed
# =============================================================================


def test_lint_toml_recipe_has_no_heredoc():
    """
    The lint-toml recipe must NOT use a shell heredoc (<<'EOF' or <<EOF).
    Shell heredocs in Makefile recipes cause make's parser to treat the
    unindented heredoc body lines as new rules, breaking 'make help' and
    any tool that parses the Makefile.
    """
    text = _makefile_text()
    lines = text.splitlines()
    in_lint_toml = False
    for line in lines:
        if re.match(r'^lint-toml:', line):
            in_lint_toml = True
            continue
        if in_lint_toml:
            if re.match(r'^[a-zA-Z0-9_][a-zA-Z0-9_\-]*:', line):
                break
            if "<<" in line and ("EOF" in line or "HEREDOC" in line):
                pytest.fail(
                    "lint-toml recipe contains a shell heredoc.\n"
                    "Unindented heredoc body lines confuse make's parser.\n"
                    f"  Offending line: {line!r}"
                )


def _lint_toml_validation_source():
    """
    Return the combined source that implements lint-toml validation.

    The validation logic may live in the Makefile recipe itself OR in a
    helper script invoked by the recipe (e.g. scripts/lint_toml.py).
    We check both the recipe lines and any .py file referenced from the recipe.
    """
    text = _makefile_text()
    lines = text.splitlines()
    in_lint_toml = False
    recipe_lines = []
    for line in lines:
        if re.match(r'^lint-toml:', line):
            in_lint_toml = True
            continue
        if in_lint_toml:
            if re.match(r'^[a-zA-Z0-9_][a-zA-Z0-9_\-]*:', line):
                break
            if line.startswith('\t'):
                recipe_lines.append(line)

    recipe = "\n".join(recipe_lines)

    # If the recipe delegates to a Python script, include that script's source too.
    script_source = ""
    script_match = re.search(r'python3\s+(scripts/\S+\.py)', recipe)
    if script_match:
        script_path = REPO_ROOT / script_match.group(1)
        if script_path.exists():
            script_source = script_path.read_text()

    return recipe + "\n" + script_source


def test_lint_toml_recipe_validates_pyproject_toml():
    """lint-toml logic (recipe + helper script) must reference pyproject.toml."""
    source = _lint_toml_validation_source()
    assert "pyproject.toml" in source, (
        "lint-toml validation logic must reference 'pyproject.toml'"
    )


def test_lint_toml_recipe_validates_gitleaks_toml():
    """lint-toml logic (recipe + helper script) must reference .gitleaks.toml."""
    source = _lint_toml_validation_source()
    assert ".gitleaks.toml" in source, (
        "lint-toml validation logic must reference '.gitleaks.toml'"
    )


def test_lint_toml_recipe_uses_python3():
    """lint-toml recipe must invoke python3 (not a docker image)."""
    text = _makefile_text()
    lines = text.splitlines()
    in_lint_toml = False
    recipe_lines = []
    for line in lines:
        if re.match(r'^lint-toml:', line):
            in_lint_toml = True
            continue
        if in_lint_toml:
            if re.match(r'^[a-zA-Z0-9_][a-zA-Z0-9_\-]*:', line):
                break
            if line.startswith('\t'):
                recipe_lines.append(line)
    recipe = "\n".join(recipe_lines)
    assert "python3" in recipe, "lint-toml recipe must invoke python3"


def test_lint_toml_recipe_uses_tomllib():
    """lint-toml logic (recipe + helper script) must use tomllib for validation."""
    source = _lint_toml_validation_source()
    assert "tomllib" in source, "lint-toml validation logic must use tomllib"


# =============================================================================
# Group 7: test-phase-92 target
# =============================================================================


def test_test_phase_92_target_exists():
    """test-phase-92 target must be defined in the Makefile."""
    text = _makefile_text()
    targets = _targets_from_makefile(text)
    assert "test-phase-92" in targets, "test-phase-92 target not found in Makefile"


def test_test_phase_92_is_phony():
    """test-phase-92 must be declared in .PHONY."""
    text = _makefile_text()
    phony = _phony_from_makefile(text)
    assert "test-phase-92" in phony, "test-phase-92 not in .PHONY declaration"


def test_test_phase_92_runs_pytest():
    """test-phase-92 recipe must invoke pytest."""
    text = _makefile_text()
    lines = text.splitlines()
    in_target = False
    recipe_lines = []
    for line in lines:
        if re.match(r'^test-phase-92:', line):
            in_target = True
            continue
        if in_target:
            if re.match(r'^[a-zA-Z0-9_][a-zA-Z0-9_\-]*:', line):
                break
            if line.startswith('\t'):
                recipe_lines.append(line)
    recipe = "\n".join(recipe_lines)
    assert "pytest" in recipe, "test-phase-92 must invoke pytest"
    assert "tests/phase-92" in recipe, "test-phase-92 must point to tests/phase-92/"


# =============================================================================
# Group 8: Lint-all success message
# =============================================================================


def test_lint_all_has_success_echo():
    """lint-all recipe must print a completion message."""
    text = _makefile_text()
    lines = text.splitlines()
    in_target = False
    recipe_lines = []
    for line in lines:
        if re.match(r'^lint-all:', line):
            in_target = True
            continue
        if in_target:
            if re.match(r'^[a-zA-Z0-9_][a-zA-Z0-9_\-]*:', line):
                break
            if line.startswith('\t'):
                recipe_lines.append(line)
    recipe = "\n".join(recipe_lines)
    assert "lint-all" in recipe.lower() or "complete" in recipe.lower() or "passed" in recipe.lower(), (
        "lint-all recipe must print a completion/success message"
    )


# =============================================================================
# Group 9: No duplicate target definitions for new targets
# =============================================================================


@pytest.mark.parametrize("target", PHASE92_INDIVIDUAL_TARGETS + PHASE92_AGGREGATE_TARGETS + ["test-phase-92"])
def test_no_duplicate_target_definition(target):
    """Each target must be defined exactly once in the Makefile."""
    text = _makefile_text()
    pattern = re.compile(rf'^{re.escape(target)}:', re.MULTILINE)
    matches = pattern.findall(text)
    assert len(matches) == 1, (
        f"Target '{target}' is defined {len(matches)} times (expected 1)"
    )


# =============================================================================
# Group 10: lint-toml can actually run and validate TOML files
# =============================================================================


def test_lint_toml_pyproject_is_valid_toml():
    """pyproject.toml must parse successfully with tomllib/tomli.

    So what? A corrupted pyproject.toml silently breaks pip, build tools, and
    lint-toml itself. This test catches parse errors before they reach CI.
    """
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            pytest.skip("neither tomllib nor tomli available")

    toml_file = REPO_ROOT / "pyproject.toml"
    if not toml_file.exists():
        pytest.skip("pyproject.toml not present in repo root")

    with open(toml_file, "rb") as fh:
        data = tomllib.load(fh)
    assert isinstance(data, dict), "pyproject.toml must parse to a dict"


def test_lint_toml_gitleaks_is_valid_toml():
    """.gitleaks.toml must parse successfully with tomllib/tomli.

    So what? An unparseable .gitleaks.toml silently disables secret scanning.
    """
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            pytest.skip("neither tomllib nor tomli available")

    toml_file = REPO_ROOT / ".gitleaks.toml"
    if not toml_file.exists():
        pytest.skip(".gitleaks.toml not present in repo root")

    with open(toml_file, "rb") as fh:
        data = tomllib.load(fh)
    assert isinstance(data, dict), ".gitleaks.toml must parse to a dict"


# =============================================================================
# Group 11: Phase 92 "Other fixes" — deliverables without prior test coverage
# =============================================================================


def test_lint_docker_includes_scale_compose():
    """lint-docker recipe must validate docker-compose.scale.yml.

    So what? docker-compose.scale.yml defines the multi-instance scaling
    topology. If it drifts out of Docker Compose spec, scale deployments fail
    silently at runtime. Phase 92 explicitly added it to the lint-docker pass.
    """
    text = _makefile_text()
    lines = text.splitlines()
    in_target = False
    recipe_lines = []
    for line in lines:
        if re.match(r'^lint-docker:', line):
            in_target = True
            continue
        if in_target:
            if re.match(r'^[a-zA-Z0-9_][a-zA-Z0-9_\-]*:', line):
                break
            if line.startswith('\t'):
                recipe_lines.append(line)
    recipe = "\n".join(recipe_lines)
    assert "docker-compose.scale.yml" in recipe, (
        "lint-docker recipe must include deploy/docker/docker-compose.scale.yml\n"
        "(phase-92 deliverable: scale compose file added to docker lint pass)"
    )


def test_golangci_yaml_enables_gosec():
    """gosec must be enabled in .golangci.yaml (phase-92 deliverable).

    So what? gosec detects Go security anti-patterns (hardcoded credentials,
    unsafe operations). Without it, the Go linter pass has no security SAST.
    """
    golangci = (REPO_ROOT / ".golangci.yaml").read_text()
    assert "gosec" in golangci, (
        "gosec linter must be enabled in .golangci.yaml\n"
        "(phase-92 deliverable: Go security pattern detection)"
    )


def test_golangci_yaml_enables_bodyclose():
    """bodyclose must be enabled in .golangci.yaml (phase-92 deliverable).

    So what? Unclosed HTTP response bodies are resource leaks that cause
    connection pool exhaustion under load. bodyclose catches them statically.
    """
    golangci = (REPO_ROOT / ".golangci.yaml").read_text()
    assert "bodyclose" in golangci, (
        "bodyclose linter must be enabled in .golangci.yaml\n"
        "(phase-92 deliverable: unclosed HTTP response body detection)"
    )
