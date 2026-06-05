"""Unit tests for the Makefile integrity guard (scripts/meta_lint.py).

PHASE_224 sub-phase A. Two layers:

1. Synthetic-fixture tests — feed the parser/checkers tiny hand-written Makefile
   snippets and assert each check detects (or passes) the right thing. These are
   the real proof the guard is correct, and are green from day one.
2. A gate against the *real* Makefile, expected to fail until sub-phases B–E
   repair it (`xfail(strict=True)` so it flips to a hard failure the moment the
   Makefile is clean, forcing removal of the marker at sub-phase F).
"""
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import meta_lint  # noqa: E402


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
def test_parse_basic_target_with_prereqs_and_recipe():
    mk = meta_lint.parse_makefile("foo: bar baz\n\t@echo hi\n")
    assert "foo" in mk.targets
    assert mk.targets["foo"].prereqs == ["bar", "baz"]
    assert mk.targets["foo"].has_recipe is True


def test_parse_ignores_variable_assignments():
    mk = meta_lint.parse_makefile("PYTHON := python3\nWORKERS ?= 4\nfoo:\n\t@echo hi\n")
    assert set(mk.targets) == {"foo"}


def test_parse_multi_target_rule_shares_prereqs():
    mk = meta_lint.parse_makefile("a b: dep\n\t@echo x\n")
    assert mk.targets["a"].prereqs == ["dep"]
    assert mk.targets["b"].prereqs == ["dep"]


def test_parse_backslash_continuation_in_header():
    mk = meta_lint.parse_makefile("agg: one two \\\n     three\n\t@echo x\n")
    assert mk.targets["agg"].prereqs == ["one", "two", "three"]


def test_inline_semicolon_recipe_counts_as_recipe():
    mk = meta_lint.parse_makefile("foo: ; @echo hi\n")
    assert mk.targets["foo"].has_recipe is True


def test_phony_collected_across_continuation():
    mk = meta_lint.parse_makefile(".PHONY: a b \\\n        c\na:\n\t@echo x\n")
    assert {"a", "b", "c"} <= mk.phony


# --------------------------------------------------------------------------- #
# Regression: the literal-`\n` corruption that disabled `scan`, `scan-all`, …
# A line like `# deduplicated phony line\nscan:` is a COMMENT to make, so the
# target must NOT be parsed as real.
# --------------------------------------------------------------------------- #
def test_literal_backslash_n_target_is_treated_as_comment():
    text = "real:\n\t@echo hi\n# deduplicated phony line\\nscan:\n\t@$(MAKE) scan-all\n"
    mk = meta_lint.parse_makefile(text)
    assert "real" in mk.targets
    assert "scan" not in mk.targets, "literal-\\n line must be a comment, not a target"


# --------------------------------------------------------------------------- #
# $(MAKE) edge extraction
# --------------------------------------------------------------------------- #
def test_make_call_edge_detected():
    mk = meta_lint.parse_makefile("agg:\n\t@$(MAKE) sub-one\nsub-one:\n\t@echo x\n")
    assert "sub-one" in mk.targets["agg"].make_calls


def test_make_call_extracted_even_with_echo_fallback():
    mk = meta_lint.parse_makefile('agg:\n\t@$(MAKE) sub || echo "warn"\n')
    assert "sub" in mk.targets["agg"].make_calls


def test_make_word_in_echo_prose_is_not_a_call():
    mk = meta_lint.parse_makefile('foo:\n\t@echo "please make sure things work"\n')
    assert mk.targets["foo"].make_calls == set()


# --------------------------------------------------------------------------- #
# Advertised-name extraction
# --------------------------------------------------------------------------- #
def test_advertised_make_command_detected():
    mk = meta_lint.parse_makefile('help:\n\t@echo "  make scan   - run scans"\n')
    assert "scan" in meta_lint.advertised_targets(mk)


def test_advertised_help_row_detected():
    mk = meta_lint.parse_makefile('help:\n\t@echo "  doc-health        - check docs"\n')
    assert "doc-health" in meta_lint.advertised_targets(mk)


def test_advertised_stops_at_arguments():
    mk = meta_lint.parse_makefile('help:\n\t@echo "  make test-ip IP=1.2.3.4 - sim"\n')
    adv = meta_lint.advertised_targets(mk)
    assert "test-ip" in adv
    assert "IP" not in adv


def test_advertised_allowlist_excludes_literal_ssh_example():
    mk = meta_lint.parse_makefile('help:\n\t@echo "  ssh -L 9091:localhost:9091 USER@HOST"\n')
    assert "ssh" not in meta_lint.advertised_targets(mk)


def test_slash_shorthand_expansion():
    assert meta_lint._expand_slash_shorthand("management-up/down/logs/shell") == [
        "management-up",
        "management-down",
        "management-logs",
        "management-shell",
    ]
    assert meta_lint._expand_slash_shorthand("plain") == ["plain"]


# --------------------------------------------------------------------------- #
# Individual checks
# --------------------------------------------------------------------------- #
def test_check_advertised_exist_flags_missing():
    mk = meta_lint.parse_makefile('help:\n\t@echo "  make ghost - x"\n')
    errors = meta_lint.check_advertised_exist(mk)
    assert any("ghost" in e for e in errors)


def test_check_prereqs_exist_flags_dangling():
    mk = meta_lint.parse_makefile("foo: nonexistent-dep\n\t@echo x\n")
    errors = meta_lint.check_prereqs_exist(mk)
    assert any("nonexistent-dep" in e for e in errors)


def test_check_prereqs_allows_existing_file(tmp_path):
    f = tmp_path / "afile"
    f.write_text("x")
    mk = meta_lint.parse_makefile(f"foo: {f}\n\t@echo x\n")
    assert meta_lint.check_prereqs_exist(mk) == []


def test_check_prereqs_ignores_variables():
    mk = meta_lint.parse_makefile("foo: $(SOMEVAR)\n\t@echo x\n")
    assert meta_lint.check_prereqs_exist(mk) == []


def test_check_make_calls_exist_flags_dangling():
    mk = meta_lint.parse_makefile("agg:\n\t@$(MAKE) ghost-sub\n")
    errors = meta_lint.check_make_calls_exist(mk)
    assert any("ghost-sub" in e for e in errors)


def test_check_phony_flags_phantom():
    mk = meta_lint.parse_makefile(".PHONY: realonly ghost\nrealonly:\n\t@echo x\n")
    errors = meta_lint.check_phony_sane(mk)
    assert any("ghost" in e for e in errors)


def test_check_phony_flags_noop_target():
    # A target with no recipe, no prereqs, no $(MAKE) calls is a silent no-op.
    mk = meta_lint.parse_makefile("realonly:\n\t@echo x\n")
    # Force a no-op target by declaring one with nothing after it.
    mk.targets["noop"] = meta_lint.Target(name="noop", line=99)
    errors = meta_lint.check_phony_sane(mk)
    assert any("noop" in e and "no-op" in e for e in errors)


def test_check_umbrella_excludes_heavy_detects_violation():
    mk = meta_lint.parse_makefile("lint: bench\nbench:\n\t@echo heavy\n")
    errors = meta_lint.check_umbrellas_exclude_heavy(mk)
    assert any("bench" in e for e in errors)


def test_check_umbrella_clean_when_no_heavy():
    mk = meta_lint.parse_makefile("lint: lint-one\nlint-one:\n\t@echo ok\n")
    assert meta_lint.check_umbrellas_exclude_heavy(mk) == []


# --------------------------------------------------------------------------- #
# Whole-file: a clean synthetic Makefile yields zero integrity errors
# --------------------------------------------------------------------------- #
def test_clean_makefile_has_no_errors(tmp_path):
    mk_text = (
        ".PHONY: lint scan test lint-one scan-one test-one help\n"
        "help:\n"
        '\t@echo "  make lint   - lint"\n'
        '\t@echo "  make scan   - scan"\n'
        '\t@echo "  make test   - test"\n'
        "lint: lint-one\n"
        "\t@echo linting\n"
        "scan: scan-one\n"
        "\t@echo scanning\n"
        "test: test-one\n"
        "\t@echo testing\n"
        "lint-one:\n\t@echo x\n"
        "scan-one:\n\t@echo x\n"
        "test-one:\n\t@echo x\n"
    )
    path = tmp_path / "Makefile"
    path.write_text(mk_text)
    assert meta_lint.run_integrity_checks(str(path)) == []


# --------------------------------------------------------------------------- #
# Gate against the real Makefile — RED until PHASE_224 B–E land, then must be
# made green by removing this xfail at sub-phase F (strict=True enforces that).
# --------------------------------------------------------------------------- #
@pytest.mark.xfail(
    strict=True,
    reason="PHASE_224 B-E repair the Makefile; remove this xfail at sub-phase F",
)
def test_real_makefile_has_no_integrity_violations():
    errors = meta_lint.run_integrity_checks(str(REPO_ROOT / "Makefile"))
    assert errors == [], "Makefile integrity violations:\n" + "\n".join(errors)
