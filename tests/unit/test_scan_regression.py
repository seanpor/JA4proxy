"""
tests/unit/test_scan_regression.py

Unit tests for the PR regression gate — Phase 847c.

The gate's whole value is a contract about **exit codes**, so that is what these
tests pin:

    0  nothing security-relevant touched, or every finding already in the baseline
    1  a touched surface carries a finding the baseline does not have
    2  we could not answer the question (no baseline, no diff, no scan)

The 2 == "fail closed" rows are the important ones: every one of them is a path
where a naive implementation returns 0 because it has nothing to report, and
every one of them would then be trusted.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))

import scan_regression as gate  # noqa: E402


def _git_repo(
    tmp_path: Path,
    base_text: str,
    head_text: str,
    path: str = ".trivyignore.third-party",
    files: tuple[str, ...] | None = None,
):
    """A two-commit repo: *base_text* at the first commit, *head_text* at HEAD.

    Returns `(repo path, base commit sha)`. The waiver-set comparison reads the
    files at a revision, so it needs a real repository — a mock would test the
    mock.

    Every applied ignorefile is created, not just the one under test: the
    comparison reads all three, and a file that cannot be read at either end is
    an ERROR (fail closed), not "unchanged". Pass *files* to create a subset.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }

    def git(*args: str) -> str:
        proc = subprocess.run(
            ["git", *args], cwd=repo, env=env, capture_output=True, text=True, check=True
        )
        return proc.stdout.strip()

    def write_all(text_for) -> None:
        for name in files if files is not None else gate.APPLIED_WAIVER_FILES:
            target = repo / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text_for(name), encoding="utf-8")

    git("init", "-q")
    write_all(lambda name: base_text if name == path else "# untouched\n")
    git("add", "-A")
    git("commit", "-q", "--allow-empty", "-m", "base")
    base = git("rev-parse", "HEAD")
    write_all(lambda name: head_text if name == path else "# untouched\n")
    git("add", "-A")
    git("commit", "-q", "--allow-empty", "-m", "head")
    return str(repo), base


def _finding(cve="CVE-2026-9001", severity="HIGH", fixed=""):
    return {"severity": severity, "package": "pkg", "installed": "1.0", "fixed": fixed}


def _baseline(**surfaces):
    return {
        "version": 1,
        "recorded_at": "t",
        "surfaces": {name: {"findings": findings} for name, findings in surfaces.items()},
    }


def _patch_git(monkeypatch, changed, base_refs, head_refs, makefile="", waiver_set_changed=False):
    """Replace the git layer so exit-code behaviour is testable without a repo."""

    def fake_changed(base, head="HEAD", repo="."):
        return list(changed)

    def fake_compose(rev, repo="."):
        return base_refs if rev == "base" else head_refs

    def fake_file(rev, path, repo="."):
        return makefile

    monkeypatch.setattr(gate, "changed_files", fake_changed)
    monkeypatch.setattr(gate, "compose_refs_at", fake_compose)
    monkeypatch.setattr(gate, "file_at", fake_file)
    monkeypatch.setattr(gate, "waiver_set_changed", lambda *a, **k: waiver_set_changed)


class TestDetection:
    """Which surfaces a change touches — the decision that removes the noise."""

    def test_docs_only_touches_nothing(self):
        refs = {"redis": frozenset({"7.4.11"})}
        assert gate.touched_surfaces(["README.md", "docs/x.md"], refs, refs, {}) == {}

    def test_image_added(self):
        touched = gate.touched_surfaces(
            ["deploy/docker/docker-compose.prod.yml"],
            {},
            {"grafana/grafana": frozenset({"13.2.4-ubuntu"})},
            {},
        )
        assert touched == {
            "image:grafana/grafana": {
                "ref": "grafana/grafana:13.2.4-ubuntu",
                "reason": "image added",
            }
        }

    def test_image_version_change(self):
        touched = gate.touched_surfaces(
            ["x.yml"],
            {"redis": frozenset({"7.4.10"})},
            {"redis": frozenset({"7.4.11"})},
            {},
        )
        assert touched["image:redis"]["ref"] == "redis:7.4.11"
        assert "7.4.10 -> 7.4.11" in touched["image:redis"]["reason"]

    def test_unchanged_image_is_not_a_surface(self):
        refs = {"redis": frozenset({"7.4.11"})}
        assert gate.touched_surfaces(["x.yml"], refs, dict(refs), {}) == {}

    def test_ambiguous_version_fails_closed(self):
        """Two versions across the compose files => no artifact to scan."""
        with pytest.raises(gate.DiffError, match="ambiguous"):
            gate.touched_surfaces(
                ["x.yml"],
                {"redis": frozenset({"7.4.10"})},
                {"redis": frozenset({"7.4.10", "7.4.11"})},
                {},
            )

    def test_dockerfile_change_maps_to_the_first_party_image(self):
        touched = gate.touched_surfaces(
            ["deploy/docker/Dockerfile.go-proxy"],
            {},
            {},
            {"deploy/docker/Dockerfile.go-proxy": "ja4proxy:2.0.0"},
        )
        assert touched["image:ja4proxy"]["ref"] == "ja4proxy:2.0.0"
        assert "Dockerfile changed" in touched["image:ja4proxy"]["reason"]

    def test_dockerfile_without_a_build_line_is_not_a_surface(self):
        assert (
            gate.touched_surfaces(
                ["deploy/docker/Dockerfile.unknown"], {}, {}, {"other": "x:1"}
            )
            == {}
        )

    def test_requirements_touches_the_pypi_surface(self):
        touched = gate.touched_surfaces(["requirements.txt"], {}, {}, {})
        assert touched["pypi"]["ref"] == "requirements.txt"

    def test_pyproject_touches_the_pypi_surface(self):
        touched = gate.touched_surfaces(["pyproject.toml"], {}, {}, {})
        assert "pypi" in touched

    def test_first_party_compose_image_bump(self):
        touched = gate.touched_surfaces(
            ["x.yml"],
            {"ja4proxy": frozenset({"2.0.0"})},
            {"ja4proxy": frozenset({"2.0.1"})},
            {},
        )
        assert touched["image:ja4proxy"]["ref"] == "ja4proxy:2.0.1"


class TestWaiverSetChangedCli:
    """The CI trigger asks this question on its own, so the answer has a contract.

    Exit codes: 0 = changed, 1 = unchanged, 2 = could not tell. "Could not
    tell" has to be distinguishable, or the caller has to choose between
    running the full scan and staying quiet — and the caller must choose to
    run it.
    """

    def test_unchanged_exits_1(self, tmp_path, monkeypatch, capsys):
        repo, base = _git_repo(
            tmp_path,
            "# header\nCVE-2026-1 exp:2026-12-01\n",
            "# header\nCVE-2026-1 exp:2026-12-01\n",
        )
        monkeypatch.chdir(repo)
        assert gate.main(["--base", base, "--head", "HEAD", "--waiver-set-changed"]) == 1
        assert "unchanged" in capsys.readouterr().out

    def test_changed_exits_0(self, tmp_path, monkeypatch, capsys):
        repo, base = _git_repo(
            tmp_path,
            "# header\nCVE-2026-1 exp:2026-12-01\n",
            "# header\n",
        )
        monkeypatch.chdir(repo)
        assert gate.main(["--base", base, "--head", "HEAD", "--waiver-set-changed"]) == 0
        assert "changed" in capsys.readouterr().out

    def test_could_not_tell_exits_2(self, tmp_path, monkeypatch, capsys):
        repo, base = _git_repo(
            tmp_path,
            "# header\nCVE-2026-1 exp:2026-12-01\n",
            "# header\nCVE-2026-1 exp:2026-12-01\n",
            files=(".trivyignore.third-party",),
        )
        monkeypatch.chdir(repo)
        assert gate.main(["--base", base, "--head", "HEAD", "--waiver-set-changed"]) == 2
        assert "cannot determine" in capsys.readouterr().err


class TestMakefileMap:
    def test_real_makefile_is_parsed(self):
        mapping = gate.dockerfile_image_map((_ROOT / "Makefile").read_text())
        assert mapping["deploy/docker/Dockerfile.go-proxy"] == "ja4proxy:2.0.0"
        assert len(mapping) >= 5

    def test_no_pairs_gives_empty_map(self):
        assert gate.dockerfile_image_map("# nothing here") == {}

    def test_make_shell_variables_are_not_a_surface(self):
        """`-f "$$df" -t "$$tag"` is a shell loop's variables, not a build rule.

        Parsed literally it produced a surface `image:"$$tag"` that cannot be
        scanned, so the gate failed closed on a surface that never existed —
        and the gate could not pass at all, on any PR that widened its scope.
        """
        makefile = (
            "\t\t\tDOCKER_BUILDKIT=1 docker build -q "
            '-f "$$df" -t "$$tag" "$$ctx" >/dev/null; \\\n'
        )
        assert gate.dockerfile_image_map(makefile) == {}

    def test_the_real_makefile_yields_no_bogus_surface(self):
        mapping = gate.dockerfile_image_map((_ROOT / "Makefile").read_text())
        assert not [k for k in mapping if "$$" in k]
        assert not [v for v in mapping.values() if "$$" in v]


class TestRequirementsSelection:
    def test_prefers_requirements_txt(self):
        assert gate.requirements_of(["pyproject.toml", "requirements.txt"]) == "requirements.txt"

    def test_prefers_the_requirements_file_over_another_auditable_one(self):
        assert gate.requirements_of(["requirements-test.txt", "requirements.txt"]) == "requirements.txt"

    def test_audits_a_changed_requirements_file(self):
        assert gate.requirements_of(["requirements-test.txt"]) == "requirements-test.txt"

    def test_pyproject_only_still_audits_a_requirements_file(self):
        """`pip-audit -r pyproject.toml` errors, and exit 2 on a config edit is the
        unrelated-red the split exists to remove. The surface is still in scope."""
        assert gate.requirements_of(["pyproject.toml"]) == "requirements.txt"

    def test_never_returns_a_file_pip_audit_cannot_read(self):
        for changed in (["pyproject.toml"], ["Pipfile"], ["Pipfile.lock"], ["sub/pyproject.toml"]):
            assert gate.AUDITABLE_DEPS_RE.search(gate.requirements_of(changed)), changed

    def test_pyproject_only_touches_the_pypi_surface(self):
        touched = gate.touched_surfaces(["pyproject.toml"], {}, {}, {})
        assert touched["pypi"]["ref"] == "requirements.txt"


class TestUnscannedDockerfiles:
    """A touched file the gate cannot judge must be reported, never silent."""

    def test_reports_a_dockerfile_outside_the_build_set(self):
        assert gate.unscanned_dockerfiles(["Dockerfile.tools"], {}) == ["Dockerfile.tools"]

    def test_does_not_report_a_scanned_dockerfile(self):
        mapping = {"deploy/docker/Dockerfile.go-proxy": "ja4proxy:2.0.0"}
        assert gate.unscanned_dockerfiles(list(mapping), mapping) == []

    def test_ignores_non_dockerfile_paths(self):
        assert gate.unscanned_dockerfiles(["scripts/scan_regression.py", "docs/x.md"], {}) == []

    def test_is_sorted_and_deduplicated_for_a_readable_report(self):
        assert gate.unscanned_dockerfiles(
            ["b/Dockerfile.two", "a/Dockerfile.two", "a/Dockerfile.one"], {}
        ) == ["a/Dockerfile.one", "a/Dockerfile.two", "b/Dockerfile.two"]

    def test_main_reports_it_without_failing_the_gate(self, monkeypatch, capsys):
        monkeypatch.setattr(gate, "changed_files", lambda base, head="HEAD", repo=".": ["Dockerfile.tools"])
        monkeypatch.setattr(gate, "compose_refs_at", lambda rev, repo=".": {})
        monkeypatch.setattr(gate, "file_at", lambda rev, path, repo=".": "")

        assert gate.main([]) == 0, "an unscanned Dockerfile must not fail an unrelated PR"

        assert "not judged by this gate" in capsys.readouterr().err


class TestWaiverInputsAreASurface:
    """A waiver change moves the gate's own inputs, so nothing is out of scope.

    Without this, deleting a waiver row touches no compose file, no Dockerfile
    and no requirements file — so a surface-scoped gate would look at nothing and
    pass, and the finding the deletion un-waived would go unseen until the
    scheduled monitor ran. That is the one fail-open path in a diff-scoped gate.
    """

    def test_a_removed_entry_is_detected(self, tmp_path):
        """The load-bearing case: a waiver entry disappears."""
        repo, base = _git_repo(
            tmp_path,
            "# header\nCVE-2026-1 exp:2026-12-01\nCVE-2026-2 exp:2026-12-01\n",
            "# header\nCVE-2026-1 exp:2026-12-01\n",
        )
        assert gate.waiver_set_changed(base, "HEAD", repo=repo)

    def test_an_added_entry_is_detected(self, tmp_path):
        repo, base = _git_repo(
            tmp_path,
            "# header\nCVE-2026-1 exp:2026-12-01\n",
            "# header\nCVE-2026-1 exp:2026-12-01\nCVE-2026-2 exp:2026-12-01\n",
        )
        assert gate.waiver_set_changed(base, "HEAD", repo=repo)

    def test_a_changed_expiry_is_detected(self, tmp_path):
        repo, base = _git_repo(
            tmp_path,
            "# header\nCVE-2026-1 exp:2026-12-01\n",
            "# header\nCVE-2026-1 exp:2027-01-01\n",
        )
        assert gate.waiver_set_changed(base, "HEAD", repo=repo)

    def test_a_comment_only_change_is_NOT_a_waiver_change(self, tmp_path):
        """Rewording the generated header changes no verdict for any surface.

        Byte comparison cannot tell a documentation edit from a waiver edit,
        so the gate used to widen to every surface for one. Any upstream CVE
        disclosed that night then reddened a PR that had nothing to do with it
        — the exact failure this gate exists to prevent.
        """
        repo, base = _git_repo(
            tmp_path,
            "# header\nCVE-2026-1 exp:2026-12-01\n",
            "# a better header\nCVE-2026-1 exp:2026-12-01\n",
        )
        assert not gate.waiver_set_changed(base, "HEAD", repo=repo)

    def test_a_comment_above_an_entry_is_NOT_a_waiver_change(self, tmp_path):
        """The rationale above an entry is documentation too."""
        repo, base = _git_repo(
            tmp_path,
            "# why\nCVE-2026-1 exp:2026-12-01\n",
            "# why else\nCVE-2026-1 exp:2026-12-01\n",
        )
        assert not gate.waiver_set_changed(base, "HEAD", repo=repo)

    def test_a_deleted_ignorefile_is_a_waiver_change(self, tmp_path):
        """Everything it waived is unwaived now — fail closed."""
        repo, base = _git_repo(
            tmp_path,
            "# header\nCVE-2026-1 exp:2026-12-01\n",
            "",
        )
        assert gate.waiver_set_changed(base, "HEAD", repo=repo)

    def test_a_file_unreadable_at_both_ends_is_an_ERROR(self, tmp_path):
        """A comparison that did not happen must not read as "unchanged".

        All three applied ignorefiles are tracked at every relevant revision,
        so a file that cannot be read at either end means the git layer is
        broken. Reading that as "the waiver set did not change" would skip the
        full scan on a PR that may well have deleted a waiver.
        """
        repo, base = _git_repo(
            tmp_path,
            "# header\nCVE-2026-1 exp:2026-12-01\n",
            "# header\nCVE-2026-1 exp:2026-12-01\n",
            files=(".trivyignore.third-party",),
        )
        with pytest.raises(gate.DiffError):
            gate.waiver_set_changed(base, "HEAD", repo=repo)

    def test_the_registry_alone_is_not_compared(self, tmp_path):
        """The bot writes its own metadata there without waiving anything.

        Comparing the registry's bytes would widen the gate on every bot PR,
        so an unrelated upstream CVE would redden automated work that has
        nothing to do with it. A registry edit that really changes the waiver
        set changes the generated files with it — `make lint` refuses a
        registry and its generated files that disagree.
        """
        assert "security/waivers.yaml" not in gate.APPLIED_WAIVER_FILES

    def test_applied_entries_ignore_comments_and_blanks(self):
        text = "# header\n\n  # rationale\nCVE-2026-1 exp:2026-12-01\n\n"
        assert gate.applied_waiver_entries(text) == ["CVE-2026-1 exp:2026-12-01"]

    def test_unrelated_file_is_not_a_waiver_input(self):
        assert gate.APPLIED_WAIVER_FILES == (
            ".trivyignore.third-party",
            ".trivyignore.first-party",
            ".pip-audit-ignores",
        )

    def test_all_surfaces_covers_compose_dockerfiles_and_pypi(self):
        everything = gate.all_surfaces(
            ["security/waivers.yaml"],
            {"redis": frozenset({"7.4.11"})},
            {"deploy/docker/Dockerfile.go-proxy": "ja4proxy:2.0.0"},
        )
        assert set(everything) == {"image:redis", "image:ja4proxy", "pypi"}

    def test_compose_ref_wins_over_the_makefile_build_tag(self):
        """The deployed tag is what the waiver is about, so it must win."""
        everything = gate.all_surfaces(
            [],
            {"ja4proxy-tap": frozenset({"2.0.0"})},
            {"deploy/docker/Dockerfile.ja4-tap": "ja4proxy-tap:1.0.0"},
        )
        assert everything["image:ja4proxy-tap"]["ref"] == "ja4proxy-tap:2.0.0"

    def test_main_scans_every_surface_on_a_waiver_change(self, monkeypatch, capsys):
        _patch_git(
            monkeypatch,
            ["security/waivers.yaml"],
            {"redis": frozenset({"1"})},
            {"redis": frozenset({"1"})},
            makefile="-f deploy/docker/Dockerfile.go-proxy -t ja4proxy:2.0.0",
            waiver_set_changed=True,
        )
        monkeypatch.setattr(gate, "load_baseline", lambda path=None: _baseline())
        seen: list[str] = []
        monkeypatch.setattr(gate, "scan_surface", lambda s, r, c: seen.append(s) or {})

        assert gate.main(["--base", "base", "--head", "head"]) == 0
        assert seen == ["image:ja4proxy", "image:redis", "pypi"]
        captured = capsys.readouterr()
        assert "every surface is in scope" in captured.err
        # Must not pollute stdout: `--plan` writes parseable JSON there.
        assert "every surface is in scope" not in captured.out

    def test_deleted_waiver_fails_when_the_finding_reappears(self, monkeypatch, capsys):
        _patch_git(
            monkeypatch,
            [".trivyignore.third-party"],
            {},
            {},
            makefile="",
            waiver_set_changed=True,
        )
        monkeypatch.setattr(gate, "load_baseline", lambda path=None: _baseline())
        monkeypatch.setattr(gate, "scan_surface", lambda *a: {"CVE-2026-1": _finding("CVE-2026-1")})

        assert gate.main(["--base", "base", "--head", "head"]) == 1
        assert "CVE-2026-1" in capsys.readouterr().out


class TestExitCodes:
    def test_nothing_touched_exits_zero_without_scanning(self, monkeypatch, capsys):
        _patch_git(monkeypatch, ["README.md"], {"redis": frozenset({"1"})}, {"redis": frozenset({"1"})})
        scanned = []
        monkeypatch.setattr(gate, "scan_surface", lambda *a: scanned.append(a) or {})

        assert gate.main(["--base", "base", "--head", "head"]) == 0
        assert scanned == [], "no surface means no scan — the whole point of the split"
        assert "no security-relevant surface touched" in capsys.readouterr().out

    def test_new_finding_exits_one(self, monkeypatch, capsys):
        _patch_git(monkeypatch, ["x.yml"], {"redis": frozenset({"1"})}, {"redis": frozenset({"2"})})
        monkeypatch.setattr(gate, "load_baseline", lambda path=None: _baseline(**{"image:redis": {}}))
        monkeypatch.setattr(gate, "scan_surface", lambda *a: {"CVE-2026-9001": _finding()})

        assert gate.main(["--base", "base", "--head", "head"]) == 1
        out = capsys.readouterr().out
        assert "CVE-2026-9001" in out
        assert "introduces unwaived findings" in out

    def test_known_findings_exit_zero(self, monkeypatch, capsys):
        _patch_git(monkeypatch, ["x.yml"], {"redis": frozenset({"1"})}, {"redis": frozenset({"2"})})
        monkeypatch.setattr(
            gate, "load_baseline", lambda path=None: _baseline(**{"image:redis": {"CVE-1": {}}})
        )
        monkeypatch.setattr(gate, "scan_surface", lambda *a: {"CVE-1": _finding("CVE-1")})

        assert gate.main(["--base", "base", "--head", "head"]) == 0
        assert "already present in the baseline" in capsys.readouterr().out

    def test_clean_surface_exits_zero(self, monkeypatch, capsys):
        _patch_git(monkeypatch, ["x.yml"], {"redis": frozenset({"1"})}, {"redis": frozenset({"2"})})
        monkeypatch.setattr(gate, "load_baseline", lambda path=None: _baseline())
        monkeypatch.setattr(gate, "scan_surface", lambda *a: {})

        assert gate.main(["--base", "base", "--head", "head"]) == 0
        assert "no HIGH/CRITICAL findings" in capsys.readouterr().out

    def test_scan_failure_exits_two(self, monkeypatch, capsys):
        """A scan that cannot run must never read as clean (Phase 847b's lesson)."""

        def boom(*_a):
            raise RuntimeError("trivy exploded")

        _patch_git(monkeypatch, ["x.yml"], {"redis": frozenset({"1"})}, {"redis": frozenset({"2"})})
        monkeypatch.setattr(gate, "load_baseline", lambda path=None: _baseline())
        monkeypatch.setattr(gate, "scan_surface", boom)

        assert gate.main(["--base", "base", "--head", "head"]) == 2
        assert "failing closed" in capsys.readouterr().err

    def test_unreadable_baseline_exits_two(self, monkeypatch, capsys):
        _patch_git(monkeypatch, ["x.yml"], {"redis": frozenset({"1"})}, {"redis": frozenset({"2"})})

        def broken(path=None):
            # Raise the class *this module* bound at import time: `scripts` is
            # importable as a package, so `scripts.scan_baseline` and a bare
            # `scan_baseline` are two module objects with two BaselineError
            # classes. main() catches its own, which is the one that matters.
            raise gate.BaselineError("baseline is a lie")

        monkeypatch.setattr(gate, "load_baseline", broken)

        assert gate.main(["--base", "base", "--head", "head"]) == 2
        assert "refusing to guess" in capsys.readouterr().err

    def test_diff_failure_exits_two(self, monkeypatch, capsys):
        def broken(*_a, **_k):
            raise gate.DiffError("no such ref")

        monkeypatch.setattr(gate, "changed_files", broken)

        assert gate.main(["--base", "base", "--head", "head"]) == 2
        assert "cannot determine what this PR touches" in capsys.readouterr().err

    def test_plan_prints_json_and_does_not_scan(self, monkeypatch, capsys):
        _patch_git(monkeypatch, ["x.yml"], {"redis": frozenset({"1"})}, {"redis": frozenset({"2"})})
        monkeypatch.setattr(
            gate, "scan_surface", lambda *a: pytest.fail("--plan must not scan")
        )

        assert gate.main(["--base", "base", "--head", "head", "--plan"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["surfaces"]["image:redis"]["ref"] == "redis:2"

    def test_dockerfile_change_scans_the_first_party_image(self, monkeypatch):
        _patch_git(
            monkeypatch,
            ["deploy/docker/Dockerfile.go-proxy"],
            {},
            {},
            makefile="-f deploy/docker/Dockerfile.go-proxy -t ja4proxy:2.0.0",
        )
        monkeypatch.setattr(gate, "load_baseline", lambda path=None: _baseline())
        seen = []
        monkeypatch.setattr(gate, "scan_surface", lambda surface, ref, cache: seen.append((surface, ref)) or {})

        assert gate.main(["--base", "base", "--head", "head"]) == 0
        assert seen == [("image:ja4proxy", "ja4proxy:2.0.0")]
