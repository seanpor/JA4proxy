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
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))

import scan_regression as gate  # noqa: E402


def _finding(cve="CVE-2026-9001", severity="HIGH", fixed=""):
    return {"severity": severity, "package": "pkg", "installed": "1.0", "fixed": fixed}


def _baseline(**surfaces):
    return {
        "version": 1,
        "recorded_at": "t",
        "surfaces": {name: {"findings": findings} for name, findings in surfaces.items()},
    }


def _patch_git(monkeypatch, changed, base_refs, head_refs, makefile=""):
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


class TestMakefileMap:
    def test_real_makefile_is_parsed(self):
        mapping = gate.dockerfile_image_map((_ROOT / "Makefile").read_text())
        assert mapping["deploy/docker/Dockerfile.go-proxy"] == "ja4proxy:2.0.0"
        assert len(mapping) >= 5

    def test_no_pairs_gives_empty_map(self):
        assert gate.dockerfile_image_map("# nothing here") == {}


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

    def test_waiver_registry_change_is_detected(self):
        assert gate.waiver_inputs_changed(["security/waivers.yaml"])

    def test_generated_ignorefiles_are_detected(self):
        assert gate.waiver_inputs_changed([".trivyignore.third-party"])
        assert gate.waiver_inputs_changed([".trivyignore.first-party"])
        assert gate.waiver_inputs_changed([".pip-audit-ignores"])

    def test_unrelated_file_is_not_a_waiver_input(self):
        assert not gate.waiver_inputs_changed(["scripts/scan_regression.py", "README.md"])

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
        _patch_git(monkeypatch, [".trivyignore.third-party"], {}, {}, makefile="")
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
