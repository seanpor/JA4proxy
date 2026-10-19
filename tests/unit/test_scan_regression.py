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

    def test_falls_back_to_a_pypi_file(self):
        assert gate.requirements_of(["sub/pyproject.toml"]) == "sub/pyproject.toml"


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
