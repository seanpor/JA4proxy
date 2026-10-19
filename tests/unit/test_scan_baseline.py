"""
tests/unit/test_scan_baseline.py

Unit tests for the CVE baseline model — Phase 847c.

The baseline is the reference data the PR gate judges against, so the two
properties worth pinning are:

  1. it refuses to load when it cannot be trusted (missing, malformed, wrong
     version, wrong shape) — a gate that guesses is worse than no gate;
  2. an unrecorded surface counts as **entirely new**, so introducing a
     vulnerable image/dependency fails without a special case.

Both are fail-safe directions, and both are asserted here rather than left to
the integration test, because a regression in either turns the gate green when
it should be red.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))

import scan_baseline  # noqa: E402
from check_trivyignore_drift import VulnRow  # noqa: E402


def _row(cve="CVE-2026-100349", severity="HIGH", fixed="0.146.0"):
    return VulnRow(
        cve=cve,
        package="github.com/getkin/kin-openapi",
        installed="v0.144.0",
        severity=severity,
        fixed=fixed,
    )


def _write(tmp_path, payload):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(payload))
    return path


class TestImageIdentity:
    """A surface is keyed by name; tag and digest are provenance, not identity."""

    def test_bare_name_is_unchanged(self):
        assert scan_baseline.image_name("redis") == "redis"

    def test_tag_is_stripped(self):
        assert scan_baseline.image_name("grafana/grafana:13.2.4-ubuntu") == "grafana/grafana"

    def test_registry_port_is_kept(self):
        # The only colon that is not a tag separator is a port.
        assert scan_baseline.image_name("localhost:5000/team/x:1.2") == "localhost:5000/team/x"

    def test_digest_is_stripped(self):
        assert scan_baseline.image_name("redis@sha256:abc") == "redis"

    def test_digest_pinned_ref_also_drops_its_tag(self):
        # Found live: the compose-pinned redis ref carries BOTH a tag and a
        # digest, and dropping only the digest left the tag in the surface key.
        assert (
            scan_baseline.image_name(
                "redis:7.4.11-alpine@sha256:520775a41a63e77e06c73e35d2fd9cc15921a609516818796b4ecbb813078bc7"
            )
            == "redis"
        )

    def test_tag_and_digest_forms_of_one_image_share_a_surface(self):
        """The recorder and the gate must agree, whichever form compose uses."""
        assert scan_baseline.surface_for_image(
            scan_baseline.image_name("redis:7.4.11-alpine@sha256:abc")
        ) == scan_baseline.surface_for_image(scan_baseline.image_name("redis:7.4.11-alpine"))

    def test_surface_key_namespaces_images(self):
        assert scan_baseline.surface_for_image("grafana/grafana") == "image:grafana/grafana"


class TestLoadBaselineRefusesUntrustedData:
    def test_missing_file_names_the_remedy(self, tmp_path):
        with pytest.raises(scan_baseline.BaselineError) as exc:
            scan_baseline.load_baseline(tmp_path / "absent.json")
        assert "scan-baseline" in str(exc.value)

    def test_invalid_json(self, tmp_path):
        path = tmp_path / "baseline.json"
        path.write_text("{not json")
        with pytest.raises(scan_baseline.BaselineError, match="not valid JSON"):
            scan_baseline.load_baseline(path)

    def test_unsupported_version(self, tmp_path):
        path = _write(tmp_path, {"version": 99, "surfaces": {}})
        with pytest.raises(scan_baseline.BaselineError, match="unsupported version"):
            scan_baseline.load_baseline(path)

    def test_missing_surfaces(self, tmp_path):
        path = _write(tmp_path, {"version": 1})
        with pytest.raises(scan_baseline.BaselineError, match="'surfaces' object"):
            scan_baseline.load_baseline(path)

    def test_surface_without_findings_object(self, tmp_path):
        path = _write(tmp_path, {"version": 1, "surfaces": {"image:x": {"ref": "x:1"}}})
        with pytest.raises(scan_baseline.BaselineError, match="findings"):
            scan_baseline.load_baseline(path)

    def test_valid_baseline_loads(self, tmp_path):
        path = _write(
            tmp_path,
            {"version": 1, "recorded_at": "t", "surfaces": {"image:x": {"findings": {}}}},
        )
        assert scan_baseline.load_baseline(path)["surfaces"]["image:x"]["findings"] == {}


class TestTheDiff:
    def test_known_finding_is_not_new(self):
        baseline = {"surfaces": {"image:x": {"findings": {"CVE-1": {}}}}}
        assert scan_baseline.new_findings(baseline, "image:x", {"CVE-1"}) == set()

    def test_new_finding_is_reported(self):
        baseline = {"surfaces": {"image:x": {"findings": {"CVE-1": {}}}}}
        assert scan_baseline.new_findings(baseline, "image:x", {"CVE-1", "CVE-2"}) == {"CVE-2"}

    def test_unrecorded_surface_is_entirely_new(self):
        """Fail-safe: no evidence it pre-existed means it did not."""
        baseline = {"surfaces": {}}
        assert scan_baseline.new_findings(baseline, "image:new", {"CVE-1", "CVE-2"}) == {
            "CVE-1",
            "CVE-2",
        }

    def test_clean_surface_is_clean(self):
        baseline = {"surfaces": {"image:x": {"findings": {"CVE-1": {}}}}}
        assert scan_baseline.new_findings(baseline, "image:x", set()) == set()


class TestRecording:
    def test_records_fix_version_not_a_boolean(self):
        entry = scan_baseline.record_findings([_row()], "x:1", "sha256:abc")
        assert entry["findings"]["CVE-2026-100349"]["fixed"] == "0.146.0"
        assert entry["ref"] == "x:1"
        assert entry["digest"] == "sha256:abc"

    def test_no_fix_is_recorded_as_empty(self):
        entry = scan_baseline.record_findings([_row(fixed="")], "x:1", None)
        assert entry["findings"]["CVE-2026-100349"]["fixed"] == ""

    def test_non_gating_severity_raises(self):
        """A MEDIUM reaching the baseline would silently widen what a PR may add."""
        with pytest.raises(ValueError, match="non-gating severity"):
            scan_baseline.record_findings([_row(severity="MEDIUM")], "x:1", None)

    def test_baseline_surfaces_are_sorted(self):
        doc = scan_baseline.build_baseline(
            {"image:z": {"findings": {}}, "image:a": {"findings": {}}}, "t"
        )
        assert list(doc["surfaces"]) == ["image:a", "image:z"]

    def test_rendered_output_is_stable(self):
        doc = scan_baseline.build_baseline({"image:x": {"findings": {}}}, "2026-10-19T00:00:00Z")
        assert scan_baseline.render_baseline(doc) == scan_baseline.render_baseline(doc)
        assert json.loads(scan_baseline.render_baseline(doc)) == doc


class TestPipAuditContract:
    """The dependency surface must use the same waivers, without a second list."""

    def test_ignore_args_parse_the_generated_format(self, tmp_path):
        ignore = tmp_path / ".pip-audit-ignores"
        ignore.write_text(
            "# GENERATED — do not edit\n"
            "\n"
            "--ignore-vuln CVE-2025-50181\n"
            "--ignore-vuln CVE-2026-59951\n"
        )
        assert scan_baseline.ignore_vuln_args(str(ignore)) == [
            "--ignore-vuln",
            "CVE-2025-50181",
            "--ignore-vuln",
            "CVE-2026-59951",
        ]

    def test_missing_ignorefile_is_an_error(self, tmp_path):
        with pytest.raises(scan_baseline.BaselineError, match="render_waivers"):
            scan_baseline.ignore_vuln_args(str(tmp_path / "absent"))

    def test_command_runs_in_the_pinned_tools_image(self, tmp_path):
        ignore = tmp_path / ".pip-audit-ignores"
        ignore.write_text("--ignore-vuln CVE-1\n")
        cmd = scan_baseline.pip_audit_cmd("requirements.txt", str(ignore))
        assert scan_baseline.TOOLS_IMAGE in cmd
        assert cmd[cmd.index("-r") + 1] == "requirements.txt"
        assert cmd[cmd.index("-f") + 1] == "json"
        assert cmd[-2:] == ["--ignore-vuln", "CVE-1"]

    def test_pypi_findings_join_fix_versions(self):
        deps = [
            {
                "name": "urllib3",
                "version": "2.0.0",
                "vulns": [{"id": "PYSEC-2026-1", "fix_versions": ["2.0.7", "2.1.0"]}],
            }
        ]
        entry = scan_baseline.pypi_findings(deps)["PYSEC-2026-1"]
        assert entry["fixed"] == "2.0.7, 2.1.0"
        assert entry["package"] == "urllib3"

    def test_pypi_findings_skip_entries_without_id(self):
        deps = [{"name": "x", "version": "1", "vulns": [{"fix_versions": []}]}]
        assert scan_baseline.pypi_findings(deps) == {}


class TestDigestProvenance:
    def test_digest_comes_from_the_report(self):
        report = {"Metadata": {"RepoDigests": ["grafana/grafana@sha256:deadbeef"]}}
        assert scan_baseline.report_digest(report) == "sha256:deadbeef"

    def test_no_repo_digests_gives_none(self):
        assert scan_baseline.report_digest({"Metadata": {}}) is None
        assert scan_baseline.report_digest({}) is None
