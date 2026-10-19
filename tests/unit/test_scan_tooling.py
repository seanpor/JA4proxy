"""
tests/unit/test_scan_tooling.py

Unit tests for the image-scan gates — Phase 847b ("scan tooling correctness").

Three defects were exposed during Phase 824c, each a way the tooling actively
misled a human triaging under pressure. The first one is load-bearing: it is the
bug that made a real 5-CVE image look like a one-CVE image.

Doing the work surfaced more of the same family, all covered here: a scan that
cannot run passed as clean (847b.4), a locally-built image was classified as
third-party (847b.5), and a workflow still applied the pre-822 ignorefile.
`scan-first-party` carried the *identical* counting and silent-pass defects that
the plan only attributed to `scan-images`, so both gates are tested.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
scripts_dir = _ROOT / "scripts"
sys.path.insert(0, str(scripts_dir))

import check_image_versions  # noqa: E402
import check_trivyignore_drift  # noqa: E402
import trivy_image_report  # noqa: E402

# A real captured `trivy image --format json` for grafana/grafana:13.2.4-ubuntu,
# excerpted verbatim (5 kin-openapi HIGH entries, plus the real Result header).
GRAFANA_JSON = _ROOT / "tests" / "fixtures" / "trivy-grafana-kin-openapi.json"
# The real `--format table` output for the same scan, same verbatim excerpt.
GRAFANA_TABLE = _ROOT / "tests" / "fixtures" / "trivy-grafana-kin-openapi.table.txt"

KIN_OPENAPI_HIGH_IDS = {
    "CVE-2026-100349", "CVE-2026-100351", "CVE-2026-100352",
    "CVE-2026-100353", "CVE-2026-100354",
}


def _code_lines(text: str) -> list[str]:
    """Full-line comments only, so a *documented* mention of a filename is not
    mistaken for a live reference. Shell `#`/`@#` and YAML `#` share this shape."""
    return [l for l in text.splitlines()
            if not (l.lstrip().startswith("#") or l.lstrip().startswith("@#"))]


# --- 847b.1: counts come from JSON, not from severity tokens in a table -------

class TestJsonCounting:
    def test_counter_finds_every_high_in_one_library_group(self):
        """The whole point: 5 distinct kin-openapi HIGHs must count as 5."""
        rows = check_trivyignore_drift.vuln_rows(
            check_trivyignore_drift.load_report(GRAFANA_JSON)
        )
        assert len(rows) == 5
        assert {r.cve for r in rows} == KIN_OPENAPI_HIGH_IDS
        assert all(r.severity == "HIGH" for r in rows)
        assert {r.package for r in rows} == {"github.com/getkin/kin-openapi"}

    def test_grouped_table_undercounts_those_five_to_one(self):
        """Pin the defect itself, using the REAL table Trivy emitted.

        Trivy's table groups by library and prints the severity once per group,
        so four of these five CVEs have a blank Severity cell. The old
        `grep -v "Total:" | grep -c HIGH` therefore reported 1 for the group —
        which is why the count had to move to JSON rather than be patched.
        """
        lines = [l for l in GRAFANA_TABLE.read_text().splitlines() if "Total:" not in l]
        assert sum(1 for l in lines if "HIGH" in l) == 1
        # ...while the true number is right there in the same output, discarded:
        assert "Total: 5 (HIGH: 5, CRITICAL: 0)" in GRAFANA_TABLE.read_text()

    def test_gate_reports_five_not_one(self, capsys):
        """End-to-end through the gate's CLI: the human sees 5."""
        rc = trivy_image_report.main(["--json-file", str(GRAFANA_JSON)])
        out = capsys.readouterr().out
        assert rc == 1                      # gate still fails
        assert "5 HIGH + 0 CRITICAL" in out  # ...but reports the true count
        for cve in KIN_OPENAPI_HIGH_IDS:
            assert cve in out               # every id is individually visible

    def test_rows_are_deduplicated_by_cve_id_not_by_row(self):
        """Trivy emits one row per (target, package, CVE); one waived id must not
        inflate the count just because the same CVE appears under several layers."""
        doc = {"Results": [
            {"Vulnerabilities": [
                {"VulnerabilityID": "CVE-1", "Severity": "HIGH", "PkgName": "p"},
                {"VulnerabilityID": "CVE-1", "Severity": "HIGH", "PkgName": "p"},
                {"VulnerabilityID": "CVE-2", "Severity": "HIGH", "PkgName": "p"},
            ]}
        ]}
        assert [r.cve for r in check_trivyignore_drift.vuln_rows(doc)] == ["CVE-1", "CVE-2"]

    def test_critical_wins_over_high_for_the_same_id(self):
        doc = {"Results": [{"Vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "Severity": "HIGH", "PkgName": "p"},
            {"VulnerabilityID": "CVE-1", "Severity": "CRITICAL", "PkgName": "p"},
        ]}]}
        rows = check_trivyignore_drift.vuln_rows(doc)
        assert [r.severity for r in rows] == ["CRITICAL"]

    def test_gate_and_drift_checker_share_one_parser(self):
        """The gate and the drift checker must agree, or the gate can fail on a
        finding the drift checker calls waived (847b.3)."""
        doc = check_trivyignore_drift.load_report(GRAFANA_JSON)
        from_map = check_trivyignore_drift.findings_from_scan(GRAFANA_JSON)
        from_rows = {r.cve: r.severity for r in check_trivyignore_drift.vuln_rows(doc)}
        assert from_map == from_rows


# --- 847b.2: failure messages must name files that exist ----------------------

class TestFailureMessages:
    def test_scan_images_failure_names_the_generated_files(self):
        makefile = (_ROOT / "Makefile").read_text()
        assert "security/waivers.yaml" in makefile          # authoring location
        assert ".trivyignore.third-party" in makefile       # generated artifact
        # The exact message that pointed at a deleted file must be gone:
        assert "see .trivyignore for documented exceptions" not in makefile

    def test_first_party_failure_message_names_the_split_file(self):
        makefile = (_ROOT / "Makefile").read_text()
        assert "dated .trivyignore.first-party entry" in makefile


# --- 847b.3: the two consumers must not diverge --------------------------------

class TestConsumerAlignment:
    def test_makefile_and_ci_read_the_same_generated_ignore_sources(self):
        """Both consumers must read the GENERATED files, not inline lists.

        847a closed the 2-vs-6 divergence between them; this asserts the shape of
        the fix so neither can drift back to an inline list.
        """
        makefile = "\n".join(_code_lines((_ROOT / "Makefile").read_text()))
        ci = "\n".join(_code_lines((_ROOT / ".github" / "workflows" / "ci.yml").read_text()))
        for text in (makefile, ci):
            assert ".pip-audit-ignores" in text
            assert "--ignore-vuln" not in text, "an inline ignore list has reappeared"

    def test_every_ignorefile_consumer_names_a_file_that_exists(self):
        """The guard that would have caught go-proxy-image.yml applying no waivers.

        Only lines that actually *consume* an ignorefile are checked — a
        `trivyignores:` field or an `--ignorefile` argument. A display name like
        "Renew soon-to-expire .trivyignore exceptions" is prose, not a path.
        """
        files = [("Makefile", (_ROOT / "Makefile").read_text())] + [
            (str(p.relative_to(_ROOT)), p.read_text())
            for p in sorted((_ROOT / ".github" / "workflows").glob("*.yml"))
        ]
        consumer = re.compile(r"(?:trivyignores:|--ignorefile[ =])\s*([^\s'\"]+)")
        checked = 0
        for name, text in files:
            for lineno, line in enumerate(_code_lines(text), 1):
                for ref in consumer.findall(line):
                    checked += 1
                    assert ref.endswith((".trivyignore.first-party", ".trivyignore.third-party")), (
                        f"{name}:{lineno} consumes {ref!r}, which does not exist "
                        f"(Phase 822 split .trivyignore into first/third-party)"
                    )
        assert checked >= 2, "expected to find ignorefile consumers to check"

    def test_reporter_default_ignorefile_exists(self):
        """`scan-images` now delegates the third-party ignorefile to the
        reporter's default, so that default must name a file that exists."""
        assert (_ROOT / trivy_image_report.DEFAULT_IGNOREFILE).is_file()
        assert trivy_image_report.DEFAULT_IGNOREFILE == ".trivyignore.third-party"


# --- the scan list itself must not drift (found while fixing the above) -------

class TestFirstPartyClassification:
    def test_first_party_lists_agree_with_the_makefile(self):
        """Two lists decide first-party-ness: the Makefile's (what `make
        scan-first-party` builds and scans) and this script's (what
        `--list-third-party` excludes). They drifted, and a locally-built image
        was offered to the third-party scan."""
        m = re.search(r"^FIRST_PARTY_IMAGES\s*:=\s*(.+)$", (_ROOT / "Makefile").read_text(), re.M)
        assert m, "FIRST_PARTY_IMAGES not found in the Makefile"
        makefile_names = {tok.split(":")[0] for tok in m.group(1).split()}
        assert makefile_names == set(check_image_versions.FIRST_PARTY_IMAGES)

    def test_scan_images_never_asks_trivy_for_a_locally_built_image(self):
        """A locally-built image has no registry to pull from. Handing it to the
        third-party scan made the gate fail — and, before 847b counted honestly,
        made it pass silently."""
        files = [
            _ROOT / "deploy" / "docker" / f
            for f in check_image_versions.SCAN_GATE_COMPOSE_FILES
        ]
        refs = check_image_versions.third_party_image_refs(files)
        assert refs, "expected a non-empty third-party image list"
        for ref in refs:
            assert ref.split(":")[0] not in check_image_versions.FIRST_PARTY_IMAGES


# --- 847b.4: a scan that cannot be read is a FAILURE, never a pass --------------

class TestNoSilentPass:
    def test_unparseable_report_fails_the_gate(self, tmp_path, capsys):
        """`grep -c HIGH` on a failed scan counts 0 — indistinguishable from clean.
        The JSON path must fail loudly instead."""
        bad = tmp_path / "unpullable.json"
        bad.write_text("not json at all\n")
        assert trivy_image_report.main(["--json-file", str(bad)]) == 1
        assert "unreadable" in capsys.readouterr().err

    def test_empty_results_report_is_clean(self, tmp_path, capsys):
        """A report with zero vulnerabilities is a genuine pass."""
        report = tmp_path / "empty.json"
        report.write_text(
            '{"SchemaVersion": 2, "ArtifactName": "clean:1.0", "Results": []}\n'
        )
        assert trivy_image_report.main(["--json-file", str(report)]) == 0
        assert "no HIGH/CRITICAL findings" in capsys.readouterr().out

    def test_scan_images_wires_the_reporter_failure_into_fail(self):
        """`|| fail=1` must actually be present, so a non-zero reporter exit
        reddens the target rather than being ignored — and the scope must stay
        explicit rather than hiding behind the script's default."""
        makefile = (_ROOT / "Makefile").read_text()
        assert (
            'trivy_image_report.py --ignorefile /scan/.trivyignore.third-party '
            '"$$img" || fail=1' in makefile
        )


# --- both gates, not just the one the plan named --------------------------------

def _target(name: str) -> str:
    """The recipe body of one Makefile target — from its rule line to the first
    column-0 line that ends the recipe."""
    body: list[str] = []
    for line in (_ROOT / "Makefile").read_text().splitlines():
        if body:
            if line and not line.startswith("\t"):
                break
            body.append(line)
        elif re.match(rf"^{re.escape(name)}:", line):
            body.append(line)
    return "\n".join(body)


class TestBothImageGates:
    """847b.1 and 847b.4 lived in *both* image gates.

    The plan named `scan-images` alone, but `scan-first-party` carried the same
    `grep -v "Total:" | grep -c` on the same grouped table, and the same
    `2>&1 | grep -E ... || true` that swallowed a failed scan as a pass.
    """

    def test_both_targets_run_the_json_gate_and_fail_on_it(self):
        for target in ("scan-images", "scan-first-party"):
            body = _target(target)
            assert "scripts/trivy_image_report.py" in body, (
                f"{target} no longer runs the JSON gate"
            )
            assert "|| fail=1" in body, f"{target} ignores a failing gate"

    def test_first_party_gate_passes_the_socket_and_its_own_ignorefile(self):
        """Locally-built images exist in no registry, so this gate must mount the
        docker socket — and must apply first-party waivers, not third-party ones."""
        body = _target("scan-first-party")
        assert "--docker-socket" in body
        assert "--ignorefile /scan/.trivyignore.first-party" in body

    def test_no_severity_grep_counting_survives_anywhere(self):
        """Guard the defect class rather than this instance: counting severity
        tokens in a human-rendered table is wrong in both directions."""
        makefile = (_ROOT / "Makefile").read_text()
        assert 'grep -v "Total:"' not in makefile
        assert 'grep -E -c "CRITICAL|HIGH"' not in makefile


# --- --ignorefile must never silently re-home a typo ----------------------------

class TestIgnoreFilePath:
    def test_both_spellings_resolve_to_the_same_trivy_path(self):
        assert trivy_image_report.resolve_ignorefile(
            ".trivyignore.third-party", cwd=_ROOT
        ) == "/scan/.trivyignore.third-party"
        assert trivy_image_report.resolve_ignorefile(
            "/scan/.trivyignore.third-party", cwd=_ROOT
        ) == "/scan/.trivyignore.third-party"

    def test_a_path_outside_the_mount_is_rejected_not_re_homed(self):
        """A plain `basename()` would turn `/etc/hosts` into `/scan/hosts`."""
        for bad in ("/etc/hosts", "../waivers.yaml", "/", "..", ""):
            with pytest.raises(ValueError, match="repo root"):
                trivy_image_report.resolve_ignorefile(bad, cwd=_ROOT)

    def test_a_missing_ignore_file_fails_before_trivy_runs(self):
        with pytest.raises(FileNotFoundError, match="does not exist"):
            trivy_image_report.resolve_ignorefile(
                ".trivyignore.this-one-is-not-generated", cwd=_ROOT
            )

    def test_the_gate_reports_a_bad_ignorefile_as_exit_two_not_a_pass(self):
        rc = trivy_image_report.main(
            ["--ignorefile", "/etc/hosts", "grafana/grafana:13.2.4-ubuntu"]
        )
        assert rc == 2
