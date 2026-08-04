"""
tests/unit/test_pin_table_autofix.py

Unit tests for scripts/pin_table_autofix.py -- Phase 812 (812-C).

`git ls-remote` is mocked throughout (never a real network call in tests,
per CLAUDE.md's testing standards) via monkeypatching subprocess.run.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

scripts_dir = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

import pin_table_autofix as autofix  # noqa: E402


TEST_FILE_TEMPLATE = '''\
KNOWN_ACTION_SHAS: dict[str, dict[str, str]] = {{
    "actions/checkout": {{
        "v4.1.1": "b4ffde65f46336ab88eb53be808477a3936bae11",
    }},
    "some-owner/some-action": {{
{extra}    }},
}}
'''


def _write_test_file(tmp_path: Path, extra: str = "") -> Path:
    p = tmp_path / "test_workflow_pinning.py"
    p.write_text(TEST_FILE_TEMPLATE.format(extra=extra), encoding="utf-8")
    return p


def _write_workflow(tmp_path: Path, uses_line: str) -> Path:
    wf_dir = tmp_path / "workflows"
    wf_dir.mkdir(exist_ok=True)
    (wf_dir / "example.yml").write_text(
        f"name: Example\non: push\njobs:\n  x:\n    steps:\n      - {uses_line}\n",
        encoding="utf-8",
    )
    return wf_dir


def _mock_ls_remote(monkeypatch, sha_by_ref: dict[str, str]):
    def fake_run(cmd, **kwargs):
        ref = cmd[-1]
        sha = sha_by_ref.get(ref, "")
        return subprocess.CompletedProcess(cmd, 0, stdout=f"{sha}\trefs/tags/x\n" if sha else "", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)


def test_known_good_triple_gets_patched(tmp_path, monkeypatch):
    test_file = _write_test_file(tmp_path)
    wf_dir = _write_workflow(
        tmp_path,
        'uses: some-owner/some-action@' + "a" * 40 + "  # v1.2.3",
    )
    _mock_ls_remote(monkeypatch, {"refs/tags/v1.2.3": "a" * 40})

    rc = autofix.main(
        ["--workflow-dir", str(wf_dir), "--test-file", str(test_file), "--note", "test-note"]
    )
    assert rc == 0
    content = test_file.read_text(encoding="utf-8")
    assert f'"v1.2.3": "{"a" * 40}"' in content
    assert "test-note" in content


def test_mismatched_sha_fails_loudly_and_does_not_patch(tmp_path, monkeypatch):
    test_file = _write_test_file(tmp_path)
    original = test_file.read_text(encoding="utf-8")
    wf_dir = _write_workflow(
        tmp_path,
        'uses: some-owner/some-action@' + "b" * 40 + "  # v9.9.9",
    )
    # ls-remote returns a DIFFERENT sha than the diff claims -- the actual
    # supply-chain-hole case this script exists to catch.
    _mock_ls_remote(monkeypatch, {"refs/tags/v9.9.9": "c" * 40})

    rc = autofix.main(["--workflow-dir", str(wf_dir), "--test-file", str(test_file)])
    assert rc == 1
    # No changes at all -- all-or-nothing.
    assert test_file.read_text(encoding="utf-8") == original


def test_idempotent_when_already_patched(tmp_path, monkeypatch):
    test_file = _write_test_file(
        tmp_path, extra=f'        "v1.2.3": "{"a" * 40}",\n'
    )
    wf_dir = _write_workflow(
        tmp_path,
        'uses: some-owner/some-action@' + "a" * 40 + "  # v1.2.3",
    )

    def fail_if_called(cmd, **kwargs):
        raise AssertionError("git ls-remote should not be called for an already-known triple")

    monkeypatch.setattr(subprocess, "run", fail_if_called)

    rc = autofix.main(["--workflow-dir", str(wf_dir), "--test-file", str(test_file)])
    assert rc == 0  # no-op, no network call needed at all


def test_unknown_action_with_no_existing_block_is_not_auto_created(tmp_path, monkeypatch):
    test_file = _write_test_file(tmp_path)
    wf_dir = _write_workflow(
        tmp_path,
        'uses: brand-new/action@' + "d" * 40 + "  # v1.0.0",
    )
    _mock_ls_remote(monkeypatch, {"refs/tags/v1.0.0": "d" * 40})

    original = test_file.read_text(encoding="utf-8")
    rc = autofix.main(["--workflow-dir", str(wf_dir), "--test-file", str(test_file)])
    assert rc == 1  # verified, but no block to patch into -- reported, not auto-created
    assert test_file.read_text(encoding="utf-8") == original


def test_annotated_tag_dereference_fallback(tmp_path, monkeypatch):
    """The ossf/scorecard-action v2.4.4 gotcha from PR #379: plain
    refs/tags/vX returns the annotated tag OBJECT sha; refs/tags/vX^{}
    dereferences to the actual commit. Must try the fallback.
    """
    test_file = _write_test_file(tmp_path)
    wf_dir = _write_workflow(
        tmp_path,
        'uses: some-owner/some-action@' + "e" * 40 + "  # v2.4.4",
    )
    _mock_ls_remote(
        monkeypatch,
        {
            "refs/tags/v2.4.4": "f" * 40,  # tag object sha -- doesn't match
            "refs/tags/v2.4.4^{}": "e" * 40,  # dereferenced commit -- matches
        },
    )
    rc = autofix.main(["--workflow-dir", str(wf_dir), "--test-file", str(test_file)])
    assert rc == 0
    assert f'"v2.4.4": "{"e" * 40}"' in test_file.read_text(encoding="utf-8")


def test_action_name_injection_attempt_rejected(tmp_path, monkeypatch):
    test_file = _write_test_file(tmp_path)
    # A 40-hex-char string is required by SHA_AND_TAG_RE for the sha group,
    # and the tag group only allows v[0-9A-Za-z.-_]+ -- so the regex itself
    # already blocks most shell-metacharacter injection attempts at the
    # extraction stage. This test asserts the explicit validation gate is
    # also in place as defense in depth, matching the phase doc's stated
    # design (subprocess arg-list form is the real injection defense; the
    # regex is a second layer).
    ok, detail = autofix.verify_sha("not a valid action name!", "v1.0.0", "a" * 40)
    assert ok is False
    assert "fails strict validation" in detail


def test_no_changes_when_nothing_new(tmp_path, monkeypatch):
    test_file = _write_test_file(
        tmp_path, extra=f'        "v1.2.3": "{"a" * 40}",\n'
    )
    wf_dir = _write_workflow(
        tmp_path,
        'uses: some-owner/some-action@' + "a" * 40 + "  # v1.2.3",
    )
    rc = autofix.main(["--workflow-dir", str(wf_dir), "--test-file", str(test_file)])
    assert rc == 0
