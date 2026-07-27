"""Phase 61 — verify GitHub Actions workflows are SHA-pinned and permission-scoped.

Every `uses:` line in `.github/workflows/*.yml` must reference a 40-character
hex commit SHA (not a tag like ``@v4``), with the one documented exception of
reusable workflows loaded via ``uses: owner/repo/.github/workflows/foo.yml@vTAG``
(GitHub only accepts a ref, not a SHA, for those — ``release-cli.yml`` already
uses this form for ``slsa-framework/slsa-github-generator``).

Every workflow must also declare a top-level ``permissions:`` block so the
default ``GITHUB_TOKEN`` scope is explicitly narrowed.
"""

from __future__ import annotations

import glob
import os
import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"

SHA_PIN_RE = re.compile(r"^[^/\s]+/[^@\s]+@[a-f0-9]{40}(\s|$)")
REUSABLE_WORKFLOW_RE = re.compile(r"^[^/\s]+/[^@\s]+/\.github/workflows/[^@\s]+@")

# `uses: owner/repo[/path]@SHA  # vTAG` — captures (owner/repo[/path], SHA, vTAG).
SHA_AND_TAG_RE = re.compile(
    r"uses:\s*([^/\s]+/[^@\s]+)@([a-f0-9]{40})\s*#\s*(v[0-9A-Za-z.\-_]+)"
)

# Vendored truth table: action ref -> {tag: SHA}.
#
# This is the only place where the SHA-vs-tag-comment correspondence is
# asserted. Tests cannot reach the network, so this allowlist is the
# verification surface. When Dependabot opens a SHA bump PR, ALSO update this
# table — that is the contract that prevents the "wrong SHA + lying comment"
# class of supply-chain hole flagged in the Phase 61 external review.
#
# To verify a row by hand:
#     git ls-remote https://github.com/<owner>/<repo> refs/tags/<tag>
KNOWN_ACTION_SHAS: dict[str, dict[str, str]] = {
    # phase-302: Dependabot auto-merge workflow
    "dependabot/fetch-metadata": {
        "v2.3.0": "d7267f607e9d3fb96fc2fbe83e0af444713e90b7",
        "v3.1.0": "25dd0e34f4fe68f24cc83900b1fe3fe149efef98",  # phase-307 (PR #105)
    },
    "actions/checkout": {
        "v4.1.1": "b4ffde65f46336ab88eb53be808477a3936bae11",  # scorecard.yml
        "v4.2.2": "11bd71901bbe5b1630ceea73d27597364c9af683",
        "v6.0.2": "de0fac2e4500dabe0009e67214ff5f5447ce83dd",
        "v6.0.3": "df4cb1c069e1874edd31b4311f1884172cec0e10",  # phase-307 (PR #105)
        "v7.0.0": "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",  # PR #347
    },
    # phase-227: Trivy DB cache in the scan job (ci.yml)
    "actions/cache": {
        "v4.2.3": "5a3ec84eff668545956fd18022155c47e93e2684",
        "v5.0.5": "27d5ce7f107fe9357f9df03efb73ab90386fccae",  # phase-307 (PR #105)
        "v6.1.0": "55cc8345863c7cc4c66a329aec7e433d2d1c52a9",  # PR #347
    },
    # scorecard.yml (OpenSSF Scorecard workflow) — verified via git ls-remote
    "ossf/scorecard-action": {
        "v2.3.1": "0864cf19026789058feabb7e87baa5f140aac736",
        "v2.4.3": "4eaacf0543bb3f2c246792bd56e8cdeffafb205a",  # phase-307 (PR #105)
    },
    "github/codeql-action/upload-sarif": {
        "v3.35.4": "7fd177fa680c9881b53cdab4d346d32574c9f7f4",
        "v4.36.2": "8aad20d150bbac5944a9f9d289da16a4b0d87c1e",  # phase-307 (PR #105)
    },
    "actions/setup-go": {
        "v5.2.0": "3041bf56c941b39c61721a86cd11f3bb1338122a",
        "v5.6.0": "40f1582b2485089dde7abd97c1529aa768e1baff",
        "v6.4.0": "4a3601121dd01d1626a1e23e37211e3254c1c06c",
        "v6.5.0": "924ae3a1cded613372ab5595356fb5720e22ba16",  # PR #347
    },
    "actions/setup-python": {
        "v5.0.0": "0a5c61591373683505ea898e09a3ea4f39ef2b9c",
        "v6.2.0": "a309ff8b426b58ec0e2a45f0f869d46889d02405",
        "v6.3.0": "ece7cb06caefa5fff74198d8649806c4678c61a1",  # PR #347
    },
    "trufflesecurity/trufflehog": {
        "v3.88.2": "a94d152bf65bebf5baa486d3d4dfee520af2ceed",
        "v3.94.3": "47e7b7cd74f578e1e3145d48f669f22fd1330ca6",
        "v3.95.5": "d411fff7b8879a62509f3fa98c07f247ac089a51",  # phase-307 (PR #105)
        "v3.95.9": "27b0417c16317ca9a472a9a8092acce143b49c55",  # PR #347
    },
    "returntocorp/semgrep-action": {
        "v1": "713efdd345f3035192eaa63f56867b88e63e4e5d",
    },
    "actions/dependency-review-action": {
        "v4.5.0": "3b139cfc5fae8b618d3eae3675e383bb1769c019",
        "v4.9.0": "2031cfc080254a8a887f58cffee85186f0e49e48",
        "v5.0.0": "a1d282b36b6f3519aa1f3fc636f609c47dddb294",  # phase-307 (PR #105)
    },
    # phase-107w.3: lychee link-check workflow (docs-link-check.yml)
    "lycheeverse/lychee-action": {
        "v2.8.0": "8646ba30535128ac92d33dfc9133794bfdd9b411",
        "v2.9.0": "e7477775783ea5526144ba13e8db5eec57747ce8",  # PR #347
    },
    # phase-64: smoke-k8s CI job
    "azure/setup-helm": {
        "v4.3.0": "b9e51907a09c216f16ebe8536097933489208112",
    },
    "helm/kind-action": {
        "v1.12.0": "a1b0e391336a6ee6713a0583f8c6240d70863de3",
    },
    # release-cli.yml — verified upstream during Phase 61 review-fix.
    "crazy-max/ghaction-import-gpg": {
        "v6.2.0": "cb9bde2e2525e640591a934b1fd28eef1dcaf5e5",
        "v7.0.0": "2dc316deee8e90f13e1a351ab510b4d5bc0c82cd",
    },
    "goreleaser/goreleaser-action": {
        "v6.3.0": "9c156ee8a17a598857849441385a2041ef570552",
        "v7.0.0": "ec59f474b9834571250b370d4735c50f8e2d1e29",
        "v7.2.2": "5daf1e915a5f0af01ddbcd89a43b8061ff4f1a89",  # phase-307 (PR #105)
        "v7.2.3": "f06c13b6b1a9625abc9e6e439d9c05a8f2190e94",  # PR #347
    },
    "docker/setup-qemu-action": {
        "v3.2.0": "49b3bc8e6bdd4a60e6116a5414239cba5943d3cf",
        "v4.0.0": "ce360397dd3f832beb865e1373c09c0e9f86d70a",
        "v4.1.0": "06116385d9baf250c9f4dcb4858b16962ea869c3",  # phase-307 (PR #105)
        "v4.2.0": "96fe6ef7f33517b61c61be40b68a1882f3264fb8",  # PR #347
    },
    "docker/setup-buildx-action": {
        "v3.8.0": "6524bf65af31da8d45b59e8c27de4bd072b392f5",
        "v4.0.0": "4d04d5d9486b7bd6fa91e7baf45bbb4f8b9deedd",
        "v4.1.0": "d7f5e7f509e45cec5c76c4d5afdd7de93d0b3df5",  # phase-307 (PR #105)
        "v4.2.0": "bb05f3f5519dd87d3ba754cc423b652a5edd6d2c",  # PR #347
    },
    "docker/login-action": {
        "v3.3.0": "9780b0c442fbb1117ed29e0efdff1e18412f7567",
        "v4.1.0": "4907a6ddec9925e35a0a9e82d7399ccc52663121",
        "v4.2.0": "650006c6eb7dba73a995cc03b0b2d7f5ca915bee",  # phase-307 (PR #105)
        "v4.4.0": "af1e73f918a031802d376d3c8bbc3fe56130a9b0",  # PR #347
    },
    "docker/metadata-action": {
        "v5.6.1": "369eb591f429131d6889c46b94e711f089e6ca96",
        "v6.0.0": "030e881283bb7a6894de51c315a6bfe6a94e05cf",
        "v6.1.0": "80c7e94dd9b9319bd5eb7a0e0fe9291e23a2a2e9",  # phase-307 (PR #105)
        "v6.2.0": "dc802804100637a589fabce1cb79ff13a1411302",  # PR #347
    },
    "docker/build-push-action": {
        "v6.13.0": "ca877d9245402d1537745e0e356eab47c3520991",
        "v7.1.0": "bcafcacb16a39f128d818304e6c9c0c18556b85f",
        "v7.2.0": "f9f3042f7e2789586610d6e8b85c8f03e5195baf",  # phase-307 (PR #105)
        "v7.3.0": "53b7df96c91f9c12dcc8a07bcb9ccacbed38856a",  # PR #347
    },
    # phase-202d — Go proxy image CI workflow (go-proxy-image.yml)
    "sigstore/cosign-installer": {
        "v3.7.0": "dc72c7d5c4d10cd6bcb8cf6e3fd625a9e5e537da",
        "v4.1.1": "cad07c2e89fa2edd6e2d7bab4c1aa38e53f76003",
        "v4.1.2": "6f9f17788090df1f26f669e9d70d6ae9567deba6",  # phase-307 (PR #105)
    },
    "anchore/sbom-action": {
        "v0.17.8": "55dc4ee22412511ee8c3142cbea40418e6cec693",
        "v0.24.0": "e22c389904149dbc22b58101806040fa8d37a610",
    },
    "aquasecurity/trivy-action": {
        "v0.29.0": "18f2510ee396bbf400402947b394f2dd8c87dbb0",
        "v0.35.0": "57a97c7e7821a5776cebc9bb87c984fa69cba8f1",
        "v0.36.0": "ed142fd0673e97e23eac54620cfb913e5ce36c25",  # phase-307 (PR #105)
    },
    # phase-202a — SLSA reusable workflow, SHA-pinned per ADR-202a Path A.
    # Full path-keyed because the uses: reference includes `.github/workflows/...yml`.
    "slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml": {
        "v2.1.0": "f7dd8c54c2067bafc12ca7a55595d5ee9b75204a",
    },
    # phase-105h — PDF docs build workflow (docs-pdf.yml). Per ADR-105a.
    "xu-cheng/latex-action": {
        "v3.3.0": "e2f99d4b3685b0da93f97e1b86ad8fab81105098",
        # phase-307 (PR #105): upstream tags this release `4.1.0` / `v4` (no
        # `v`-prefixed `v4.1.0` ref); Dependabot's comment normalises it to
        # v4.1.0. SHA verified == refs/tags/4.1.0.
        "v4.1.0": "6549dc21effb2730855a1281407ecfcececc6c1b",
    },
    "actions/upload-artifact": {
        "v4": "ea165f8d65b6e75b540449e92b4886f43607fa02",  # scorecard.yml
        "v7.0.1": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    },
    # phase-800 — scheduled-run failure notifier (ci.yml)
    "actions/github-script": {
        "v7.1.0": "f28e40c7f34bde8b3046d885e986cb6290c5673b",
        "v9.0.0": "3a2844b7e9c422d3c10d287c895573f7108da1b3",  # PR #347
    },
}


def _workflow_files() -> list[Path]:
    files = sorted(Path(p) for p in glob.glob(str(WORKFLOW_DIR / "*.yml")))
    assert files, f"No workflow files found under {WORKFLOW_DIR}"
    return files


def _iter_uses(node):
    """Yield every ``uses:`` string value in a parsed workflow."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "uses" and isinstance(v, str):
                yield v
            else:
                yield from _iter_uses(v)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_uses(item)


def test_every_workflow_parses_as_yaml():
    for f in _workflow_files():
        with f.open() as fh:
            yaml.safe_load(fh)


def test_every_uses_line_is_sha_pinned():
    failures: list[str] = []
    for f in _workflow_files():
        with f.open() as fh:
            doc = yaml.safe_load(fh)
        for use in _iter_uses(doc):
            if REUSABLE_WORKFLOW_RE.match(use):
                # reusable workflows cannot be pinned to a SHA by GitHub rules
                continue
            if not SHA_PIN_RE.match(use + " "):
                failures.append(f"{f.name}: {use}")
    assert (
        not failures
    ), "Unpinned uses: entries found (must be 40-char SHA):\n  " + "\n  ".join(failures)


def test_every_workflow_has_top_level_permissions():
    failures: list[str] = []
    for f in _workflow_files():
        with f.open() as fh:
            doc = yaml.safe_load(fh)
        if not isinstance(doc, dict) or "permissions" not in doc:
            failures.append(f.name)
    assert (
        not failures
    ), "Workflows missing top-level permissions block:\n  " + "\n  ".join(failures)


def test_branch_protection_script_executable():
    script = REPO_ROOT / "scripts" / "branch_protection.sh"
    assert script.exists(), f"{script} missing"
    assert os.access(script, os.X_OK), f"{script} not executable"


def test_sha_matches_tag_comment():
    """Every `uses: ...@<SHA>  # vTAG` must match the vendored allowlist.

    Catches the "comment lies about which version this SHA actually is" class
    of supply-chain hole. The Phase 61 external review found exactly this:
    a setup-python pin labelled v5.0.0 was actually upstream v4.7.1.
    """
    failures: list[str] = []
    for f in _workflow_files():
        text = f.read_text()
        for action, sha, tag in SHA_AND_TAG_RE.findall(text):
            known = KNOWN_ACTION_SHAS.get(action)
            if known is None:
                failures.append(
                    f"{f.name}: {action}@{sha}  # {tag} — action not in "
                    f"KNOWN_ACTION_SHAS allowlist; add it after verifying "
                    f"with `git ls-remote https://github.com/{action} "
                    f"refs/tags/{tag}`"
                )
                continue
            expected = known.get(tag)
            if expected is None:
                failures.append(
                    f"{f.name}: {action}@{sha}  # {tag} — tag {tag} not in "
                    f"allowlist for {action}; known tags: {sorted(known)}"
                )
                continue
            if expected != sha:
                failures.append(
                    f"{f.name}: {action}@{sha}  # {tag} — comment claims "
                    f"{tag} but that tag's real SHA is {expected}"
                )
    assert not failures, "SHA / tag-comment mismatches:\n  " + "\n  ".join(failures)


# Required status checks that come from workflows OTHER than ci.yml. Each maps a
# check name -> the workflow file whose job declares it. Such a workflow MUST run
# on every pull_request (no `paths:` filter), otherwise a required-but-unreported
# check would block every PR that doesn't touch the filtered paths.
EXTERNAL_REQUIRED_CONTEXTS = {
    "lychee on conformance + audience-scoped docs": ".github/workflows/docs-link-check.yml",
}


def test_branch_protection_contexts_match_ci_job_names():
    """branch_protection.sh contexts must equal the required CI job names.

    The required set = ci.yml's non-continue-on-error jobs (excluding the PR-only
    dependency-review) PLUS the explicitly-declared EXTERNAL_REQUIRED_CONTEXTS
    from other workflows. A drift here silently turns branch protection into a
    no-op gate (a required check that never fires => PR can merge regardless), so
    this is the highest silent-failure risk.
    """
    ci = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    script = REPO_ROOT / "scripts" / "branch_protection.sh"
    with ci.open() as fh:
        doc = yaml.safe_load(fh)

    # `dependency-review` is PR-only; `continue-on-error` jobs are informational
    # (not required checks). Everything else must appear in branch_protection.sh.
    job_names = {
        j["name"]
        for jid, j in doc["jobs"].items()
        if jid != "dependency-review"
        and isinstance(j, dict)
        and "name" in j
        and not j.get("continue-on-error", False)
    }
    assert job_names, "ci.yml has no jobs with `name:` fields"

    # Each external required check must be a real job AND its workflow must run on
    # every PR (no `paths:` filter), else it would block PRs by never reporting.
    for check, wf_path in EXTERNAL_REQUIRED_CONTEXTS.items():
        wf = REPO_ROOT / wf_path
        assert wf.exists(), f"EXTERNAL_REQUIRED_CONTEXTS workflow missing: {wf_path}"
        wf_doc = yaml.safe_load(wf.read_text())
        wf_jobs = {j.get("name") for j in (wf_doc.get("jobs") or {}).values() if isinstance(j, dict)}
        assert check in wf_jobs, f"'{check}' is not a job name in {wf_path}"
        # PyYAML parses the `on:` key as the boolean True, so accept either form.
        on = wf_doc.get("on", wf_doc.get(True, {})) or {}
        pr = (on.get("pull_request") if isinstance(on, dict) else None) or {}
        assert "paths" not in pr, (
            f"{wf_path} is a required check but its pull_request trigger has a "
            f"`paths:` filter — it must run on every PR or it will block PRs that "
            f"don't touch those paths."
        )

    expected = job_names | set(EXTERNAL_REQUIRED_CONTEXTS)

    script_text = script.read_text()
    context_re = re.compile(r"contexts\]\[\]=([^\"\\\n]+?)\"")
    contexts = set(context_re.findall(script_text))
    assert contexts, "branch_protection.sh has no contexts[][] entries"

    missing_in_script = expected - contexts
    extra_in_script = contexts - expected
    assert not missing_in_script and not extra_in_script, (
        f"branch_protection.sh contexts drift from required check names.\n"
        f"  required but missing from script: {sorted(missing_in_script)}\n"
        f"  in script but not a required check: {sorted(extra_in_script)}"
    )


def test_dependabot_config_present_and_valid():
    cfg = REPO_ROOT / ".github" / "dependabot.yml"
    assert cfg.exists(), f"{cfg} missing"
    with cfg.open() as fh:
        doc = yaml.safe_load(fh)
    assert doc.get("version") == 2
    ecosystems = {u["package-ecosystem"] for u in doc["updates"]}
    assert {"github-actions", "pip", "gomod"} <= ecosystems, ecosystems


if __name__ == "__main__":
    import sys

    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    rc = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except AssertionError as e:
            rc = 1
            print(f"FAIL {t.__name__}: {e}")
    sys.exit(rc)
