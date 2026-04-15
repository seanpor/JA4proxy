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
    "actions/checkout": {
        "v4.2.2": "11bd71901bbe5b1630ceea73d27597364c9af683",
        "v6.0.2": "de0fac2e4500dabe0009e67214ff5f5447ce83dd",
    },
    "actions/setup-go": {
        "v5.2.0": "3041bf56c941b39c61721a86cd11f3bb1338122a",
        "v5.6.0": "40f1582b2485089dde7abd97c1529aa768e1baff",
        "v6.4.0": "4a3601121dd01d1626a1e23e37211e3254c1c06c",
    },
    "actions/setup-python": {
        "v5.0.0": "0a5c61591373683505ea898e09a3ea4f39ef2b9c",
        "v6.2.0": "a309ff8b426b58ec0e2a45f0f869d46889d02405",
    },
    "trufflesecurity/trufflehog": {
        "v3.88.2": "a94d152bf65bebf5baa486d3d4dfee520af2ceed",
        "v3.94.3": "47e7b7cd74f578e1e3145d48f669f22fd1330ca6",
    },
    "returntocorp/semgrep-action": {
        "v1": "713efdd345f3035192eaa63f56867b88e63e4e5d",
    },
    "actions/dependency-review-action": {
        "v4.5.0": "3b139cfc5fae8b618d3eae3675e383bb1769c019",
        "v4.9.0": "2031cfc080254a8a887f58cffee85186f0e49e48",
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
    },
    "docker/setup-qemu-action": {
        "v3.2.0": "49b3bc8e6bdd4a60e6116a5414239cba5943d3cf",
        "v4.0.0": "ce360397dd3f832beb865e1373c09c0e9f86d70a",
    },
    "docker/setup-buildx-action": {
        "v3.8.0": "6524bf65af31da8d45b59e8c27de4bd072b392f5",
        "v4.0.0": "4d04d5d9486b7bd6fa91e7baf45bbb4f8b9deedd",
    },
    "docker/login-action": {
        "v3.3.0": "9780b0c442fbb1117ed29e0efdff1e18412f7567",
        "v4.1.0": "4907a6ddec9925e35a0a9e82d7399ccc52663121",
    },
    "docker/metadata-action": {
        "v5.6.1": "369eb591f429131d6889c46b94e711f089e6ca96",
        "v6.0.0": "030e881283bb7a6894de51c315a6bfe6a94e05cf",
    },
    "docker/build-push-action": {
        "v6.13.0": "ca877d9245402d1537745e0e356eab47c3520991",
        "v7.1.0": "bcafcacb16a39f128d818304e6c9c0c18556b85f",
    },
    # phase-202d — Go proxy image CI workflow (go-proxy-image.yml)
    "sigstore/cosign-installer": {
        "v3.7.0": "dc72c7d5c4d10cd6bcb8cf6e3fd625a9e5e537da",
    },
    "anchore/sbom-action": {
        "v0.17.8": "55dc4ee22412511ee8c3142cbea40418e6cec693",
    },
    "aquasecurity/trivy-action": {
        "v0.29.0": "18f2510ee396bbf400402947b394f2dd8c87dbb0",
    },
    # phase-202a — SLSA reusable workflow, SHA-pinned per ADR-202a Path A.
    # Full path-keyed because the uses: reference includes `.github/workflows/...yml`.
    "slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml": {
        "v2.1.0": "f7dd8c54c2067bafc12ca7a55595d5ee9b75204a",
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
    assert not failures, (
        "Unpinned uses: entries found (must be 40-char SHA):\n  "
        + "\n  ".join(failures)
    )


def test_every_workflow_has_top_level_permissions():
    failures: list[str] = []
    for f in _workflow_files():
        with f.open() as fh:
            doc = yaml.safe_load(fh)
        if not isinstance(doc, dict) or "permissions" not in doc:
            failures.append(f.name)
    assert not failures, (
        "Workflows missing top-level permissions block:\n  "
        + "\n  ".join(failures)
    )


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


def test_branch_protection_contexts_match_ci_job_names():
    """branch_protection.sh contexts must equal the set of `name:` fields
    on required jobs in ci.yml. A drift here silently turns branch
    protection into a no-op gate (required check that never fires =>
    PR can merge regardless). Highest silent-failure risk in Phase 61.
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

    script_text = script.read_text()
    context_re = re.compile(r"contexts\]\[\]=([^\"\\\n]+?)\"")
    contexts = set(context_re.findall(script_text))
    assert contexts, "branch_protection.sh has no contexts[][] entries"

    missing_in_script = job_names - contexts
    extra_in_script = contexts - job_names
    assert not missing_in_script and not extra_in_script, (
        f"branch_protection.sh contexts drift from ci.yml job names.\n"
        f"  in ci.yml but missing from script: {sorted(missing_in_script)}\n"
        f"  in script but missing from ci.yml: {sorted(extra_in_script)}"
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
