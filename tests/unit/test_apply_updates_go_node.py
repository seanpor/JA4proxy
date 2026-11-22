"""Unit tests for scripts/apply_updates_go_node.py."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts import apply_updates_go_node as mod


class _FakeHTTPResponse:
    """Minimal context-manager mock for urllib.request.urlopen."""

    def __init__(self, payload: dict) -> None:
        self._body = json.dumps(payload).encode("utf-8")

    def read(self, amt: int | None = None) -> bytes:
        return self._body if amt is None else self._body[:amt]

    def __enter__(self) -> _FakeHTTPResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


class TestVersionParsing:
    """Version spec parsing and npm registry response handling."""

    @pytest.mark.parametrize(
        ("spec", "expected_prefix", "expected_ver"),
        [
            ("^1.14.0", "^", "1.14.0"),
            ("~2.3.4", "~", "2.3.4"),
            (">=1.0.0", ">=", "1.0.0"),
            ("1.14.0", "", "1.14.0"),
        ],
    )
    def test_parse_version_spec(
        self, spec: str, expected_prefix: str, expected_ver: str
    ) -> None:
        prefix, ver = mod._parse_version_spec(spec)
        assert prefix == expected_prefix
        assert ver == expected_ver

    def test_fetch_npm_latest_version_parses_semver(self) -> None:
        requested_urls: list[str] = []

        def fake_urlopen(req: object, timeout: int = 15) -> _FakeHTTPResponse:
            requested_urls.append(getattr(req, "full_url", str(req)))
            return _FakeHTTPResponse({"name": "sql.js", "version": "1.17.0"})

        with patch.object(mod.urllib.request, "urlopen", side_effect=fake_urlopen):
            version = mod._fetch_npm_latest_version("sql.js")

        assert version == "1.17.0"
        assert requested_urls == ["https://registry.npmjs.org/sql.js/latest"]

    def test_fetch_npm_latest_version_rejects_invalid_version(self) -> None:
        with (
            patch.object(
                mod.urllib.request,
                "urlopen",
                return_value=_FakeHTTPResponse({"version": "not-a-semver; rm -rf /"}),
            ),
            pytest.raises(ValueError, match="Invalid npm version"),
        ):
            mod._fetch_npm_latest_version("sql.js")


class TestGoModuleUpdates:
    """Go dependency upgrade commands, GOROOT handling, and rollback on failure."""

    def test_update_go_modules_invokes_expected_commands(self, tmp_path: Path) -> None:
        mod_a = tmp_path / "root"
        mod_b = tmp_path / "deploy" / "terraform-provider"
        mod_a.mkdir(parents=True)
        mod_b.mkdir(parents=True)
        (mod_a / "go.mod").write_text("module example.com/a\n")
        (mod_a / "go.sum").write_text("sum-a\n")
        (mod_b / "go.mod").write_text("module example.com/b\n")
        (mod_b / "go.sum").write_text("sum-b\n")

        calls: list[tuple[list[str], Path | None, dict[str, str] | None]] = []

        def fake_run(
            cmd: list[str],
            cwd: Path | None = None,
            env: dict[str, str] | None = None,
            timeout: int = 120,
        ) -> tuple[str, str, int]:
            calls.append((cmd, cwd, env))
            return ("", "", 0)

        snap_dir = tmp_path / "snap-go"
        (snap_dir / "bin").mkdir(parents=True)
        snap_go_bin = snap_dir / "bin" / "go"
        snap_go_bin.write_text("#!/bin/sh\n")

        with (
            patch.object(mod, "_SNAP_GOROOT", snap_dir),
            patch.object(mod, "_run", side_effect=fake_run),
        ):
            rc = mod.update_go_modules([mod_a, mod_b])

        assert rc == 0
        assert len(calls) == 6
        expected_cmds = [
            ([str(snap_go_bin), "get", "-u", "./..."], mod_a),
            ([str(snap_go_bin), "mod", "tidy"], mod_a),
            ([str(snap_go_bin), "mod", "verify"], mod_a),
            ([str(snap_go_bin), "get", "-u", "./..."], mod_b),
            ([str(snap_go_bin), "mod", "tidy"], mod_b),
            ([str(snap_go_bin), "mod", "verify"], mod_b),
        ]
        for (cmd, cwd, env), (exp_cmd, exp_cwd) in zip(calls, expected_cmds, strict=True):
            assert cmd == exp_cmd
            assert cwd == exp_cwd
            assert env is not None
            assert env["GOROOT"] == str(snap_dir)

    def test_update_go_modules_rolls_back_on_failure(self, tmp_path: Path) -> None:
        orig_mod = "module example.com/a\ngo 1.27\n"
        orig_sum = "original-checksum\n"
        (tmp_path / "go.mod").write_text(orig_mod)
        (tmp_path / "go.sum").write_text(orig_sum)

        def fake_run(
            cmd: list[str],
            cwd: Path | None = None,
            env: dict[str, str] | None = None,
            timeout: int = 120,
        ) -> tuple[str, str, int]:
            if cmd[1:3] == ["get", "-u"]:
                (tmp_path / "go.mod").write_text("CORRUPTED\n")
                (tmp_path / "go.sum").write_text("CORRUPTED\n")
                return ("", "", 0)
            if cmd[1:3] == ["mod", "tidy"]:
                return ("", "tidy failed", 1)
            return ("", "", 0)

        with patch.object(mod, "_run", side_effect=fake_run):
            rc = mod.update_go_modules([tmp_path])

        assert rc == 1
        assert (tmp_path / "go.mod").read_text() == orig_mod
        assert (tmp_path / "go.sum").read_text() == orig_sum

    def test_update_go_modules_rolls_back_all_modules_on_second_module_failure(
        self, tmp_path: Path
    ) -> None:
        mod_a = tmp_path / "root"
        mod_b = tmp_path / "provider"
        mod_a.mkdir()
        mod_b.mkdir()
        (mod_a / "go.mod").write_text("orig-a-mod\n")
        (mod_a / "go.sum").write_text("orig-a-sum\n")
        (mod_b / "go.mod").write_text("orig-b-mod\n")
        (mod_b / "go.sum").write_text("orig-b-sum\n")

        def fake_run(
            cmd: list[str],
            cwd: Path | None = None,
            env: dict[str, str] | None = None,
            timeout: int = 120,
        ) -> tuple[str, str, int]:
            if cwd == mod_a and cmd[1:3] == ["get", "-u"]:
                (mod_a / "go.mod").write_text("updated-a-mod\n")
                (mod_a / "go.sum").write_text("updated-a-sum\n")
                return ("", "", 0)
            if cwd == mod_b and cmd[1:3] == ["mod", "verify"]:
                return ("", "checksum mismatch", 1)
            return ("", "", 0)

        with patch.object(mod, "_run", side_effect=fake_run):
            rc = mod.update_go_modules([mod_a, mod_b])

        assert rc == 1
        assert (mod_a / "go.mod").read_text() == "orig-a-mod\n"
        assert (mod_a / "go.sum").read_text() == "orig-a-sum\n"
        assert (mod_b / "go.mod").read_text() == "orig-b-mod\n"
        assert (mod_b / "go.sum").read_text() == "orig-b-sum\n"

    def test_update_go_modules_dry_run_makes_no_changes(self, tmp_path: Path) -> None:
        (tmp_path / "go.mod").write_text("module example.com/a\n")
        with patch.object(mod, "_run") as mock_run:
            rc = mod.update_go_modules([tmp_path], dry_run=True)

        assert rc == 0
        mock_run.assert_not_called()


class TestNodeSqlJsUpdates:
    """Node / sql.js dependency updates, lockfile regeneration, and rollback."""

    def test_update_node_updates_package_json_and_runs_npm_lockfile(
        self, tmp_path: Path
    ) -> None:
        pkg_json = tmp_path / "package.json"
        lock_json = tmp_path / "package-lock.json"
        pkg_json.write_text(json.dumps({"dependencies": {"sql.js": "^1.14.0"}}, indent=2) + "\n")
        lock_json.write_text(json.dumps({"name": "test", "lockfileVersion": 3}) + "\n")

        npm_calls: list[list[str]] = []

        def fake_run(
            cmd: list[str],
            cwd: Path | None = None,
            env: dict[str, str] | None = None,
            timeout: int = 120,
        ) -> tuple[str, str, int]:
            npm_calls.append(cmd)
            return ("", "", 0)

        with (
            patch.object(mod, "_fetch_npm_latest_version", return_value="1.17.0"),
            patch.object(mod, "_run", side_effect=fake_run),
        ):
            rc = mod.update_node_packages(repo_root=tmp_path)

        assert rc == 0
        updated = json.loads(pkg_json.read_text())
        assert updated["dependencies"]["sql.js"] == "^1.17.0"
        assert npm_calls == [["npm", "install", "--package-lock-only", "--ignore-scripts"]]

    def test_update_node_rolls_back_on_npm_failure(self, tmp_path: Path) -> None:
        pkg_json = tmp_path / "package.json"
        lock_json = tmp_path / "package-lock.json"
        orig_pkg = json.dumps({"dependencies": {"sql.js": "^1.14.0"}}, indent=2) + "\n"
        orig_lock = json.dumps({"name": "test", "lockfileVersion": 3}) + "\n"
        pkg_json.write_text(orig_pkg)
        lock_json.write_text(orig_lock)

        with (
            patch.object(mod, "_fetch_npm_latest_version", return_value="1.17.0"),
            patch.object(mod, "_run", return_value=("", "npm ERESOLVE", 1)),
        ):
            rc = mod.update_node_packages(repo_root=tmp_path)

        assert rc == 1
        assert pkg_json.read_text() == orig_pkg
        assert lock_json.read_text() == orig_lock

    def test_update_node_dry_run_preserves_files(self, tmp_path: Path) -> None:
        pkg_json = tmp_path / "package.json"
        orig_pkg = json.dumps({"dependencies": {"sql.js": "^1.14.0"}}, indent=2) + "\n"
        pkg_json.write_text(orig_pkg)

        with (
            patch.object(mod, "_fetch_npm_latest_version", return_value="1.17.0"),
            patch.object(mod, "_run") as mock_run,
        ):
            rc = mod.update_node_packages(repo_root=tmp_path, dry_run=True)

        assert rc == 0
        assert pkg_json.read_text() == orig_pkg
        mock_run.assert_not_called()

    def test_update_node_runs_scan_js_when_requested(self, tmp_path: Path) -> None:
        pkg_json = tmp_path / "package.json"
        pkg_json.write_text(json.dumps({"dependencies": {"sql.js": "^1.14.0"}}, indent=2) + "\n")
        calls: list[list[str]] = []

        def fake_run(
            cmd: list[str],
            cwd: Path | None = None,
            env: dict[str, str] | None = None,
            timeout: int = 120,
        ) -> tuple[str, str, int]:
            calls.append(cmd)
            return ("", "", 0)

        with (
            patch.object(mod, "_fetch_npm_latest_version", return_value="1.17.0"),
            patch.object(mod, "_run", side_effect=fake_run),
        ):
            rc = mod.update_node_packages(repo_root=tmp_path, run_scan=True)

        assert rc == 0
        assert calls[0] == ["npm", "install", "--package-lock-only", "--ignore-scripts"]
        assert calls[1] == [
            "npx",
            "--yes",
            "--ignore-scripts",
            "retire@5.7.0",
            "--path",
            "management/static",
        ]

    def test_update_node_syncs_vendor_sqljs_and_rolls_back_on_scan_failure(
        self, tmp_path: Path
    ) -> None:
        pkg_json = tmp_path / "package.json"
        orig_pkg = json.dumps({"dependencies": {"sql.js": "^1.14.0"}}, indent=2) + "\n"
        pkg_json.write_text(orig_pkg)

        vendor_dir = tmp_path / "management" / "static" / "vendor" / "sql.js"
        vendor_dir.mkdir(parents=True)
        (vendor_dir / "sql-wasm.js").write_bytes(b"old-js")
        checksums = tmp_path / "management" / "static" / "vendor" / "CHECKSUMS.txt"
        orig_checksums = "deadbeef  htmx.min.js\n"
        checksums.write_text(orig_checksums)

        dist_dir = tmp_path / "node_modules" / "sql.js" / "dist"
        dist_dir.mkdir(parents=True)
        (dist_dir / "sql-wasm.js").write_bytes(b"new-js")
        (dist_dir / "sql-wasm.wasm").write_bytes(b"new-wasm")

        def fake_run(
            cmd: list[str],
            cwd: Path | None = None,
            env: dict[str, str] | None = None,
            timeout: int = 120,
        ) -> tuple[str, str, int]:
            if cmd[0] == "npm":
                return ("", "", 0)
            return ("", "retire CVE found", 13)

        with (
            patch.object(mod, "_fetch_npm_latest_version", return_value="1.17.0"),
            patch.object(mod, "_run", side_effect=fake_run),
        ):
            rc = mod.update_node_packages(repo_root=tmp_path, run_scan=True)

        assert rc == 1
        assert pkg_json.read_text() == orig_pkg
        assert (vendor_dir / "sql-wasm.js").read_bytes() == b"old-js"
        assert not (vendor_dir / "sql-wasm.wasm").exists()
        assert checksums.read_text() == orig_checksums


class TestCliMain:
    """CLI flag routing for --go, --node, --dry-run."""

    def test_main_routes_go_only(self) -> None:
        with (
            patch.object(mod, "update_go_modules", return_value=0) as mock_go,
            patch.object(mod, "update_node_packages", return_value=0) as mock_node,
        ):
            rc = mod.main(["--go", "--dry-run"])

        assert rc == 0
        mock_go.assert_called_once_with(dry_run=True)
        mock_node.assert_not_called()

    def test_main_routes_node_only(self) -> None:
        with (
            patch.object(mod, "update_go_modules", return_value=0) as mock_go,
            patch.object(mod, "update_node_packages", return_value=0) as mock_node,
        ):
            rc = mod.main(["--node", "--scan-js"])

        assert rc == 0
        mock_go.assert_not_called()
        mock_node.assert_called_once_with(dry_run=False, run_scan=True)
