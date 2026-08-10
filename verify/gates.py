#!/usr/bin/env python3
"""correctness-kit / gates.py — the deterministic gate runner.

Single-file, stdlib-only. Implements the "correctness-first pipeline" from
PRACTICAL-GUIDE.md (gates G0-G2 and the golden battery), plus ledger,
model-pin stamping, and regression-battery triage.

Usage:
  python3 verify/gates.py init                # create config, battery, ledger
  python3 verify/gates.py run                 # run all gates (exit 0 = pass)
  python3 verify/gates.py run --pre-commit    # staged-change aware, for git hooks
  python3 verify/gates.py battery-add NAME 'command' EXIT   # add a regression trap
  python3 verify/gates.py review FILE...      # G3: independent content-quality review
  python3 verify/gates.py ledger              # show recent ledger lines

Design rules (see llm-reframing/03, 05, 08, 11):
  * Gates are deterministic and non-LLM: they share no prior with the
    generator, so they cannot be gamed by it.
  * Every failure becomes permanent memory: `battery-add` turns any failure
    into a fixture so the same class cannot regress silently.
  * Correctness over speed: the runner is allowed to take its time; it is
    never allowed to pass a wrong artifact. Fail closed.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

DEFAULT_CONFIG = {
    "battery_dir": "verify/golden_battery",
    "ledger_path": "verify/ledger.jsonl",
    "stamp_path": ".opencode/gates-passed.json",
    "model_pins": ".opencode/model-pins.json",
    "require_derivation_log": True,
    "derivation_log_path": "DERIVATION.md",
    "source_exts": [".py", ".ts", ".js", ".go", ".rs", ".sh"],
    "fixture_timeout_s": 120,
}


def _load_config(root: Path) -> dict[str, Any]:
    cfg = dict(DEFAULT_CONFIG)
    p = root / "verify" / "config.json"
    if p.exists():
        try:
            cfg.update(json.loads(p.read_text()))
        except Exception as exc:  # fail closed on malformed config
            print(f"GATE ERROR: verify/config.json unreadable: {exc}")
            sys.exit(1)
    return cfg


def _git(root: Path, *args: str) -> str | None:
    try:
        out = subprocess.run(
            ["git", *args],
            cwd=root, capture_output=True, text=True, timeout=30,
        )
        if out.returncode != 0:
            return None
        return out.stdout.strip()
    except Exception:
        return None


def _model_pin(root: Path, cfg: dict[str, Any]) -> dict[str, str]:
    p = root / cfg["model_pins"]
    if not p.exists():
        print(f"WARN: no model pin at {cfg['model_pins']} — set it so ledger "
              f"entries are attributable to a model/version (churn-aware).")
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def _derivation_log_ok(root: Path, cfg: dict[str, Any], staged: list[str]) -> bool:
    if not cfg.get("require_derivation_log"):
        return True
    # Only require the log when a real source change is staged.
    if not any(s.endswith(tuple(cfg["source_exts"])) for s in staged):
        return True
    candidates = [root / cfg["derivation_log_path"],
                  root / ".opencode" / "derivations" / "latest.md"]
    return any(c.exists() for c in candidates)


def _load_fixtures(root: Path, cfg: dict[str, Any]) -> list[dict[str, Any]]:
    fixtures: list[dict[str, Any]] = []
    battery = root / cfg["battery_dir"]
    if not battery.is_dir():
        return fixtures
    for path in sorted(battery.glob("*.json")):
        try:
            data = json.loads(path.read_text())
        except Exception as exc:
            fixtures.append({"name": f"UNREADABLE:{path.name}", "command": "exit 1",
                             "expect_exit": 0, "unreadable": str(exc)})
            continue
        items = data if isinstance(data, list) else [data]
        for it in items:
            it = dict(it)
            it.setdefault("name", path.stem)
            it.setdefault("kind", "known_good")
            # known_good: command must exit 0. known_bad: the bad thing must
            # still be absent (command must exit non-zero, e.g. grep no-match).
            it.setdefault("expect_exit", 0 if it["kind"] == "known_good" else 1)
            it["file"] = path.name
            fixtures.append(it)
    return fixtures


def _run_fixture(root: Path, f: dict[str, Any], timeout: int) -> tuple[bool, str]:
    cmd = f.get("command", "")
    if not cmd:
        return False, "fixture has no command"
    try:
        proc = subprocess.run(
            shlex.split(cmd), cwd=root, capture_output=True, text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"timed out after {timeout}s"
    except Exception as exc:
        return False, f"could not run: {exc}"
    expected = int(f.get("expect_exit", 0))
    ok = proc.returncode == expected
    if ok and f.get("expect_stdout_contains"):
        ok = f["expect_stdout_contains"] in proc.stdout
        if not ok:
            return False, f"stdout did not contain {f['expect_stdout_contains']!r}"
    detail = ""
    if not ok:
        tail = (proc.stdout + proc.stderr).strip().splitlines()[-6:]
        detail = "; ".join(tail)
    return ok, detail


def cmd_init(root: Path, _args) -> int:
    (root / "verify" / "golden_battery").mkdir(parents=True, exist_ok=True)
    (root / ".opencode").mkdir(parents=True, exist_ok=True)
    cfgp = root / "verify" / "config.json"
    if not cfgp.exists():
        cfgp.write_text(json.dumps(DEFAULT_CONFIG, indent=2) + "\n")
    ledger = root / DEFAULT_CONFIG["ledger_path"]
    if not ledger.exists():
        ledger.write_text("")
    pin = root / ".opencode" / "model-pins.json"
    if not pin.exists():
        pin.write_text(json.dumps({
            "model": "ollama/deepseek-r1:14b",
            "version": "pin-your-exact-model-version-here",
            "note": "Fleet churn: never leave this unpinned. Every artifact is "
                    "attributed to (model, version).",
        }, indent=2) + "\n")
    print(f"initialised kit in {root}")
    print("  next: add fixtures to verify/golden_battery/*.json, then")
    print("  run:  python3 verify/gates.py run")
    return 0


def cmd_battery_add(root: Path, args) -> int:
    if not args.name or not args.command:
        print("usage: gates.py battery-add NAME 'command' EXIT")
        return 2
    fixture = {"name": args.name, "kind": "known_bad", "command": args.command,
               "expect_exit": int(args.exit_code)}
    battery = root / DEFAULT_CONFIG["battery_dir"]
    battery.mkdir(parents=True, exist_ok=True)
    target = battery / f"{args.name.replace(' ', '_')}.json"
    target.write_text(json.dumps(fixture, indent=2) + "\n")
    print(f"added regression trap: {target} (expect_exit={args.exit_code})")
    return 0


def cmd_ledger(root: Path, _args) -> int:
    ledger = root / DEFAULT_CONFIG["ledger_path"]
    if not ledger.exists():
        print("no ledger yet")
        return 0
    for line in ledger.read_text().splitlines()[-20:]:
        try:
            rec = json.loads(line)
            print(f"{rec.get('ts','?')} {rec.get('outcome','?'):4s} "
                  f"fixtures={rec.get('fixtures_total','?'):3d} "
                  f"failures={rec.get('failures')} model={rec.get('model','-')}")
        except Exception:
            print(line)
    return 0


def cmd_review(root: Path, args) -> int:
    """G3 rung: independent content-quality review (delegates to the harness).

    Presence is enforced separately by the `quality_review_required` battery
    fixture (fail closed). The verdict here is advisory until the reviewer has
    a calibration record (fail open) — see verify/checks/check_quality.py.
    """
    cmd = [sys.executable, "verify/checks/check_quality.py", "review"]
    cmd += args.paths
    if args.dry_run:
        cmd.append("--dry-run")
    try:
        proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True,
                              timeout=660)
    except subprocess.TimeoutExpired:
        print("quality review timed out after 660s")
        return 1
    except Exception as exc:
        print(f"quality review could not run: {exc}")
        return 1
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="")
    return proc.returncode


def cmd_run(root: Path, args) -> int:
    cfg = _load_config(root)
    pin = _model_pin(root, cfg)
    started = time.time()

    # staged files (git hook context) or full tree (CI / interactive)
    staged: list[str] = []
    if args.pre_commit:
        name_only = _git(root, "diff", "--cached", "--name-only")
        staged = name_only.splitlines() if name_only else []

    failures: list[dict[str, str]] = []
    skipped = 0
    fixtures = _load_fixtures(root, cfg)
    for f in fixtures:
        if f.get("skip"):
            skipped += 1
            continue
        ok, detail = _run_fixture(root, f, int(cfg["fixture_timeout_s"]))
        mark = "PASS" if ok else "FAIL"
        print(f"[{mark}] {f.get('name','?')}  (expect_exit={f.get('expect_exit')})")
        if not ok:
            failures.append({"name": f.get("name", "?"), "file": f.get("file", "?"),
                             "reason": detail})

    # derivation-log gate (G5)
    log_ok = _derivation_log_ok(root, cfg, staged)
    print(f"[{'PASS' if log_ok else 'FAIL'}] derivation-log requirement "
          f"(staged sources: {len(staged)})")
    if not log_ok:
        failures.append({"name": "derivation-log", "file": cfg["derivation_log_path"],
                         "reason": "missing or outdated; create DERIVATION.md"})

    head = _git(root, "rev-parse", "HEAD") or "-"
    duration = round(time.time() - started, 2)
    record = {
        "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "outcome": "FAIL" if failures else "PASS",
        "fixtures_total": len(fixtures),
        "skipped": skipped,
        "failures": failures,
        "git_head": head,
        "model": pin.get("model", "-"),
        "model_version": pin.get("version", "-"),
        "pre_commit": bool(args.pre_commit),
        "duration_s": duration,
    }

    # persist ledger + stamp regardless of outcome (ledger needs failures too)
    ledger = root / cfg["ledger_path"]
    try:
        with ledger.open("a") as fh:
            fh.write(json.dumps(record) + "\n")
    except Exception as exc:
        print(f"WARN: ledger write failed: {exc}")

    stamp = root / cfg["stamp_path"]
    try:
        stamp.parent.mkdir(parents=True, exist_ok=True)
        stamp.write_text(json.dumps(record, indent=2))
    except Exception as exc:
        print(f"WARN: stamp write failed: {exc}")

    print(f"\n{len(fixtures) - skipped} fixtures, {len(failures)} failures, "
          f"{duration}s, model={pin.get('model', '-')}")
    if failures:
        print("\nFAILED GATES (fix these, add regression traps, then re-run):")
        for f in failures:
            print(f"  - {f['name']} [{f['file']}]: {f['reason']}")
        return 1
    print("GATES PASS — safe to commit.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="gates.py")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run")
    p_run.add_argument("--pre-commit", action="store_true",
                       help="staged-change aware; run from git pre-commit hook")
    p_run.set_defaults(func=cmd_run)

    p_init = sub.add_parser("init")
    p_init.set_defaults(func=cmd_init)

    p_add = sub.add_parser("battery-add")
    p_add.add_argument("name")
    p_add.add_argument("command")
    p_add.add_argument("exit_code", default="1", nargs="?")
    p_add.set_defaults(func=cmd_battery_add)

    p_led = sub.add_parser("ledger")
    p_led.set_defaults(func=cmd_ledger)

    p_rev = sub.add_parser("review")
    p_rev.add_argument("paths", nargs="+")
    p_rev.add_argument("--dry-run", action="store_true")
    p_rev.set_defaults(func=cmd_review)

    args = parser.parse_args()
    root = Path.cwd()
    return args.func(root, args)


if __name__ == "__main__":
    sys.exit(main())
