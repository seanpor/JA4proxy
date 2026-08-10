#!/usr/bin/env python3
"""check_quality.py — the content-quality gate (G3 rung).

Content quality has no oracle, so it cannot be a deterministic battery
fixture in the way invariant/link checks are. What CAN be made deterministic
is the REVIEW HARNESS: the machine enforces schema, threshold, correlation,
recency and calibration; only the SCORING is the reviewer model's.

Design (from llm-reframing/06, 07, 15 — PRACTICAL-GUIDE.md §5 G3):
  * Presence is a HARD requirement: a genuine, recent, independent review
    artifact must exist for a load-bearing change. Fail closed.
  * Verdict is CALIBRATED, not trusted: until the reviewer model has a
    calibration record (>= calibration_min_n adjudications) with acceptable
    precision, a below-threshold verdict is ADVISORY (exit 0 + loud warning),
    not a hard block. Fail open on weak gates.
  * Independence is enforced: author_family must differ from reviewer_family.
    Same-family review is correlated verification (the three-witness
    illusion) and is rejected.
  * Every review is recorded as DATA in the ledger and as an artifact in
    verify/reviews/, so it feeds the calibration loop, not the bin.

Usage:
  python3 verify/checks/check_quality.py review <paths...> [--dry-run]
  python3 verify/checks/check_quality.py validate <artifact.json>
  python3 verify/checks/check_quality.py validate --required <reviews_dir>
  python3 verify/checks/check_quality.py calibrate <adjudications.json>

Exit 0 = pass / advisory-ok; 1 = hard fail.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
import unicodedata
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]

DIMENSIONS = ("soundness", "coverage", "consistency", "risk_awareness",
              "actionability")


def _norm_family(value: str | None) -> str:
    """Canonical family identity, robust against Unicode spoofing.

    Pipeline: NFKC-normalize (collapses fullwidth/homoglyph forms to ASCII),
    drop every character in Unicode categories C (control/format/private/
    surrogate/unassigned) and Z (all separators incl. NBSP and zero-width
    spaces), then casefold. The result is a canonical skeleton so spoofed
    encodings of the same family — 'ＤＥＥＰＳＥＥＫ－Ｒ１', 'deepseek\u200br1',
    'deepseek\u00a0r1' — all collapse to 'deepseek-r1'. Empty string means
    'no family' and validation fails closed."""
    s = unicodedata.normalize("NFKC", str(value or ""))
    out = [ch for ch in s if unicodedata.category(ch)[0] not in "CZ"]
    return "".join(out).casefold()

RUBRIC = """You are an INDEPENDENT reviewer. You have only the artifact under
review and the problem it was meant to solve. You do NOT see the author's
tests, design notes, or prior reviews. Judge the artifact on its own.

Score each dimension 0-5 and justify each score in concrete terms. Refer to
specific passages. Do NOT pad. If a dimension cannot be scored from the
artifact alone, give it the lowest plausible score and say why.

Rubric:
  soundness        — are the claims supported? any false, unsupported, or
                     self-serving statements?
  coverage         — does it address the stated problem fully? major gaps?
  consistency      — internally consistent? contradictions or self-undermining?
  risk_awareness   — how well does it SURFACE its own failure modes and
                     mitigation? (score the surfacing, not the risk level)
  actionability    — specific enough to act on? concrete, no hand-waving?

Return ONLY JSON with this exact schema:
{"dimensions": {"soundness": 0, "coverage": 0, "consistency": 0,
  "risk_awareness": 0, "actionability": 0},
 "justifications": {"soundness": "...", "coverage": "...", "consistency":
  "...", "risk_awareness": "...", "actionability": "..."},
 "top_failure_modes": ["...", "..."]}
"""


def _load_config(root: Path) -> dict[str, Any]:
    cfg: dict[str, Any] = {}
    p = root / "verify" / "config.json"
    if p.exists():
        try:
            cfg = json.loads(p.read_text())
        except Exception:
            cfg = {}
    return cfg


def _load_pins(root: Path) -> dict[str, Any]:
    p = root / ".opencode" / "model-pins.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def _bounded_chat_url(url: str) -> str:
    """Validate the Ollama base URL before it reaches urllib.

    The URL comes from verify/config.json — a repo-controlled file, but a
    tampered copy must not be able to make the gate's urllib call read files
    (file:// scheme) or phone an arbitrary host. Only http(s) to a loopback
    host is acceptable.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"ollama_url must be http(s), got {parsed.scheme!r}")
    host = parsed.hostname or ""
    if not (host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")):
        raise ValueError(f"ollama_url must point at loopback, got {host!r}")
    return url


def _ollama_chat(url: str, model: str, prompt: str, timeout: int) -> str:
    # Pins use opencode's provider-prefixed form (ollama/name:tag); the raw
    # Ollama API wants the bare model name. Normalize at the API boundary
    # only — attribution keeps the full pin.
    api_model = model.split("ollama/", 1)[-1]
    payload = {
        "model": api_model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.2, "num_ctx": 16384},
    }
    req = urllib.request.Request(
        _bounded_chat_url(url) + "/api/chat",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    # _bounded_chat_url constrains the URL to http(s) loopback, so no file://
    # read or external phone-home is possible.
    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode())
    return data["message"]["content"]


def _extract_json(text: str) -> dict[str, Any]:
    try:
        return json.loads(text)
    except Exception:
        pass
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("reviewer did not return JSON")
    return json.loads(text[start:end + 1])


def _schema_errors(parsed: dict[str, Any], q: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    dims = parsed.get("dimensions")
    justs = parsed.get("justifications")
    modes = parsed.get("top_failure_modes")
    if not isinstance(dims, dict):
        errs.append("missing 'dimensions' object")
    if not isinstance(justs, dict):
        errs.append("missing 'justifications' object")
    if not isinstance(modes, list):
        errs.append("missing 'top_failure_modes' list")
    if errs:
        return errs
    min_len = int(q.get("min_justification_len", 40))
    for d in DIMENSIONS:
        v = dims.get(d)
        if not isinstance(v, int) or not (0 <= v <= 5):
            errs.append(f"dimension {d}: score {v!r} not in 0..5")
        j = justs.get(d)
        if not isinstance(j, str) or not j.strip():
            errs.append(f"dimension {d}: justification missing")
        elif len(j.strip()) < min_len:
            errs.append(f"dimension {d}: justification too thin "
                        f"({len(j.strip())} < {min_len} chars)")
    return errs


def _verdict(dims: dict[str, int], q: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    vals = list(dims.values())
    avg = sum(vals) / len(vals)
    minimum = min(vals)
    detail = {"avg": round(avg, 2), "min": minimum}
    return avg >= q["min_avg"] and minimum >= q["min_dim"], detail


def _latest_artifact(directory: Path, max_age_hours: int) -> Path | None:
    if not directory.is_dir():
        return None
    now = _dt.datetime.now(_dt.timezone.utc)
    best: tuple[_dt.datetime, Path] | None = None
    for p in directory.glob("review-*.json"):
        try:
            mtime = _dt.datetime.fromtimestamp(p.stat().st_mtime, _dt.timezone.utc)
        except Exception:
            continue
        if best is None or mtime > best[0]:
            best = (mtime, p)
    if best is None:
        return None
    age = now - best[0]
    return best[1] if age.total_seconds() <= max_age_hours * 3600 else None


def _load_calibration(root: Path) -> dict[str, Any]:
    p = root / "verify" / "reviews" / "calibration.json"
    if not p.exists():
        return {"adjudications": [], "stats": {"n": 0, "pass_precision": 1.0}}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {"adjudications": [], "stats": {"n": 0, "pass_precision": 1.0}}


def _validate_artifact(root: Path, path: Path, q: dict[str, Any],
                       pins: dict[str, Any]) -> tuple[int, list[str]]:
    try:
        art = json.loads(path.read_text())
    except Exception as exc:
        return 1, [f"unreadable artifact: {exc}"]
    status = art.get("status", "ok")
    if status == "unavailable":
        return 1, ["review could not be produced (reviewer unreachable) — "
                   "the change is not yet quality-gated"]
    schema_errs = _schema_errors(art, q)
    if schema_errs:
        return 1, schema_errs
    reviewer_family = _norm_family(art.get("reviewer_family"))
    author_family = _norm_family(art.get("author_family"))
    if not reviewer_family or not author_family:
        return 1, ["cannot establish independence: review artifact is missing a "
                   f"family (author_family={art.get('author_family')!r}, "
                   f"reviewer_family={art.get('reviewer_family')!r}). Set "
                   "author/reviewer families in .opencode/model-pins.json, "
                   "then re-run `python3 verify/gates.py review <files...>`."]
    if reviewer_family == author_family:
        return 1, ["correlated reviewer: same family as author "
                   f"({author_family}) — this is the three-witness illusion"]
    passed, detail = _verdict(art["dimensions"], q)
    cal = _load_calibration(root)
    stats = cal["stats"]
    calibrated = stats["n"] >= q["calibration_min_n"]
    if not passed:
        if calibrated and stats["pass_precision"] >= q["calibration_min_precision"]:
            return 1, [f"below threshold {detail} and reviewer is calibrated "
                       f"(n={stats['n']}, precision={stats['pass_precision']})"]
        return 0, [f"below threshold {detail} — ADVISORY only (reviewer "
                   f"uncalibrated, n={stats['n']}); record an adjudication to "
                   f"strengthen this gate"]
    return 0, []


def cmd_review(root: Path, args) -> int:
    cfg = _load_config(root)
    q = cfg.get("quality", {})
    pins = _load_pins(root)
    reviewer = pins.get("reviewer", {}).get("model") or q.get("default_reviewer")
    author = pins.get("author", {}).get("model") or "unknown/unknown"
    if not reviewer:
        print("ERROR: no reviewer pin. Add 'reviewer' to "
              ".opencode/model-pins.json")
        return 2
    body = RUBRIC + "\n\nARTIFACT UNDER REVIEW:\n\n"
    for p in args.paths:
        fp = root / p
        if not fp.is_file():
            print(f"ERROR: no such file: {p}")
            return 2
        body += f"===== {p} =====\n{fp.read_text(encoding='utf-8')}\n"
    if args.dry_run:
        print(body)
        return 0
    artifacts = root / q["artifacts_dir"]
    artifacts.mkdir(parents=True, exist_ok=True)
    author_family = _norm_family(pins.get("author", {}).get("family"))
    reviewer_family = _norm_family(pins.get("reviewer", {}).get("family"))
    if not author_family or not reviewer_family:
        print("ERROR: model-pins.json must define distinct, non-empty "
              "author.family and reviewer.family — independence cannot be "
              "established without them.")
        return 2
    if author_family == reviewer_family:
        print("ERROR: author.family and reviewer.family are the same — "
              "this is correlated verification. Use a different-family "
              "reviewer.")
        return 2
    url = q.get("ollama_url", "http://localhost:11434")
    try:
        raw = _ollama_chat(url, reviewer, body, int(q.get("review_timeout_s", 300)))
    except Exception as exc:
        print(f"WARN: reviewer unreachable ({exc}) — writing 'unavailable' "
              f"artifact; the required-gate will block until a real review "
              f"exists.")
        art = {"status": "unavailable", "reviewer": reviewer,
               "reviewer_family": reviewer_family,
               "author_family": author_family,
               "paths": args.paths, "error": str(exc)}
        _write_artifact(artifacts, art, reviewer)
        return 0
    try:
        parsed = _extract_json(raw)
    except Exception as exc:
        print(f"WARN: reviewer returned non-JSON ({exc}) — treating as "
              f"unavailable.")
        art = {"status": "unavailable", "reviewer": reviewer,
               "reviewer_family": reviewer_family,
               "author_family": author_family,
               "paths": args.paths, "error": f"non-JSON: {raw[:200]}"}
        _write_artifact(artifacts, art, reviewer)
        return 0
    art = {
        "status": "ok",
        "reviewer": reviewer,
        "reviewer_family": reviewer_family,
        "reviewer_version": pins.get("reviewer", {}).get("version"),
        "author": author,
        "author_family": author_family,
        "paths": args.paths,
        "dimensions": parsed["dimensions"],
        "justifications": parsed["justifications"],
        "top_failure_modes": parsed.get("top_failure_modes", []),
    }
    code, notes = _validate_artifact(root, _write_artifact(artifacts, art, reviewer),
                                     q, pins)
    passed, detail = _verdict(art["dimensions"], q)
    print(f"quality review by {reviewer}: {'PASS' if passed else 'BELOW THRESHOLD'} "
          f"{detail}")
    for d in DIMENSIONS:
        print(f"  {d:16s} {art['dimensions'][d]}/5  "
              f"{art['justifications'][d][:110]}")
    for n in notes:
        print(f"NOTE: {n}")
    _ledger(root, reviewer, code, notes)
    return code


def _write_artifact(artifacts: Path, art: dict[str, Any], reviewer: str) -> Path:
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    slug = reviewer.replace("/", "_").replace(":", "_")
    target = artifacts / f"review-{stamp}-{slug}.json"
    target.write_text(json.dumps(art, indent=2) + "\n")
    return target


def _ledger(root: Path, reviewer: str, code: int, notes: list[str]) -> None:
    ledger = root / "verify" / "ledger.jsonl"
    try:
        with ledger.open("a") as fh:
            fh.write(json.dumps({
                "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
                "outcome": "PASS" if code == 0 else "FAIL",
                "fixtures_total": 0,
                "failures": [{"name": "quality_review", "reason": n} for n in notes],
                "model": reviewer,
                "gate": "quality_review",
            }) + "\n")
    except Exception as exc:
        print(f"WARN: ledger write failed: {exc}")


def cmd_validate(root: Path, args) -> int:
    cfg = _load_config(root)
    q = cfg.get("quality", {})
    pins = _load_pins(root)
    if args.required:
        directory = root / args.required
        path = _latest_artifact(directory, int(q.get("max_age_hours", 48)))
        if path is None:
            print(f"FAIL: no genuine review artifact newer than "
                  f"{q.get('max_age_hours', 48)}h in {directory}. "
                  f"Run: python3 verify/gates.py review <files...>")
            return 1
        print(f"check_quality: found review artifact {path.name}")
    else:
        path = root / args.artifact
    code, notes = _validate_artifact(root, path, q, pins)
    if notes:
        for n in notes:
            print(f"  - {n}")
    return code


def _derive_verdict(art: dict[str, Any], q: dict[str, Any]) -> str:
    if art.get("status") != "ok" or "dimensions" not in art:
        return "unavailable"
    passed, _ = _verdict(art["dimensions"], q)
    return "pass" if passed else "fail"


def _adjudication_errors(root: Path, q: dict[str, Any],
                         adj: dict[str, Any]) -> list[str]:
    """Authenticate an adjudication: it must reference a real, completed review
    artifact by the same reviewer. Adjudication is a HUMAN act — the point is
    traceability, not preventing humans from judging."""
    errs: list[str] = []
    hv = adj.get("human_verdict")
    if hv not in ("accept", "reject"):
        errs.append(f"human_verdict must be 'accept' or 'reject', got {hv!r}")
    art_name = adj.get("artifact")
    if not art_name:
        errs.append("adjudication missing 'artifact' — must reference a review "
                    f"artifact in {q['artifacts_dir']}/")
        return errs
    apath = root / q["artifacts_dir"] / art_name
    if not apath.is_file():
        errs.append(f"artifact not found: {q['artifacts_dir']}/{art_name}")
        return errs
    try:
        art = json.loads(apath.read_text())
    except Exception as exc:
        errs.append(f"artifact unreadable: {exc}")
        return errs
    if adj.get("reviewer") and adj["reviewer"] != art.get("reviewer"):
        errs.append(f"reviewer mismatch: adjudication names {adj['reviewer']!r}, "
                    f"artifact is by {art.get('reviewer')!r}")
    if art.get("status") != "ok":
        errs.append(f"artifact {art_name} is not a completed review "
                    f"(status={art.get('status')!r})")
    return errs


def cmd_calibrate(root: Path, args) -> int:
    cfg = _load_config(root)
    q = cfg.get("quality", {})
    arg = args.adjudications
    if arg.lstrip().startswith(("{", "[")):
        try:
            new_adj = json.loads(arg)
        except Exception as exc:
            print(f"ERROR: cannot parse inline adjudications: {exc}")
            return 2
    else:
        path = root / arg
        try:
            new_adj = json.loads(path.read_text())
        except Exception as exc:
            print(f"ERROR: cannot read {path}: {exc}")
            return 2
    if isinstance(new_adj, dict):
        new_adj = [new_adj]
    cal_dir = root / q["artifacts_dir"]
    cal_dir.mkdir(parents=True, exist_ok=True)
    ok_adj: list[dict[str, Any]] = []
    rejected: list[tuple[dict[str, Any], list[str]]] = []
    for adj in new_adj:
        errs = _adjudication_errors(root, q, adj)
        if errs:
            rejected.append((adj, errs))
            continue
        art = json.loads((cal_dir / adj["artifact"]).read_text())
        adj = dict(adj)
        adj.setdefault("reviewer", art.get("reviewer"))
        adj["gate_verdict"] = _derive_verdict(art, q)
        adj.setdefault("ts", _dt.datetime.now(_dt.timezone.utc)
                       .isoformat(timespec="seconds"))
        ok_adj.append(adj)
    if rejected:
        for adj, errs in rejected:
            print("REJECTED adjudication (nothing written):")
            for e in errs:
                print(f"  - {e}")
        return 2
    cal = _load_calibration(root)
    cal["adjudications"].extend(ok_adj)
    n = len(cal["adjudications"])
    passes = sum(1 for a in cal["adjudications"]
                 if a.get("human_verdict") == "accept")
    cal["stats"] = {"n": n, "pass_precision": round(passes / n, 3) if n else 1.0}
    (cal_dir / "calibration.json").write_text(
        json.dumps(cal, indent=2) + "\n")
    ledger = root / "verify" / "ledger.jsonl"
    try:
        with ledger.open("a") as fh:
            for adj in ok_adj:
                fh.write(json.dumps({
                    "ts": adj["ts"], "outcome": "ADJUDICATED",
                    "fixtures_total": 0, "failures": [],
                    "model": adj.get("reviewer", "-"), "gate": "calibration",
                    "artifact": adj["artifact"],
                    "human_verdict": adj["human_verdict"],
                    "gate_verdict": adj["gate_verdict"],
                }) + "\n")
    except Exception as exc:
        print(f"WARN: ledger write failed: {exc}")
    print(f"calibration updated: {len(ok_adj)} adjudication(s), n={n}, "
          f"pass_precision={cal['stats']['pass_precision']} "
          f"(calibrated at n>={q['calibration_min_n']})")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_rev = sub.add_parser("review")
    p_rev.add_argument("paths", nargs="+")
    p_rev.add_argument("--dry-run", action="store_true")
    p_rev.set_defaults(func=cmd_review)

    p_val = sub.add_parser("validate")
    p_val.add_argument("artifact", nargs="?")
    p_val.add_argument("--required", metavar="DIR", help="validate the newest "
                       "artifact in DIR; fail if none is fresh")
    p_val.set_defaults(func=cmd_validate)

    p_cal = sub.add_parser("calibrate")
    p_cal.add_argument("adjudications")
    p_cal.set_defaults(func=cmd_calibrate)

    args = ap.parse_args()
    root = ROOT
    return args.func(root, args)


if __name__ == "__main__":
    sys.exit(main())
