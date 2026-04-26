#!/usr/bin/env python3
"""process_metrics.py — emit an engineering-process metrics report.

Generates a markdown report (NOT Prometheus metrics) summarising four
engineering-process metrics for the JA4proxy project:

1. **Phase throughput** — phases marked COMPLETE in the last quarter
   (90-day window), per ``docs/phases/manifest.yaml`` ``completed:`` field.
2. **Average phase duration** — ``completed - created`` for completed
   phases (when both dates are present). Falls back to the first git commit
   touching the phase doc when ``created`` is absent.
3. **CI reliability** — % green builds on ``main`` in the last 90 days.
   Source: GitHub Actions REST API
   (``GET /repos/{owner}/{repo}/actions/runs?branch=main&per_page=100``).
4. **Mean-time-to-green** — for each ``main``-branch failure, the time until
   the next green build on ``main``. Averaged over the window.

Required GitHub token scopes (provided via ``GITHUB_TOKEN``):

- ``actions:read`` (read workflow runs)
- ``contents:read`` (read repository metadata)

Rate-limit / unauthenticated behaviour
--------------------------------------

If ``GITHUB_TOKEN`` is unset OR the API returns ``HTTP 403`` with
``X-RateLimit-Remaining: 0``, the script degrades gracefully: the markdown
report contains a warning line for each unavailable metric and the script
exits ``0``. Other I/O errors writing the output file produce exit ``2``.

CLI::

    python3 scripts/process_metrics.py --output docs/engineering-method/retrospectives/latest-metrics.md
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import statistics
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = ROOT / "docs" / "phases" / "manifest.yaml"
DEFAULT_OUTPUT = (
    ROOT / "docs" / "engineering-method" / "retrospectives" / "latest-metrics.md"
)
DEFAULT_REPO = "Sean-OR/JA4proxy"  # informational only; overridden via env
WINDOW_DAYS = 90


@dataclass
class CIMetrics:
    """Container for CI reliability + MTTG numbers."""

    total_runs: int
    green_runs: int
    reliability_pct: float
    mttg_hours: float | None  # None when no recovery samples exist
    warning: str | None  # populated in degraded mode


# ── Date helpers ──────────────────────────────────────────────────────────────


def _today() -> _dt.date:
    """Return today's date. Indirected for testing."""
    return _dt.date.today()


def _parse_date(value: Any) -> _dt.date | None:
    """Best-effort parse of a value into a ``date``.

    Accepts ``date``, ``datetime``, or ISO-8601 string; returns ``None`` for
    anything else (including the literal Python ``None`` and empty strings).
    """
    if value is None or value == "":
        return None
    if isinstance(value, _dt.datetime):
        return value.date()
    if isinstance(value, _dt.date):
        return value
    if isinstance(value, str):
        try:
            return _dt.date.fromisoformat(value.strip())
        except ValueError:
            return None
    return None


# ── Manifest-driven metrics ───────────────────────────────────────────────────


def load_manifest(path: Path) -> dict:
    """Load and return the phase manifest YAML, or ``{}`` on missing file."""
    if not path.is_file():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _git_first_commit_date(doc_path: Path) -> _dt.date | None:
    """Return the date of the earliest git commit that touched ``doc_path``.

    Returns ``None`` if git is unavailable or the file is not tracked.
    """
    try:
        result = subprocess.run(
            [
                "git",
                "log",
                "--diff-filter=A",
                "--follow",
                "--format=%aI",
                "--",
                str(doc_path),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    output = (result.stdout or "").strip().splitlines()
    if not output:
        return None
    # Take the LAST line — that's the earliest commit (git log is reverse-chrono).
    return _parse_date(output[-1])


def phase_throughput(
    manifest: dict,
    window_days: int = WINDOW_DAYS,
    today: _dt.date | None = None,
) -> int:
    """Return the count of phases COMPLETE within ``window_days`` of today."""
    today = today or _today()
    cutoff = today - _dt.timedelta(days=window_days)
    count = 0
    phases = manifest.get("phases", {}) or {}
    for entry in phases.values():
        if not isinstance(entry, dict):
            continue
        if entry.get("status") != "COMPLETE":
            continue
        completed = _parse_date(entry.get("completed"))
        if completed is None:
            continue
        if cutoff <= completed <= today:
            count += 1
    return count


def average_phase_duration_days(
    manifest: dict,
    phases_dir: Path | None = None,
    use_git_fallback: bool = False,
) -> float | None:
    """Return the mean ``completed - created`` in days, or ``None`` if no data.

    When a phase entry has no ``created`` field, ``use_git_fallback`` enables
    a probe of the originating phase doc's first git commit. This is opt-in
    because git probes can be slow on cold caches.
    """
    durations: list[int] = []
    phases = manifest.get("phases", {}) or {}
    for key, entry in phases.items():
        if not isinstance(entry, dict):
            continue
        if entry.get("status") != "COMPLETE":
            continue
        completed = _parse_date(entry.get("completed"))
        if completed is None:
            continue
        created = _parse_date(entry.get("created"))
        if created is None and use_git_fallback and phases_dir is not None:
            # Use the action_plan if it points at a phase doc, otherwise infer.
            ap = entry.get("action_plan")
            doc_path: Path | None = None
            if isinstance(ap, str) and ap:
                candidate = ROOT / ap
                if candidate.is_file():
                    doc_path = candidate
            if doc_path is None:
                # Fall back to PHASE_<key>.md
                cand = phases_dir / f"PHASE_{key}.md"
                if cand.is_file():
                    doc_path = cand
            if doc_path is not None:
                created = _git_first_commit_date(doc_path)
        if created is None:
            continue
        delta = (completed - created).days
        if delta < 0:
            continue
        durations.append(delta)
    if not durations:
        return None
    return statistics.fmean(durations)


# ── GitHub Actions metrics ────────────────────────────────────────────────────


def _github_repo() -> str:
    """Return the ``owner/repo`` slug. Tries ``GITHUB_REPOSITORY`` env first."""
    return os.environ.get("GITHUB_REPOSITORY") or DEFAULT_REPO


def _fetch_workflow_runs(
    repo: str,
    token: str,
    per_page: int = 100,
    timeout: float = 15.0,
) -> tuple[list[dict], str | None]:
    """Fetch up to ``per_page`` recent workflow runs on ``main``.

    Returns ``(runs, warning)`` — ``warning`` is a non-empty string when the
    API returned a degraded response (rate-limit / 403). On success
    ``warning`` is ``None``.
    """
    url = (
        f"https://api.github.com/repos/{repo}/actions/runs"
        f"?branch=main&per_page={per_page}"
    )
    req = urllib.request.Request(url)  # noqa: S310 - HTTPS GitHub API only
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "JA4proxy-process-metrics/1.0")
    try:
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        remaining = exc.headers.get("X-RateLimit-Remaining") if exc.headers else None
        if exc.code == 403 and (remaining == "0" or remaining is None):
            return [], (
                "CI metrics unavailable — GitHub API rate-limited "
                "(HTTP 403, X-RateLimit-Remaining=0)"
            )
        return [], f"CI metrics unavailable — GitHub API HTTP {exc.code}"
    except urllib.error.URLError as exc:
        return [], f"CI metrics unavailable — network error: {exc.reason}"
    except (TimeoutError, OSError) as exc:
        return [], f"CI metrics unavailable — I/O error: {exc}"

    runs = payload.get("workflow_runs") if isinstance(payload, dict) else None
    if not isinstance(runs, list):
        return [], "CI metrics unavailable — unexpected API response shape"
    return runs, None


def _filter_recent(runs: list[dict], window_days: int = WINDOW_DAYS) -> list[dict]:
    """Return runs whose ``created_at`` is within the trailing window."""
    cutoff = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=window_days)
    out: list[dict] = []
    for run in runs:
        created_raw = run.get("created_at") or run.get("run_started_at")
        if not isinstance(created_raw, str):
            continue
        try:
            created = _dt.datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
        except ValueError:
            continue
        if created >= cutoff:
            out.append(run)
    return out


def _conclusion_is_green(conclusion: str | None) -> bool:
    return conclusion == "success"


def _conclusion_is_red(conclusion: str | None) -> bool:
    return conclusion in {"failure", "timed_out", "startup_failure"}


def compute_ci_metrics(runs: list[dict]) -> CIMetrics:
    """Compute reliability and mean-time-to-green from raw run dicts."""
    total = len(runs)
    if total == 0:
        return CIMetrics(0, 0, 0.0, None, warning=None)

    green = sum(1 for r in runs if _conclusion_is_green(r.get("conclusion")))
    reliability = (green / total) * 100.0

    # Mean time to green: walk runs in chronological order, look for failures
    # and pair each with the next green run.
    def _start(run: dict) -> _dt.datetime | None:
        s = run.get("run_started_at") or run.get("created_at")
        if not isinstance(s, str):
            return None
        try:
            return _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None

    chrono = sorted(
        (r for r in runs if _start(r) is not None),
        key=lambda r: _start(r),  # type: ignore[arg-type,return-value]
    )
    deltas: list[float] = []
    pending_failure_at: _dt.datetime | None = None
    for run in chrono:
        when = _start(run)
        if when is None:
            continue
        if _conclusion_is_red(run.get("conclusion")):
            if pending_failure_at is None:
                pending_failure_at = when
        elif _conclusion_is_green(run.get("conclusion")):
            if pending_failure_at is not None:
                deltas.append((when - pending_failure_at).total_seconds() / 3600.0)
                pending_failure_at = None
    mttg = statistics.fmean(deltas) if deltas else None
    return CIMetrics(total, green, reliability, mttg, warning=None)


# ── Report rendering ──────────────────────────────────────────────────────────


def _fmt_pct(value: float) -> str:
    return f"{value:.1f}%"


def _fmt_hours(value: float | None) -> str:
    if value is None:
        return "n/a (no failure→green pairs in window)"
    return f"{value:.2f} h"


def _fmt_days(value: float | None) -> str:
    if value is None:
        return "n/a (no completed phases with both `created` and `completed`)"
    return f"{value:.1f} days"


def render_report(
    *,
    today: _dt.date,
    throughput: int,
    avg_duration: float | None,
    ci: CIMetrics | None,
    ci_warning: str | None,
    window_days: int = WINDOW_DAYS,
) -> str:
    """Render the full markdown report."""
    lines: list[str] = []
    lines.append("# Engineering Process Metrics")
    lines.append("")
    lines.append(f"> Generated: {today.isoformat()}")
    lines.append(f"> Window: trailing {window_days} days")
    lines.append("")
    lines.append("Auto-emitted by `scripts/process_metrics.py`. Do not edit by hand.")
    lines.append("")
    lines.append("## Phase throughput")
    lines.append("")
    lines.append(
        f"- Phases marked COMPLETE in the last {window_days} days: **{throughput}**"
    )
    lines.append("")
    lines.append("## Average phase duration")
    lines.append("")
    lines.append(f"- Mean `completed - created`: **{_fmt_days(avg_duration)}**")
    lines.append("")
    lines.append("## CI reliability (main branch)")
    lines.append("")
    if ci_warning:
        lines.append(f"- ⚠️ {ci_warning}")
    elif ci is not None:
        lines.append(f"- Total runs: {ci.total_runs}")
        lines.append(f"- Green runs: {ci.green_runs}")
        lines.append(f"- Reliability: **{_fmt_pct(ci.reliability_pct)}**")
    lines.append("")
    lines.append("## Mean-time-to-green (main branch)")
    lines.append("")
    if ci_warning:
        lines.append(f"- ⚠️ {ci_warning}")
    elif ci is not None:
        lines.append(f"- Mean recovery time: **{_fmt_hours(ci.mttg_hours)}**")
    lines.append("")
    return "\n".join(lines) + "\n"


# ── Orchestrator ──────────────────────────────────────────────────────────────


def gather_ci_metrics(
    repo: str | None = None,
    *,
    token: str | None = None,
) -> tuple[CIMetrics | None, str | None]:
    """Return ``(metrics, warning)``. ``warning`` is non-empty on degradation."""
    token = token if token is not None else os.environ.get("GITHUB_TOKEN")
    if not token:
        return None, "CI metrics unavailable — GITHUB_TOKEN missing or rate-limited"
    repo = repo or _github_repo()
    runs, warn = _fetch_workflow_runs(repo, token)
    if warn is not None:
        return None, warn
    recent = _filter_recent(runs)
    return compute_ci_metrics(recent), None


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = argparse.ArgumentParser(
        description="Emit engineering-process metrics as markdown."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Where to write the markdown report.",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=MANIFEST_PATH,
        help="Override the manifest path (testing).",
    )
    parser.add_argument(
        "--repo",
        type=str,
        default=None,
        help="GitHub owner/repo slug (defaults to env GITHUB_REPOSITORY).",
    )
    parser.add_argument(
        "--use-git-fallback",
        action="store_true",
        help="When `created:` is missing, probe git log for first commit date.",
    )
    args = parser.parse_args(argv)

    try:
        manifest = load_manifest(args.manifest)
    except (OSError, yaml.YAMLError) as exc:
        sys.stderr.write(f"failed to load manifest {args.manifest}: {exc}\n")
        return 2

    today = _today()
    throughput = phase_throughput(manifest, today=today)
    avg_duration = average_phase_duration_days(
        manifest,
        phases_dir=args.manifest.parent if args.manifest else None,
        use_git_fallback=args.use_git_fallback,
    )
    ci_metrics, ci_warning = gather_ci_metrics(args.repo)

    report = render_report(
        today=today,
        throughput=throughput,
        avg_duration=avg_duration,
        ci=ci_metrics,
        ci_warning=ci_warning,
    )

    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
    except OSError as exc:
        sys.stderr.write(f"failed to write {args.output}: {exc}\n")
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
