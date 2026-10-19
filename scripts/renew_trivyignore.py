#!/usr/bin/env python3
"""Renew soon-to-expire Trivy waivers (Phase 812, 812-B; registry-aware in 847a).

Since Phase 847a the `.trivyignore.*` files are GENERATED from
`security/waivers.yaml`. Editing them directly is reverted by the drift test, so
this script now renews the REGISTRY (`created:` / `expires:`) and re-renders the
derived files — the write path moved, the renewal policy did not.

Bumps the window of every trivy waiver expiring within `--within-days` (default
5) to `today + --days` (default 90) — computed from *today*, never from the
entry's own (soon-to-be-stale) old expiry, which is exactly the drift that let a
window creep longer through repeated renewals. `created:` moves to today so the
window stays within the policy `max_window_days`.

Deliberately does NOT decide whether a newer upstream image tag clears the CVE —
that judgment stays with the human reviewing the PR this feeds. See
`docs/phases/PHASE_812.md` §812-B and `docs/phases/PHASE_847d.md`.

Prints a summary of what changed (for the calling workflow's PR body) and exits
0 if nothing needed renewal, 1 on error. Idempotent.
"""
from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

try:  # works as `python3 scripts/x.py` and as `from scripts.x import ...`
    from scripts import render_waivers
except ImportError:  # invoked directly, scripts/ on sys.path
    import render_waivers


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--within-days", type=int, default=5)
    parser.add_argument("--days", "--renew-days", type=int, default=90, dest="days")
    parser.add_argument("--today", default="", help="override today (YYYY-MM-DD)")
    parser.add_argument("--registry", type=Path, default=render_waivers.REGISTRY)
    args = parser.parse_args(argv)

    today = date.fromisoformat(args.today) if args.today else date.today()

    try:
        registry = render_waivers.load_registry(args.registry)
    except render_waivers.RegistryError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 1

    before = {
        w["id"]: w["expires"]
        for w in registry.get("waivers") or []
        if w.get("source") == "trivy"
    }
    renewed = render_waivers.renew_expiring(
        registry, args.within_days, args.days, today
    )

    if not renewed:
        print(
            f"No exceptions expiring within {args.within_days} day(s) — nothing to renew."
        )
        return 0

    render_waivers.save_registry(registry, args.registry)
    render_waivers.write_derived(render_waivers.render_all(registry))

    print(f"Renewed {renewed} exception(s):")
    for wid in sorted(before):
        after = next(
            (w["expires"] for w in registry["waivers"] if w.get("id") == wid), None
        )
        if after != before[wid]:
            print(f"  - {wid}: {before[wid]} -> {after}")
    print(
        "\nREVIEWER: verify no newer upstream image tag clears each CVE above "
        "before merging (compare total CVE counts the same way past renewals "
        "have — see docs/runbooks/security_scan_exceptions.md). This script "
        "only renews the time window; it does not check for a real fix."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
