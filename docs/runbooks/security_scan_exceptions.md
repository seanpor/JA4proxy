# Runbook: Security Scan Exceptions (`.trivyignore.*`)

> **Phase 847a — the ignorefiles are now GENERATED. Do not edit them by hand.**
>
> Every waiver is authored once in **`security/waivers.yaml`** and rendered into
> `.trivyignore.first-party`, `.trivyignore.third-party` and `.pip-audit-ignores`
> by `scripts/render_waivers.py`:
>
> ```bash
> $EDITOR security/waivers.yaml
> python3 scripts/render_waivers.py      # regenerate the derived files
> python3 scripts/render_waivers.py --check   # what CI runs: fails if stale
> ```
>
> Hand-editing a generated file is reverted by
> `tests/unit/test_waivers_registry.py`, which fails CI when a derived file does
> not match the registry (same discipline as `TODO.md`, Phase 332). The same
> registry feeds the `Makefile` `lint-static` gate *and* the `ci.yml`
> `dependency-audit-python` job, so those two pip-audit ignore lists can no
> longer diverge (they had: 6 in the Makefile vs 2 in ci.yml).

> **Phase 822 — there are TWO trivy exception files, with different rules.**
>
> | File | Consumed by | Rule |
> |---|---|---|
> | `.trivyignore.first-party` | `make scan-first-party` | **A fix reachable by ANY rebuild we can perform is not a waiver candidate.** We control these images — do the fix. |
> | `.trivyignore.third-party` | `make scan-images` | **No fix reachable without replacing the image.** These are pinned upstream tags we cannot rebuild. |
>
> They were one file until Phase 822, and the Makefile passed it to both scans.
> Trivy's ignorefile has no per-image scoping, so a waiver written for an
> abandoned monitoring sidecar also suppressed the same finding in the proxy we
> ship — observed with `CVE-2026-39821`/`CVE-2026-46600`, both of which were
> fixed outright by a Go builder bump once the scopes were separated.
>
> `make scan-exceptions` reports both, tagged by scope.

`make scan` fails the build on any CRITICAL CVE in our images. When a CVE has
**no fix available** and is **not exploitable in our context**, it can be granted
a *justified, time-windowed* exception in the ignorefile for that image's
scope (see the table above). This is the **only**
sanctioned way to suppress a scan finding — and it always expires.

> Policy (Phase 226): no blanket ignores. Anything with an available fix is
> patched via `apt-get/apk upgrade` in the Dockerfile, **never** ignored here.

## View current exceptions

```bash
make scan-exceptions
```

Lists every entry with its expiry, **days remaining**, status (`ok` / `SOON` ≤3d
/ `EXPIRED` / `NO-EXP`) and justification. Exits non-zero if any entry is expired
or has no `exp:` date, so stale exceptions can't be forgotten.

## Registry entry format (`security/waivers.yaml`)

Author waivers in the registry, not in the ignorefile:

```yaml
  - id: CVE-2026-8376
    scope: third-party          # selects the ignorefile; first-party is stricter
    severity: CRITICAL
    source: trivy               # trivy | pip-audit
    carriers: ["python:3.14-slim"]
    rationale: >-
      Perl interpreter heap overflow, perl-base on python:3.14-slim. Debian marks
      it `affected` with no fixed version. We never run the perl interpreter on
      untrusted input.
    reachability: build-time-only
    fix_available: false        # if false, recheck_trigger is REQUIRED
    recheck_trigger: "Debian ships a fixed perl-base in the slim base"
    created: 2026-10-17
    expires: 2027-01-15         # must be <= created + policy.max_window_days
```

`scripts/render_waivers.py` turns each entry into the ignorefile form
(justification comment block above `CVE-… exp:YYYY-MM-DD`):

```
# Perl interpreter heap overflow, perl-base on python:3.14-slim. Debian marks
# it `affected` with no fixed version. ...
#
# Carriers:
#   - python:3.14-slim
# Reachability: build-time-only
# Severity: CRITICAL
# Re-check when: Debian ships a fixed perl-base in the slim base
CVE-2026-8376 exp:2027-01-15
```

Trivy ignores the CVE **until** `exp:`, then it re-surfaces and the scan fails
again — forcing a re-review. `fix_available: false` requires a `recheck_trigger`
so the author must state the concrete upstream change that would obsolete the
waiver.

## Operator: add / edit / delete

All actions edit **`security/waivers.yaml`**, then re-render:

| Action | How |
|--------|-----|
| **Add** | Confirm there is genuinely no fix (`make scan` shows `fix_deferred`/`affected`). Add a waiver to `security/waivers.yaml` stating *why no fix* and *why not exploitable here*, with `created: <today>` and `expires: <today+90d>`. Run `python3 scripts/render_waivers.py`. |
| **Edit / extend** | Change `expires:` (and `created:` to keep the window ≤90d) and update `rationale`. **Max window: 90 days** (third-party sidecars) — enforced by the renderer. |
| **Delete** | When a fix lands, remove the entry from the registry and re-render. `scripts/renew_trivyignore.py` does this automatically for entries a scan no longer sees (a *dead* waiver). |
| **Re-affirm** | `python3 scripts/renew_trivyignore.py --within-days 5 [--scan-dir DIR]` classifies each expiring entry as **dead** (removed), **fixable** (the fix is proposed; the window is *not* extended) or **escalated** (dates left untouched, with the next step printed). Since Phase 847d there is **no bulk-renew**: extending an expiry requires evidence, so a date cannot be pushed forward automatically. |

> **No auto-renew (Phase 847d).** There is deliberately no command that extends a
> waiver's `expires:`. The old behaviour bumped every window inside the notice
> period, which meant a 90-day expiry was renewed indefinitely without anyone
> checking whether a fix had shipped. To keep a waiver alive you now record *why*
> (update `rationale` and set a new `created:`/`expires:` within 90 days). If a
> script or workflow offers to refresh the date for you, that is a bug.

Always run `make scan-exceptions` after editing, and `make scan` to confirm the
gate is satisfied. CI runs `render_waivers.py --check`, so a registry edit that
was not re-rendered (or a hand-edited generated file) fails the build.

## Where a finding is caught (Phase 847c)

Since Phase 847c a CVE is judged in one of two places, and which one an operator
is looking at changes what to do:

| | `make scan-regression` (required, every PR) | `make scan-monitor` (daily, scheduled) |
|---|---|---|
| Scans | only the surfaces **this PR touches** | everything: third-party images, first-party images, `requirements.txt` |
| Compares | findings vs `security/baseline.json` | findings vs the baseline **and** the registry |
| Result | fails the PR, on a finding the baseline does not have | files one deduplicated issue per unwaived finding |

`security/baseline.json` records what `main` already carries, per surface, with
the artifact's digest as provenance. **Refresh it deliberately** — after a fix or
a waiver lands *and is on `main`*:

```bash
make scan-baseline                 # re-record the baseline from the current tree
git diff security/baseline.json    # should show only the finding(s) you removed
```

Never refresh it to turn a red PR green: the gate is telling you the PR adds a
finding the baseline does not have. Refresh only once the finding is genuinely
gone from `main`.

`make scan` (the full scan) still runs on push and schedule, and on a PR only
when the waiver set itself moved — deleting a waiver touches no scanned file, so
it would otherwise be the one change that scanned nothing. The monitor reopens an
issue whose finding has come back rather than filing a second one, and a monitor
run that could not scan reports that (it comments the scheduled-failure issue) —
a scanner that failed is never reported as "nothing found".

## Rules

1. **No blanket ignores** — one entry per CVE, each individually justified.
2. **Every trivy entry needs an `exp:` date** (max 90 days for third-party sidecars) — the renderer rejects a longer window.
3. **Fixable ⇒ patch, don't ignore** — only no-fix CVEs belong here, and `fix_available: false` must name a `recheck_trigger`.
4. **Automated Upstream Tag Verification (Phase 827)** — Third-party sidecar waivers are audited against OCI/Docker Hub registries via `scripts/check_upstream_image_updates.py`. If a newer upstream tag is published by the vendor, the sidecar image MUST be upgraded rather than renewing the waiver.
5. **Never edit a generated file** — `.trivyignore.first-party`, `.trivyignore.third-party` and `.pip-audit-ignores` are rendered from `security/waivers.yaml`; `tests/unit/test_waivers_registry.py` fails CI on drift.
6. Prefer a **real fix** (base-image change or tag bump) over repeatedly extending an exception.
