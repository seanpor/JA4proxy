---
phase: 333
title: Bootstrap Finish — Go Wizard Migration & 231b Close-Out
created: 2026-06-15
audience: [developer, operator]
---

# Bootstrap Finish: Go Wizard Migration & 231b Close-Out

## Goal

Close Phase 231b by migrating `bootstrap.sh` from the deprecated Python setup
wizard to the Go-native `ja4p init` (Phase 161), archiving superseded code, and
fixing stale LaTeX documentation.

## Scope

1. **`scripts/bootstrap.sh`** — replace `python3 setup_wizard.py` call with
   `ja4p init` (native mode: direct binary; container mode: one-shot docker run);
   update `do_check()` to verify `ja4p` binary / Docker image; remove Python
   from runtime deps (wizard no longer needs it).
2. **Archive Python wizard** — add deprecation header to
   `scripts/setup_wizard.py` and `tests/unit/test_setup_wizard.py`.
3. **LaTeX install chapter** — update `ch02-installation.tex` to reference
   `ja4p init`, remove Python prereq, fix stale "inline or tap" topology.
4. **Manifest** — mark Phase 231b COMPLETE, add Phase 333 entry.
5. **Close-out** — archive 231b phase doc, run `make lint-phases`, `make sync`.

## Implementation Plan

### A — `scripts/bootstrap.sh`

- `run_wizard()`: for `native` mode call `"$ROOT/bin/ja4p" init`; for `container`
  mode call `docker run --rm -it -v "$ROOT:$ROOT" -v /etc/systemd/system:/etc/systemd/system
  -w "$ROOT" ja4proxy:2.0.0 ja4p init`.
- `do_check()`: check `ja4p` binary (native) or Docker image (container).
- `install_runtime_deps()`: remove `python3` dep (wizard is Go-native).

### B — Archive Python Wizard

- Add deprecation banner referencing Phase 161's `ja4p init` to both
  `scripts/setup_wizard.py` and `tests/unit/test_setup_wizard.py`.

### C — LaTeX Documentation

- `ch02-installation.tex`: replace `setup_wizard.py` references with `ja4p init`;
  remove Python from prerequisites table; fix topology options (inline only);
  describe generated files (`.env`, `proxy.yml`, `haproxy.cfg`, systemd unit).

### D — Manifest & Close-Out

- Set `Phase 231b: status: COMPLETE`, add `completed: 2026-06-15`.
- Move `docs/phases/PHASE_231b.md` → `docs/phases/complete/PHASE_231b.md`.
- Add `Phase 333` entry.
- Run `make lint-phases && make sync`.

## Test Strategy

- `make lint` / `make lint-phases` green.
- Verify `bootstrap.sh --help` output is correct.
- LaTeX compiles clean (no syntax errors).

## Acceptance Criteria

- `bootstrap.sh` calls `ja4p init` (not `setup_wizard.py`); `--check` verifies
  `ja4p` binary (native) or `ja4proxy:2.0.0` image (container).
- `setup_wizard.py` and its tests have deprecation banner.
- LaTeX install chapter reflects Go wizard, no stale Python/TAP references.
- `Phase 231b: status: COMPLETE` in manifest; phase doc archived.
- `make lint-phases` exits 0.

## Out of Scope

- Real-host VM E2E validation (clean-VM boot, offline-tarball, firewall-from-remote)
  — requires physical/virtual host outside CI; deferred as acknowledged gap.
- Changes to `ja4p init` itself (Phase 161 owns it).
- Changes to the 230-238 UI programme.
