# Phase 800 Notes — Code Health Loop (reworked)

## Timeline

- **2026-07-14** — original implementation (`ca4e5381`): one bash script that ran weakened
  gates, "auto-fixed", auto-committed with `git add -A`, and always exited 0. Marked
  COMPLETE in the manifest on delivery.
- **2026-07-18** — critical review, then live verification in isolated clones. Branch
  rewound and rebuilt as three honest commits; tooling redesigned (this rework).

## Verified defects of the original implementation

All observed by running it, not inferred (evidence: verification session logs; runs were
made in throwaway clones so no real branch was contaminated):

1. **Fabricated fix counts.** `FIXED (3)` was a counter of fixers *invoked*. Observed
   reporting "3" when 18 files / 230 lines changed, and "3" when zero changes were made.
2. **Unsafe commits.** `git add -A` swept a planted "DO NOT COMMIT" file and an untracked
   scratch file into `fix(phase-800): cycle-1 auto-fixes (3 issues)`. On a `main`
   checkout it committed straight to `main` (no branch guard), sweeping in the script
   itself. This same defect had already contaminated `ca4e5381` with 12 unrelated files.
3. **Exit 0 on every path.** Including `./script.sh 0` and `./script.sh abc`, both of
   which printed `Status: ✅ CLEAN` having run no gates at all.
4. **No verification.** Gates were never re-run after "fixing"; `make lint-static` still
   exited 2 (CVEs) immediately after the script declared FIXED and exited 0.
5. **Weaker gates than documented** (lint-static / scan-js / host pytest-unit vs the
   promised `make lint/scan/test`); Go tests never ran; host tool versions drift from
   the CI-pinned toolchain (host gofmt reformatted 5 files CI considers clean).
6. **Unreachable early exit** — any persistent failure (CVEs) re-armed the counter, so
   the loop always burned all cycles and could not detect being stuck.
7. Shellcheck violations; shared `/tmp` log paths clobbered by concurrent runs;
   same-second report-file overwrites; phase marked COMPLETE while its own acceptance
   criteria (lint green) demonstrably failed.

## Rework decisions

- **Detect / fix / commit separated** (see `docs/phases/PHASE_800.md`). The script only
  detects and reports; the `/code-health` skill fixes with judgment and must re-run the
  failed gate before claiming a fix; commits name files explicitly.
- **Exit codes are the contract**: 0 CLEAN / 1 RESIDUAL / 2 STUCK (failure fingerprint
  unchanged vs previous all-gates run) / 64 REFUSED. STUCK detection is a sha256 over
  normalised salient failure lines — a heuristic aid, the logs are the truth.
- **Guards**: refuses `main`; all-gates runs refuse a dirty tree (report must describe a
  reproducible commit); `--gate` subset runs allow dirty (mid-fix verification).
- **Report ≤33×170 enforced by construction** (budgeted elision + tab flattening), with a
  belt-and-braces `wc` assert. ASCII-safe truncation.
- **Acceptance reframed**: accuracy is the bar, green is the goal. A truthful RESIDUAL
  run passes; a fabricated CLEAN fails.

## Dependency work in this rework

Diagnosed with a full-graph `pip install --dry-run --ignore-installed --report` and PyPI
metadata queries; both open CVEs turned out to be **walled off by semgrep**:

- `click` 8.1.8 (PYSEC-2026-2132): fix is 8.3.3, but semgrep — every version through
  latest 1.170.0 — hard-pins `click~=8.1.8`. A `click>=8.3.3` pin makes resolution
  impossible (observed as pip `resolution-too-deep`).
- `protobuf` 4.25.9 (PYSEC-2026-1805): fix is 5.29.6. The `protobuf<5.0` wall comes from
  `opentelemetry-proto 1.25.0`, pinned via semgrep≤1.136's `opentelemetry-*~=1.25.0`.
  semgrep≥1.137 moves to OTEL ~=1.37 (protobuf 5-compatible) **but** hard-pins
  `mcp==1.12.2/1.16.0/1.23.3`, which would undo our `mcp>=1.28.0` pin (CVE-2025-66416).
  Three-way deadlock; keeping the mcp protection was judged least-harm (mcp is the
  directly pinned CVE fix; click/protobuf are dev/CI tooling deps in the tools image).
- Both acknowledged via `--ignore-vuln` in the `lint-static` pip-audit call, following
  the existing acknowledged-transitive-CVE pattern (urllib3, pygments), with comments in
  the Makefile and `requirements.txt` naming the exact removal condition: **a semgrep
  release with OTEL≥1.37 and mcp≥1.28** (then pin `protobuf>=5.29.6`).
  **Flagged for maintainer review.**
- `google-cloud-storage` floor raised 2.0 → 3.0 (kept): the loose 2022-era floor gave
  pip a huge backtrack space; the successful full-graph resolution used 3.x happily
  (gcs 3.13.0 + api-core 2.30.3 + protobuf 4.25.9).
- 3 `F821 httpx` errors in `tests/unit/management/conftest.py` fixed with a
  `TYPE_CHECKING` import (annotations were already string-quoted).

## Residuals / follow-ups

- click + protobuf CVE acknowledgements above (upstream-blocked; revisit on semgrep
  releases — watch for an OTEL≥1.37 + mcp≥1.28 combination).
- Option if the acknowledgements become unacceptable: give semgrep its own container/venv
  (precedent: `Dockerfile.bandit` isolates bandit on Python 3.11) so its pins stop
  constraining the shared tools image.
- Full-tier `make scan` needs built images and preflight (`.env`, backend cert); on a
  cold environment the scan gate reports an environment failure honestly rather than
  masking it — that is by design, but operators should run `make build` first.
- 5 Go test files (`cmd/ja4pd/*_test.go`, `internal/wizard/*_test.go`,
  `internal/config/validate_test.go`) are reformatted by host gofmt but accepted by CI —
  symptom of host-vs-pinned toolchain drift; left untouched deliberately.
