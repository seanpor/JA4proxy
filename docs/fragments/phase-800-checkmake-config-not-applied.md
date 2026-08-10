- **Pass `.checkmake.ini` explicitly (Phase 800)**: checkmake does not
  auto-discover `.checkmake.ini` from the working directory, so `lint-makefiles`
  had been running with default rules. Verified three ways on a probe Makefile:
  file in cwd with no flag → `maxbodylength` still reported; file absent →
  identical; `--config=.checkmake.ini` → suppressed. On this repo's Makefile that
  is the difference between **13** spurious `maxbodylength` violations and **0**.
  `lint-makefiles` now passes `--config=.checkmake.ini`, and says so out loud when
  checkmake is not installed instead of skipping silently. Corrects a second row
  in `docs/phases/complete/PHASE_802.md`; the `.semgrepignore` row in that table
  was re-tested and **confirmed correct**.
