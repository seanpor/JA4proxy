- **Dead pip waivers are now detected** (Phase 848, issue #642). The nightly monitor
  audits `requirements.txt` *without* the waiver flags, splits the result in process
  into waived / unwaived / dead (alias-aware, so a waiver naming a GHSA id is never
  called dead), and files one auto-closing `[cve-waiver] <ID>` issue per dead id. A
  dead ignore is a live suppression waiting for a regression, so this closes the one
  place the "zero silent findings" property was not watching.
- `render_waivers.py --drop <ID>` removes a dead waiver through the validated splice
  (comments survive; a carrier another waiver still claims makes it refuse) and
  regenerates the derived files in the same command.
