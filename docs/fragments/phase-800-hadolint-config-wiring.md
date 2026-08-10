- **Make `.hadolint.yaml` actually apply (Phase 800)**: the file had two
  independent defects. `lint-docker` piped each Dockerfile via stdin with **no
  volume mount**, so the container could never read it; and the file used the
  top-level key `ignore:` where hadolint's schema is `ignored:` — an unknown key
  it accepts silently while applying nothing. The five suppressions were live
  only as duplicated `--ignore` CLI flags. `lint-docker` now mounts the repo
  read-only and passes `--config .hadolint.yaml`, the key is corrected, and the
  flags are gone, making the file the single source of truth. Verified: reverting
  the key to `ignore:` now fails `lint-docker` loudly instead of silently
  suppressing nothing.
- **Delete the dead `.mlc.json` (Phase 800)**: markdown-link-check is invoked
  nowhere — no Makefile target, workflow, or script reads it. It was superseded
  by lychee and left behind; the only remaining references are historical phase
  documents.
