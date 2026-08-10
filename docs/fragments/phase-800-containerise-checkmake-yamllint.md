- **Containerise checkmake and yamllint (Phase 800)**: the last two linters that
  ran from the host rather than a pinned image. `lint-makefiles` called a bare
  `checkmake` behind a `command -v` guard, and nothing in the repo ever installed
  it — no CI step, no tools image — so the guard always took the else branch and
  the step silently checked nothing, everywhere, for its whole existence. It now
  runs from `mrtazz/checkmake` pinned to an immutable commit tag (the project
  publishes no semantic versions) and fails on non-zero exit, which is checkmake's
  violation count. `lint-yaml` called a bare host `yamllint` with no guard at all,
  so it hard-failed anywhere yamllint was absent and otherwise used whatever
  version the host had; `yamllint==1.35.*` is now pinned in `Dockerfile.tools`.
  Both verified to genuinely enforce: removing `.checkmake.ini` fails
  `lint-makefiles` with `Error 13`, and yamllint's config demonstrably changes its
  output (line-length errors fire under true defaults, suppressed with the repo
  config). Every linter in the repo now runs from a pinned image.
