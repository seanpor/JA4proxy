- **Restore Python SAST coverage (Phase 800)**: re-pinned `Dockerfile.bandit` to
  `python:3.11-slim`. PR #340 auto-bumped it to `3.14-slim`, which broke bandit's
  `ast.Num`-dependent plugins: 6 plugins (B104–B108) stopped loading and 32 of 33
  files under `src/analytics/` raised exceptions instead of being scanned — while
  bandit still **exited 0**, so the gate reported green with effectively no
  coverage. Added `tests/test_bandit_toolchain.py` to fail loudly if the pin is
  bumped again or if bandit is invoked outside the pinned image.
