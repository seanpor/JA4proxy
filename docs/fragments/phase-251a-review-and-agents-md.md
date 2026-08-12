- **Correct AGENTS.md branch-protection docs; expert-review Phase 251a plan**:
  AGENTS.md wrongly claimed `main` is non-strict — API verification shows
  require-branches-up-to-date is ON, so the merging section now documents the
  strict-mode rebase treadmill and the `gh pr update-branch --rebase` recovery
  loop. The Phase 251a plan (JA4PROXY-2026-0089) gained a Review History
  section adjudicating two expert reviews, plus design notes: cancel-before-
  replace ordering, blocklists-before-feedDownloader construction order,
  cancel funcs for all four enrichment components regardless of enabled
  state, and a bounded old/new worker overlap window.
