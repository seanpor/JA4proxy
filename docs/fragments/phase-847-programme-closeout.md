- **Phase 847 (CVE process programme) is complete and its steady state is
  measured: 18 deployed surfaces, 0 unwaived HIGH/CRITICAL findings, fixable
  queue 0.** Seven sub-phases merged (`847a` #620, `847b` #621, `847c` #623,
  `847d` #635, `847e` #636, `847f`/`847g`/`824c` #640). The required PR gate is
  now `Scan Regression (surfaces touched)` — it compares against a recorded
  per-surface baseline, so an upstream advisory-DB change no longer reddens
  unrelated PRs; the full `make scan` is de-required and runs on push/schedule
  as the drift watch instead.
- **Every waiver is now an executed assertion with a date.** `security/waivers.yaml`
  is the only place one is authored; it renders both Trivy ignorefiles and the
  pip-audit ignore list, a drift test fails CI on a hand edit, and each of the
  **21** remaining entries names a registered reachability check that CI runs
  (20 machine-checked, 1 attested, 0 broken). Three pre-existing justifications
  were proven false and fixed — including a `not-imported` check that passed
  vacuously for namespace distributions — which was the point: the prose was the
  unreliable part.
- **The MEDIUM band is gated and ratcheted, not promised away.** Measured before
  it was gated (152 findings, 847e), re-measured after the 847g image bumps and
  now **79**, with `MEDIUM_CEILING_MAX` lowered to 79 in the same commit so
  accretion has to be a reviewed edit rather than a file that quietly grows.
- **Seventeen dead waivers were deleted rather than renewed** (registry 37 → 21).
  Ten image waivers went when 847g's bumps carried them out of the finding (two
  Docker Engine CVEs in `grafana/alloy`, eight in `grafana/loki`); seven more went
  at close-out, when an audit with the ignore list disabled showed
  `.pip-audit-ignores` held ids for findings that no longer exist (four
  `urllib3`, `pygments`, `protobuf`, `PYSEC-2026-2132`, all now resolved to fixed
  versions). That mattered: a dead ignore keeps `--ignore-vuln` alive, so a
  regression back into the vulnerable range would have been suppressed silently.
  Both removals used the validated `render_waivers.remove_entries` splice. The
  underlying gap — the pip side has no dead-waiver check, unlike
  `check_trivyignore_drift --fail-on-dead` for Trivy — is tracked as issue #642.
- **Known limits are written down, not implied away:** one reachability claim
  (`input-path-unreachable`, haproxy) is attested rather than machine-checked;
  `pip-audit` reports no severity, so pip findings are gated as HIGH regardless of
  their advisory CVSS; and issue #622 (no `push` workflow run after an auto-merged
  PR) remains a CI-plumbing gap outside this programme.
