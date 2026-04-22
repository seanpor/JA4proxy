<!--
JA4proxy PR template. Phase 121h enforces that PRs touching
security-sensitive code cite a canonical finding ID (or explicitly opt out).
See docs/security/CLOSURE_VERIFICATION.md for the full protocol.
-->

## Summary

<!-- 1-3 bullets on what this PR does and why -->

## Security finding citation

Check exactly one (see `docs/security/CLOSURE_VERIFICATION.md` §PR template):

- [ ] **Addresses canonical finding(s):** `JA4PROXY-YYYY-NNNN` (list all)
- [ ] **No finding** — this PR is a net-new feature or refactor with no
      security-finding motivator. Brief justification:
      <!-- e.g. "docs-only typo fix" / "adds a Grafana panel" -->
- [ ] **Finding TBA** — emergency fix; canonical ID will be back-filled into
      `docs/security/findings.yaml` within 48 hours of merge. Expected
      source report / IDs:
      <!-- e.g. "will be ingested from 2026-06-14 incident report as HIGH" -->

If this PR touches security-sensitive code paths — `internal/security/**`,
`internal/pipeline/**`, `internal/proxyproto/**`, `internal/tls/**`,
`internal/redis/**`, `src/security/**`, `src/tap/**`, `proxy.py`,
`src/mgmt/**`, `config/proxy.yml` bypass / TLS / rate-limit keys,
`tests/pentest/**`, `internal/security/pentest/**`, `docs/security/**`,
`docs/decisions/**`, or `docs/phases/PHASE_1[0-2][0-9].md` — one of the
above **must** be checked. The CI job `check-finding-citation` enforces this.

## Regression test

<!-- If this PR moves a finding to FIXED, the regression test path goes here
     so reviewers can eyeball it: -->
- Regression test: `tests/pentest/test_<...>.py::test_<...>` (or N/A)
- Observed red on commit: `<sha or branch tip>` (or N/A)
- Observed green on this PR's HEAD: yes / no

## Test plan

- [ ] `make test-unit` passes
- [ ] `make verify-findings` passes (if `findings.yaml` changed)
- [ ] `make verify-findings-green` passes (if any regression test touched)
- [ ] Integration / E2E / chaos tests considered; run if relevant

## Docs / observability

- [ ] `CHANGELOG.md` entry added if user-visible
- [ ] `docs/REDIS_SCHEMA.md` updated if Redis keys changed
- [ ] `docs/OBSERVABILITY_STANDARDS.md` + dashboards / alerts updated if
      metrics or log schema changed
- [ ] ADR written or updated if a non-obvious decision was made

🤖 Generated with [Claude Code](https://claude.com/claude-code)
