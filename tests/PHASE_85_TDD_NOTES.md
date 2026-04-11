# Phase 85 — TDD Notes (test-writer agent)

## Start-of-work verification

```
$ git branch --show-current
worktree-agent-a0d4a2b5

$ git log --oneline -5
4bf12f9 chore: standardise CLI build output to bin/, fix .gitignore
60b3ddd phase-83/100: fix item numbering collision — rename 100-O/P (Phase 83) to 100-U/V
30825e9 phase-83: critical review fixes — bypass key validation, release artifacts
00d7643 Merge branch 'claude/phase-83-integration': Phase 83 — ja4proxy-cli Go Binary
8df83b5 phase-83: mark COMPLETE; sync roadmap; update CHANGELOG; add Phase 100 items 100-O/P

$ ls src/analytics/ti_feeds 2>&1
ls: cannot access '.../src/analytics/ti_feeds': No such file or directory
NOT YET CREATED (expected) ✔ red is correct

$ grep -n "class ManagedBy" management/api/models.py
238:class ManagedBy(str, Enum):
  members: terraform | operator | api | analytics | legacy | migration
  → "feed" not yet added (Phase 85 will add it)

$ grep -n "router.post" management/api/routes/bans.py
89:@router.post("/api/v1/bans/{ip:path}", response_model=BanCreateResponse)
  ✔ confirms the path-encoded IP form; tests assert the URL pattern, not the body field
```

## Surprises / deviations from the task brief

1. **`tests/unit/test_pages.py` does not yet exist in this worktree.** The task brief
   asks me to "add cases" to it. I instead create a new dedicated file
   `tests/unit/test_pages_threat_intel.py` with the same shape — when the merge round
   runs, the orchestrator can absorb it into the canonical `test_pages.py` if one is
   created by another agent. Either way the test logic ships and runs.
2. **`tests/chaos/test_ti_feed_chaos.py` already exists** but covers Phase 48/59 hot-path
   TI providers (`MISP`, `GreyNoise`, `AlienVault`, `VirusTotal`, `ThreatFox`). My new
   chaos files use distinct names (`test_ti_feed_taxii_unavailable.py`,
   `test_ti_feed_mgmt_api_429.py`, `test_ti_feed_redis_unavailable.py`) and target the
   Phase 85 `analytics.ti_feeds.*` modules. No collision.
3. **fakeredis 2.34.1** is already a project test dep — used for the sidecar-index
   tests as planned.

## Approved skips

None added by Phase 85 tests. Zero-skip policy is honoured.

## Hard gates verified by these tests

- **GDPR contribution payload whitelist**: `tests/unit/analytics/ti_feeds/test_contribution.py`
  asserts that any disallowed field raises `ValueError` at serialise time, not just at lint
  time. Disabled-by-default is also asserted. Once-per-hour WARN is asserted via mock clock.
- **Credential leak**: `tests/adversarial/test_ti_feeds_credential_leak.py` actually captures
  `caplog`, iterates the live Prometheus `REGISTRY`, and inspects audit-log writes for the
  literal token strings — not a symbolic check.
- **Differential cleanup**: `tests/integration/test_ti_feeds_cleanup.py` asserts that the
  2 dropped indicators get DELETE'd from blocklist while the 3 surviving ones stay.
- **Conflict resolution / first writer wins**: `tests/integration/test_ti_feeds_conflict.py`
  asserts each feed's sidecar tracks only its own creations.
- **Bans path is `POST /api/v1/bans/{ip:path}`**: `tests/unit/analytics/ti_feeds/test_mgmt_client.py`
  asserts the URL the client calls — guards against the historical wrong-doc form.
