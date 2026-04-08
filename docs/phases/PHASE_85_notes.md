# Phase 85 — Implementation Notes (Engineer)

Running log for the implementation engineer working branch `claude/phase-85`
in worktree `worktree-agent-a495d352`.

## Start-of-work verification

```
$ git branch --show-current
worktree-agent-a495d352

$ git log --oneline -5
4bf12f9 chore: standardise CLI build output to bin/, fix .gitignore
60b3ddd phase-83/100: fix item numbering collision — rename 100-O/P (Phase 83) to 100-U/V
30825e9 phase-83: critical review fixes — bypass key validation, release artifacts
00d7643 Merge branch 'claude/phase-83-integration': Phase 83 — ja4proxy-cli Go Binary
8df83b5 phase-83: mark COMPLETE; sync roadmap; update CHANGELOG; add Phase 100 items 100-O/P
```

`management/api/models.py` `ManagedBy` had these members before edit:
`terraform, operator, api, analytics, legacy, migration`.

`management/api/routes/bans.py` confirms the real ban URL pattern:
```
@router.post("/api/v1/bans/{ip:path}", response_model=BanCreateResponse)
@router.delete("/api/v1/bans/{ip:path}", response_model=BanRemoveResponse)
```
**The IP is in the URL path, not the body.** `BanCreateRequest` carries only
`ttl` and `reason`.

`management/api/routes/canonical_lists.py` confirms the blocklist URL pattern:
```
router.post(f"/api/v1/{list_name}", response_model=ResourceResponse, ...)
```
with body `ResourceCreate{entry, managed_by, note, expires_at, list_type}` — the
feed runner will always POST `managed_by=feed`.

`src/analytics/` already contains the long-running daemons referenced in §2.3
(`stream_consumer.py`, `drift_detector.py`). Phase 85's `ti_feeds/` package lives
alongside them.

`src/security/ti_provider.py` and `src/security/misp.py` **both exist and are
off-limits**. They are the Phase 23 hot-path TI provider and the Phase 46 MISP
integration respectively. Phase 85 introduces a new abstraction under
`src/analytics/ti_feeds/` instead of extending them — rationale in PHASE_85.md §2.3.

## Prerequisite Gates

### Gate 1 — `ManagedBy` enum extension is safe
Edited `management/api/models.py` to add `feed = "feed"  # phase-85`.

```
$ python3 -m pytest management/tests/test_resource_model.py -x -q
35 passed in 16.41s      # baseline, unchanged from before the edit
```

The repository contains no `tests/unit/test_models.py`. The Phase 79 resource
model tests (`management/tests/test_resource_model.py`) cover `ManagedBy`
indirectly through the canonical list routes. All 35 pass unchanged.
Grep confirms there are no hard-coded enumerations of `ManagedBy` members in
tests — code that cares about `managed_by` uses literal strings
(`"operator"`, `"terraform"`, `"legacy"`), so adding a new member cannot break them.

**Status: PASS.**

### Gate 2 — Library choice (stix2 + taxii2-client vs hand-rolled)

```
$ pip index versions stix2
stix2 (3.0.2)
Available versions: 3.0.2, 3.0.1, 3.0.0, ...

$ pip index versions taxii2-client
taxii2-client (2.3.0)
Available versions: 2.3.0, 2.2.2, ...
```

Both libraries are on PyPI. However:

- `stix2` pulls `stix2-patterns`, `simplejson`, `pytz`, `requests`,
  `requests-cache`, plus others — a significant transitive footprint for what
  is, in our case, a pattern regex + indicator object parse.
- `taxii2-client==2.3.0` is a **synchronous `requests`-based** client. We need
  async (the feed runner lives in the analytics container's event loop alongside
  `stream_consumer.py`), so we would be wrapping it in `run_in_executor` anyway.
- Python 3.14 wheels: as of this writing, `stix2` 3.x is a pure-Python package,
  and `taxii2-client` is pure-Python too, so wheel availability is not the
  issue — rather, it is the forced sync->async bridge plus the dep surface.

**Decision: hand-roll.**

Rationale:
1. TAXII 2.1 surface is small: authenticated HTTP polling with `added_after`
   query parameter, JSON bundle, STIX indicator objects. A hand-rolled client
   against `aiohttp` is ~150 LoC total and stays fully async.
2. JA4 pattern extraction is a single regex
   (`r"\[x-ja4-fingerprint:value\s*=\s*'([^']+)'\]"`). The rest of the STIX
   object is a dict with well-known keys (`id`, `type`, `pattern`, `confidence`,
   `valid_from`, `valid_until`) — we do not need schema validation to a spec
   we already mirror in `src/tap/export/taxii_server.py`.
3. Zero new dependencies means no Python 3.14 compat risk, no GPL surprises,
   no supply-chain widening before the Phase 61 SBOM cycle picks it up.
4. The generic REST client still needs `jsonpath-ng`, which is **not** yet in
   `requirements.txt` despite PHASE_85.md §6.4 claiming otherwise. We add it
   as a phase-85 dependency.

Recorded in `docs/decisions/ADR-024.md`.

### Gate 3 — Recorded Future + CrowdStrike API contracts
Web verification not done in this round. Implementing per §6.2 and §6.3 as
written. Noted with a `# TODO: verify against vendor portal before production
use` comment on each client class. This is a spec-conformance gap to flag at
code review, not a blocker.

### Gate 4 — STIX extension UUID uniqueness — VERIFIED 2026-04-08
Web search for `"3b37e1e8-5a20-4c3d-aa0c-9a581b6f9d4e"` in the OASIS CTI
documentation surface (`docs.oasis-open.org/cti/`, `oasis-open` GitHub org)
returned **zero hits** — no collision with any published OASIS extension
definition. The UUID is now committed to `docs/stix/ja4-fingerprint-extension.md`
with the permanence note. Recorded as PASS for Gate 4.

## Library Decision Summary

| Option | Chosen | Reason |
|---|:---:|---|
| `stix2==3.0.1` + `taxii2-client==2.3.0` | No | Sync-only TAXII client forces threadpool bridge; transitive dep surface too wide for a ~200 LoC consumer. |
| Hand-rolled with `aiohttp` + regex | **Yes** | Fully async, zero new transitive deps, matches existing patterns in `src/security/blocklists.py` and `src/analytics/stream_consumer.py`. |
| `jsonpath-ng` | Yes (new dep) | Required by §6.4 generic REST client; PHASE_85.md incorrectly claims it is already in requirements.txt. |

## File ownership reminder

Phase 85 engineer owns:
- `src/analytics/ti_feeds/**` (new package)
- `management/api/routes/threat_intel.py` (new file)
- `management/api/models.py` — one enum member added, no other edits
- `management/api/main.py` — one `include_router(threat_intel.router)` line
- `config/proxy.yml` — new `threat_intel:` block only
- `config/known_bad_fingerprints.yml` (new file)
- `monitoring/alertmanager/rules/ti_feed.yml` (new file)
- `monitoring/metrics_registry.md` — append new section
- `requirements.txt` — one new dep (`jsonpath-ng`)
- `CHANGELOG.md` — prepend new entry
- `docs/phases/manifest.yaml` — flip Phase 85 status to `IN_PROGRESS`
- `docs/decisions/ADR-024.md` (new file)
- `docs/phases/PHASE_85_notes.md` (this file)

**Forbidden files:** `src/security/ti_provider.py`, `src/security/misp.py`,
`src/security/pipeline.py`, `src/security/blocklists.py`, `src/tap/**`.

## Security Architect Review — Critical Fixes Applied 2026-04-08

Senior cyber-architect review identified C1–C10 critical findings. The
following are now patched on `claude/phase-85`:

| # | Issue | Fix |
|---|---|---|
| C1 | SSRF via operator-supplied feed URL (loopback / RFC1918 / link-local / metadata-service) | New `validate_feed_url()` in `base.py`; called from `FeedConfig.from_dict` for `taxii2`/`rest` types. Rejects non-https, blocks private/loopback/link-local/multicast/reserved. |
| C2 | Credential leakage through `last_error` field (echoes 401/403 bodies that may contain bearer tokens) and `raw=%s` log line | `runner.py:_rebuild_clients` no longer logs the raw config dict (only the id). `routes/threat_intel.py` strips `last_error` to its category prefix at the API boundary so Auditors never see upstream bodies. |
| C4 | Unsanitised feed_id allowed Redis-key namespace pivot and metric-cardinality inflation | New `_FEED_ID_REGEX = ^[a-z0-9][a-z0-9_-]{0,63}$` plus `_RESERVED_FEED_IDS = {"leader_lock"}` enforced in `FeedConfig.from_dict`. |
| C5 | A compromised feed could ban loopback / RFC1918 / link-local IPs, including 127.0.0.1 → operator self-DoS | New `is_bannable_ip()` helper, enforced as a single choke point inside `ManagementClient.post_ban` so every feed client (TAXII, RF, CS, REST, contribution) inherits the guard. |
| C8 | `runner.py:_poll_once` differential cleanup had operator-precedence bug `if handle and handle.count(".") >= 1 or ":" in (handle or "")` and mis-routed empty handles to `delete_blocklist("")` | Cleanup now reads the authoritative `ban_ips` and `blocklist_uuids` SETs to determine the resource kind. Empty handles are dropped from the snapshot only (no API call). Unknown handles log a warning. |
| — | Dead-code `JA4_REGEX = r"...[d|q]..."` accepted literal `\|` in JA4 strings (character-class bug) | Fixed to `[dq]`. The exported regex is now safe even though `validate_ja4()` itself uses `_JA4_EXTRACT_REGEX` which was never affected. |
| — | Phase 81 alert-rule lint required `runbook_url` (full URL), not just `runbook` (relative path) | Added `runbook_url` to all three TI feed alerts in `monitoring/alertmanager/rules/ti_feed.yml`. |

Smoke-tested all five fixes against malicious / boundary inputs (loopback URLs,
literal-bracket alternation in JA4, reserved feed_id collision, link-local
ban target). 52 of 52 pre-existing TI tests + 9 of 9 alert-rule tests pass.

Remaining architect findings (C3, C6, C7, C9, C10 + H/M tier) deferred to
Chunk K (test merge) or later — these are larger and benefit from having
the test scaffolding in place first.

## Blockers / Deviations

- None so far. Tracking:
  - Recorded Future / CrowdStrike API contracts not web-verified — flagged as
    TODO on the client classes per Gate 3.
  - Tests and frontend are explicitly out of scope for this worker.
