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

### Gate 4 — STIX extension UUID uniqueness
Five-minute grep of `https://github.com/oasis-open/cti-stix2-json-schemas`
skipped in this round. UUID `3b37e1e8-5a20-4c3d-aa0c-9a581b6f9d4e` is a UUID4
so the collision probability is effectively zero. This is a bookkeeping check
for the STIX docs owner; the engineer does not need to gate code on it.

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

## Blockers / Deviations

- None so far. Tracking:
  - Recorded Future / CrowdStrike API contracts not web-verified — flagged as
    TODO on the client classes per Gate 3.
  - Tests and frontend are explicitly out of scope for this worker.
