# Phase 85: Threat Intelligence Ingestion

> **Prerequisites**
> - Phase 20 (TAP mode + TAXII publisher) — COMPLETE
> - Phase 79 (Management API, RBAC, token auth) — COMPLETE
> - Phase 80 (ECS structured logging) — COMPLETE
>
> Phase 20 delivers the outbound TAXII *publisher*. Phase 80 delivers the outbound event format.
> This phase delivers the symmetric inbound side: JA4proxy as a threat intelligence *consumer*.

---

## 1. Overview

JA4proxy already publishes threat intelligence via Phase 20 (`src/tap/export/taxii_server.py`).
This phase adds the inbound path: polling external feeds and turning STIX indicators into
JA4proxy rules through the Phase 79 Management API — not by writing to Redis directly.

The strategic opportunity is that JA4proxy sees the TLS fingerprint of every threat actor —
something IP-reputation feeds do not capture. A curated JA4 fingerprint exchange format
becomes a reusable standard for the security community. This phase defines that standard and
ships the client code to consume it.

### 1.1 Deliverables

1. **TAXII 2.1 consumer** — polls STIX 2.1 indicators from any TAXII 2.1 server.
2. **`x-ja4-fingerprint` custom Cyber Observable Object (SCO)** — STIX 2.1 extension for JA4 values.
3. **Recorded Future connector** — thin wrapper over the TAXII client.
4. **CrowdStrike Falcon Intel connector** — OAuth2 REST client (Falcon does not expose TAXII).
5. **Generic REST connector** — configurable JSONPath-driven client for internal platforms.
6. **Bundled seed file** — `config/known_bad_fingerprints.yml` with ≥10 vetted fingerprints.
7. **Feed management API + UI** — enable/disable/monitor per feed through Phase 79.
8. **Community contribution client stub** — opt-in, disabled; hosted endpoint does not yet exist.

### 1.2 Non-goals

| Not in scope | Why |
|---|---|
| Running a hosted community feed (`https://feed.ja4proxy.io/`) | Business track, see §13 |
| MISP integration | Already delivered by Phase 46 (`src/security/misp.py`) |
| Hot-path scoring signals from feeds | Phase 23 `TIProvider` already covers that (`src/security/ti_provider.py`) |
| Replacing Phase 8 Spamhaus blocklists | Spamhaus stays as-is; this phase is additive |
| OASIS TC registration of the extension | Done as a community PR in §13, not a blocking gate |

### 1.3 The Contribution Flywheel

The longer the product is deployed, the more JA4 fingerprints it accumulates. A curated,
community-sourced JA4 feed becomes a strategic moat — applying the same reputation flywheel
Spamhaus built for IPs to TLS client behaviour. Phase 85 delivers the engineering pieces
(client code, seed file, STIX extension, stubbed contribution endpoint); §13 describes the
non-engineering work to light up the hosted service.

### 1.4 Current Status & Remaining Work (review 2026-04-08)

> Read this section first if you are picking the phase up. It supersedes the
> impression you might form by skimming §3–§13.

**Already committed on `claude/phase-85`:**

| Area | Status | Notes |
|---|---|---|
| `src/analytics/ti_feeds/` package (14 modules, ~3.1k LoC) | DONE | base, runner, state, circuit_breaker, mgmt_client, taxii, recorded_future, crowdstrike, rest_generic, seed_file, contribution, stix_ja4, metrics, `__init__` |
| `management/api/routes/threat_intel.py` (5 routes) | DONE | Wired in `management/api/main.py` |
| `ManagedBy.feed` enum extension + `TIFeedStatus` models | DONE | `management/api/models.py` |
| `config/known_bad_fingerprints.yml` (14 entries) | DONE | Exceeds the >=10 acceptance bar |
| `config/proxy.yml` — `threat_intel:` block | DONE | |
| `monitoring/alertmanager/rules/ti_feed.yml` | DONE | Three alerts present |
| `monitoring/metrics_registry.md` Phase-85 section | DONE | All 8 + seed-file metric documented |
| ADR-024 (hand-rolled STIX/TAXII decision) | DONE | Hand-roll chosen over `stix2`+`taxii2-client` |

**Being produced in a parallel test worktree (`agent-a0d4a2b5`, NOT yet merged):**

- `tests/unit/analytics/ti_feeds/` — base, state, circuit_breaker, mgmt_client, taxii, recorded_future, crowdstrike, rest_generic, stix_ja4, seed_file, contribution
- `tests/integration/test_ti_feeds_{e2e,cleanup,conflict,hot_reload}.py`
- `tests/adversarial/test_ti_feeds_{malformed_stix,huge_bundle,credential_leak}.py`
- `tests/chaos/test_ti_feed_{taxii_unavailable,mgmt_api_429,redis_unavailable}.py`

If you are not the test author, **do not write tests in this branch** — pull from the test
worktree at merge time (Chunk K).

**Missing — these are the bite-sized work items in §1.5.** Pick one chunk, finish it, commit,
then take the next. Do not bundle chunks unless they share a single concern.

---

## 1.5 Bite-Sized Work Items (for less-experienced workers)

Each chunk has: **goal**, **files to touch**, **how to verify**, **definition of done**.
Chunks are independent unless marked otherwise.

### Chunk A — Add `jsonpath-ng` to `requirements.txt`  *(15 min, blocks installs)*

**Goal:** `rest_generic.py` imports `jsonpath_ng.parse`; the dependency was never added.
A clean `pip install -r requirements.txt` will leave `rest_generic` non-functional.
ADR-024 explicitly says this dep would be added — it was not.

**Files:** `requirements.txt`

**Action:** append at the bottom:

```
jsonpath-ng==1.6.1  # phase-85: REST generic TI feed client
```

(Use the latest 1.6.x available on PyPI; do not pin newer than what is tested elsewhere.)

**Verify:**

```
pip install jsonpath-ng==1.6.1
python3 -c "from src.analytics.ti_feeds import rest_generic; print('ok')"
```

**Done when:** import succeeds and the line lives at the bottom of `requirements.txt`
with the `# phase-85` comment.

---

### Chunk B — Wire `TIFeedRunner` into the analytics container  *(1–2 h, makes feature actually run)*

**Goal:** Today the runner exists but nothing starts it. The analytics container
(`src/analytics/main.py`) starts only the HTTP server. The feed runner must be launched
as a background `asyncio.Task` next to the existing analytics daemons.

**Files:** `src/analytics/main.py` only.

**Action:**

1. Read the existing startup sequence (look for `_start_http_server`).
2. After the HTTP server starts, instantiate `TIFeedRunner` from
   `src.analytics.ti_feeds.runner`. Pass it: the loaded `config.threat_intel` block, the
   shared `aiohttp.ClientSession`, the Redis client, and the management-API base URL +
   bearer token from env (`JA4PROXY_FEED_CLIENT_TOKEN`).
3. Start it with `asyncio.create_task(runner.run())` and store the handle.
4. On shutdown, call `runner.stop()` and `await` the task with a 5 s timeout.
5. If `config.threat_intel.enabled` is `False` or absent, log INFO `"ti_feeds disabled"` and skip.

**Verify:** start the analytics container locally with `threat_intel.enabled: true` and a
single disabled feed; logs show `"ti_feeds runner started"` and clean shutdown on SIGTERM.

**Done when:** runner starts, runs at least one scheduling tick, and shuts down cleanly.

**Do not:** edit `runner.py` itself in this chunk — just call it.

---

### Chunk C — `docs/REDIS_SCHEMA.md` updates  *(30 min)*

**Goal:** Document the six `ti_feed:*` keys from §2.2 in the canonical schema doc.

**Files:** `docs/REDIS_SCHEMA.md`

**Action:** Append a new `## Phase 85 — Threat Intelligence Feeds` section. Copy the table
from §2.2 of this phase doc. For each key state: pattern, type, TTL, writer, reader, purpose.
Mention that `ti_feed:leader_lock` follows the Phase 8 leader-election pattern and has
30 s TTL.

**Done when:** all six keys are present and the file still parses as Markdown.

---

### Chunk D — `CHANGELOG.md` entry  *(15 min)*

**Goal:** Standard format Phase 85 entry at the top of `CHANGELOG.md`.

**Files:** `CHANGELOG.md`

**Action:** Prepend `## [85] - 2026-04-XX - Threat Intelligence Ingestion` with sub-sections
**Added** (the package, routes, models, seed file, alerts, ADR-024) and **Notes** (no
breaking changes; `ManagedBy` enum now includes `feed`). Match the voice of the existing
Phase 83 entry.

**Done when:** entry is at the top, format matches existing entries, no other phases edited.

---

### Chunk E — `docs/phases/manifest.yaml` flip to IN_PROGRESS  *(5 min, do once)*

**Goal:** The manifest still says `status: PROPOSED`. Until §12 acceptance criteria fully
pass, it should be `IN_PROGRESS`. Flip to `COMPLETE` only after Chunk L passes.

**Files:** `docs/phases/manifest.yaml` (Phase 85 block only — no other edits)

**Action:** change `status: PROPOSED` to `status: IN_PROGRESS`. Run `make sync` (regenerates
TODO.md and PROJECT_STATUS.md). Commit all three regenerated files together.

**Done when:** `make sync` is clean and the regenerated docs include the new status.

---

### Chunk F — STIX extension docs (`docs/stix/`)  *(2–3 h, no Python)*

**Goal:** The `x-ja4-fingerprint` SCO extension is the standards-track deliverable. Code
is done; the spec docs do not exist.

**Files (all NEW, mkdir `docs/stix/` and `docs/stix/ja4-fingerprint/`):**

1. `docs/stix/README.md` — index pointing to the other two
2. `docs/stix/ja4-fingerprint-extension.md` — prose spec, copy/expand §4 of this phase doc
3. `docs/stix/ja4-fingerprint/schema.json` — JSON Schema for the SCO

**Action steps for the schema (the only non-mechanical part):**

- Top-level `$schema: "https://json-schema.org/draft/2020-12/schema"`.
- `type: object`, `required: [type, spec_version, id, value]`.
- `properties.type.const = "x-ja4-fingerprint"`.
- `properties.value`: copy the JA4 regex from `src/analytics/ti_feeds/stix_ja4.py` rather
  than re-deriving — schema and code must match exactly.
- `properties.extensions` accepting the extension-definition UUID
  `extension-definition--3b37e1e8-5a20-4c3d-aa0c-9a581b6f9d4e`.
- Validate the example SCO from §4.2 of this phase doc against your schema:

  ```
  python3 -c "import jsonschema, json; jsonschema.validate(json.load(open('example.json')), json.load(open('docs/stix/ja4-fingerprint/schema.json')))"
  ```

**For the prose doc:** include the §4.1, §4.2, §4.3 worked examples verbatim. Add the
permanence note: *"This UUID is permanent. Do not change post-publication."* on the
extension-definition UUID line.

**Done when:** all three files exist, schema validates the example, README links them.

---

### Chunk G — Verify Recorded Future API contract (Gate 3, partial)  *(1 h, web research)*

**Goal:** `src/analytics/ti_feeds/recorded_future.py` was implemented from this phase doc
without checking the live RF developer portal. Gate 3 was deferred in the notes file.

**Action (research only — do not edit code):**

1. Read `src/analytics/ti_feeds/recorded_future.py` end to end. Note every URL, header,
   query parameter, and JSON field name it depends on.
2. Visit the Recorded Future developer portal documentation (operator-supplied URL — ask
   if you don't have one).
3. For each URL/header/field, write one line: matches docs / mismatches doc says X.
4. Record findings in `PHASE_85_notes.md` under `## Gate 3 — Recorded Future verification`.
5. **If mismatches found:** open a fresh `## Followups` section. Do **not** patch the
   client code in this chunk — surface the mismatches and let a human decide.

**Done when:** notes file has the verification table and either "no changes needed" or a
followup list.

---

### Chunk H — Verify CrowdStrike Falcon Intel API contract (Gate 3, partial)  *(1 h, web research)*

**Goal:** Same as Chunk G but for `crowdstrike.py`. Specifically verify:

- `POST /oauth2/token` with `scope=indicators:read` (vs the broader scope some clients use)
- `GET /intel/combined/indicators/v1` query parameters: `type`, `malicious_confidence`,
  pagination cursor field name
- Response envelope: `resources[]`, `meta.pagination.offset` cursor — confirm these field
  names against current docs

**Action:** same shape as Chunk G — research, table, no code edits.

**Done when:** `PHASE_85_notes.md` has a `## Gate 3 — CrowdStrike verification` table.

---

### Chunk I — STIX extension UUID uniqueness check (Gate 4)  *(15 min)*

**Goal:** Five-minute search of `https://github.com/oasis-open/cti-stix2-json-schemas` for
the literal string `3b37e1e8-5a20-4c3d-aa0c-9a581b6f9d4e`. Add a one-line confirmation to
`PHASE_85_notes.md` under `## Gate 4 — STIX UUID uniqueness`.

**Done when:** the line exists with the search URL and date.

---

### Chunk J — Frontend "Threat Intelligence" page  *(1–2 days, React)*

**Goal:** §8.3 calls for a UI page. The backend routes are ready (§8.1). Add a single
React route `/threat-intel` that calls `GET /api/v1/threat-intel/feeds` and renders one
card per feed.

**Files:** under `frontend/src/` (exact layout depends on the existing Phase 79 frontend
shell — read `frontend/src/routes/` first to mimic an existing page like `/blocklist`).

**Per card:**

- Feed id, type, status badge (green/yellow/red mapped from `status` field).
- Indicators managed, 24h additions/removals.
- Last poll time, next poll time.
- Enable/Disable toggle (only visible if user role >= Operator). On toggle, call
  `POST /api/v1/threat-intel/feeds/{id}/enable` or `.../disable`.
- "Poll now" button (Operator only). Calls `POST .../poll`.
- Last error message + timestamp if `error_count_24h > 0`.

**Tests:** add an entry in `tests/unit/test_pages.py`:

- GET `/threat-intel` with valid auth → 200, `text/html`, body contains `"Threat Intelligence"`.
- GET `/threat-intel` without auth → status code < 500.

**Done when:** page loads in a dev server, both `test_pages.py` cases pass, role-gated
controls are hidden for Auditor role.

---

### Chunk K — Merge the test worktree  *(30–60 min, COORDINATION REQUIRED)*

**Goal:** A parallel worktree (`agent-a0d4a2b5`) holds Phase 85 unit/integration/adversarial/
chaos tests. They were authored against the committed code on `claude/phase-85`, so the
merge should be clean.

**Action:**

1. Read the test worktree commit log to confirm scope:
   `git -C .claude/worktrees/agent-a0d4a2b5 log --oneline`.
2. Cherry-pick or merge the test commits onto `claude/phase-85` — preserve all commit
   messages, do not squash.
3. Run `make test` from a clean checkout. **All Phase 85 tests must pass; existing tests
   must not regress.** Per the project test count baseline (2687 pass / 21 skip), the new
   total should be `2687 + N` where N is the count of new tests added, with no failures.
4. If any test fails, do **not** delete or `xfail` it. Diagnose the root cause; the test
   author and the implementation author must agree on the fix. Note disagreements in
   `PHASE_85_notes.md`.

**Done when:** `make test` is green and the test count delta matches the test commit log.

---

### Chunk L — Acceptance gate sweep & manifest flip to COMPLETE  *(1 h, last chunk)*

**Goal:** Walk every checkbox in §12. Each passing item gets a one-line proof in
`PHASE_85_notes.md` (test name, file path, command output, or doc URL). Each failing item
becomes a new chunk above. Only when **every** §12 checkbox is checked do you:

1. Flip `docs/phases/manifest.yaml` Phase 85 to `status: COMPLETE`.
2. Run `make sync`.
3. Commit `manifest.yaml`, `TODO.md`, `PROJECT_STATUS.md`, and `PHASE_85_notes.md` as one
   atomic commit.
4. Push and open the merge to `main`.

**Done when:** all of §12 is verifiable from `PHASE_85_notes.md` and `make sync` is clean.

---

### Chunk dependency graph

```
A (jsonpath-ng) ──┐
                  ├──► K (merge tests) ──► L (gate sweep)
B (wire runner) ──┘                                ▲
                                                   │
C (REDIS_SCHEMA) ──┐                               │
D (CHANGELOG)     ─┤                               │
E (manifest flip) ─┼──────────────────────────────►│
F (docs/stix/)    ─┤                               │
G (RF gate)       ─┤                               │
H (CS gate)       ─┤                               │
I (UUID gate)     ─┤                               │
J (frontend)      ─┘                               │
```

A, B, K are on the **critical path** — without them the feature does not run or has no
test coverage. C–I are documentation/verification and parallel-safe. J is the biggest
single chunk and is also parallel-safe (different files).

---

## 2. Integration With Existing Infrastructure

This phase is a **consumer of the Phase 79 Management API**, not a peer system. All rule
mutations flow through REST so that audit logs, RBAC, and the resource model stay consistent
with manual and Terraform-managed entries.

### 2.1 Management API Endpoints Actually Called

| Intent | Method | Path | Body |
|---|---|---|---|
| Add IP ban | `POST` | `/api/v1/bans/{ip:path}` | `BanCreateRequest{ttl:int, reason:str}` |
| Remove IP ban | `DELETE` | `/api/v1/bans/{ip:path}` | — |
| List active bans (for reconciliation) | `GET` | `/api/v1/bans` | — |
| Add JA4/blocklist entry | `POST` | `/api/v1/blocklist` | `ResourceCreate{entry, managed_by, note, expires_at}` |
| Remove blocklist entry | `DELETE` | `/api/v1/blocklist/{resource_id}` | — |
| List blocklist (filtered) | `GET` | `/api/v1/blocklist?managed_by=feed` | — |

> **Important:** `POST /api/v1/bans/{ip:path}` takes the IP in the URL path (URL-decoded so
> IPv6 addresses work percent-encoded) — **not** a JSON body field. The body contains only
> `ttl` and `reason`. Earlier drafts of this phase incorrectly described a
> `POST /api/v1/bans` endpoint with an `ip` body field; workers must not reintroduce that.

**Auth**: the feed client holds an Operator-role bearer token minted via the Phase 79 token
endpoint. The token lives in the analytics container as environment variable
`JA4PROXY_FEED_CLIENT_TOKEN`. Rotation is operator responsibility; no auto-rotation in this
phase.

### 2.2 Provenance Model

Phase 79's `ManagedBy` enum (`management/api/models.py`) is closed. Phase 85 extends it with
exactly one new member:

```python
# management/api/models.py — phase-85 edit
class ManagedBy(str, Enum):
    terraform = "terraform"
    operator = "operator"
    api = "api"
    analytics = "analytics"
    legacy = "legacy"
    migration = "migration"
    feed = "feed"              # phase-85
```

Because `managed_by=feed` alone does not identify *which* feed, Phase 85 maintains its own
Redis sidecar index keyed by feed ID. The Management API does not know about this index —
it is internal to the feed runner:

| Key | Type | Purpose | TTL |
|---|---|---|---|
| `ti_feed:{feed_id}:blocklist_uuids` | SET | Resource UUIDs created by this feed | none |
| `ti_feed:{feed_id}:ban_ips` | SET | IP strings banned by this feed | none |
| `ti_feed:{feed_id}:active_stix_ids` | HASH | `{stix_indicator_id → resource_uuid_or_ip}` — the set of indicators present in the last successful poll, used for differential cleanup | none |
| `ti_feed:{feed_id}:poll_state` | HASH | `{last_success_ts, last_error_ts, last_added_after, circuit_state, failure_count, consecutive_successes}` | none |
| `ti_feed:{feed_id}:runtime_enabled` | String (`"1"`/`"0"`) | UI toggle override; unset → use config | none |
| `ti_feed:leader_lock` | String + TTL | Single-leader election across analytics replicas (Phase 8 pattern) | 30s |

Each feed-created blocklist resource carries `note="feed:{feed_id}:{stix_indicator_id}"` so
that `GET /api/v1/blocklist/{id}` shows the source without needing the sidecar.

Feed-created bans carry `reason="feed:{feed_id}"` for the same reason.

**Invariant:** *Rules created by a feed are only removed by that feed's cleanup pass or by
an explicit human delete.* A feed never touches rules it did not create, even if it finds
an exact duplicate — duplicates are resolved by §2.4.

### 2.3 Why Not Reuse `src/security/ti_provider.py`?

Phase 23's `TIProvider` ABC (`src/security/ti_provider.py`) is a *hot-path scorer* — it
contributes `RiskSignal` values during live connection processing. Phase 85 feeds are
*batch pollers* writing persistent rules through REST. Different responsibilities,
different lifetimes, different failure modes. Trying to shoehorn batch polling into
`TIProvider` would force the scorer to worry about TAXII state machines.

Phase 85 therefore introduces a new abstraction under `src/analytics/ti_feeds/` alongside
the existing analytics daemons (`stream_consumer.py`, `drift_detector.py`, etc.).
`TIProvider` is left untouched.

### 2.4 Conflict Resolution Between Feeds

Two different feeds may publish the same JA4 or IP. The rule is:

1. **First writer wins.** The feed runner attempts to `POST`; if the Management API returns
   the existing resource (idempotent — canonical_lists.py returns 200 with the pre-existing
   record), the feed does *not* claim that UUID in its sidecar.
2. **Each feed tracks only rules it created.** If feed A created a rule and feed B later
   sees the same indicator, feed B records nothing and cleanup for feed B ignores the rule.
3. **Cleanup races**: if feed A removes its last indicator for a JA4 that feed B also
   publishes, feed B will recreate it on the next poll. This is acceptable — the window is
   bounded by the longer of the two poll intervals.

This is simpler than reference-counting and is the pattern Phase 79 Terraform provider
(anthropic's in-house) already assumes.

### 2.5 Bulk Ingest & Rate Limiting

A single TAXII poll can return thousands of indicators. Workers must:

- Process indicators in **batches of 50**, with `asyncio.gather(*, return_exceptions=True)`
  per batch so one bad indicator never stalls the poll.
- Sleep **50 ms between batches** to stay under the Phase 79 rate limiter
  (operator role: 100 req/s default — see `management/api/rate_limit.py`).
- Abort the poll (not the feed) if more than 10% of indicators in a poll return HTTP 5xx —
  this indicates a Management API problem, not a feed problem. Circuit-break the feed only
  if three *full* polls fail in a row.

---

## 3. Prerequisite Verification Gates

Workers must verify the following **before writing any code**. Each gate produces a
one-line confirmation recorded in `PHASE_85_notes.md` along with the URL or command that
proved it.

1. **`ManagedBy` enum extension is safe.** Adding `feed = "feed"` must not break:
   - `tests/unit/test_models.py`
   - Terraform provider fixtures (Phase 83 / Phase 93)
   - Any frontend TypeScript type mirror in `frontend/src/types/` (if present)
2. **Library choice**: decide between `stix2==3.0.1` + `taxii2-client==2.3.0` (OASIS-maintained)
   vs hand-rolled `aiohttp` parsing. Default to the libraries; fall back to hand-rolled only
   if transitive deps are unacceptable. Record the decision in ADR-024.
3. **Python 3.14 wheel availability** for `stix2` and `taxii2-client` (Phase 67 moved the
   analytics container to 3.14). Check PyPI; if no wheels, pin to source build or use
   3.11-compat subset.
4. **Recorded Future API contract**: verify the described token-exchange and collection IDs
   against the RF developer portal. Cite the dev-docs URL. If the vendor has changed the API
   since this doc was written, update §5.1 before implementing.
5. **CrowdStrike Falcon Intel API contract**: confirm `POST /oauth2/token` scope and
   `GET /intel/combined/indicators/v1` query parameters against the current Falcon docs.
   Cite the URL in `PHASE_85_notes.md`.
6. **STIX extension UUID uniqueness**: search
   `https://github.com/oasis-open/cti-stix2-json-schemas` for
   `3b37e1e8-5a20-4c3d-aa0c-9a581b6f9d4e`. (Collision is astronomically unlikely for a UUID4,
   but a human may have picked the same value — this is a five-minute check, not a gate that
   changes the code.) Record the confirmed UUID as permanent in
   `docs/stix/ja4-fingerprint-extension.md` with the note *"This UUID is permanent. Do not
   change post-publication."*

If any gate fails or cannot be verified, open a note in `PHASE_85_notes.md` and raise at the
daily standup. Do not work around unverified assumptions.

---

## 4. JA4 STIX 2.1 Extension

The standard STIX 2.1 spec allows only `stix | pcre | sigma | snort | suricata | yara` as
values for `Indicator.pattern_type`. A new pattern type cannot be invented without a
custom SDO. The correct approach is:

1. Define `x-ja4-fingerprint` as a **new Cyber Observable Object (SCO)** via a STIX extension
   with `extension_type: "new-sco"`.
2. Keep `pattern_type: "stix"` on `Indicator` objects, and reference the new SCO inside the
   pattern expression: `[x-ja4-fingerprint:value = '…']`.

This is consistent with the Phase 20 TAP TAXII *publisher* (`src/tap/export/taxii_server.py`
already emits `"pattern_type": "stix"`), so publisher and consumer round-trip cleanly.

### 4.1 Extension Definition

```json
{
  "type": "extension-definition",
  "spec_version": "2.1",
  "id": "extension-definition--3b37e1e8-5a20-4c3d-aa0c-9a581b6f9d4e",
  "name": "JA4 Fingerprint SCO",
  "description": "Defines x-ja4-fingerprint as a STIX 2.1 Cyber Observable Object representing a JA4 TLS ClientHello fingerprint.",
  "created": "2026-04-08T00:00:00Z",
  "modified": "2026-04-08T00:00:00Z",
  "created_by_ref": "identity--ja4proxy-project",
  "schema": "https://ja4proxy.io/stix/extensions/ja4-fingerprint/schema.json",
  "version": "1.0",
  "extension_types": ["new-sco"]
}
```

### 4.2 `x-ja4-fingerprint` SCO

```json
{
  "type": "x-ja4-fingerprint",
  "spec_version": "2.1",
  "id": "x-ja4-fingerprint--0e3b8c44-5f2e-4d2a-9ed7-8a1a2b3c4d5e",
  "value": "t10d170900_9dc949161b6c_b64c0ad42cb7",
  "extensions": {
    "extension-definition--3b37e1e8-5a20-4c3d-aa0c-9a581b6f9d4e": {
      "extension_type": "new-sco",
      "likely_category": "c2_framework",
      "likely_tool": "cobalt_strike",
      "ja4x": null,
      "source": "ja4proxy-community-feed"
    }
  }
}
```

### 4.3 Indicator Referencing the SCO

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--a1b2c3d4-5678-4aaa-9bbb-ccccddddeeee",
  "name": "Cobalt Strike default TLS profile",
  "pattern_type": "stix",
  "pattern": "[x-ja4-fingerprint:value = 't10d170900_9dc949161b6c_b64c0ad42cb7']",
  "indicator_types": ["malicious-activity"],
  "confidence": 95,
  "valid_from": "2026-04-08T00:00:00Z",
  "kill_chain_phases": [
    {"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}
  ]
}
```

The consumer parses `pattern` with a small regex targeting `x-ja4-fingerprint:value = '…'`
and extracts the JA4 string. The `stix2` library can also be used for full parsing.

### 4.4 Documentation

- `docs/stix/ja4-fingerprint-extension.md` — prose specification and worked examples.
- `docs/stix/ja4-fingerprint/schema.json` — JSON Schema for the SCO (for publishing to
  `https://ja4proxy.io/stix/extensions/ja4-fingerprint/schema.json` as a business-track item).
- `docs/stix/README.md` — index pointing to both of the above.

Voice: neutral technical prose. No marketing claims like "establishes JA4proxy as the
reference implementation". Describe the extension, not the project.

---

## 5. Feed Implementations

### 5.1 File Layout

```
src/analytics/ti_feeds/
├── __init__.py
├── base.py              # FeedClient ABC; FeedPollResult dataclass
├── runner.py            # AsyncIO scheduler; polls enabled feeds on their intervals
├── state.py             # Redis sidecar index (§2.2) read/write
├── circuit_breaker.py   # Per-feed CLOSED/OPEN/HALF-OPEN state machine
├── mgmt_client.py       # aiohttp client for Phase 79 Management API
├── taxii.py             # TAXII 2.1 client (uses taxii2-client lib)
├── recorded_future.py   # Thin wrapper over taxii.py
├── crowdstrike.py       # Falcon Intel REST OAuth2 client
├── rest_generic.py      # JSONPath-driven REST client
├── seed_file.py         # Loader for config/known_bad_fingerprints.yml
├── stix_ja4.py          # Extension schema loader + parse helpers
└── contribution.py      # Stub client for future community feed
```

Tests live under `tests/unit/analytics/ti_feeds/` with one module per source file, plus
`tests/integration/test_ti_feeds_e2e.py` for API round-trip tests.

### 5.2 `FeedClient` Base Class

```python
# src/analytics/ti_feeds/base.py

@dataclass
class FeedPollResult:
    feed_id: str
    stix_ids_seen: set[str]              # indicator ids present in this poll
    created: list[tuple[str, str]]       # (stix_id, resource_uuid_or_ip) pairs newly added
    skipped_below_confidence: int
    errors: list[str]
    poll_duration_s: float

class FeedClient(abc.ABC):
    def __init__(self, config: FeedConfig, mgmt: ManagementClient, state: FeedState): ...

    @abc.abstractmethod
    async def poll(self) -> FeedPollResult:
        """Fetch current indicators and apply them via the Management API.

        Implementers MUST:
        - Respect config.min_confidence
        - Call state.record_created(...) for every new rule
        - Populate FeedPollResult.stix_ids_seen with ALL indicators that passed confidence
        - Never delete rules — cleanup is handled by runner.py via state diff
        """
```

### 5.3 Cleanup Pass (Differential)

After every successful poll:

```python
# runner.py — pseudo-code
result = await feed.poll()
previous_ids = await state.get_active_stix_ids(feed_id)
dropped_ids  = previous_ids.keys() - result.stix_ids_seen
for stix_id in dropped_ids:
    handle = previous_ids[stix_id]     # UUID or IP
    await mgmt.delete(handle)           # routed to blocklist or bans endpoint
    await state.remove(feed_id, stix_id)
# Replace the active set atomically
await state.replace_active_stix_ids(feed_id, new_ids=result.stix_ids_seen)
```

This closes the *"what was removed from the feed?"* gap that the previous draft left open.

### 5.4 Circuit Breaker

Per-feed CLOSED → OPEN → HALF-OPEN state machine. Tunables live in `config/proxy.yml` under
`threat_intel.circuit_breaker:`:

```yaml
threat_intel:
  circuit_breaker:
    failure_threshold: 3       # consecutive failures before opening
    open_timeout_s: 600        # 10 minutes before HALF-OPEN probe
    backoff_max_s: 3600        # max backoff: 1 hour
```

**Naming note**: Phase 14e / Phase 59 already defined
`threat_intelligence.circuit_breaker_failure_threshold` and `recovery_probe_interval` for
the hot-path TI providers. Phase 85 uses a **distinct block** (`threat_intel.circuit_breaker`)
because the batch-poller semantics differ — the hot-path breaker opens on a single failing
call; the batch breaker opens on N consecutive poll cycles. Do not conflate them.

### 5.5 Indicator Processing Flow

```
for indicator in poll_response.objects:
    if indicator.type != "indicator": continue
    if indicator.confidence < feed.min_confidence:
        metrics.skipped_below_confidence.inc()
        log.debug("below-confidence", ...)
        continue
    if is_ip_pattern(indicator.pattern):
        ip = parse_ip(indicator.pattern)
        await mgmt.post_ban(ip, ttl=feed.ban_ttl, reason=f"feed:{feed.id}")
        state.mark(feed.id, indicator.id, handle=ip, kind="ban")
    elif is_ja4_pattern(indicator.pattern):
        ja4 = parse_ja4(indicator.pattern)
        resp = await mgmt.post_blocklist(
            entry=ja4,
            managed_by="feed",
            note=f"feed:{feed.id}:{indicator.id}",
            expires_at=indicator.valid_until,
        )
        state.mark(feed.id, indicator.id, handle=resp.id, kind="blocklist")
    else:
        metrics.unsupported_pattern.inc(labels={"feed": feed.id})
```

`is_ip_pattern` and `is_ja4_pattern` live in `stix_ja4.py`.

---

## 6. Feed Configuration

### 6.1 TAXII 2.1

```yaml
# config/proxy.yml
threat_intel:
  enabled: true
  feeds:
    - id: taxii-isac
      type: taxii2
      url: "https://taxii.example-isac.org/taxii2/"
      collection_id: "enterprise-attack"
      username: "${TAXII_ISAC_USERNAME}"
      password: "${TAXII_ISAC_PASSWORD}"
      poll_interval_minutes: 60
      enabled: true
      min_confidence: 70
      ban_ttl_hours: 168       # 7 days
      consume: [indicator]
```

Env var expansion uses the existing `config/loader.py` helper (Phase 0). Any `${VAR}`
reference unresolved at load time is an error — the feed is disabled with a startup WARN,
not silently retried.

### 6.2 Recorded Future

```yaml
    - id: recorded-future
      type: recorded_future
      api_token: "${RF_API_TOKEN}"
      feeds:
        - ip_threat_intel
        - c2_server_tracking
      min_rf_risk_score: 75
      ban_ttl_hours: 72
      enabled: false           # opt-in
```

### 6.3 CrowdStrike Falcon Intel

```yaml
    - id: crowdstrike-falcon
      type: crowdstrike
      client_id: "${CS_CLIENT_ID}"
      client_secret: "${CS_CLIENT_SECRET}"
      indicator_types: [ip_address]
      min_malicious_confidence: high    # low|medium|high
      poll_interval_minutes: 30
      ban_ttl_hours: 48
      enabled: false
```

Falcon Intel uses OAuth2 client credentials flow:

1. `POST https://api.crowdstrike.com/oauth2/token` with `scope=indicators:read`
2. `GET /intel/combined/indicators/v1?type=ip_address&malicious_confidence=high`
3. Paginate via the `Meta.Pagination.Offset` cursor (cursor-based, not page-based).

### 6.4 Generic REST

```yaml
    - id: internal-ti
      type: rest
      url: "https://threatintel.corp.internal/api/v1/indicators"
      auth:
        type: bearer
        token: "${INTERNAL_TI_TOKEN}"
      ip_jsonpath: "$.indicators[*].value"
      ttl_jsonpath: "$.indicators[*].expires_in"
      ban_ttl_hours: 24
      poll_interval_minutes: 15
```

Uses `jsonpath-ng` (already in `requirements.txt` from Phase 46). No new dependency.

---

## 7. Curated JA4 Fingerprint Feed

### 7.1 Bundled Seed File

Ship `config/known_bad_fingerprints.yml` with **at least 10** vetted fingerprints from public
security research. Loaded at startup if `threat_intel.seed_file.enabled: true`, routed
through the Management API the same way as any feed (so the entries get `managed_by=feed`
and `note=feed:seed_file:...`).

```yaml
# config/known_bad_fingerprints.yml — phase-85
# Source: public security research, verified against production traffic.
# Loaded at startup when threat_intel.seed_file.enabled: true.
fingerprints:
  - ja4: "t10d170900_9dc949161b6c_b64c0ad42cb7"
    name: "Cobalt Strike default TLS profile"
    category: c2_framework
    source: "https://github.com/FoxIO-LLC/ja4/tree/main/technical_details"
    confidence: 98
  # ... at least 9 more entries, each with ja4, name, category, source, confidence
```

Workers must provide **≥10 real entries** in the final commit — this is the acceptance
criterion. The previous draft's three-entry example is illustrative only.

### 7.2 Community Contribution Client (Stub)

The contribution client code exists but is disabled by default. When the hosted feed
service is lit up (see §13), customers opt in:

```yaml
threat_intel:
  feed_contribution:
    enabled: false             # opt-in, never default
    submit_threshold: 90
    submit_min_occurrences: 100
    anonymise: true
    endpoint: "https://feed.ja4proxy.io/api/v1/contribute"   # future hosted service
    api_key: "${JA4PROXY_FEED_API_KEY}"
```

**If `enabled: true` and the endpoint is unreachable**, log a single WARNING per hour and
continue — do not retry in a tight loop.

### 7.3 GDPR / Privacy Constraints on Contributions

The `anonymise: true` flag is not sufficient on its own. Workers must ensure contributed
data contains **none of the following**:

- Raw source IP addresses (use `/24` or `/48` CIDRs if network context is essential).
- Full URLs or `Host` headers.
- TLS SNI values (could leak internal hostnames).
- Timestamps at finer than 1-hour bucketing.
- Any field sourced from `AuditLog` or `enrichment.*`.

The payload schema is a closed whitelist of fields:
`{ja4, category, triggering_signals[], occurrences_count, first_seen_bucket, last_seen_bucket, confirmed_fp_rate}`.

A unit test in `tests/unit/analytics/ti_feeds/test_contribution.py` asserts that
any attempt to serialise a disallowed field raises `ValueError`. This is the hard gate,
not a convention.

Reference: Phase 21 GDPR hardening doc (`docs/compliance/GDPR.md`).

---

## 8. Feed Management API & UI

### 8.1 New API Endpoints

Added to `management/api/routes/threat_intel.py`:

| Method | Path | Role | Purpose |
|---|---|---|---|
| `GET` | `/api/v1/threat-intel/feeds` | Auditor | List all feeds with status |
| `GET` | `/api/v1/threat-intel/feeds/{feed_id}` | Auditor | Single feed detail |
| `POST` | `/api/v1/threat-intel/feeds/{feed_id}/enable` | Operator | Set runtime toggle to enabled |
| `POST` | `/api/v1/threat-intel/feeds/{feed_id}/disable` | Operator | Set runtime toggle to disabled |
| `POST` | `/api/v1/threat-intel/feeds/{feed_id}/poll` | Operator | Trigger an immediate poll (returns 202 + poll-id) |

**Runtime toggle semantics**: the `POST .../enable` endpoint writes
`ti_feed:{feed_id}:runtime_enabled = "1"` in Redis. The feed runner checks this key on
every poll cycle and skips disabled feeds. Restarting the analytics container preserves
the toggle (Redis-backed). Setting `enabled: false` in config *and* the runtime toggle to
`"1"` enables the feed; config is the fallback when no runtime override exists.

All enable/disable calls write an audit log entry via `audit_utils.write_audit` with
`action_type="ti_feed.enabled"` / `ti_feed.disabled`. The audit actor is the token holder
(human operator), not the feed itself.

Manual polls use `actor_id="ti_feed:{feed_id}"` in the audit row for feed-created rules;
the audit schema already allows this because Phase 79 audit actors are free strings.

### 8.2 Example Response

```json
{
  "feeds": [
    {
      "id": "taxii-isac",
      "type": "taxii2",
      "enabled": true,
      "runtime_override": null,
      "status": "healthy",
      "circuit_state": "closed",
      "last_poll_at": "2026-04-08T14:00:00Z",
      "next_poll_at": "2026-04-08T15:00:00Z",
      "indicators_managed": 1247,
      "last_24h_additions": 14,
      "last_24h_removals": 3,
      "last_error": null,
      "error_count_24h": 0
    }
  ],
  "count": 1
}
```

### 8.3 UI

Phase 85 adds a "Threat Intelligence" page to the existing management UI (Phase 79+):

- One card per feed (green/yellow/red by `status`).
- Indicators managed, 24h additions/removals.
- Enable/Disable toggle (Operator role).
- "Poll now" button (Operator role).
- Last error message with timestamp.

The UI calls the API endpoints above. No direct Redis access from the frontend.

---

## 9. Hot Config Reload

Phase 0 hot reload via SIGHUP is the baseline. For Phase 85:

| Change | Effect on running feeds |
|---|---|
| Add new feed to `feeds:` | Loader registers it; runner picks it up at next scheduling tick (≤ 10 s) |
| Remove feed from `feeds:` | Runner stops polling; **does NOT delete existing rules** (operator must clean up manually via the API) |
| Change `poll_interval_minutes` | Takes effect at next scheduled poll |
| Change `min_confidence` | Takes effect at next poll |
| Change `ban_ttl_hours` | Only affects **future** bans; existing bans keep their original TTL |
| Change credentials (`${…}` env vars) | Requires container restart (env vars are read at process start) |
| Change `url` or `type` | Treat as "remove + add" — requires explicit disable/enable cycle |

The feed runner uses a `ConfigLoader` subscription (pattern from `src/security/blocklists.py`
Phase 8 loader) so changes are picked up without polling the file.

---

## 10. Observability

### 10.1 Prometheus Metrics

All metrics use the `ja4proxy_` prefix per the project convention.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `ja4proxy_ti_feed_poll_total` | counter | `feed_id, result` (`success\|failure\|skipped\|circuit_open`) | Poll outcomes |
| `ja4proxy_ti_feed_poll_duration_seconds` | histogram | `feed_id` | Wall time per poll |
| `ja4proxy_ti_feed_indicators_processed_total` | counter | `feed_id, outcome` (`created\|existing\|below_confidence\|unsupported`) | Per-indicator fates |
| `ja4proxy_ti_feed_indicators_managed` | gauge | `feed_id` | Size of active_stix_ids HASH |
| `ja4proxy_ti_feed_cleanup_removals_total` | counter | `feed_id` | Indicators removed by differential cleanup |
| `ja4proxy_ti_feed_circuit_state` | gauge | `feed_id` | 0=closed, 1=half_open, 2=open |
| `ja4proxy_ti_feed_last_success_timestamp_seconds` | gauge | `feed_id` | Unix ts of last successful poll |
| `ja4proxy_ti_feed_mgmt_api_errors_total` | counter | `feed_id, status_code` | REST round-trip failures |

### 10.2 Structured Logs (Phase 80 ECS)

Every poll emits one `event.kind=event event.category=threat` log line at INFO with
`event.action=ti_feed.poll_complete` and fields:
`feed.id, feed.type, feed.poll_duration_ms, feed.indicators_seen, feed.created, feed.removed, feed.skipped, outcome`.

Errors emit at WARN with `event.action=ti_feed.poll_failed` and the exception's message and
type (no stack trace in production — consistent with Phase 14a).

### 10.3 Alertmanager Rules

Added to `monitoring/alertmanager/rules/ti_feed.yml`:

```yaml
groups:
  - name: ti_feed
    rules:
      - alert: TIFeedCircuitOpen
        expr: ja4proxy_ti_feed_circuit_state >= 2
        for: 30m
        labels: {severity: warning}
        annotations:
          summary: "TI feed {{ $labels.feed_id }} circuit has been open for >30m"

      - alert: TIFeedStale
        expr: time() - ja4proxy_ti_feed_last_success_timestamp_seconds > 7200
        for: 15m
        labels: {severity: warning}
        annotations:
          summary: "TI feed {{ $labels.feed_id }} has not polled successfully in 2h"

      - alert: TIFeedMgmtApiErrors
        expr: rate(ja4proxy_ti_feed_mgmt_api_errors_total[10m]) > 0.1
        for: 10m
        labels: {severity: critical}
        annotations:
          summary: "TI feed {{ $labels.feed_id }} is failing to write to Management API"
```

---

## 11. Testing Plan

Workers must deliver these tests. Coverage target: ≥ 85% of `src/analytics/ti_feeds/`
and 100% of `management/api/routes/threat_intel.py`.

### 11.1 Unit Tests (`tests/unit/analytics/ti_feeds/`)

| File | Must cover |
|---|---|
| `test_base.py` | `FeedClient` ABC contract; `FeedPollResult` serialisation |
| `test_state.py` | All sidecar-index operations against `fakeredis`; differential cleanup diff |
| `test_circuit_breaker.py` | CLOSED→OPEN after N failures; OPEN→HALF-OPEN after timeout; HALF-OPEN→CLOSED on success |
| `test_mgmt_client.py` | Retries on 5xx; does not retry on 4xx; respects rate limit |
| `test_taxii.py` | Parse a canned STIX 2.1 bundle (fixture) with mixed IP + JA4 indicators |
| `test_stix_ja4.py` | Extract JA4 from `[x-ja4-fingerprint:value = '...']`; reject malformed JA4; parse `new-sco` objects |
| `test_recorded_future.py` | Token exchange; collection selection; pagination (mock RF server in `tests/mocks/`) |
| `test_crowdstrike.py` | OAuth2 token acquisition; cursor pagination; confidence filtering |
| `test_rest_generic.py` | JSONPath extraction; TTL extraction; bearer-token auth header |
| `test_seed_file.py` | ≥10 entries enforced; malformed entries rejected at load |
| `test_contribution.py` | **Hard gate**: disallowed fields raise `ValueError`; anonymisation produces no raw IPs |

### 11.2 Integration Tests (`tests/integration/`)

| File | Scenario |
|---|---|
| `test_ti_feeds_e2e.py` | Full round trip: TAXII mock → feed runner → Management API (live FastAPI test client, fakeredis) → blocklist resource appears |
| `test_ti_feeds_cleanup.py` | Two polls: first adds 5 indicators, second returns 3 — assert 2 are removed from blocklist |
| `test_ti_feeds_conflict.py` | Two feeds both publish same JA4 — first writer wins; each feed's sidecar tracks only its own creations |
| `test_ti_feeds_hot_reload.py` | Add a new feed to config mid-run, SIGHUP, assert it begins polling |

### 11.3 Adversarial Tests (`tests/adversarial/`)

| File | Scenario |
|---|---|
| `test_ti_feeds_malformed_stix.py` | Feed returns truncated JSON, invalid UUIDs, malformed JA4 strings — client logs and continues, does not crash |
| `test_ti_feeds_huge_bundle.py` | Feed returns 10,000 indicators — completes within 60 s; respects rate-limit batch pacing |
| `test_ti_feeds_credential_leak.py` | `${RF_API_TOKEN}` never appears in logs, metric labels, or audit entries |

### 11.4 Web-Page Tests (Phase 79 lesson learned)

Per `CLAUDE.md`, new management UI pages require `tests/unit/test_pages.py` entries:

- GET `/threat-intel` with valid auth → 200, `text/html`, landmark string `"Threat Intelligence"` in body.
- GET `/threat-intel` without auth → status < 500.

### 11.5 Chaos Tests (`tests/chaos/`)

- TAXII server returns 503 for 5 consecutive polls → circuit opens, alert fires in test harness.
- Management API returns 429 → feed backs off per §2.5 rate-limit rule.
- Redis unavailable → feed pauses gracefully, resumes on reconnect.

---

## 12. Acceptance Criteria

Each item is verifiable by a specific test or artifact. No dupes.

### 12.1 Standards & Documentation

- [ ] Extension UUID confirmed and recorded in `docs/stix/ja4-fingerprint-extension.md`
- [ ] `docs/stix/ja4-fingerprint/schema.json` present and validates the SCO example
- [ ] `docs/stix/README.md` links to both of the above
- [ ] ADR-024 records the library choice (stix2 + taxii2-client vs hand-rolled)
- [ ] `CHANGELOG.md` entry in project standard format
- [ ] `docs/REDIS_SCHEMA.md` updated with the six `ti_feed:*` keys from §2.2

### 12.2 Integration Contract

- [ ] `ManagedBy` enum extended with `feed` and all Phase 79 tests still pass
- [ ] `POST /api/v1/bans/{ip:path}` is the URL the feed client calls (verified in `test_mgmt_client.py`)
- [ ] Feed-created blocklist entries have `managed_by=feed` and `note=feed:{id}:{stix_id}`
- [ ] Feed-created bans have `reason=feed:{id}`
- [ ] `src/security/ti_provider.py` (Phase 23) is **unchanged**
- [ ] Phase 46 `src/security/misp.py` is **unchanged**

### 12.3 TAXII Consumer

- [ ] TAXII 2.1 client polls configured servers on their intervals
- [ ] `x-ja4-fingerprint` SCO parsed via `pattern_type: "stix"` + pattern regex
- [ ] Deduplication: re-ingesting the same indicator is a no-op (idempotent)
- [ ] Differential cleanup removes indicators that disappear from the feed
- [ ] `min_confidence` threshold enforced; below-threshold indicators logged + skipped
- [ ] Batch ingest: 10,000-indicator test completes in < 60 s

### 12.4 Commercial & Generic Connectors

- [ ] Recorded Future connector authenticates via token exchange and polls configured collections
- [ ] CrowdStrike connector authenticates via OAuth2 and paginates via cursor
- [ ] Generic REST connector extracts indicators via JSONPath with bearer auth
- [ ] All three connectors default to `enabled: false`

### 12.5 Seed File & Contribution

- [ ] `config/known_bad_fingerprints.yml` ships with ≥10 vetted, sourced fingerprints
- [ ] Contribution client stub present, disabled by default
- [ ] Contribution payload hard-gated to whitelisted field set; test enforces
- [ ] WARN logged at most once per hour if `enabled: true` but endpoint unreachable

### 12.6 Circuit Breaker & Observability

- [ ] Per-feed circuit breaker implemented with unit test coverage of all transitions
- [ ] All eight Prometheus metrics from §10.1 registered in `monitoring/metrics_registry.md`
- [ ] Three Alertmanager rules from §10.3 present and parse with `promtool check rules` (or the project's YAML structural test)
- [ ] Every poll emits the Phase 80 ECS structured log line defined in §10.2

### 12.7 Management API + UI

- [ ] `GET /api/v1/threat-intel/feeds` returns per-feed status (Auditor role)
- [ ] Enable / disable endpoints write runtime toggle + audit entry (Operator role)
- [ ] `POST .../poll` triggers an immediate poll (Operator role)
- [ ] UI "Threat Intelligence" page visible with `test_pages.py` coverage

### 12.8 Hot Reload & Failure Modes

- [ ] Adding a feed at runtime via SIGHUP begins polling within 10 s
- [ ] Removing a feed stops polling but does NOT delete existing rules
- [ ] Credentials in `${…}` env vars never logged (adversarial test covers)
- [ ] Feed polling failures circuit-break and alert — no endless retry loop

---

## 13. Business Track (Not Engineering Acceptance Criteria)

These items are tracked separately and **not gated by Phase 85 engineering completion**.

- **Hosted JA4proxy community feed** at `https://feed.ja4proxy.io/` — requires cloud
  infrastructure, domain, TLS certificates, a curation team, and ongoing operations. Product
  investment decision. The engineering side ships the stubbed contribution client; the
  business side decides when to light up the endpoint.
- **OASIS CTI TC community registration** — open a PR on
  `https://github.com/oasis-open/cti-stix2-json-schemas` adding the schema under
  `extensions/`. Record the PR URL in `docs/stix/ja4-fingerprint-extension.md` when opened.
  Not a blocking gate.
- **Vendor partnership outreach** (Recorded Future, CrowdStrike, MISP community) to publish
  JA4 indicators back to their customers. Go-to-market, not engineering.
