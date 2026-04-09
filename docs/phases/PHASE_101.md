# Phase 101: Phase 85 Hardening (Threat-Intel Feed Runner)

> **Origin:** Critical security architect review of Phase 85 conducted on
> 2026-04-09 immediately after the Phase 85 §12 acceptance gate flipped
> COMPLETE. The review found that the §12 functional gate passes but the
> security gate does not. Phase 85 ships an automated mass-banning pipeline
> with no breaker between "feed says X" and "production blocks X".
>
> **Status:** PLANNED. Do **not** deploy `dial > 0` with
> `threat_intel.enabled: true` and any feed `enabled: true` until C1, C3,
> and H1 below are closed. C2-partial, C4, and H7 were closed in-branch
> on phase-85 (commits 7c8ccac, 78162eb, ee80232) — this phase covers the
> remainder.

---

## Why this is its own phase, not Phase 100 items

Phase 100 is the rolling cross-phase gap register for one-off items that
don't justify a dedicated phase. Phase 85 hardening is different:

* Multiple findings (C1, C2-full, C3, H1) are interlocking — the safe
  default position for the runner cannot be reached by closing any one of
  them in isolation.
* The `success_criteria` in §3 below should run as one acceptance sweep,
  not as drip-fed items.
* Several items require new config schema (`max_new_per_poll`, etc.) and
  it is cleaner to land them as one config + code + test atomic unit.

If you find a one-off Phase-85-related cleanup that doesn't intersect any
of the items below, file it under Phase 100 instead.

---

## 1. Findings already closed on phase-85 (reference only)

| ID  | Severity | Title | Closed by |
|-----|----------|-------|-----------|
| C2-partial | CRITICAL | 10% deletion cap on differential cleanup | 78162eb |
| C4  | CRITICAL | Default `threat_intel` + `seed_file` to disabled | ee80232 |
| H7  | HIGH | Defer `stix_ids_seen.add()` until mgmt write succeeds | 7c8ccac |

These are listed here only so a reader of PHASE_101 has a complete view.
Do not re-open them.

---

## 2. Open items

---

### Item 101-C1: Per-feed safety caps (`max_new_per_poll`, `max_owned_total`)

**Severity:** CRITICAL
**Effort:** ~1 day (config schema + runner gate + tests)

#### Context

A misconfigured or compromised feed can today drive an unbounded number of
`POST /api/v1/bans` calls in a single poll. The runner enforces no upper
bound — the only brake is the per-feed circuit breaker, which trips on
*errors*, not on volume. A feed that begins returning legitimate-looking
HTTP 200 with 50 000 indicators per page would happily ban all of them.

This collides head-on with the project's core asymmetry: false positives
are catastrophic, false negatives are recoverable.

#### Exact changes

1. `src/analytics/ti_feeds/base.py` — extend `FeedConfig` with
   ```python
   max_new_per_poll: int = 500
   max_owned_total: int = 50_000
   max_delta_per_poll: int = 0  # 0 = unlimited
   ```
   All three honour `from_dict` so YAML can override per-feed.

2. `src/analytics/ti_feeds/runner.py` `_poll_once` — after `client.poll()`
   returns and *before* we touch the snapshot:
   - If `len(result.created) > cfg.max_new_per_poll`: log
     `event=feed_capped_new`, slice `result.created[: cfg.max_new_per_poll]`,
     and increment a new `ti_feed_caps_hit_total{feed_id, kind="new"}`
     counter. The truncated indicators are *not* added to the snapshot
     (so next poll will retry them).
   - If `len(previous_ids) >= cfg.max_owned_total`: refuse to apply any
     new indicators this cycle, log `event=feed_capped_total`, increment
     `ti_feed_caps_hit_total{kind="total"}`. Cleanup is still allowed.
   - If `cfg.max_delta_per_poll > 0` and the absolute delta
     `|len(seen) - len(previous_ids)|` exceeds it: refuse to apply *any*
     mutations this cycle, log `event=feed_capped_delta`, increment
     `ti_feed_caps_hit_total{kind="delta"}`.

3. `config/proxy.yml` — add the three keys to every example feed entry
   under `threat_intel.feeds[*]`, with conservative defaults and inline
   comments explaining the blast-radius brake.

4. `monitoring/alertmanager/rules/ti_feed.yml` — add a `TIFeedCapsHit`
   warning rule (`rate(ja4proxy_ti_feed_caps_hit_total[15m]) > 0`) with a
   runbook link to `docs/runbooks/ti_feed_caps_hit.md` (new file).

#### Verify

```bash
python3 -m pytest tests/unit/ -k ti_feed_caps -x
make lint-phases
```

A new `tests/unit/test_ti_feed_caps.py` should cover all three cap kinds
with parametrised cases.

---

### Item 101-C2: Two-empty-poll gate before bulk cleanup

**Severity:** CRITICAL
**Effort:** ~2 hours

#### Context

The 10% deletion cap committed in 78162eb is a brake, not a fix. A feed
that legitimately shrinks over many cycles still converges to zero. The
real defence is: never act on a *single* empty/near-empty poll. Wait for
two consecutive empties before allowing any cleanup beyond the cap.

This needs a per-feed counter in `FeedState` so it survives runner
restarts.

#### Exact changes

1. `src/analytics/ti_feeds/state.py` — add
   ```python
   async def get_empty_streak(self, feed_id: str) -> int: ...
   async def bump_empty_streak(self, feed_id: str) -> int: ...
   async def reset_empty_streak(self, feed_id: str) -> None: ...
   ```
   Backed by a Redis string `ti_feed:{feed_id}:empty_streak` with no TTL.

2. `src/analytics/ti_feeds/runner.py` `_poll_once` — after computing
   `dropped` but before applying any deletions:
   - If `len(result.stix_ids_seen) == 0`: `bump_empty_streak`. If the
     resulting streak is `< 2`, set `dropped = {}` and log
     `event=cleanup_skipped_empty_streak | streak=N`. Snapshot is *not*
     replaced (we don't trust the empty result enough to overwrite the
     last good one).
   - If `len(result.stix_ids_seen) > 0`: `reset_empty_streak` and
     proceed to the existing 10% cap path.

3. `tests/unit/analytics/ti_feeds/test_runner_empty_streak.py` — new
   file with cases: first empty poll skips cleanup; second empty allows
   cleanup but capped at 10%; non-empty poll resets the streak.

#### Verify

```bash
python3 -m pytest tests/unit/analytics/ti_feeds/test_runner_empty_streak.py -x
```

---

### Item 101-C3: `ja4_safe_to_block(ja4)` FP corpus check

**Severity:** CRITICAL
**Effort:** ~3 hours

#### Context

The TAXII / REST clients today validate JA4 indicators only by *shape*
(`is_valid_ja4`). There is no FP corpus check. A feed publishing a JA4
that matches Chrome 120 stable would cause a hard block on every Chrome
120 client because the canonical blocklist bypasses the dial.

The FP corpus exists already (`tests/adversarial/ja4_corpus/`) — it just
isn't consulted from the apply path.

#### Exact changes

1. `src/analytics/ti_feeds/ja4_safety.py` — new module:
   ```python
   def ja4_safe_to_block(ja4: str) -> tuple[bool, str]:
       """Return (safe, reason). False if ja4 hits the FP allow corpus."""
   ```
   Loads the FP corpus once at module import (lru_cache around the file
   read). The corpus path is configurable via env var
   `JA4PROXY_FP_CORPUS_PATH` for tests.

2. `src/analytics/ti_feeds/taxii.py` `_apply_indicator` JA4 branch — after
   `is_valid_ja4(ja4)` and before `post_blocklist`:
   ```python
   safe, reason = ja4_safe_to_block(ja4)
   if not safe:
       _INDICATORS_PROCESSED.labels(feed_id=feed_id, outcome="fp_blocked").inc()
       result.errors.append(f"fp_corpus blocked: {reason}")
       return
   ```

3. Same wiring in `src/analytics/ti_feeds/rest_generic.py` JA4 branch.

4. `src/analytics/ti_feeds/seed_file.py` `run_once` — same check before
   each `post_blocklist`. The seed file should *never* be allowed to push
   a known-good JA4 either, even though it's an operator-curated file.

5. New metric `ja4proxy_ti_feed_fp_blocked_total{feed_id}` and a
   `TIFeedFPBlocked` Alertmanager warning rule (any non-zero rate is a
   smoking gun: either the feed is hostile or our FP corpus is wrong).

#### Verify

```bash
python3 -m pytest tests/unit/analytics/ti_feeds/test_ja4_safety.py -x
python3 -m pytest tests/adversarial/test_ti_feeds_fp_block.py -x
```

The adversarial test should construct a synthetic feed that publishes
the Chrome 120 JA4 from the FP corpus, run it through the runner, and
assert that `post_blocklist` is *never* called.

---

### Item 101-H1: Real `aiohttp` resolver / SSRF mitigation

**Severity:** HIGH
**Effort:** ~half a day

#### Context

`base.validate_feed_url` rejects literal RFC1918 / loopback / link-local
hosts but does *not* defend against DNS-based SSRF: a feed configured
with `https://feed.example.com/` whose DNS A record currently points to
`169.254.169.254` (cloud metadata) will be polled successfully.

The fix is to use a custom `aiohttp.TCPConnector(resolver=...)` that
resolves the hostname *and then* checks the resulting IP against the
private/loopback/link-local set before returning it.

#### Exact changes

1. `src/analytics/ti_feeds/safe_resolver.py` — new module:
   ```python
   class SafeResolver(aiohttp.AbstractResolver):
       async def resolve(self, host, port=0, family=socket.AF_UNSPEC):
           hosts = await self._inner.resolve(host, port, family)
           for h in hosts:
               if not is_publicly_routable_ip(h["host"]):
                   raise aiohttp.ClientConnectorError(
                       connection_key=None,
                       os_error=PermissionError(f"SSRF blocked: {h['host']}"),
                   )
           return hosts
   ```

2. `src/analytics/ti_feeds/base.py` `is_publicly_routable_ip` — pull the
   helper out of the existing `validate_feed_url` so the resolver can
   share it. Cover IPv4-mapped, 6to4, Teredo recursively (already done).

3. Every TCPConnector instantiation in the four clients — taxii.py,
   crowdstrike.py, recorded_future.py, rest_generic.py — switches to
   `aiohttp.TCPConnector(resolver=SafeResolver())`.

4. `tests/adversarial/test_ti_feeds_ssrf.py` — new file. Patch
   `socket.getaddrinfo` to return `169.254.169.254` for a synthetic
   hostname, run a real `TAXIIClient.poll()` against that host, assert
   the poll returns a `result.errors` entry containing `"SSRF blocked"`
   and that `post_ban` was never called.

#### Verify

```bash
python3 -m pytest tests/adversarial/test_ti_feeds_ssrf.py -x
```

---

### Item 101-H2: Manual-poll endpoint rate limit

**Severity:** HIGH
**Effort:** ~1 hour

#### Context

`POST /api/v1/threat-intel/feeds/{id}/poll` has no rate limit. An
authenticated Operator (or a stolen Operator token) can XADD to the
trigger stream as fast as they like. Each trigger costs one full poll —
remote API quota burn, mgmt-API write storm, leader-lock contention.

#### Exact changes

1. `management/api/routes/threat_intel.py` — add a
   `slowapi`-style limiter (or the existing `limit_per_minute`
   decorator from Phase 79) at 6/min/feed_id.

2. `tests/unit/test_threat_intel_api.py` — assert that the 7th request
   in 60 s returns 429 with a `Retry-After` header.

#### Verify

```bash
python3 -m pytest tests/unit/test_threat_intel_api.py::test_poll_rate_limit -x
```

---

### Item 101-H3: CSRF middleware on `/api/v1/threat-intel/*` write routes

**Severity:** HIGH
**Effort:** ~2 hours (assuming a CSRF middleware lands as part of this item)

#### Context

The Management API today relies on `SameSite=lax` cookies as its only
CSRF defence. `lax` does not protect POST requests submitted from a
form on an attacker-controlled site. The threat-intel routes are write
endpoints and should additionally require a double-submit CSRF token.

This item also closes the gap for every other Phase 79 mutating route,
not just threat-intel — which is why the effort is non-trivial.

#### Exact changes

1. `management/api/middleware/csrf.py` — new middleware that:
   - On every `GET /api/v1/*` response: set a `csrf_token` cookie
     (HttpOnly false, SameSite=strict, Secure in prod) and an
     `X-CSRF-Token` response header containing the same value.
   - On every `POST/PUT/PATCH/DELETE /api/v1/*` request: require the
     `X-CSRF-Token` header to match the `csrf_token` cookie. Reject 403
     with body `{"error": "csrf_token_mismatch"}`.
   - Tokens are HMAC over `(session_id, issued_at)` with the existing
     `MANAGEMENT_SECRET_KEY`. Validity 1 h.

2. `management/api/main.py` — register the middleware after auth.

3. `management/templates/base.html` — read the `csrf_token` cookie in
   the Alpine bootstrap and inject it as a header on every fetch via a
   global `$fetch` wrapper.

4. `tests/unit/test_csrf.py` — full happy / mismatch / expired matrix.

#### Verify

```bash
python3 -m pytest tests/unit/test_csrf.py -x
python3 -m pytest tests/unit/test_pages_threat_intel.py -x
```

---

### Item 101-H4: Recorded Future regional endpoint support

**Severity:** HIGH
**Effort:** ~1 hour

#### Context

`_RF_TAXII_ROOT` is hardcoded to `https://api.recordedfuture.com/taxii2/`.
RF customers in EU / APAC contractually route through `eu` / `apac`
sub-domains and the global endpoint will return 403 from those tenancies.
This was missed in Chunk G because the verification used a US tenant.

#### Exact changes

1. `src/analytics/ti_feeds/recorded_future.py` — make the TAXII root
   come from `config.url` first, falling back to `_RF_TAXII_ROOT`. Honour
   `https://api.eu.recordedfuture.com/taxii2/` etc. literally.

2. `config/proxy.yml` recorded_future example — show the EU endpoint as
   a comment with a note about which tenants need it.

3. `docs/phases/PHASE_85_notes.md` — append a "Chunk G addendum" line.

#### Verify

```bash
python3 -m pytest tests/unit/analytics/ti_feeds/test_recorded_future.py -x
```

---

### Item 101-H5: CrowdStrike regional / GovCloud endpoint support

**Severity:** HIGH
**Effort:** ~1 hour

Same shape as 101-H4 but for `_FALCON_AUTH_URL` and
`_FALCON_INDICATORS_URL`. Falcon offers `api.us-2.crowdstrike.com`,
`api.eu-1.crowdstrike.com`, and `api.laggar.gcw.crowdstrike.com`
(GovCloud). Pull both URLs from `config.url` with the existing values as
fallback.

---

### Item 101-H6: Re-shape `test_ti_feed_taxii_unavailable.py`

**Severity:** HIGH
**Effort:** ~1 hour

#### Context

The chaos test asserts that the runner survives a TAXII server returning
500s. It does not assert what the architect review actually wants: that
*after* a 500 storm, no new bans were created and no existing bans were
removed. As written, the test is satisfied by a runner that crashes the
analytics container — that crash would also leave existing rules intact.

#### Exact changes

Replace the test body with:

```python
async def test_taxii_500_storm_does_not_mutate_state(...):
    # Pre-populate the snapshot with 100 indicators.
    # Configure a TAXII server that returns 500 for the next 10 polls.
    # Run the runner for 10 cycles.
    # Assert: snapshot still has 100 entries.
    # Assert: mgmt.post_ban call count is 0 (no new bans).
    # Assert: mgmt.delete_ban call count is 0 (no cleanups).
    # Assert: circuit state is OPEN.
```

---

## 3. Medium-severity items

These are filed as a single bullet list with one-line summaries because
each is small enough to land independently. Pick them up in any order.

| ID | Title | File hint |
|----|-------|-----------|
| 101-M1 | TAXII bundle size cap (reject `> N MiB` responses before parse) | taxii.py |
| 101-M2 | Per-feed `User-Agent` header (currently shared global UA) | base.py + 4 clients |
| 101-M3 | `ti_feed_indicators_managed` Gauge → use `Counter` for delta | metrics.py |
| 101-M4 | `compute_dropped_ids` should return a stable-ordered list, not a dict | state.py |
| 101-M5 | Replace `BLE001` `Exception` catches in clients with explicit unions | 4 clients |
| 101-M6 | `seed_file.run_once` should run inside a leader lock | seed_file.py |
| 101-M7 | Audit log entry on every feed `enable` / `disable` runtime override | threat_intel.py route |

---

## 4. Low-severity items

| ID | Title |
|----|-------|
| 101-L1 | `_OneShotBundle` adapter docs out of date after H7 |
| 101-L2 | Three Phase 85 runbooks need a real-deployment dry run |
| 101-L3 | `tests/unit/test_pages_threat_intel.py` xfail to be removed once Redis fixture lands |
| 101-L4 | `monitoring/metrics_registry.md` lacks Phase 101 entries (will be added with each item) |

---

## 5. Success criteria for Phase 101 COMPLETE

- All `101-C*` items closed.
- All `101-H*` items closed.
- All `101-M*` items either closed or explicitly punted to Phase 100 with
  a one-line note in this doc.
- Acceptance sweep from a fresh clone:
  ```bash
  python3 -m pytest tests/unit/analytics/ti_feeds/ tests/adversarial/test_ti_feeds_*.py -x
  make lint-phases
  ```
- A doc-check that the operator's deploy story is now: enable
  `threat_intel.enabled: true`, enable a feed, raise the dial — and at
  no step in that sequence can a single misbehaving feed mass-ban real
  traffic.

---

## 6. Out of scope

The following were considered for Phase 101 and explicitly punted:

- **Per-feed signing keys / verifying STIX bundle signatures.** Several
  feeds support detached JWS or PGP signing of bundles. Worth doing but
  belongs in its own phase because it touches every client.
- **GDPR-compliant feed contribution beyond the existing gate.** The
  contribution path landed in Chunk D. Hardening it is Phase 86 or
  later, not 101.
- **Replacing `aiohttp` with `httpx`.** Not a security item.
