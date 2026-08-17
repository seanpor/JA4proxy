# Phase 826 — Connect the Intelligence pipeline end-to-end

**Status:** PROPOSED
**Depends on:** the socket_timeout fix in `90551b27` (layer 1, already landed)

## Why

The management console has a fully-built **Intelligence** panel:
confidence tiers, evidence counts, FP-rate estimate, model version and
training date, suggested action, and dismiss / mark-false-positive controls
(`management/templates/partials/intelligence.html`, `partials.py:1071`).
There is a whole review page behind it (`/intelligence-review`).

It has never displayed a single finding.

Asked "where's the Intelligence?", the honest answer on 2026-08-17 was: the UI
is done, the writer is done, and **nothing in between has ever worked**. Three
independent faults sit in series between the proxy and that panel. Layer 1 is
fixed; layers 2 and 3 are this phase.

This matters beyond the demo: it is the difference between a product that
*scores* traffic and one that *explains* it. Every finding the panel is
designed to show — campaign, slow scan, JA4 intelligence — is computed by code
that already exists in `src/analytics/` and has never once been fed.

## The three layers

### Layer 1 — the consumer could not read (FIXED, `90551b27`)

`xreadgroup(block=5000)` against a client whose `socket_timeout` defaulted to
5s in redis-py 8.x. The deadlines were identical; the client always lost the
race. `Stream consumer error: Timeout reading from redis:6379`, forever, on a
1s retry loop.

Fixed by pinning `socket_timeout` explicitly and clamping the block window
below it. Guarded by `tests/unit/test_redis_blocking_timeouts.py`.

**Verified:** analytics went from a continuous error loop to zero errors and
now reads the stream.

### Layer 2 — producer and consumer speak different schemas

They were written against each other but never connected, so the mismatch was
never observable until layer 1 was fixed.

The proxy XADDs a **single field** `event` containing an ECS JSON blob
(`cmd/ja4pd/main.go:688-706`). Actual entry from the live stream:

```json
{"@timestamp":"2026-08-17T17:45:25.298824415Z","event.action":"allow",
 "event.risk_score":35,"source.ip":"172.25.0.4","service.name":"ja4proxy",
 "ja4proxy.fingerprint.ja4":"t13d1212h2_eac1b15b5477_8e6e362c5eac",
 "ja4proxy.sni":"backend","ja4proxy.dial_setting":75}
```

The consumer expects **flat, differently-named** fields
(`src/analytics/validation.py:9-41`):

| Consumer needs | Proxy emits | Note |
|---|---|---|
| `timestamp` (epoch float) | `@timestamp` (RFC3339 string) | type *and* name differ |
| `src_ip` | `source.ip` | |
| `score` (0–100) | `event.risk_score` | |
| `action` | `event.action` | see valid-set gap below |
| `ja4` | `ja4proxy.fingerprint.ja4` | |
| `proxy_id` | *(absent)* | validated, never sent |
| *(nested under `event`)* | ECS blob in one field | envelope must be unwrapped first |

Additional gap: `validate_event_comprehensive` accepts only
`allow|block|monitor|tarpit`, but the proxy's action decider also emits
`flag`, `rate_limit` and `ban`. Even with names mapped, those three would be
rejected — and `rate_limit` is currently the *only* non-allow action the demo
stack produces at scale.

### Layer 3 — HMAC required by one side, never applied by the other

`hmac_required` defaults to `True` with secret `default-secret-change-me`
(`src/analytics/config.py:78`). The consumer verifies a `hmac` field over
`json.dumps(event, sort_keys=True, separators=(",",":"))`
(`src/analytics/authentication.py:34-58`).

The Go proxy has HMAC code for webhooks and pub/sub but **never signs stream
events** — no `hmac` reference in `cmd/ja4pd/main.go`.

Measured after layer 1 was fixed: **7,749 events rejected**, every one
`Event validation failed: HMAC verification failed`. This is the current wall.

## Decisions needed before building

**D1 — which schema wins?**
Recommend: **adapt the consumer to ECS.** ECS is the documented, standards-based
format already used for SIEM/webhook delivery, and it keeps the change off the
Go hot path. The flat `src_ip` schema is the older internal one with a single
consumer.

**D2 — widen the valid-action set.**
Add `flag`, `rate_limit`, `ban`. Without this the analytics node is blind to
the actions the proxy actually takes most often.

**D3 — HMAC: sign, or scope the trust?**
Not a free choice; decide deliberately rather than by default.
- *Sign in the proxy* — correct long-term, but a hot-path change and a shared
  secret to distribute.
- *Rely on the Redis ACL* — `XADD events:connection` is already restricted to
  the `proxy` user, so HMAC here is defence-in-depth against a compromised
  Redis or leaked proxy credential, not the primary control.

Recommend: keep `hmac_required` configurable, default it **on**, and have the
proxy sign. Do **not** silently disable it to make the demo work — that trades
a real control for a cosmetic win and would go undocumented.

## Acceptance criteria

1. An end-to-end test drives traffic through the proxy and asserts a finding
   appears in `analytics:findings:index` — the assertion that would have failed
   for every one of the three layers above.
2. Console shows real findings; `/intelligence-review` lists them; dismiss and
   mark-FP round-trip.
3. Zero `Invalid event` / `Stream consumer error` lines in analytics logs
   during a traffic run.
4. A metric for rejected events, alerted on. **This bug's real lesson is that
   the pipeline failed loudly into a log nobody read** — the consumer must
   export ingest-success and rejection counters, and a rejection rate near
   100% must page.
5. `proxy_id` populated, so multi-node deployments can attribute findings.
6. HMAC decision from D3 implemented and documented in an ADR.

## Related

- Nothing scores above 55, so `block`/`ban`/`tarpit` never fire — separate
  product issue, but it caps what Intelligence can find. Findings are only as
  interesting as the actions feeding them.
- The JA4 corpus is 12 fingerprints, browsers only, ~2 years stale
  (`fixtures/ti_feeds/ja4_fp_corpus.txt`). JA4 intelligence findings will be
  weak until that is refreshed.
