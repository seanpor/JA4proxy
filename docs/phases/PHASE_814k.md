---
phase: 814k
title: "Data layer — Redis ACL scoping, analytics stream-key drift, GDPR purge targets the wrong stream"
status: IN_PROGRESS
size: MEDIUM
created: 2026-08-06
audience: [security, developer, operations]
---

# Data layer: Redis ACL scoping + Stream drift

> Sub-phase 814k of the Phase 814 pentest programme
> (`PHASE_814.md` §5). This document is written just before the sub-phase
> runs, against what the live range actually showed.

## The finding that reorders this sub-phase

The handoff deferred a single item to 814k: *"the analytics Redis ACL user is
scoped to `~analytics:*` keys — can it actually read the proxy event stream it
is meant to consume?"* Investigating that on the live range surfaced **four**
related defects, not one. All are the same class: **the Redis ACL template and
the analytics/GDPR stream plumbing silently drifted out of sync with what the
Go proxy actually writes.**

This is the exact failure mode the project has hit three times before (810, 812,
815): a hand-maintained configuration (here the ACL file and the stream key)
that nothing drift-checks, so it quietly stopped matching reality.

### Confirmed findings

| # | Finding | Evidence (live range, production posture) | Severity (proposed) |
|---|---|---|---|
| **A** | Analytics ACL user cannot read the stream it must consume | `redis_acl.conf.template:55` grants `analytics` only `~analytics:*`; `stream_consumer.py:83` needs the `ja4proxy:events` stream. Range crash-loops on `NoPermissionError` at `xgroup_create`. | **HIGH** (H-2 device-dead; the analytics node is part of the shipped product and never starts in production posture) |
| **B** | Proxy ACL user under-scoped → rate limiting, audit trail, event stream **silently dead** | Live proxy logs: `NOPERM script|load` (`sliding_window.lua` — rate limiting unavailable, repeatedly), `NOPERM` on `proxy:*`, `concurrent:*`, `audit:*` keys. The proxy cannot `ScriptLoad` the rate-limit Lua, write its heartbeat, concurrency counters, or the audit trail. | **HIGH** (H-2 silent failure of two security controls) |
| **C** | Stream-key drift: analytics consumes the **retired** `ja4proxy:events`; Go proxy writes `events:connection` | `config/proxy.yml:885` / `main.go:1290` `events:connection`; `src/analytics/config.py:72` / `config/analytics.yaml:12` `ja4proxy:events`. Phase 807 retired `ja4proxy:events`. Even with ACL A fixed, analytics reads a stream nothing writes. | **MEDIUM** (M-4: analytics node, not the proxy path) when paired with A; alone it is a design-consistency bug |
| **D** | GDPR purge targets the **wrong stream** | `management/compliance/purge.py:51` purges `ja4proxy:events`; the real PII-bearing stream is `events:connection` (which `purge.py` never touches). GDPR retention is not enforced on the actual stream. | **HIGH** (regulatory: GDPR Art 5/25/32 retention & erasure of PII is not applied to the only stream that holds connection PII) |

**A, B, and D each independently justify registration.** C makes plain that
any fix to the ACL must point analytics at the stream the Go proxy actually
writes, and D means the GDPR enforcement runs only by shipping default.

## Goal (plain language)

Make Redis least-privilege scoping and the data-layer stream path match what
the Go proxy, analytics node, and GDPR task actually do. After this sub-phase:

1. The proxy's ACL user can run every command and touch every key the Go proxy
   genuinely uses (rate-limit `script\|load`, `proxy:*`, `concurrent:*`,
   `audit:*`, and the `events:connection` stream).
2. The analytics ACL user can both read the stream it consumes **and** write
   the `analytics:*` keys it produces — AND consume the stream the Go proxy
   really emits.
3. The analytics node reads `events:connection` (the Go proxy stream), not the
   retired `ja4proxy:events`.
4. GDPR purge deletes from the stream that actually holds the data.
5. A drift gate / test prevents each of these from silently re-drifting.

## Scope

In scope: the Redis ACL template, the ACL bootstrap script, the proxy and
analytics stream-key config, the GDPR purge stream target, and regression
tests (two-state).

Out of scope: the analytics ECS-vs-flat event schema adaptation (whether the
analytics consumer parses the `event` field the Go proxy writes — that is a
separate analytics-schema finding, 814i/814k item, not an ACL problem). This
sub-phase gets the ACLs and stream *route* correct; schema parsing is tracked
separately.

Out of scope: audit of every other ACL user (ja4tap, exporter, management) —
verified only for completeness, no change unless shown broken.

## The fixes

### Fix A — analytics ACL: grant the stream + its own `analytics:*` keys

`config/redis_acl.conf.template` — the `analytics` user needs read on the
stream **and** write on `analytics:*`:

```acl
user analytics on >${ANALYTICS_REDIS_PASSWORD} resetkeys ~analytics:* ~events:connection ~ti_feed:* +@read +@write +ping +xgroup +xack +xreadgroup +xadd -@admin +script|load
```

Wait — determine exactly which commands the analytics consumer uses
(does it need `script|load`? → verify on the range). Confirmed need:
`xgroup_create`, `xreadgroup`, `xack`, `pfadd`, `expire`, `set`, `zadd`,
`hset`, `hgetall`, `get`, `xlen`, `xrange`, `exists`, `ping`. The ACL must
grant `resetkeys ~analytics:* ~events:connection` (`~ti_feed:manual_poll_triggers` if analytics polls it), plus the channel/command set. To be verified from code, not assumed.

### Fix B — proxy ACL: add the missing commands / key patterns

`redis_acl.conf.template` proxy user add:
- `+script\|load` (the rate-limit Lua; without it rate limiting is dead)
- `~proxy:*` (heartbeat `proxy:heartbeat:{hostname}`)
- `~concurrent:*`, `~behavioral:*`, `~audit:*`
- `~events:connection` (so `XADD` to the real stream works)

Mirror in `scripts/redis-acl-setup.sh` (used by the standalone path).

### Fix C — analytics stream key

`config/analytics.yaml` + `src/analytics/config.py` default: change stream
`key` from `ja4proxy:events` to `events:connection`. So analytics consumes the
stream the Go proxy actually writes.

### Fix D — GDPR purge target

`management/compliance/purge.py` `_STREAM_KEY = "ja4proxy:events"` → the
stream that holds the per-connection PII is `events:connection`. Change the
purge to trim that stream. Check `management/compliance/pack_builder.py` too
(it also reads `ja4proxy:events` — must read `events:connection`).

### Drift prevention

Add a regeneration side to `scripts/sync_reference_docs.py`? **No** — this
phase does not touch the 815 generator. Instead: a lint test that reads the
ACL template and the config stream keys and asserts the analytics ACL grants
`~events:` and `~analytics:*`, the proxy ACL grants `~concurrent:*`,
`~audit:*`, `~proxy:*`, `+script\|load`, purge targets `events:connection`,
and analytics + purge both reference the same stream key. This test fails
if anyone re-points one without the other.

## Test strategy (two-state)

- Unit test `tests/unit/test_redis_acl_coverage.py`:
  - parse `redis_acl.conf.template`, assert each ACLL (proxy and analytics)
    grants the command/key patterns each service uses (checked from a canonical
    allow-list in the test);
  - assert `scripts/redis-acl-setup.sh` grants match the template;
  - assert purge + analytics + proxy config reference the same stream key.
  - **Verify it fails on the pre-fix code** (the current template grants
    none of these ACL-analytics gaps).
- Integration: bring the range Redis up (or use the tools image + a throwaway
  Redis) and assert, as the `proxy` user: `SCRIPT LOAD` the Lua, `SET
  proxy:heartbeat:x`, `SET concurrent:x`, `SET audit:x`, `XADD
  events:connection` all succeed; as the `analytics` user, `XGROUP CREATE
  events:connection` (or `xadd`+`xreadgroup` per the fix) and `SET analytics:x`
  both succeed; as `analytics`, a `GET config:dial` must **fail** (least
  privilege held).
- GDPR unit test: purge on a seeded `events:connection` stream removes it;
  `ja4proxy:events` is no longer the target.
- Confirm analytics container starts without `NoPermissionError` (range).

## Acceptance criteria

- [ ] The range's `analytics` container comes up and stays up (no
      `NoPermissionError`).
- [ ] The range's `proxy` container's rate limiting works (no `script|load`
      NOPERM) and heartbeat/audit/concurrent writes succeed.
- [ ] Analytics consumes `events:connection`.
- [ ] GDPR purge deletes from `events:connection`.
- [ ] `make test`, `make lint`, `make scan` green, zero warnings.
- [ ] Registration done via `findings_register.py add` for A, B, D (and C as
      MEDIUM or via supersede). Two-state tests committed.
- [ ] `make verify-findings` green.

## Out of scope

- ECS-vs-flat analytics event schema parsing (separate finding).
- Re-auditing other ACL users.
- Phase 815 generator changes.

## Risks

- Least-privilege regressions is out of scope; the test asserts least privilege
  is **preserved** (analytics cannot read `config:dial`).
- The fix must keep `fail-open` for rate limiting — but rate limiting was
  *already silently disabled* by the bug; restoring it is the safe direction
  (a control was absent, the fix restores it, not fail-closed).