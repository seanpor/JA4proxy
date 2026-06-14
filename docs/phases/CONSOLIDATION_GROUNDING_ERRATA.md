# Grounding Errata — Phase 230–238 (RESOLVED — folded into the plans)

**Status:** RESOLVED on 2026-06-14 (phase-324). Every finding below was
re-verified against `main` and folded into the relevant phase doc, so the
230–238 plans are now grounded in the actual code. This file is retained only as
an audit trail of *why* those plans changed — there is no remaining action here.

The original detailed errata (claim / ground-truth `file:line` / impact / fix for
each item) is preserved in git history (PR #133 era and this file's prior
revisions).

## Disposition of each finding (all re-verified against `main`, still valid when fixed)

| # | Finding | Folded into |
|---|---|---|
| 1 | Connection-event stream key is `events:connection`, not `ja4proxy:events` (`cmd/ja4pd/main.go:1262`) | `PHASE_234.md` (constant + prose), `PHASE_232b.md` |
| 2 | Stream entry is a single `event` field of flat dot-keyed ECS JSON (`event.action`, `event.risk_score`, `source.ip`, `ja4proxy.fingerprint.ja4`, …) — not top-level fields | `PHASE_234.md` (both parse loops + `_VALID_ACTIONS` + prose), `PHASE_232b.md` |
| 3 | No producer for `proxy:heartbeat:*` / `mgmt:node:*` — status is always "down". Program **must add** the Go producer; standardise on `proxy:heartbeat:{instance_id}` | `PHASE_234.md` §5.0 (new producer prerequisite), `PHASE_232b.md`, `docs/REDIS_SCHEMA.md` (corrected the false "written by the proxy" note) |
| 4 | Dial auto-revert relied on Redis keyspace-expiry notifications (disabled by default, lossy). Replaced with a polling loop over a persistent `config:dial_override` record | `PHASE_237.md` §4a/4b + tests + acceptance criteria |
| minor | Stale `JA4proxy2` checkout paths | swept to `JA4proxy` across `PHASE_233/234/235/236/237/238` (and the 232x set) |

**Verified-correct (no change needed):** Prometheus config paths (233), analytics
alert keys (236), and the `ban_cidr:{cidr}` key (237) all still match the code on
`main` as the original errata recorded.

**Not in this pass:** stale `JA4proxy2` paths also exist in some already-complete
phase docs (`complete/PHASE_231`, `141`, `226`); left untouched as historical
records.
