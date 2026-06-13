# Grounding Errata — Phase 230–238 Container & Interface Consolidation

**Status:** Advisory errata for the PROPOSED Phase 230–238 program (merged in #133).
**Author:** Code-review grounding pass (originally raised against the now-abandoned
duplicate Phase 320–328 program, PR #134).
**Purpose:** The 230–238 plans are sound in shape, but several load-bearing
*facts* — a Redis stream key, the connection-event payload structure, a heartbeat
key, and the dial auto-revert trigger — do **not** match the actual code on
`main`. Building to the docs as written would produce UI panels that read empty
streams, a proxy-status indicator that is always "down", and a dial auto-revert
that never fires. This doc records each mismatch with code evidence so the
program owner can correct the affected sub-phase docs before implementation.

These are **not edits to the 230–238 docs** — they are kept separate so the
#133 owner retains authorship. Each item below names the doc, the line, the
claim, the ground truth (with `file:line`), the impact, and the fix.

> **Why keep this even though the plans are PROPOSED?** A planning doc that
> hard-codes the wrong key name is more dangerous than a vague one: an
> implementer copies the literal and ships a consumer that silently reads
> nothing. Catching it at the plan stage is the cheapest possible point.

---

## 1. Wrong connection-event stream key — `ja4proxy:events` vs `events:connection`

**Where:** `PHASE_232.md:479` (`_EVENTS_STREAM_KEY = "ja4proxy:events"`),
`PHASE_234.md:444` (`_STREAM_KEY = "ja4proxy:events"`), and the prose at
`PHASE_234.md:88,105,112,119,432`.

**Claim:** The per-connection proxy event stream is `ja4proxy:events`.

**Ground truth:** The Go proxy writes connection events to **`events:connection`**
(`cmd/ja4pd/main.go:1262` sets `streamKey = "events:connection"`; the `XADD` is at
`cmd/ja4pd/main.go:1280`). `ja4proxy:events` is the *legacy* stream the analytics
consumer defaults to (`src/analytics/stream_consumer.py`); the proxy does not
write per-connection events there.

**Impact:** The situation bar (232) and the Threat Posture endpoint (234) read an
empty/legacy stream → zero counts, blank panels, "No Data" forever even under
live traffic.

**Fix:** Change both stream-key constants and all prose references to
`events:connection`. If `ja4proxy:events` is still wanted for analytics, document
the two streams' distinct roles rather than conflating them.

---

## 2. Connection-event payload is a single `event` field of FLAT dot-keyed JSON

**Where:** `PHASE_232.md:547-557` and `PHASE_234.md:500-512` — both iterate
`for _id, fields in entries:` and read `fields.get("action_taken")`,
`fields.get("score")` / `fields.get("risk_score")`, `fields.get("ip")` /
`fields.get("client_ip")`, `fields.get("ja4")`.

**Claim:** Each stream entry exposes top-level fields named `action_taken`,
`score`/`risk_score`, `ip`/`client_ip`, `ja4`.

**Ground truth:** The proxy `XADD`s **one** stream field named `event` whose value
is a JSON string (`cmd/ja4pd/main.go:1280`:
`XAddErr(..., map[string]interface{}{"event": string(event)})`). That JSON uses
**flat, dot-delimited ECS keys** (`cmd/ja4pd/main.go:672-687`):

| Field in the JSON | Meaning |
|---|---|
| `@timestamp` | RFC3339Nano timestamp |
| `event.action` | `allow, flag, rate_limit, tarpit, block, ban` |
| `event.risk_score` | integer score (note: **not** `score`) |
| `source.ip`, `source.port` | client IP / port (note: **not** `ip`/`client_ip`) |
| `destination.ip`, `destination.port` | backend |
| `ja4proxy.fingerprint.ja4` | the JA4 (note: **not** `ja4` and **not** `tls.ja4`) |
| `ja4proxy.sni` | SNI |
| `ja4proxy.dial_setting` | dial at decision time |

So `fields` has exactly one key, `"event"`; the dotted names are **string keys
inside the parsed JSON**, never nested objects and never top-level stream fields.

**Impact:** Every `fields.get(...)` returns the default → all counters stay zero
and every IP/JA4/score renders blank, even after fixing item 1.

**Fix:** Parse per entry, then index the flat dot-keys:

```python
import json
for _entry_id, fields in entries:
    raw = fields.get("event")
    if not raw:
        continue
    try:
        ev = json.loads(raw)
    except (ValueError, TypeError):
        continue
    action = ev.get("event.action", "")
    score  = int(ev.get("event.risk_score", 0) or 0)
    ip     = ev.get("source.ip", "")
    ja4    = ev.get("ja4proxy.fingerprint.ja4", "")
```

Index with the literal dotted string (`ev["source.ip"]`), never `ev["source"]["ip"]`.

---

## 3. `proxy:heartbeat:*` has no producer — proxy-status is always "down"

**Where:** `PHASE_232.md:480,513-516` and `PHASE_234.md:1105,1145-1149` read
`proxy:heartbeat:*` to decide proxy up/down; the comments assert "The proxy writes
`proxy:heartbeat:<instance_id>` keys with a TTL."

**Claim:** The Go proxy writes `proxy:heartbeat:*` heartbeat keys.

**Ground truth:** It does not. A repo-wide search of `cmd/`, `internal/`, and `go/`
finds **no writer** for `proxy:heartbeat:*` (nor for `mgmt:node:*`, which
`management/api/routes/nodes.py` reads and `docs/REDIS_SCHEMA.md` *also* wrongly
claims the proxy writes). No process emits either key today.

**Impact:** The `SCAN proxy:heartbeat:*` always returns empty → the situation bar
shows the full-width "PROXY DOWN" banner and the infra row shows the proxy down,
permanently, regardless of real health.

**Fix:** This program must **add the producer**, not just the consumer. Add a
heartbeat worker to `cmd/ja4pd/main.go` that periodically `HSET`s (or `SET ... EX`)
a `proxy:heartbeat:{instance_id}` key with a TTL of ~3× the write interval, so a
dead node's key lapses on its own. Pick **one** key name (`proxy:heartbeat:*` or
`mgmt:node:*`) and make producer, consumer, and `REDIS_SCHEMA.md` agree. Correct
the `REDIS_SCHEMA.md` note that asserts a writer which does not exist.

---

## 4. Dial auto-revert relies on Redis keyspace notifications (disabled by default, lossy)

**Where:** `PHASE_237.md:519-595` — the revert is triggered by a keyspace-expiry
notification on `config:dial:revert` (`__keyevent@0__:expired`), "requires
`notify-keyspace-events Ex`".

**Claim:** When the `config:dial:revert` TTL expires, Redis fires an expiry event
the watcher consumes to restore the dial.

**Ground truth:** `notify-keyspace-events` is **empty by default in Redis** and is
**configured nowhere** in this repo (no `redis.conf` directive, no
`--notify-keyspace-events` arg in any `deploy/docker/docker-compose*.yml`).
Keyspace notifications are also **fire-and-forget**: if the watcher is
disconnected at the moment of expiry (deploy, restart, crash), the event is lost
and the dial **never reverts** — leaving the proxy stuck at an elevated setting.
The doc itself flags the related "value lost on expiry" hazard (`PHASE_237.md:563-570`),
which is a symptom of leaning on expiry events.

**Impact:** With default Redis config the revert never fires at all; even with it
enabled, a single watcher blip strands the dial. For a security control whose
whole point is "temporarily raise enforcement, then back off", silent
non-reversion is a real safety regression.

**Fix:** Replace the notification trigger with a **polling loop** over a
**persistent** record. Store `config:dial_override` (no TTL) holding
`{original_value, override_value, expires_at_epoch}`; a background task in the
management service polls every ~10s and, once `now >= expires_at`, restores
`config:dial` to `original_value`, writes the audit entry under a system actor,
and deletes the override. Polling is self-healing across restarts and needs no
Redis server-config change. (237 already reverts via a direct Redis write + audit
rather than the TOTP-gated `PUT /api/v1/dial`, so the auth path is fine — only the
*trigger* needs to change.)

---

## Verified correct — no change needed

- **Prometheus config path (233):** `PHASE_233.md:76,116` correctly cite
  `deploy/monitoring/prometheus/{prometheus.yml,alerts.yml}` — this is what the
  live stack mounts (`deploy/docker/docker-compose.prod.yml:251-252`,
  `docker-compose.monitoring.yml:16-17`). Good.
- **Analytics alert keys (236):** `analytics:alerts:calibration_issue`,
  `analytics:alerts:distribution_shift`, `analytics:shadow_scores:latest` all
  match the analytics engine defaults (`src/analytics/shadow_scoring.py:25-28`,
  `src/analytics/distribution_analyzer.py:26`).
- **CIDR ban key (237):** `ban_cidr:{cidr}` as a single trie key matches
  `internal/security/rdap_enrichment.go:268`.

---

## Minor: stale `JA4proxy2` checkout paths

Several docs hard-code `/home/sean/LLM/JA4proxy2/...` (`PHASE_232.md:473`,
`PHASE_233.md:62,174,178,194,210-211`). The repository is `JA4proxy` (no `2`).
`PHASE_238.md` already scopes "correct any occurrences of stale `JA4proxy2`
paths" — fold these into that pass, and prefer relative repo paths over absolute
home-directory paths so the docs survive a different checkout location.
