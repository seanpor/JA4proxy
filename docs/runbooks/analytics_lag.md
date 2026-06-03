<!--
title: Analytics_Lag
audience: Operators, Security Teams
last_reviewed: 2026-03-27
phase: 21
-->

# Runbook: Analytics Stream Consumer Lag

## Alert

```
ja4proxy_analytics_stream_lag_seconds > 60
```

This alert fires when the analytics consumer group is more than 60 seconds behind the
live stream of proxy events. The proxy continues to operate normally during lag — it
does not wait for analytics acknowledgment.

---

## What the Alert Means

Every proxy connection event is written to the Redis Stream `ja4proxy:events` via a
fire-and-forget `XADD`. The analytics node reads from this stream via a consumer group
(`analytics`). During normal operation the consumer reads events within milliseconds.

**During lag:**
- New connections are scored without analytics findings (score contributions from
  Phase 12 detectors are stale or absent).
- The proxy fails open on missing analytics signals — this is the intended behaviour.
- No errors are returned to clients. No proxy restarts are needed.
- The analytics node will catch up automatically once the backlog clears.

---

## Check Consumer Group Lag

### Stream length and consumer group info

```bash
redis-cli XLEN ja4proxy:events
# Total number of entries currently in the stream.

redis-cli XINFO GROUPS ja4proxy:events
# Fields to check:
#   name            — should be "analytics"
#   consumers       — number of active consumer worker threads
#   pending         — messages delivered but not yet ACK'd
#   last-delivered-id  — last ID delivered to the group
#   entries-read    — total entries consumed
#   lag             — undelivered entries (Redis 7.0+)
```

### Pending messages (delivered but not ACK'd)

```bash
redis-cli XPENDING ja4proxy:events analytics - + 10
# Lists up to 10 oldest pending messages with consumer name and idle time.
# High idle time (> 30s) indicates a stuck consumer.
```

### Stream head vs. consumer position

```bash
# Get the latest entry ID in the stream
redis-cli XREVRANGE ja4proxy:events + - COUNT 1

# Get the last delivered ID from the group
redis-cli XINFO GROUPS ja4proxy:events | grep last-delivered-id

# Difference in entry counts:
redis-cli XRANGE ja4proxy:events <last-delivered-id> + COUNT 100 | wc -l
```

---

## What Happens If Lag Grows

The stream is trimmed to a maximum of approximately 100,000 entries
(`XADD ... MAXLEN ~ 100000`). If the consumer group falls behind by more than this,
the oldest unread entries are lost.

**What is lost when entries are trimmed:**
- Per-connection metadata for the missed window (IP, JA4, score, action).
- Campaign detection input for the affected time window.
- Slow-scan detection correlation for that period.

**What is NOT lost:**
- Bans and blocks already written to Redis keys (separate from the stream).
- Rate-limit state (sliding window keys are independent).
- AbuseIPDB and RDAP cache entries.

If the stream is trimmed significantly, note the time window for the incident report.

---

## Speed Up Consumption

### 1. Check container resource limits

```bash
docker stats ja4proxy-analytics
# Look for CPU throttling (CPU % near 100%) or memory pressure (MEM USAGE near limit).
```

Increase analytics container limits in `docker-compose.yml` if throttled:

```yaml
analytics:
  deploy:
    resources:
      limits:
        cpus: '2.0'      # increase from 1.0
        memory: 1G       # increase from 512M
```

Then restart:
```bash
docker compose up -d --force-recreate analytics
```

### 2. Check Redis memory pressure

Memory pressure causes slower XREAD responses. See `docs/runbooks/redis_operations.md`
for memory diagnostics. If Redis is near `maxmemory`, free space before expecting lag
to clear.

### 3. Restart the analytics container

If the container is running but consumption has stalled (consumers show 0 in XINFO):

```bash
docker compose restart analytics
```

The analytics node uses XREADGROUP with block timeout. After restart it reconnects to
the consumer group and resumes from `last-delivered-id` — no data loss.

---

## Reset a Stuck Consumer (Skip to Latest)

Use this when: the analytics backlog has grown too large to process and you want to
resume from the current stream position, accepting the data gap.

```bash
# Move the consumer group's read pointer to the latest entry
redis-cli XGROUP SETID ja4proxy:events analytics '$'
# $ means "latest entry at time of this command"
```

After this, new events are processed normally. The gap will appear in analytics as a
missing time window — note it in the incident log.

**Also acknowledge all pending messages** (otherwise they remain in the PEL and
XPENDING will show stale entries):

```bash
# Get all pending message IDs
redis-cli XPENDING ja4proxy:events analytics - + 1000

# Acknowledge them (replace <id1> <id2> with the IDs from above)
redis-cli XACK ja4proxy:events analytics <id1> <id2> ...
```

---

## Replay from Beginning

Use this when: the analytics node crashed during initial setup and you want to reprocess
the full available history.

```bash
# Move the consumer group's read pointer to the beginning of the stream
redis-cli XGROUP SETID ja4proxy:events analytics 0
```

The analytics node will now read all retained entries (up to the stream's MAXLEN limit)
from oldest to newest. This will cause a temporary CPU spike on the analytics container
as it catches up.

Monitor progress:
```bash
watch -n 5 "redis-cli XINFO GROUPS ja4proxy:events | grep -A2 lag"
```

---

## Stream Trimming Details

The stream is trimmed on every `XADD` using approximate trimming:
```
XADD ja4proxy:events MAXLEN ~ 100000 * <fields>
```

Approximate trimming (`~`) means the actual count may slightly exceed 100,000 entries
before a trim occurs (Redis trims at node boundaries). At typical traffic rates of 100
events/second, the stream holds approximately 16–17 minutes of history.

To check retention window:
```bash
# Count entries and divide by approximate event rate
redis-cli XLEN ja4proxy:events
```

To check the oldest retained entry:
```bash
redis-cli XRANGE ja4proxy:events - + COUNT 1
# Returns the oldest entry's ID (millisecond timestamp in the ID)
```

---

## Container Restart Procedure

Full analytics node restart (safe at any time):

```bash
docker compose restart analytics
```

The consumer group state is preserved in Redis. After restart, the analytics node:
1. Reconnects to Redis.
2. Re-registers as a consumer in the `analytics` group.
3. Resumes from where it left off (pending messages are redelivered).

---

## Escalation Criteria

Escalate to the on-call engineer if:

- Consumer lag exceeds 10 minutes and analytics container shows no CPU activity.
- `XPENDING` shows messages with idle time > 5 minutes (stuck consumer, not just slow).
- Stream trimming has already occurred (oldest entry ID is newer than the lag start time).
- Redis memory pressure is causing stream writes to fail (`ja4proxy_redis_errors_total`
  increments for `XADD` operations).
- Analytics container has restarted more than 3 times in the past hour (CrashLoopBackOff
  pattern).

---

## Related

- `docs/runbooks/redis_operations.md` — Redis health and memory operations
- `docs/REDIS_SCHEMA.md` — Stream schema and field definitions
- `docs/phases/complete/PHASE_12.md` — Analytics node architecture
