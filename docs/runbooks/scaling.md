<!--
title: Scaling
audience: Operators, Security Teams
last_reviewed: 2026-03-27
phase: 21
-->

# Runbook: Scaling the Proxy

## When to Scale

Scale horizontally when either of these conditions is sustained for more than 5 minutes:

- **CPU > 80%** on the proxy container (`docker stats ja4proxy-proxy`).
- **Connection queue depth > 100** (kernel backlog): check with
  `ss -lnt | grep :8080` — the `Recv-Q` column shows queued connections.

Single-instance Python performance ceiling is approximately 350 connections/second with
real Redis (see `CLAUDE.md` performance profile). Beyond this, add instances.

---

## Adding a Second Proxy Instance

### 1. Update docker-compose.yml

Each proxy instance must have a unique `NODE_ID`. The NODE_ID is used as the Redis
consumer name in the analytics stream, ensuring each instance reports independently.

```yaml
services:
  proxy:
    image: ja4proxy:latest
    environment:
      NODE_ID: proxy-1
    ports:
      - "8080:8080"
    # ... rest of existing config

  proxy-2:
    image: ja4proxy:latest
    environment:
      NODE_ID: proxy-2
    ports:
      - "8081:8080"    # Different host port
    # Identical config to proxy service except NODE_ID and port
    volumes:
      - ./config:/app/config:ro
      - ./certs:/app/certs:ro
    depends_on:
      - redis
```

### 2. Update HAProxy backend

Add the new instance to the HAProxy backend configuration:

```haproxy
backend ja4proxy_backend
    balance leastconn
    option tcp-check

    server proxy-1 ja4proxy-proxy-1:8080 check inter 5s rise 2 fall 3
    server proxy-2 ja4proxy-proxy-2:8080 check inter 5s rise 2 fall 3
```

`leastconn` is preferred over `roundrobin` for TCP proxy workloads because connections
have variable duration (tarpit connections hold open for extended periods).

`inter 5s rise 2 fall 3`: health check every 5 seconds, mark UP after 2 successes,
mark DOWN after 3 failures.

### 3. Apply changes

```bash
# Start the new proxy instance
docker compose up -d proxy-2

# Reload HAProxy config (no traffic interruption)
docker compose exec haproxy haproxy -sf $(cat /var/run/haproxy.pid)
# Or via HAProxy socket:
docker compose exec haproxy sh -c 'echo "reload" | socat /var/run/haproxy/admin.sock -'
```

### 4. Verify

```bash
# Check both instances are receiving connections
docker stats ja4proxy-proxy-1 ja4proxy-proxy-2

# Check HAProxy stats
# http://localhost:8404/stats (if stats endpoint is configured)
```

---

## Redis Is Shared — No Redis Changes Needed

All proxy instances share the same Redis. The following data is automatically consistent
across instances:

- Bans and CIDR bans (`ban:*`, `ban_cidr:*`)
- Rate-limit sliding windows (`ratelimit:*`)
- Dial setting (`dial:setting`)
- JA4 whitelist and blacklist
- Analytics findings from Phase 12

No Redis sharding or per-instance Redis is needed. Redis handles the concurrent writes
from multiple instances without conflict because all sensitive operations use atomic
Redis commands (INCR, ZADD, Lua EVALSHA for sliding windows).

---

## Analytics Consumer Group — Multiple Instances

Each proxy instance writes to the same stream `ja4proxy:events` with its `NODE_ID` as
a field in the event. The analytics consumer group (`analytics`) reads from this single
stream regardless of how many proxy instances are writing.

The analytics node uses a single consumer group. Multiple proxy writers are handled
transparently by Redis Streams — the stream is an append-only log and all writers
simply append.

No analytics configuration changes are needed when adding proxy instances.

---

## Graceful Drain Before Removing an Instance

To remove an instance without dropping active connections:

### 1. Remove from HAProxy first

Mark the backend server as draining (new connections are not sent, existing connections
finish):

```bash
# Via HAProxy socket
docker compose exec haproxy sh -c \
  'echo "set server ja4proxy_backend/proxy-2 state drain" | socat /var/run/haproxy/admin.sock -'
```

### 2. Wait for active connections to close

```bash
# Monitor active connections on the instance
watch -n 2 "docker compose exec proxy-2 ss -nt | grep ESTABLISHED | wc -l"
# Wait until count reaches 0 or an acceptable low number.
```

Tarpit connections will hold open for their configured duration. If you cannot wait:

```bash
# Force-close tarpit connections by setting tarpit_duration to 0 temporarily
# config/proxy.yml: action_decider.tarpit_duration_seconds: 0
docker compose kill -s SIGHUP proxy-2
# Wait a few seconds for current tarpits to release, then proceed.
```

### 3. Stop the instance

```bash
docker compose stop proxy-2
```

### 4. Remove from HAProxy backend

Remove the `server proxy-2` line from the HAProxy config and reload.

---

## Reverting to Single Instance

```bash
# Stop the second instance
docker compose stop proxy-2

# Update docker-compose.yml: remove proxy-2 service
# Update HAProxy config: remove server proxy-2 line
# Reload HAProxy
docker compose exec haproxy sh -c 'echo "reload" | socat /var/run/haproxy/admin.sock -'

# Optionally remove proxy-2 container
docker compose rm proxy-2
```

---

## Phase 15 Note

The Python proxy has a hard ceiling of ~350 conn/s per instance due to the GIL. For
sustained traffic above this threshold, the Go rewrite (Phase 15) removes the GIL and
targets 10–50× throughput on the same hardware. Horizontal scaling is the correct
short-term strategy; Phase 15 is the long-term solution.

---

## Related

- `docs/phases/PHASE_15.md` — Go rewrite architecture
- `docs/decisions/ADR-002.md` — Why Go for Phase 15
- `docs/runbooks/redis_operations.md` — Redis health monitoring
