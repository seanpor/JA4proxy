#!/usr/bin/env bash
# scripts/redis-acl-setup.sh — Configure Redis ACL users for least-privilege operation
#
# Usage:
#   REDIS_PASSWORD=<admin-pass>                   ./scripts/redis-acl-setup.sh [host] [port]
#   REDIS_PROXY_PASSWORD=<proxy-pass> \
#   REDIS_ANALYTICS_PASSWORD=<analytics-pass> \
#   REDIS_PASSWORD=<admin-pass>                   ./scripts/redis-acl-setup.sh [host] [port]
#
# Creates two ACL users with DISTINCT passwords (JA4PROXY-2026-0043):
#   proxy     — allowed to read/write all proxy operational keys (ratelimit, ban, beacon, etc.)
#   analytics — read/write access to the connection event stream (events:connection),
#               its own analytics:* output keys, and ti_feed:* state keys only
#
# REDIS_PASSWORD is the credential the script uses to authenticate as the
# default user (which must already be able to run ACL SETUSER). It is
# ALSO used as a fallback for REDIS_PROXY_PASSWORD / REDIS_ANALYTICS_PASSWORD
# when those are not supplied — but in that fallback case the script prints
# a prominent WARNING and continues, because sharing credentials between
# ACL users means a single leak compromises every role. Production
# deployments must supply distinct per-user passwords.
#
# Requires Redis 6+ with ACL support (redis-cli must be on PATH).
#
set -euo pipefail

HOST="${1:-localhost}"
PORT="${2:-6379}"
ADMIN_PASS="${REDIS_PASSWORD:?REDIS_PASSWORD environment variable is required}"

# JA4PROXY-2026-0043: per-user passwords. Fall back to REDIS_PASSWORD only
# when the specific var is not set, and warn if the resulting value equals
# REDIS_PASSWORD (single-leak-compromises-all-users risk).
PROXY_PASS="${REDIS_PROXY_PASSWORD:-$ADMIN_PASS}"
ANALYTICS_PASS="${REDIS_ANALYTICS_PASSWORD:-$ADMIN_PASS}"

warn_shared() {
    local user="$1" var="$2"
    cat >&2 <<EOF

WARNING: ACL user '${user}' is reusing REDIS_PASSWORD (${var} unset).
         A leak of one credential now compromises every role. Supply
         ${var} with a distinct password for production deployments.
         (JA4PROXY-2026-0043)

EOF
}

if [ "$PROXY_PASS" = "$ADMIN_PASS" ]; then
    warn_shared "proxy" "REDIS_PROXY_PASSWORD"
fi
if [ "$ANALYTICS_PASS" = "$ADMIN_PASS" ]; then
    warn_shared "analytics" "REDIS_ANALYTICS_PASSWORD"
fi
if [ "$PROXY_PASS" = "$ANALYTICS_PASS" ] && [ "$PROXY_PASS" != "$ADMIN_PASS" ]; then
    # Both users share the same non-admin password — still a reuse risk,
    # just not the admin one. Warn separately so the ops team notices.
    cat >&2 <<EOF

WARNING: REDIS_PROXY_PASSWORD and REDIS_ANALYTICS_PASSWORD are identical.
         A leak of one ACL user password compromises the other. Supply
         distinct values per user. (JA4PROXY-2026-0043)

EOF
fi

echo "Configuring Redis ACL users on ${HOST}:${PORT} ..."

# proxy user — least-privilege: only the key patterns and commands the proxy needs.
# Phase 814k (JA4PROXY-2026-0099): mirrors config/redis_acl.conf.template
# exactly. The additions below were previously missing, which made rate
# limiting (no +SCRIPT|LOAD → EVALSHA fails), the heartbeat, concurrency
# counters, audit trail, the connection event stream, and pub/sub config
# hot-reload ALL silently dead in production posture.
redis-cli -h "$HOST" -p "$PORT" -a "$ADMIN_PASS" ACL SETUSER proxy on \
  ">$PROXY_PASS" \
  "~ratelimit:*" \
  "~ban:*" \
  "~ban_cidr:*" \
  "~beacon:*" \
  "~dns:*" \
  "~abuseipdb:*" \
  "~rdap:*" \
  "~ja4:*" \
  "~config:*" \
  "~analytics:*" \
  "~proxy:*" \
  "~session:*" \
  "~lifespan:*" \
  "~concurrent:*" \
  "~behavioral:burst:*" \
  "~audit:*" \
  "~offense:*" \
  "~return_visitor:*" \
  "~fp:*" \
  "~geoip:*" \
  "~events:connection" \
  "~webhooks:dlq" \
  "~ja4proxy:dc:*:sync:*" \
  "+GET" "+SET" "+DEL" "+EXPIRE" "+TTL" "+EXISTS" "+INCR" "+SCAN" \
  "+ZADD" "+ZRANGE" "+ZRANGEBYSCORE" "+ZREMRANGEBYSCORE" "+ZCARD" "+ZINCRBY" \
  "+SADD" "+SREM" "+SISMEMBER" "+SMEMBERS" \
  "+HSET" "+HGET" "+HINCRBY" "+HGETALL" \
  "+PFADD" "+PFCOUNT" \
  "+XADD" "+XREAD" "+XGROUP" "+XREADGROUP" "+XACK" \
  "+EVALSHA" "+EVAL" "+SCRIPT|LOAD" \
  "+PING" "+SUBSCRIBE" \
  "&config:*" "&ja4:*" "&geoip:*"

echo "  proxy user configured"

# analytics user — read the connection event stream + write its own output.
# Phase 814k (JA4PROXY-2026-0098): the original grant was "~ja4proxy:events
# +XADD +XREAD +XREADGROUP +XACK" — both wrong stream key AND wrong keys.
# The Go proxy writes events:connection, and the node also needs ~analytics:*
# and ~ti_feed:* to persist its own outputs + threat-intel feed state.
redis-cli -h "$HOST" -p "$PORT" -a "$ADMIN_PASS" ACL SETUSER analytics on \
  ">$ANALYTICS_PASS" \
  "resetkeys" \
  "~analytics:*" \
  "~events:connection" \
  "~ti_feed:*" \
  "+GET" "+SET" "+HSET" "+HGET" "+HGETALL" "+HDEL" "+DEL" "+EXPIRE" "+INCR" \
  "+SADD" "+SREM" "+SMEMBERS" \
  "+ZADD" "+ZCARD" "+ZREMRANGEBYRANK" \
  "+XADD" "+XREVRANGE" "+XREAD" "+XGROUP" "+XREADGROUP" "+XACK" "+PFADD" \
  "+PING" "+MULTI" "+EXEC" "+DISCARD" "-@ADMIN"

echo "  analytics user configured"

echo ""
echo "Redis ACL users configured successfully."
echo ""
redis-cli -h "$HOST" -p "$PORT" -a "$ADMIN_PASS" ACL LIST
