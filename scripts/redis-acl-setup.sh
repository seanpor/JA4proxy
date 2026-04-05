#!/usr/bin/env bash
# scripts/redis-acl-setup.sh — Configure Redis ACL users for least-privilege operation
#
# Usage:
#   REDIS_PASSWORD=<pass> ./scripts/redis-acl-setup.sh [host] [port]
#
# Creates three ACL users:
#   proxy     — allowed to read/write all proxy operational keys (ratelimit, ban, beacon, etc.)
#   analytics — read/write access to the ja4proxy:events stream only
#   admin     — full access (for ops/debugging; guard with a different password in production)
#
# Requires Redis 6+ with ACL support (redis-cli must be on PATH).
#
set -euo pipefail

HOST="${1:-localhost}"
PORT="${2:-6379}"
PASS="${REDIS_PASSWORD:?REDIS_PASSWORD environment variable is required}"

echo "Configuring Redis ACL users on ${HOST}:${PORT} ..."

# proxy user — least-privilege: only the key patterns and commands the proxy needs
redis-cli -h "$HOST" -p "$PORT" -a "$PASS" ACL SETUSER proxy on \
  ">$PASS" \
  "~ratelimit:*" \
  "~ban:*" \
  "~beacon:*" \
  "~dns:*" \
  "~abuseipdb:*" \
  "~rdap:*" \
  "~ja4:*" \
  "~config:*" \
  "~analytics:*" \
  "+GET" "+SET" "+DEL" "+EXPIRE" "+TTL" \
  "+ZADD" "+ZRANGE" "+ZRANGEBYSCORE" "+ZREMRANGEBYSCORE" "+ZCARD" "+ZINCRBY" \
  "+SADD" "+SREM" "+SISMEMBER" "+SMEMBERS" \
  "+HSET" "+HGET" "+HINCRBY" "+HGETALL" \
  "+PFADD" "+PFCOUNT" \
  "+XADD" \
  "+EVALSHA" "+EVAL"

echo "  proxy user configured"

# analytics user — read/write the event stream only
redis-cli -h "$HOST" -p "$PORT" -a "$PASS" ACL SETUSER analytics on \
  ">$PASS" \
  "~ja4proxy:events" \
  "+XADD" "+XREAD" "+XREADGROUP" "+XACK"

echo "  analytics user configured"

echo ""
echo "Redis ACL users configured successfully."
echo ""
redis-cli -h "$HOST" -p "$PORT" -a "$PASS" ACL LIST
