#!/bin/bash
set -e

# Analytics Node Entrypoint
# Phase 12a: Foundation

echo "Starting JA4Proxy Analytics Node"
echo "=================================="

# Wait for Redis to be available
if [ "$WAIT_FOR_REDIS" = "true" ]; then
    echo "Waiting for Redis at $REDIS_HOST:$REDIS_PORT..."
    until nc -z -v -w30 "$REDIS_HOST" "$REDIS_PORT" 2>/dev/null; do
        echo "Waiting for Redis..."
        sleep 1
    done
    echo "Redis is available"
fi

# Run the application
exec "$@"