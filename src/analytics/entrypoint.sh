#!/bin/bash
set -e

# Analytics Node Entrypoint
# Phase 12a: Foundation

echo "Starting JA4Proxy Analytics Node"
echo "=================================="

# Wait for Redis to be available
if [ "$WAIT_FOR_REDIS" = "true" ]; then
    echo "Waiting for Redis at $REDIS_HOST:$REDIS_PORT..."
    until python3 -c "import socket; s=socket.socket(); s.settimeout(2); exit(s.connect_ex(('$REDIS_HOST', int('$REDIS_PORT'))))" 2>/dev/null; do
        echo "Waiting for Redis..."
        sleep 1
    done
    echo "Redis is available"
fi

# Run the application
exec "$@"