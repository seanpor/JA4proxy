#!/bin/bash
set -euo pipefail

# Wait for Redis to be ready
echo "Waiting for Redis to be ready..."
until redis-cli -h redis -p 6379 -a "${REDIS_PASSWORD:-changeme}" ping > /dev/null 2>&1; do
  sleep 1
  echo "Waiting for Redis..."
done

echo "Redis is ready!"

# Start the server
exec dumb-init -- "$@"