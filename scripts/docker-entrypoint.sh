#!/bin/bash
set -e

echo "=== DOCKER ENTRYPOINT STARTED ==="
echo "Current time: $(date)"
echo "User: $(whoami)"
echo "PID: $$"

# Inject Docker secrets as environment variables so the proxy can read them.
# Files are mounted at /run/secrets/<name> by docker-compose secrets: directives.
if [ -f /run/secrets/redis_password ]; then
    export REDIS_PASSWORD
    REDIS_PASSWORD=$(cat /run/secrets/redis_password)
fi
if [ -f /run/secrets/abuseipdb_api_key ]; then
    export ABUSEIPDB_API_KEY
    ABUSEIPDB_API_KEY=$(cat /run/secrets/abuseipdb_api_key)
fi

# Run the command
echo "Executing: $*"
exec "$@"

# This should never be reached
echo "ERROR: exec failed, force exiting"
exit 1
