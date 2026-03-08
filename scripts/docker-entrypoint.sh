#!/bin/bash
set -e

echo "=== DOCKER ENTRYPOINT STARTED ==="
echo "Current time: $(date)"
echo "User: $(whoami)"
echo "PID: $$"

# Run the command
echo "Executing: $@"
exec "$@"

# This should never be reached
echo "ERROR: exec failed, force exiting"
exit 1
