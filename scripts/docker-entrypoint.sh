#!/bin/sh
# phase-800: MUST be /bin/sh, not /bin/bash.
#
# This script is the ENTRYPOINT of deploy/docker/Dockerfile.test, whose base is
# python:3.14.6-alpine3.24. Alpine ships no bash, so `#!/bin/bash` made the
# kernel fail to exec the interpreter and Docker reported:
#
#   exec /app/scripts/docker-entrypoint.sh: no such file or directory
#
# — a famously misleading message: the *script* exists (it is right here), it is
# the shebang's interpreter that does not. That killed `make perf-test` with
# exit 255, which in turn aborted `make bench-all` before test-go-perf,
# load-test and measure-mttr could run.
#
# Nothing below is bash-specific: no arrays, no [[ ]], no local, no process
# substitution. It is POSIX as written, so /bin/sh is correct rather than a
# compromise, and no bash needs to be added to the image.
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
exec "$@"

# This should never be reached
echo "ERROR: exec failed, force exiting"
exit 1
