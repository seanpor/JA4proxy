#!/bin/bash
# Test wrapper script that ensures proper exit
echo "Starting tests..."
pytest "$@"
exit_code=$?
echo "Tests completed with exit code: $exit_code"
# Force exit with a small delay to ensure all output is flushed
sleep 1
exit $exit_code
