#!/bin/bash
# Test wrapper script that ensures proper exit with debugging
echo "=== TEST WRAPPER STARTED ==="
echo "Current time: $(date)"
echo "Arguments: $@"
echo "Starting tests..."

# Run pytest with timing
start_time=$(date +%s)
pytest "$@"
exit_code=$?
end_time=$(date +%s)

runtime=$((end_time - start_time))
echo "Tests completed with exit code: $exit_code"
echo "Runtime: ${runtime} seconds"
echo "Current time: $(date)"

# Debug process information
echo "=== PROCESS DEBUG INFO ==="
echo "Current PID: $$"
echo "Parent PID: $PPID"
echo "Active processes:"
ps aux | grep -E "(pytest|python)" | head -10

# Force exit with a small delay to ensure all output is flushed
sleep 1
echo "=== TEST WRAPPER EXITING ==="
exit $exit_code
