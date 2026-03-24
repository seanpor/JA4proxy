#!/usr/bin/env bash
# Fail if any Python file uses f-strings in logger calls.
#
# F-string arguments are evaluated unconditionally, even when the log
# level is disabled. This wastes CPU and risks leaking secrets into
# log aggregators. Use lazy %-formatting instead:
#
#   logger.info("msg: %s", value)   # ✅ lazy
#   logger.info(f"msg: {value}")    # ❌ evaluated unconditionally
#
# See docs/phases/PHASE_17b.md §17b-2a.
set -euo pipefail

DIRS="${*:-src analytics management}"

pattern='logger\.(debug|info|warning|warn|error|critical|exception)\(f"'

if grep -rn --include="*.py" -E "$pattern" $DIRS 2>/dev/null; then
    echo ""
    echo "check_logger_format: FAIL — f-string in logger call(s) above" >&2
    exit 1
fi

echo "check_logger_format: OK"
