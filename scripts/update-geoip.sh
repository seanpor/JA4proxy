#!/usr/bin/env bash
# update-geoip.sh — Download the latest IP2Location LITE country database
#
# The GeoIP database is used by JA4proxy to map IP addresses to countries for
# country-based blocking. IP2Location publish updated databases monthly.
#
# This script downloads the free LITE edition (DB1 — country only).
# No registration or API key is required for the LITE version.
#
# Usage:
#   ./scripts/update-geoip.sh          # Download and install
#   ./scripts/update-geoip.sh --check  # Check current database age only
#
# After updating: restart the proxy to load the new database.
#   make stop && make start
#
# Recommended: run monthly, e.g. via cron:
#   0 3 1 * * /path/to/scripts/update-geoip.sh >> /var/log/ja4proxy-geoip-update.log 2>&1

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'

GEOIP_DIR="${GEOIP_DIR:-./geoip}"
DB_FILE="${GEOIP_DIR}/IP2LOCATION-LITE-DB1.BIN"
DOWNLOAD_URL="https://download.ip2location.com/lite/IP2LOCATION-LITE-DB1.BIN.ZIP"
CHECK_ONLY=false

for arg in "$@"; do
    [ "$arg" = "--check" ] && CHECK_ONLY=true
done

ok()   { echo -e "${GREEN}✓${NC}  $*"; }
warn() { echo -e "${YELLOW}⚠${NC}  $*"; }
fail() { echo -e "${RED}✗${NC}  $*"; }
info() { echo -e "${CYAN}·${NC}  $*"; }

echo ""
echo "GeoIP Database — IP2Location LITE DB1"
echo "──────────────────────────────────────"
echo ""

# ── Check current database age ─────────────────────────────────────────────────
if [ -f "$DB_FILE" ]; then
    MOD_TIME=$(stat -c %Y "$DB_FILE" 2>/dev/null || stat -f %m "$DB_FILE" 2>/dev/null)
    NOW=$(date +%s)
    AGE_DAYS=$(( (NOW - MOD_TIME) / 86400 ))
    DB_DATE=$(date -d "@${MOD_TIME}" '+%Y-%m-%d' 2>/dev/null || date -r "${MOD_TIME}" '+%Y-%m-%d' 2>/dev/null || echo "unknown")
    info "Current database:  ${DB_FILE}"
    info "Last updated:      ${DB_DATE}  (${AGE_DAYS} days ago)"
    if [ "$AGE_DAYS" -gt 35 ]; then
        warn "Database is over 35 days old — update recommended (IP2Location publishes monthly)"
    elif [ "$AGE_DAYS" -gt 60 ]; then
        fail "Database is over 60 days old — GeoIP accuracy will be degraded"
    else
        ok "Database age is acceptable"
    fi
else
    warn "No database found at ${DB_FILE}"
    info "GeoIP country filtering is currently disabled"
fi

if [ "$CHECK_ONLY" = true ]; then
    echo ""
    echo "Run without --check to download the latest version."
    echo ""
    exit 0
fi

# ── Download ───────────────────────────────────────────────────────────────────
echo ""
info "Downloading from: ${DOWNLOAD_URL}"

TMPDIR_WORK=$(mktemp -d)
trap 'rm -rf "$TMPDIR_WORK"' EXIT

ZIP_FILE="${TMPDIR_WORK}/IP2LOCATION-LITE-DB1.BIN.ZIP"

if ! curl -fsSL --max-time 120 --retry 3 --retry-delay 5 \
        -o "$ZIP_FILE" \
        "$DOWNLOAD_URL"; then
    fail "Download failed."
    echo ""
    echo "  If this keeps failing:"
    echo "  1. Download manually from: https://lite.ip2location.com/"
    echo "     (Free account may be required — select DB1, BIN format)"
    echo "  2. Place the .BIN file at: ${DB_FILE}"
    echo "  3. Restart the proxy:  make stop && make start"
    exit 1
fi

ok "Downloaded: $(du -h "$ZIP_FILE" | cut -f1)"

# ── Extract ────────────────────────────────────────────────────────────────────
if ! command -v unzip > /dev/null 2>&1; then
    fail "unzip is not installed. Install it with: sudo apt install unzip"
    exit 1
fi

unzip -q -o "$ZIP_FILE" -d "$TMPDIR_WORK"
NEW_DB=$(find "$TMPDIR_WORK" -name "IP2LOCATION-LITE-DB1.BIN" | head -1)

if [ -z "$NEW_DB" ]; then
    fail "Extracted archive does not contain IP2LOCATION-LITE-DB1.BIN"
    echo "  Contents of archive:"
    unzip -l "$ZIP_FILE" | tail -10
    exit 1
fi

# ── Validate ───────────────────────────────────────────────────────────────────
DB_SIZE=$(stat -c %s "$NEW_DB" 2>/dev/null || stat -f %z "$NEW_DB" 2>/dev/null)
if [ "${DB_SIZE:-0}" -lt 1000000 ]; then
    fail "Downloaded file looks too small (${DB_SIZE} bytes) — download may be incomplete"
    exit 1
fi
ok "Validated: ${DB_SIZE} bytes"

# ── Install ────────────────────────────────────────────────────────────────────
mkdir -p "$GEOIP_DIR"

# Keep a backup of the previous database
if [ -f "$DB_FILE" ]; then
    BACKUP="${DB_FILE}.prev"
    cp "$DB_FILE" "$BACKUP"
    info "Previous database backed up to: ${BACKUP}"
fi

cp "$NEW_DB" "$DB_FILE"
ok "Installed: ${DB_FILE}"

# ── Done ───────────────────────────────────────────────────────────────────────
NEW_DATE=$(date '+%Y-%m-%d')
echo ""
echo "──────────────────────────────────────"
ok "GeoIP database updated to ${NEW_DATE}"
echo ""
echo "  The proxy reads the database at startup."
echo "  Restart to use the new database:"
echo ""
echo "    make stop && make start"
echo ""
echo "  If GeoIP filtering is not yet enabled in config/proxy.yml:"
echo "    Set geoip.enabled: true  and add countries to country_blacklist"
echo ""
echo "  Attribution: This product includes IP2Location LITE data"
echo "  available from https://lite.ip2location.com, licensed CC-BY-SA 4.0."
echo ""
