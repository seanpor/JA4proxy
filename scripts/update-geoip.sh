#!/usr/bin/env bash
# update-geoip.sh — Download the geo databases JA4proxy needs
#
# TWO databases, from two vendors, with different access rules:
#
#   1. IP2Location LITE DB1  — IP -> country. Anonymous download, no key.
#   2. MaxMind GeoLite2-ASN  — IP -> ASN number + organisation name.
#                              Requires a FREE MaxMind account and licence key.
#
# Until phase-827 this script fetched only (1), while config/proxy.yml had
# `asn_classifier.enabled: true` pointing at a GeoLite2-ASN.mmdb that nothing
# ever downloaded. The classifier therefore reported "DB absent" on every
# lookup, which silently disabled THREE scoring signals (asn_datacenter +20,
# asn_vpn +10, asn_unknown +5) and left the connection event with no ASN or
# organisation at all — so the analytics node could not distinguish a consumer
# ISP /24 from a hosting provider /24. Tor detection kept working (separate
# list, checked before the DB lookup), which is probably why it went unnoticed.
#
# The proxy warns at startup when the ASN DB is missing. Before phase-827 that
# warning told the operator to run this script, which did not fetch it.
#
# Usage:
#   ./scripts/update-geoip.sh            # Update both (ASN needs the key below)
#   ./scripts/update-geoip.sh --check    # Report the age of both, download nothing
#
# The ASN database needs a licence key, supplied either way:
#   export MAXMIND_LICENSE_KEY=...       # free: https://www.maxmind.com/en/geolite2/signup
#   (or put MAXMIND_LICENSE_KEY=... in .env — this script reads it)
#
# Without a key the country database still updates; the ASN step prints
# instructions and the script exits non-zero so automation notices.
#
# After updating: restart the proxy to load the new database.
#   make stop && make start
#
# Recommended: run monthly, e.g. via cron:
#   0 3 1 * * /path/to/scripts/update-geoip.sh >> /var/log/ja4proxy-geoip-update.log 2>&1

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'

# phase-827: was ./geoip, but docker-compose.poc.yml mounts ../../data/geoip
# at /app/geoip and config/proxy.yml reads
# /app/geoip/IP2LOCATION-LITE-DB1.BIN. The script therefore wrote the country
# database to a directory nothing mounts — `make update-geoip` reported success
# and country lookups stayed empty. Default now matches the mount.
GEOIP_DIR="${GEOIP_DIR:-./data/geoip}"
DB_FILE="${GEOIP_DIR}/IP2LOCATION-LITE-DB1.BIN"
DOWNLOAD_URL="https://download.ip2location.com/lite/IP2LOCATION-LITE-DB1.BIN.ZIP"
CHECK_ONLY=false

# Must match config/proxy.yml -> security.asn_classifier.maxmind_db_path.
ASN_DB_FILE="${ASN_DB_FILE:-./config/GeoLite2-ASN.mmdb}"
ASN_EDITION="GeoLite2-ASN"

# Convenience: most operators keep the key alongside the other secrets.
if [ -z "${MAXMIND_LICENSE_KEY:-}" ] && [ -f .env ]; then
    MAXMIND_LICENSE_KEY=$(grep -E '^MAXMIND_LICENSE_KEY=' .env 2>/dev/null | cut -d= -f2- || true)
fi
ASN_FAILED=false

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

# ── ASN database status ────────────────────────────────────────────────────────
echo ""
echo "ASN Database — MaxMind ${ASN_EDITION}"
echo "──────────────────────────────────────"
if [ -f "$ASN_DB_FILE" ]; then
    A_MOD=$(stat -c %Y "$ASN_DB_FILE" 2>/dev/null || stat -f %m "$ASN_DB_FILE" 2>/dev/null)
    A_AGE=$(( ($(date +%s) - A_MOD) / 86400 ))
    A_DATE=$(date -d "@${A_MOD}" '+%Y-%m-%d' 2>/dev/null || date -r "${A_MOD}" '+%Y-%m-%d' 2>/dev/null || echo unknown)
    info "Current database:  ${ASN_DB_FILE}"
    info "Last updated:      ${A_DATE}  (${A_AGE} days ago)"
    if [ "$A_AGE" -gt 35 ]; then
        warn "Over 35 days old — MaxMind publish weekly; update recommended"
    else
        ok "Database age is acceptable"
    fi
else
    warn "No database found at ${ASN_DB_FILE}"
    fail "ASN enrichment is DISABLED — this is not cosmetic:"
    echo "     · asn_datacenter (+20), asn_vpn (+10), asn_unknown (+5) never fire"
    echo "     · connection events carry no ASN or organisation, so findings"
    echo "       cannot tell a consumer ISP /24 from a hosting provider /24"
    echo "     · docs/reference/GOOD_TRAFFIC_PROFILE.md rule 5 is unenforceable"
fi

if [ "$CHECK_ONLY" = true ]; then
    echo ""
    echo "Run without --check to download the latest versions."
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

# ── ASN database (MaxMind GeoLite2-ASN) ────────────────────────────────────────
echo ""
echo "ASN Database — MaxMind ${ASN_EDITION}"
echo "──────────────────────────────────────"

if [ -z "${MAXMIND_LICENSE_KEY:-}" ]; then
    fail "MAXMIND_LICENSE_KEY is not set — cannot download ${ASN_EDITION}."
    echo ""
    echo "  Unlike IP2Location LITE, MaxMind require a (free) account:"
    echo "    1. Sign up:        https://www.maxmind.com/en/geolite2/signup"
    echo "    2. Create a key:   Account -> Manage License Keys"
    echo "    3. Then either:"
    echo "         export MAXMIND_LICENSE_KEY=...   (this shell)"
    echo "       or add to .env:"
    echo "         MAXMIND_LICENSE_KEY=...          (picked up automatically)"
    echo ""
    echo "  Manual alternative — download ${ASN_EDITION} (mmdb format) and place at:"
    echo "    ${ASN_DB_FILE}"
    echo ""
    echo "  Until then the proxy runs WITHOUT ASN enrichment. See"
    echo "  docs/runbooks/geoip_databases.md for what that disables."
    ASN_FAILED=true
else
    ASN_URL="https://download.maxmind.com/app/geoip_download?edition_id=${ASN_EDITION}&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"
    ASN_TGZ="${TMPDIR_WORK}/${ASN_EDITION}.tar.gz"

    # The key is a credential: never echo ASN_URL.
    info "Downloading ${ASN_EDITION} from MaxMind..."
    if ! curl -fsSL --max-time 120 --retry 3 --retry-delay 5 -o "$ASN_TGZ" "$ASN_URL"; then
        fail "Download failed. A 401 here almost always means the licence key is"
        echo "     wrong or has been revoked — check Account -> Manage License Keys."
        ASN_FAILED=true
    else
        ok "Downloaded: $(du -h "$ASN_TGZ" | cut -f1)"
        tar -xzf "$ASN_TGZ" -C "$TMPDIR_WORK"
        NEW_ASN=$(find "$TMPDIR_WORK" -name "${ASN_EDITION}.mmdb" | head -1)

        if [ -z "$NEW_ASN" ]; then
            fail "Archive did not contain ${ASN_EDITION}.mmdb"
            ASN_FAILED=true
        else
            # An mmdb starts with a binary header, not text. A truncated download
            # or an HTML error page installed under this name would leave the
            # proxy reporting "DB absent" with a file sitting right there.
            ASN_SIZE=$(stat -c %s "$NEW_ASN" 2>/dev/null || stat -f %z "$NEW_ASN" 2>/dev/null)
            if [ "${ASN_SIZE:-0}" -lt 100000 ]; then
                fail "Downloaded ${ASN_EDITION}.mmdb looks too small (${ASN_SIZE} bytes)"
                ASN_FAILED=true
            elif ! head -c 200 "$NEW_ASN" | grep -qa "MaxMind"; then
                fail "File does not look like a MaxMind database — refusing to install"
                ASN_FAILED=true
            else
                ok "Validated: ${ASN_SIZE} bytes"
                mkdir -p "$(dirname "$ASN_DB_FILE")"
                [ -f "$ASN_DB_FILE" ] && cp "$ASN_DB_FILE" "${ASN_DB_FILE}.prev" \
                    && info "Previous database backed up to: ${ASN_DB_FILE}.prev"
                cp "$NEW_ASN" "$ASN_DB_FILE"
                ok "Installed: ${ASN_DB_FILE}"
            fi
        fi
    fi
fi

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

if [ "$ASN_FAILED" = true ]; then
    echo ""
    warn "Country database updated, but the ASN database was NOT installed."
    warn "Exiting non-zero so scheduled runs surface this rather than logging success."
    exit 1
fi
