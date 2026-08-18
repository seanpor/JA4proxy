#!/usr/bin/env bash
# update-geoip.sh — Download the geo databases JA4proxy needs
#
# TWO MaxMind databases, both needing a free licence key:
#
#   GeoLite2-ASN      — IP -> ASN number + organisation name
#   GeoLite2-Country  — IP -> country
#
# phase-827 history, worth keeping because both failures were silent:
#
#   * config/proxy.yml had asn_classifier.enabled: true pointing at a
#     GeoLite2-ASN.mmdb that nothing ever downloaded, so every lookup returned
#     "DB absent". That disabled three scoring signals (asn_datacenter +20,
#     asn_vpn +10, asn_unknown +5) and left connection events with no ASN or
#     organisation, so findings could not distinguish a consumer ISP /24 from a
#     hosting provider /24.
#
#   * The country database was IP2Location's .BIN, while cmd/ja4pd opens it with
#     geoip2.Open() — MaxMind's reader, which cannot parse that vendor's format.
#     Every start logged "invalid MaxMind DB file" and country lookup stayed
#     disabled. Nothing else in the codebase read the file, so it was 2.9 MB of
#     committed data consumed by nobody. Removed; the country database is now
#     MaxMind's, which is the format the code actually requires.
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
CHECK_ONLY=false

# Must match config/proxy.yml -> security.asn_classifier.maxmind_db_path.
ASN_DB_FILE="${ASN_DB_FILE:-./config/GeoLite2-ASN.mmdb}"
ASN_EDITION="GeoLite2-ASN"

# Must match config/proxy.yml -> geoip.database_path.
COUNTRY_DB_FILE="${COUNTRY_DB_FILE:-./config/GeoLite2-Country.mmdb}"
COUNTRY_EDITION="GeoLite2-Country"
COUNTRY_FAILED=false

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

TMPDIR_WORK=$(mktemp -d)
trap 'rm -rf "$TMPDIR_WORK"' EXIT

# ── ASN database (MaxMind GeoLite2-ASN) ────────────────────────────────────────
echo ""
echo "ASN Database — MaxMind ${ASN_EDITION}"
echo "──────────────────────────────────────"

if [ -z "${MAXMIND_LICENSE_KEY:-}" ]; then
    fail "MAXMIND_LICENSE_KEY is not set — cannot download ${ASN_EDITION}."
    echo ""
    echo "  MaxMind require a (free) account:"
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
    # shellcheck disable=SC2034  # consumed by the Country block appended below
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
            # A truncated download, or an HTML error page saved under this
            # name, would leave the proxy reporting "DB absent" with a file
            # sitting right there — so validate the content, not just the size.
            #
            # The marker to look for is at the END of the file. The MaxMind DB
            # format stores its metadata section last, introduced by
            # \xab\xcd\xefMaxMind.com — in this 12 MB database it begins 214
            # bytes from the end. A first attempt at this check grepped the
            # first 200 bytes for "MaxMind" and rejected a perfectly good
            # download.
            ASN_SIZE=$(stat -c %s "$NEW_ASN" 2>/dev/null || stat -f %z "$NEW_ASN" 2>/dev/null)
            if [ "${ASN_SIZE:-0}" -lt 100000 ]; then
                fail "Downloaded ${ASN_EDITION}.mmdb looks too small (${ASN_SIZE} bytes)"
                ASN_FAILED=true
            elif ! tail -c 131072 "$NEW_ASN" | grep -qa "MaxMind.com"; then
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

# ── Country database (MaxMind GeoLite2-Country) ────────────────────────────────
# cmd/ja4pd opens the country DB with geoip2.Open(), MaxMind's reader. It was
# pointed at IP2Location's .BIN, a different vendor's format, so country lookup
# logged "invalid MaxMind DB file" and stayed disabled. Fetched here so the
# format the code requires is the format that lands on disk.
echo ""
echo "Country Database — MaxMind ${COUNTRY_EDITION}"
echo "──────────────────────────────────────"
if [ -z "${MAXMIND_LICENSE_KEY:-}" ]; then
    warn "MAXMIND_LICENSE_KEY not set — skipping ${COUNTRY_EDITION}."
    COUNTRY_FAILED=true
else
    C_URL="https://download.maxmind.com/app/geoip_download?edition_id=${COUNTRY_EDITION}&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"
    C_TGZ="${TMPDIR_WORK}/${COUNTRY_EDITION}.tar.gz"
    info "Downloading ${COUNTRY_EDITION} from MaxMind..."
    if ! curl -fsSL --max-time 120 --retry 3 --retry-delay 5 -o "$C_TGZ" "$C_URL"; then
        fail "Download failed (a 401 means the licence key is wrong or revoked)."
        COUNTRY_FAILED=true
    else
        tar -xzf "$C_TGZ" -C "$TMPDIR_WORK"
        NEW_C=$(find "$TMPDIR_WORK" -name "${COUNTRY_EDITION}.mmdb" | head -1)
        C_SIZE=$(stat -c %s "$NEW_C" 2>/dev/null || stat -f %z "$NEW_C" 2>/dev/null || echo 0)
        if [ -z "$NEW_C" ] || [ "${C_SIZE:-0}" -lt 100000 ]; then
            fail "Archive did not contain a plausible ${COUNTRY_EDITION}.mmdb"
            COUNTRY_FAILED=true
        elif ! tail -c 131072 "$NEW_C" | grep -qa "MaxMind.com"; then
            fail "File does not look like a MaxMind database — refusing to install"
            COUNTRY_FAILED=true
        else
            ok "Validated: ${C_SIZE} bytes"
            mkdir -p "$(dirname "$COUNTRY_DB_FILE")"
            [ -f "$COUNTRY_DB_FILE" ] && cp "$COUNTRY_DB_FILE" "${COUNTRY_DB_FILE}.prev"
            cp "$NEW_C" "$COUNTRY_DB_FILE"
            ok "Installed: ${COUNTRY_DB_FILE}"
        fi
    fi
fi

if [ "$COUNTRY_FAILED" = true ]; then
    ASN_FAILED=true
fi

if [ "$ASN_FAILED" = true ]; then
    echo ""
    warn "Country database updated, but the ASN database was NOT installed."
    warn "Exiting non-zero so scheduled runs surface this rather than logging success."
    exit 1
fi
