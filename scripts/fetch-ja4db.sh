#!/usr/bin/env bash
# fetch-ja4db.sh — Fetch known-bad JA4 fingerprints from FoxIO's public database
#
# Sources (tried in order):
#   1. FoxIO GitHub ja4db CSV  (primary — no auth required)
#   2. ja4db.com API           (secondary — if API key is set in .env)
#
# Workflow:
#   - New malicious fingerprints go into a Redis pending queue (ja4:pending HASH)
#   - Admin reviews with: ./scripts/ja4-admin.sh list-pending
#   - Approve:  ./scripts/ja4-admin.sh approve <fingerprint>
#   - Reject:   ./scripts/ja4-admin.sh reject  <fingerprint>
#   - Or bulk:  ./scripts/ja4-admin.sh approve-all
#
# Suitable for cron:  0 */6 * * *  /path/to/scripts/fetch-ja4db.sh >> /var/log/ja4db-fetch.log 2>&1

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

ENV_FILE="${ENV_FILE:-.env}"
REDIS_CONTAINER="${REDIS_CONTAINER:-ja4proxy-redis}"
CACHE_DIR="${CACHE_DIR:-/tmp/ja4db_cache}"

# Categories from ja4db that we consider malicious (case-insensitive match)
MALICIOUS_CATEGORIES="malware|c2|trojan|ransomware|rat|botnet|spyware|backdoor|exploit|infostealer|banker|dropper|loader|stealer|beacon|implant|agent"

# ── Helpers ────────────────────────────────────────────────────────────────────
die() { echo -e "${RED}✗ $*${NC}" >&2; exit 1; }
info() { echo -e "${CYAN}▶ $*${NC}"; }
ok()   { echo -e "${GREEN}✓ $*${NC}"; }
warn() { echo -e "${YELLOW}⚠ $*${NC}"; }

load_env() {
    [ -f "$ENV_FILE" ] || die ".env not found — run ./scripts/start-poc.sh first."
    REDIS_PASS=$(grep '^REDIS_PASSWORD=' "$ENV_FILE" 2>/dev/null | cut -d= -f2 || true)
    [ -n "$REDIS_PASS" ] || die "No REDIS_PASSWORD in .env"
    JA4DB_API_KEY=$(grep '^JA4DB_API_KEY=' "$ENV_FILE" 2>/dev/null | cut -d= -f2 || true)
}

redis_cmd() {
    docker exec "$REDIS_CONTAINER" redis-cli -a "$REDIS_PASS" --no-auth-warning "$@" 2>/dev/null
}

mkdir -p "$CACHE_DIR"

# ── Source 1: FoxIO GitHub ja4db CSV ──────────────────────────────────────────
# The FoxIO JA4 repository publishes a fingerprint database as a CSV.
# We try several known paths (the repo structure has evolved over releases).
fetch_github() {
    local urls=(
        "https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/ja4db/ja4db.csv"
        "https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/technical_details/JA4_fingerprints.csv"
        "https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/ja4db.csv"
    )
    for url in "${urls[@]}"; do
        info "Trying GitHub: $url"
        if curl -sf --max-time 30 "$url" -o "$CACHE_DIR/ja4db_github.csv" 2>/dev/null; then
            local lines
            lines=$(wc -l < "$CACHE_DIR/ja4db_github.csv")
            if [ "$lines" -gt 5 ]; then
                ok "Downloaded ja4db from GitHub ($lines lines)"
                echo "$CACHE_DIR/ja4db_github.csv"
                return 0
            fi
        fi
    done
    warn "GitHub fetch failed — trying ja4db.com"
    return 1
}

# ── Source 2: ja4db.com API ────────────────────────────────────────────────────
# If JA4DB_API_KEY is set in .env, fetch the full malware fingerprint list.
fetch_ja4db_api() {
    if [ -z "${JA4DB_API_KEY:-}" ]; then
        warn "JA4DB_API_KEY not set in .env — skipping ja4db.com API"
        return 1
    fi
    info "Querying ja4db.com API..."
    local api_url="https://ja4db.com/api/v1/export?category=malware&format=csv"
    if curl -sf --max-time 30 \
        -H "Authorization: Bearer $JA4DB_API_KEY" \
        "$api_url" -o "$CACHE_DIR/ja4db_api.csv" 2>/dev/null; then
        local lines
        lines=$(wc -l < "$CACHE_DIR/ja4db_api.csv")
        if [ "$lines" -gt 1 ]; then
            ok "Downloaded ja4db.com API export ($lines lines)"
            echo "$CACHE_DIR/ja4db_api.csv"
            return 0
        fi
    fi
    warn "ja4db.com API fetch failed"
    return 1
}

# ── Parse and queue fingerprints ───────────────────────────────────────────────
# Expects CSV with at least: fingerprint (col 1 or 4), name, category
# Multiple column layouts are handled:
#   Layout A: JA4, Application, Name, Category, Reference  (FoxIO GitHub)
#   Layout B: JA4_r, Application, Application_Category, JA4  (alternate)
#   Layout C: fingerprint, name, category, ...
queue_from_csv() {
    local csv_file="$1"
    local source="$2"
    local added=0 skipped=0 already=0

    # Detect header layout from first line
    local header
    header=$(head -1 "$csv_file" | tr '[:upper:]' '[:lower:]')

    info "Parsing $csv_file (source: $source)"
    info "Header: $header"

    # Use python3 for robust CSV parsing (handles quoted fields)
    python3 - "$csv_file" "$source" "$MALICIOUS_CATEGORIES" <<'PYEOF'
import csv, sys, json, subprocess, os, re

csv_file = sys.argv[1]
source   = sys.argv[2]
bad_cats = sys.argv[3]  # pipe-separated malicious category keywords

redis_pass = os.environ.get('REDIS_PASS', '')
redis_container = os.environ.get('REDIS_CONTAINER', 'ja4proxy-redis')

def redis(cmd_args):
    r = subprocess.run(
        ['docker', 'exec', redis_container, 'redis-cli',
         '-a', redis_pass, '--no-auth-warning'] + cmd_args,
        capture_output=True, text=True
    )
    return r.stdout.strip()

cat_re = re.compile(bad_cats, re.IGNORECASE)
added = skipped = already = 0

with open(csv_file, newline='', encoding='utf-8', errors='replace') as f:
    reader = csv.DictReader(f)
    headers = [h.lower().strip() for h in (reader.fieldnames or [])]

    # Map column names flexibly
    def col(row, *candidates):
        for c in candidates:
            for h in headers:
                if c in h:
                    return row.get(reader.fieldnames[headers.index(h)], '').strip()
        return ''

    for row in reader:
        # Extract fingerprint — prefer the processed JA4 (not JA4_r raw)
        fp = col(row, 'ja4_f', 'ja4 ') or col(row, 'ja4')
        if not fp:
            fp = col(row, 'fingerprint')
        fp = fp.strip().lower()

        # Validate JA4 format: alphanumeric + underscores, reasonable length
        if not re.match(r'^[a-z0-9_]{10,60}$', fp):
            skipped += 1
            continue

        # Extract metadata
        name     = col(row, 'name', 'application') or fp
        category = col(row, 'category', 'subcategory', 'type', 'tags')

        # Only queue if category matches malicious keywords
        if not cat_re.search(category) and not cat_re.search(name):
            skipped += 1
            continue

        # Skip if already in blacklist or whitelist
        in_bl = redis(['SISMEMBER', 'ja4:blacklist', fp])
        in_wl = redis(['SISMEMBER', 'ja4:whitelist', fp])
        if in_bl == '1' or in_wl == '1':
            already += 1
            continue

        # Add to pending HASH (ja4:pending field=fp value=json)
        metadata = json.dumps({
            'name': name[:80],
            'category': category[:40],
            'source': source,
            'fetched_at': __import__('datetime').datetime.utcnow().isoformat() + 'Z'
        })
        result = redis(['HSET', 'ja4:pending', fp, metadata])
        if result in ('0', '1'):  # 0=updated existing, 1=new field
            added += 1

print(f"RESULT:{added}:{skipped}:{already}")
PYEOF
    local result_line
    result_line=$(redis_cmd HLEN "ja4:pending" 2>/dev/null || echo "?")
    ok "Pending queue now has $result_line fingerprints awaiting review"
}

# ── Main ───────────────────────────────────────────────────────────────────────
main() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════${NC}"
    echo -e "${CYAN}  JA4proxy — ja4db fingerprint fetch    ${NC}"
    echo -e "${CYAN}════════════════════════════════════════${NC}"
    echo ""

    load_env

    # Export for use by embedded Python
    export REDIS_PASS="$REDIS_PASS"
    export REDIS_CONTAINER="$REDIS_CONTAINER"

    local csv_file=""

    # Try GitHub first
    if csv_file=$(fetch_github 2>/dev/null); then
        queue_from_csv "$csv_file" "foxio_github"
    fi

    # Then try ja4db.com API if key available
    local api_file=""
    if api_file=$(fetch_ja4db_api 2>/dev/null); then
        queue_from_csv "$api_file" "ja4db_api"
    fi

    if [ -z "$csv_file" ] && [ -z "$api_file" ]; then
        warn "No data source was reachable."
        warn "Check network connectivity, or add JA4DB_API_KEY=<key> to .env"
        exit 1
    fi

    local pending_count
    pending_count=$(redis_cmd HLEN "ja4:pending" 2>/dev/null || echo "0")

    echo ""
    echo -e "${YELLOW}Review pending fingerprints:${NC}"
    echo -e "  ./scripts/ja4-admin.sh list-pending"
    echo -e "  ./scripts/ja4-admin.sh approve <fingerprint>"
    echo -e "  ./scripts/ja4-admin.sh approve-all"
    echo ""

    if [ "${pending_count:-0}" -gt 0 ]; then
        echo -e "${RED}${pending_count} fingerprints awaiting approval.${NC}"
        echo -e "Run ${CYAN}./scripts/ja4-admin.sh list-pending${NC} to review them."
    else
        ok "No new fingerprints to review — blacklist is up to date."
    fi
    echo ""
}

main "$@"
