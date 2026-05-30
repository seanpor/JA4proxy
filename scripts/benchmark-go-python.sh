#!/usr/bin/env bash
# scripts/benchmark-go-python.sh
#
# Comprehensive benchmark suite: Go proxy vs Python proxy.
#
# Orchestrates the full benchmark lifecycle:
#   1. Build Go binary if missing
#   2. Start both proxies (or verify they are already running)
#   3. Run the Python benchmark engine (benchmark_comparison.py)
#   4. Print the report location
#
# Usage:
#   ./scripts/benchmark-go-python.sh [OPTIONS]
#
# Options:
#   --quick                 10 s per scenario, max 16 threads  (~10 min total)
#   --duration-quick SECS   Seconds per quick scenario         (default: 15)
#   --duration-long  SECS   Seconds per sustained scenario     (default: 60)
#   --max-threads N         Maximum thread count               (default: 32)
#   --scenarios LIST        Comma-separated scenarios or "all" (default: all)
#   --python-port PORT      Python proxy port                  (default: 8080)
#   --go-port PORT          Go proxy port                      (default: 8082)
#   --output-dir DIR        Report output directory            (default: auto)
#   --no-docker             Skip Docker startup; assume proxies already running
#   --skip-build            Skip Go binary build (requires existing bin/ja4proxy)
#   --no-redis-flush        Do not flush Redis between scenarios
#   --proxy python|go       Benchmark only one proxy
#   --connect-timeout SECS  Per-connection TCP timeout         (default: 2)
#   --use-proxy-protocol    Inject PPv2 header with rotating synthetic source IP
#                           Prevents per-IP rate limiting from capping the attack_500
#                           scenario. Requires proxy_protocol: true in config/proxy.yml.
#   --source-ip-pool N      Synthetic IP pool size for PPv2    (default: 1000)
#   --attack-rate N         Target conn/s for attack_500       (default: 500)
#   --fast-backend-port P   Port of fast TLS echo backend      (default: 8444)
#                           Start it first: python3 scripts/bench-tls-backend.py --port 8444
#   --help                  Show this message
#
# Environment variables honoured:
#   REDIS_PASSWORD    Redis auth password
#   GOROOT            Go root (default: /snap/go/current)
#   BACKEND_HOST      Backend hostname seen by proxy (default: backend)
#   BACKEND_PORT      Backend port                   (default: 443)
#
# Examples:
#   # Quick sanity run (both proxies already up):
#   ./scripts/benchmark-go-python.sh --quick --no-docker
#
#   # Full benchmark with Docker startup:
#   ./scripts/benchmark-go-python.sh --duration-long 60
#
#   # Only throughput scenarios, 60 s each:
#   ./scripts/benchmark-go-python.sh --scenarios peak_throughput,sustained_load \
#       --duration-long 60 --no-docker
#
#   # Go proxy only (Python not running):
#   ./scripts/benchmark-go-python.sh --proxy go --no-docker

set -euo pipefail

# ── Script location ────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

# ── Defaults ──────────────────────────────────────────────────────────────────
QUICK=false
DURATION_QUICK=15
DURATION_LONG=60
MAX_THREADS=32
SCENARIOS="all"
PYTHON_HOST="127.0.0.1"
PYTHON_PORT=8080
GO_HOST="127.0.0.1"
GO_PORT=8082
OUTPUT_DIR=""
USE_DOCKER=true
SKIP_BUILD=false
FLUSH_REDIS=true
PROXY_FILTER="go"
CONNECT_TIMEOUT=2
USE_PROXY_PROTOCOL=false
SOURCE_IP_POOL_SIZE=1000
ATTACK_RATE=500
FAST_BACKEND_PORT=8444

REDIS_PASSWORD="${REDIS_PASSWORD:-}"
# GOROOT validation: the snap Go package sets GOROOT=/usr/share/go in the shell
# environment, but the stdlib actually lives at /snap/go/current/src.  Detect
# and correct this by checking whether the fmt package exists under GOROOT.
GOROOT="${GOROOT:-/snap/go/current}"
if [[ ! -d "${GOROOT}/src/fmt" ]]; then
    GOROOT="/snap/go/current"
fi
if [[ ! -d "${GOROOT}/src/fmt" ]]; then
    # Last resort: ask the go binary itself (may still be wrong with snap, but worth trying)
    _goroot_probe="$(go env GOROOT 2>/dev/null || true)"
    if [[ -d "${_goroot_probe}/src/fmt" ]]; then
        GOROOT="${_goroot_probe}"
    fi
fi
BACKEND_HOST="${BACKEND_HOST:-backend}"
BACKEND_PORT="${BACKEND_PORT:-443}"

# ── Colour helpers ─────────────────────────────────────────────────────────────
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''
fi

log()  { printf "  %s\n" "$*"; }
ok()   { printf "  ${GREEN}✓${RESET}  %s\n" "$*"; }
warn() { printf "  ${YELLOW}⚠${RESET}  %s\n" "$*"; }
fail() { printf "  ${RED}✗${RESET}  %s\n" "$*"; }
step() { printf "\n${BOLD}${CYAN}━━━ %s ━━━${RESET}\n" "$*"; }

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --quick)            QUICK=true; shift ;;
        --duration-quick)   DURATION_QUICK="$2"; shift 2 ;;
        --duration-long)    DURATION_LONG="$2"; shift 2 ;;
        --max-threads)      MAX_THREADS="$2"; shift 2 ;;
        --scenarios)        SCENARIOS="$2"; shift 2 ;;
        --python-port)      PYTHON_PORT="$2"; shift 2 ;;
        --go-port)          GO_PORT="$2"; shift 2 ;;
        --python-host)      PYTHON_HOST="$2"; shift 2 ;;
        --go-host)          GO_HOST="$2"; shift 2 ;;
        --output-dir)       OUTPUT_DIR="$2"; shift 2 ;;
        --no-docker)        USE_DOCKER=false; shift ;;
        --skip-build)       SKIP_BUILD=true; shift ;;
        --no-redis-flush)   FLUSH_REDIS=false; shift ;;
        --proxy)            PROXY_FILTER="$2"; shift 2 ;;
        --connect-timeout)      CONNECT_TIMEOUT="$2"; shift 2 ;;
        --use-proxy-protocol)   USE_PROXY_PROTOCOL=true; shift ;;
        --source-ip-pool)       SOURCE_IP_POOL_SIZE="$2"; shift 2 ;;
        --attack-rate)          ATTACK_RATE="$2"; shift 2 ;;
        --fast-backend-port)    FAST_BACKEND_PORT="$2"; shift 2 ;;
        --help|-h)
            sed -n '3,65p' "${BASH_SOURCE[0]}"
            exit 0
            ;;
        *)
            fail "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [[ "$QUICK" == "true" ]]; then
    DURATION_QUICK=10
    DURATION_LONG=30
    MAX_THREADS=16
fi

# ── Header ────────────────────────────────────────────────────────────────────
printf '\n%s' "${BOLD}"
printf "╔══════════════════════════════════════════════════════════════╗\n"
printf "║      JA4proxy Benchmark: Go Proxy vs Python Proxy           ║\n"
printf "╚══════════════════════════════════════════════════════════════╝\n"
printf '%s\n' "${RESET}"
log "Repository:     ${REPO_ROOT}"
log "Python proxy:   ${PYTHON_HOST}:${PYTHON_PORT}"
log "Go proxy:       ${GO_HOST}:${GO_PORT}"
log "Scenarios:      ${SCENARIOS}"
log "Quick mode:     ${QUICK}"
log "Duration quick: ${DURATION_QUICK}s"
log "Duration long:  ${DURATION_LONG}s"
log "Max threads:    ${MAX_THREADS}"
log "Use Docker:     ${USE_DOCKER}"
printf "\n"

# ── Prerequisites ─────────────────────────────────────────────────────────────
step "Prerequisites"

# python3
if ! command -v python3 &>/dev/null; then
    fail "python3 not found"; exit 1
fi
ok "python3: $(python3 --version 2>&1)"

# Check benchmark_comparison.py exists
BENCH_PY="${SCRIPT_DIR}/benchmark_comparison.py"
if [[ ! -f "${BENCH_PY}" ]]; then
    fail "benchmark_comparison.py not found at ${BENCH_PY}"
    exit 1
fi
ok "benchmark_comparison.py found"

# ── Build Go binary ────────────────────────────────────────────────────────────
step "Go Binary"

if [[ "$SKIP_BUILD" == "true" ]]; then
    if [[ -f "${REPO_ROOT}/bin/ja4proxy" ]]; then
        ok "Skipping build (--skip-build); existing binary: bin/ja4proxy"
    else
        warn "No existing bin/ja4proxy and --skip-build set — Go proxy may not start"
    fi
else
    if command -v go &>/dev/null || [[ -x "${GOROOT}/bin/go" ]]; then
        GO_BIN="${GOROOT}/bin/go"
        if ! command -v go &>/dev/null; then
            log "Using Go at ${GO_BIN}"
        else
            GO_BIN="go"
        fi
        log "Building Go proxy (GOROOT=${GOROOT}) ..."
        GOROOT="${GOROOT}" "${GO_BIN}" build -o bin/ja4proxy ./cmd/proxy 2>&1 | \
            sed 's/^/    /'
        ok "bin/ja4proxy built"
    else
        warn "Go not found (GOROOT=${GOROOT}) — skipping Go binary build"
        warn "If the Go proxy is already running, use --skip-build"
    fi
fi

# ── Docker service management ─────────────────────────────────────────────────
step "Service Management"

_port_open() {
    # Returns 0 if host:port is accepting TCP connections
    local host="$1" port="$2"
    python3 -c "
import socket, sys
try:
    s = socket.create_connection(('${host}', ${port}), timeout=1)
    s.close()
    sys.exit(0)
except OSError:
    sys.exit(1)
" 2>/dev/null
}

PYTHON_UP=false
GO_UP=false

if _port_open "${PYTHON_HOST}" "${PYTHON_PORT}"; then
    PYTHON_UP=true
    ok "Python proxy already running at ${PYTHON_HOST}:${PYTHON_PORT}"
else
    warn "Python proxy not reachable at ${PYTHON_HOST}:${PYTHON_PORT}"
fi

if _port_open "${GO_HOST}" "${GO_PORT}"; then
    GO_UP=true
    ok "Go proxy already running at ${GO_HOST}:${GO_PORT}"
else
    warn "Go proxy not reachable at ${GO_HOST}:${GO_PORT}"
fi

if [[ "$USE_DOCKER" == "true" ]]; then
    # Check Docker is available
    if ! command -v docker &>/dev/null; then
        warn "docker not found — cannot start services automatically"
        USE_DOCKER=false
    fi
fi

if [[ "$USE_DOCKER" == "true" ]]; then
    # Load .env for REDIS_PASSWORD, BACKEND_HOST, etc.
    if [[ -f "${REPO_ROOT}/.env" ]]; then
        set -a
        # shellcheck source=/dev/null
        source "${REPO_ROOT}/.env"
        set +a
        ok ".env loaded"
    fi
    REDIS_PASSWORD="${REDIS_PASSWORD:-changeme}"

    if [[ "$PYTHON_UP" == "false" ]]; then
        log "Starting Python proxy stack (docker compose) ..."
        docker compose -f deploy/docker/docker-compose.poc.yml up -d --quiet-pull 2>&1 | \
            tail -5 | sed 's/^/    /'
        log "Waiting for Python proxy to become healthy ..."
        for i in $(seq 1 30); do
            if _port_open "${PYTHON_HOST}" "${PYTHON_PORT}"; then
                PYTHON_UP=true
                ok "Python proxy up (${i}s)"
                break
            fi
            sleep 2
        done
        if [[ "$PYTHON_UP" == "false" ]]; then
            warn "Python proxy did not start within 60s — continuing without it"
        fi
    fi

    if [[ "$GO_UP" == "false" ]]; then
        log "Starting Go proxy ..."
        docker compose \
            -f deploy/docker/docker-compose.poc.yml \
            up -d --quiet-pull proxy 2>&1 | tail -5 | sed 's/^/    /'
        log "Waiting for Go proxy to become healthy ..."
        for i in $(seq 1 30); do
            if _port_open "${GO_HOST}" "${GO_PORT}"; then
                GO_UP=true
                ok "Go proxy up (${i}s)"
                break
            fi
            sleep 2
        done
        if [[ "$GO_UP" == "false" ]]; then
            warn "Go proxy did not start within 60s — continuing without it"
        fi
    fi
else
    log "(--no-docker: not attempting to start services)"
fi

# Abort if neither proxy is reachable
if [[ "$PYTHON_UP" == "false" && "$GO_UP" == "false" ]]; then
    fail "Neither proxy is reachable. Start services first or remove --no-docker."
    fail "  Python: ${PYTHON_HOST}:${PYTHON_PORT}"
    fail "  Go:     ${GO_HOST}:${GO_PORT}"
    exit 1
fi

# Warn if only one is up (comparison will be partial)
if [[ "$PYTHON_UP" == "false" ]]; then
    warn "Python proxy unreachable — running Go-only benchmark"
    PROXY_FILTER="go"
elif [[ "$GO_UP" == "false" ]]; then
    warn "Go proxy unreachable — running Python-only benchmark"
    PROXY_FILTER="python"
fi

# ── Output directory ──────────────────────────────────────────────────────────
if [[ -z "$OUTPUT_DIR" ]]; then
    TIMESTAMP="$(date +%Y-%m-%d_%H-%M-%S)"
    OUTPUT_DIR="${REPO_ROOT}/reports/benchmark/${TIMESTAMP}"
fi
mkdir -p "${OUTPUT_DIR}"
ok "Output directory: ${OUTPUT_DIR}"

# ── Collect system info ───────────────────────────────────────────────────────
step "System Info"

SYS_INFO_FILE="${OUTPUT_DIR}/sysinfo.txt"
{
    printf "Date:       %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf "Hostname:   %s\n" "$(hostname)"
    printf "OS:         %s\n" "$(uname -srm)"
    printf "CPUs:       %s\n" "$(nproc)"
    if [[ -f /proc/cpuinfo ]]; then
        printf "CPU model:  %s\n" "$(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)"
    fi
    if [[ -f /proc/meminfo ]]; then
        mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
        printf "Memory:     %s GB\n" "$(( mem_kb / 1024 / 1024 ))"
    fi
    printf "Python:     %s\n" "$(python3 --version 2>&1)"
    if command -v go &>/dev/null || [[ -x "${GOROOT}/bin/go" ]]; then
        GO_BIN="${GOROOT}/bin/go"
        command -v go &>/dev/null && GO_BIN="go"
        printf "Go:         %s\n" "$(GOROOT="${GOROOT}" "${GO_BIN}" version 2>&1)"
    fi
    if [[ -f "${REPO_ROOT}/bin/ja4proxy" ]]; then
        printf "ja4proxy binary: %s\n" "$(stat -c '%s bytes, modified %y' "${REPO_ROOT}/bin/ja4proxy" 2>/dev/null || echo 'present')"
    fi
    if command -v docker &>/dev/null; then
        printf "Docker:     %s\n" "$(docker --version 2>&1)"
    fi
} > "${SYS_INFO_FILE}"
cat "${SYS_INFO_FILE}" | sed 's/^/  /'

# Capture docker stats snapshot if Docker is available and proxies are in containers
if command -v docker &>/dev/null && [[ "$USE_DOCKER" == "true" ]]; then
    log ""
    log "Docker container resources:"
    docker stats --no-stream --format \
        "  {{.Name}}: CPU={{.CPUPerc}} MEM={{.MemUsage}}" \
        2>/dev/null | grep -E "ja4proxy|proxy|redis" || true
fi

# ── Fast TLS echo backend (for attack_500 scenario) ──────────────────────────
# bench-tls-backend.py must be started before the benchmark if the attack_500
# scenario is selected and the fast backend port is not already listening.
FAST_BACKEND_PID=""
FAST_BACKEND_PY="${SCRIPT_DIR}/bench-tls-backend.py"

_scenarios_include_attack() {
    [[ "$SCENARIOS" == "all" ]] || echo "$SCENARIOS" | grep -q "attack_500"
}

if _scenarios_include_attack; then
    if _port_open "127.0.0.1" "${FAST_BACKEND_PORT}"; then
        ok "Fast TLS backend already listening on port ${FAST_BACKEND_PORT}"
    elif [[ -f "${FAST_BACKEND_PY}" ]]; then
        step "Starting Fast TLS Backend"
        log "Launching bench-tls-backend.py on port ${FAST_BACKEND_PORT} ..."
        python3 "${FAST_BACKEND_PY}" --port "${FAST_BACKEND_PORT}" \
            >"${OUTPUT_DIR}/fast-backend.log" 2>&1 &
        FAST_BACKEND_PID=$!
        log "Fast backend PID: ${FAST_BACKEND_PID}"

        for i in $(seq 1 10); do
            if _port_open "127.0.0.1" "${FAST_BACKEND_PORT}"; then
                ok "Fast TLS backend up (${i}s)"
                break
            fi
            sleep 1
        done
        if ! _port_open "127.0.0.1" "${FAST_BACKEND_PORT}"; then
            warn "Fast TLS backend did not start — attack_500 will use the regular backend"
            warn "Check ${OUTPUT_DIR}/fast-backend.log for details"
            kill "${FAST_BACKEND_PID}" 2>/dev/null || true
            FAST_BACKEND_PID=""
        fi
    else
        warn "bench-tls-backend.py not found at ${FAST_BACKEND_PY}"
        warn "attack_500 scenario will use the regular backend (may be slower)"
    fi
fi

# ── Run Go proxy natively if binary exists and Docker not used ─────────────────
NATIVE_GO_PID=""

if [[ "$GO_UP" == "false" && -f "${REPO_ROOT}/bin/ja4proxy" && "$USE_DOCKER" == "false" ]]; then
    step "Starting Go Proxy (Native)"
    CONFIG_PATH="${REPO_ROOT}/config/proxy.yml"
    if [[ ! -f "$CONFIG_PATH" ]]; then
        warn "config/proxy.yml not found — Go proxy needs config to start"
    else
        log "Launching bin/ja4proxy on port ${GO_PORT} ..."
        export REDIS_PASSWORD BACKEND_HOST BACKEND_PORT CONFIG_PATH
        "${REPO_ROOT}/bin/ja4proxy" \
            --port "${GO_PORT}" \
            --config "${CONFIG_PATH}" \
            >"${OUTPUT_DIR}/go-proxy.log" 2>&1 &
        NATIVE_GO_PID=$!
        log "Go proxy PID: ${NATIVE_GO_PID}"

        # Wait for it to come up
        for i in $(seq 1 15); do
            if _port_open "${GO_HOST}" "${GO_PORT}"; then
                GO_UP=true
                ok "Go proxy native (${i}s)"
                break
            fi
            sleep 1
        done
        if [[ "$GO_UP" == "false" ]]; then
            warn "Native Go proxy did not start — check ${OUTPUT_DIR}/go-proxy.log"
            kill "${NATIVE_GO_PID}" 2>/dev/null || true
            NATIVE_GO_PID=""
        fi
    fi
fi

# ── Build Python argument list ────────────────────────────────────────────────
step "Running Benchmark Engine"

PYTHON_ARGS=(
    "python3" "${BENCH_PY}"
    "--python-host" "${PYTHON_HOST}"
    "--python-port" "${PYTHON_PORT}"
    "--go-host" "${GO_HOST}"
    "--go-port" "${GO_PORT}"
    "--output-dir" "${OUTPUT_DIR}"
    "--duration-quick" "${DURATION_QUICK}"
    "--duration-long" "${DURATION_LONG}"
    "--max-threads" "${MAX_THREADS}"
    "--scenarios" "${SCENARIOS}"
    "--redis-host" "${PYTHON_HOST}"
    "--redis-port" "6379"
    "--connect-timeout" "${CONNECT_TIMEOUT}"
)

if [[ -n "$REDIS_PASSWORD" ]]; then
    PYTHON_ARGS+=("--redis-password" "${REDIS_PASSWORD}")
fi
if [[ "$FLUSH_REDIS" == "false" ]]; then
    PYTHON_ARGS+=("--no-redis-flush")
fi
if [[ -n "$PROXY_FILTER" ]]; then
    PYTHON_ARGS+=("--proxy" "${PROXY_FILTER}")
fi
if [[ "$QUICK" == "true" ]]; then
    PYTHON_ARGS+=("--quick")
fi
if [[ "$USE_PROXY_PROTOCOL" == "true" ]]; then
    PYTHON_ARGS+=("--use-proxy-protocol")
fi
PYTHON_ARGS+=(
    "--source-ip-pool-size" "${SOURCE_IP_POOL_SIZE}"
    "--attack-rate"         "${ATTACK_RATE}"
    "--fast-backend-port"   "${FAST_BACKEND_PORT}"
)

log "Command: ${PYTHON_ARGS[*]}"
printf "\n"

# ── Execute (tee to log file) ─────────────────────────────────────────────────
BENCH_LOG="${OUTPUT_DIR}/benchmark.log"
"${PYTHON_ARGS[@]}" 2>&1 | tee "${BENCH_LOG}"
BENCH_EXIT="${PIPESTATUS[0]}"

# ── Cleanup background processes ──────────────────────────────────────────────
if [[ -n "$NATIVE_GO_PID" ]] || [[ -n "$FAST_BACKEND_PID" ]]; then
    step "Cleanup"
    if [[ -n "$NATIVE_GO_PID" ]]; then
        log "Stopping native Go proxy (PID ${NATIVE_GO_PID}) ..."
        kill "${NATIVE_GO_PID}" 2>/dev/null || true
        wait "${NATIVE_GO_PID}" 2>/dev/null || true
        ok "Go proxy stopped"
    fi
    if [[ -n "$FAST_BACKEND_PID" ]]; then
        log "Stopping fast TLS backend (PID ${FAST_BACKEND_PID}) ..."
        kill "${FAST_BACKEND_PID}" 2>/dev/null || true
        wait "${FAST_BACKEND_PID}" 2>/dev/null || true
        ok "Fast TLS backend stopped"
    fi
fi

# ── Capture post-benchmark docker stats ───────────────────────────────────────
if command -v docker &>/dev/null && [[ "$USE_DOCKER" == "true" ]]; then
    step "Post-Benchmark Resource Usage"
    docker stats --no-stream --format \
        "  {{.Name}}: CPU={{.CPUPerc}} MEM={{.MemUsage}} NET={{.NetIO}}" \
        2>/dev/null | grep -E "ja4proxy|proxy|redis" || true
fi

# ── Final summary ─────────────────────────────────────────────────────────────
step "Results"

REPORT_MD="${OUTPUT_DIR}/report.md"
REPORT_JSON="${OUTPUT_DIR}/raw_results.json"

if [[ -f "$REPORT_MD" ]]; then
    ok "Markdown report: ${REPORT_MD}"
else
    warn "Markdown report not generated"
fi
if [[ -f "$REPORT_JSON" ]]; then
    ok "JSON data:        ${REPORT_JSON}"
fi
if [[ -f "$BENCH_LOG" ]]; then
    ok "Console log:      ${BENCH_LOG}"
fi
if [[ -f "$SYS_INFO_FILE" ]]; then
    ok "System info:      ${SYS_INFO_FILE}"
fi

printf "\n"
if [[ "${BENCH_EXIT}" -eq 0 ]]; then
    printf "  %s%sBenchmark complete.%s\n\n" "${GREEN}" "${BOLD}" "${RESET}"
else
    printf "  %s%sBenchmark exited with code %s.%s\n" \
        "${RED}" "${BOLD}" "${BENCH_EXIT}" "${RESET}"
    printf "  Check %s for details.\n\n" "${BENCH_LOG}"
fi

exit "${BENCH_EXIT}"
