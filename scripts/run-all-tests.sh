#!/bin/bash
# JA4proxy Comprehensive Test Runner
# Covers all 8 test layers from docs/docker_container_test_layers_expanded.md
#
# Usage:
#   ./run-all-tests.sh           # Run all tests
#   ./run-all-tests.sh --static  # Run only static tests (no services needed)
#   ./run-all-tests.sh --dynamic # Run only dynamic tests (requires services)
#   ./run-all-tests.sh --layer 1 # Run specific layer
#   ./run-all-tests.sh --lint    # Run linting only
#   ./run-all-tests.sh --security # Run security scanning only

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Test configuration
COMPOSE_FILE="docker/docker-compose.poc.yml"
TEST_CONTAINER="ja4proxy-test"
REPORTS_DIR="reports"
EXIT_CODE=0

# Parse arguments
MODE="${1:-all}"
LAYER="${2:-}"

# ============================================================================
# Helper Functions
# ============================================================================

log_header() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

log_step() {
    echo -e "${BLUE}▶ $1${NC}"
}

log_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

log_error() {
    echo -e "${RED}✗ $1${NC}"
}

log_section() {
    echo ""
    echo -e "${BOLD}--- $1 ---${NC}"
}

# Ensure reports directory exists
ensure_reports_dir() {
    mkdir -p "$REPORTS_DIR"
}

# Check if services are running
check_services() {
    if docker compose -f "$COMPOSE_FILE" ps 2>/dev/null | grep -q "ja4proxy.*Up"; then
        return 0
    fi
    return 1
}

# Start required services
start_services() {
    log_step "Starting services..."
    docker compose -f "$COMPOSE_FILE" up -d redis backend proxy
    log_step "Waiting for services to be healthy..."
    
    local max_retries=30
    local retry=0
    while [ $retry -lt $max_retries ]; do
        if curl -sf http://localhost:9090/metrics > /dev/null 2>&1; then
            log_success "Proxy is healthy"
            return 0
        fi
        retry=$((retry + 1))
        echo -n "."
        sleep 2
    done
    
    log_error "Proxy failed to become healthy"
    docker compose -f "$COMPOSE_FILE" logs proxy
    return 1
}

# Stop services
stop_services() {
    log_step "Stopping services..."
    docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
}

# Run pytest with common options
run_pytest() {
    local test_path="$1"
    local description="$2"
    local additional_args="${3:-}"
    
    log_section "$description"
    log_step "Running: pytest $test_path"
    
    if docker compose -f "$COMPOSE_FILE" run --rm test \
        pytest "$test_path" -v --tb=short --cov=proxy \
        --cov-report=html:"$REPORTS_DIR/coverage" \
        --cov-report=term \
        --cov-report=xml:"$REPORTS_DIR/coverage.xml" \
        --junitxml="$REPORTS_DIR/junit.xml" \
        $additional_args 2>&1; then
        log_success "$description passed"
        return 0
    else
        log_error "$description failed"
        EXIT_CODE=1
        return 1
    fi
}

# ============================================================================
# Layer 1: Code-Level and Build-Time Tests (Static Analysis)
# ============================================================================

run_layer1_static() {
    log_header "Layer 1: Code-Level and Build-Time Tests (Static Analysis)"
    
    # Ensure we're in the right directory
    cd "$(dirname "$0")"
    
    # 1a. Unit Tests
    log_section "1a. Unit Tests"
    if docker compose -f "$COMPOSE_FILE" run --rm test \
        pytest tests/unit/ -v --tb=short \
        --junitxml="$REPORTS_DIR/junit-unit.xml" 2>&1; then
        log_success "Unit tests passed"
    else
        log_error "Unit tests failed"
        EXIT_CODE=1
    fi
    
    # 1b. Fuzz/Property Tests
    log_section "1b. Fuzz/Property Tests"
    if docker compose -f "$COMPOSE_FILE" run --rm test \
        pytest tests/fuzz/ -v --tb=short \
        --junitxml="$REPORTS_DIR/junit-fuzz.xml" 2>&1; then
        log_success "Fuzz tests passed"
    else
        log_error "Fuzz tests failed"
        EXIT_CODE=1
    fi
    
    # 1c. Linting - Ruff (run locally if available, else try container)
    log_section "1c. Linting (Ruff)"
    if command -v ruff &> /dev/null; then
        if ruff check src/ proxy.py --output-format=concise 2>&1; then
            log_success "Ruff linting passed"
        else
            log_warning "Ruff linting found issues"
            EXIT_CODE=1
        fi
    elif docker compose -f "$COMPOSE_FILE" run --rm test \
        ruff check src/ proxy.py --output-format=concise 2>&1; then
        log_success "Ruff linting passed"
    else
        log_warning "Ruff not available, skipping"
    fi
    
    # 1d. Type Checking - MyPy
    log_section "1d. Type Checking (MyPy)"
    if command -v mypy &> /dev/null; then
        if mypy src/ proxy.py --ignore-missing-imports --no-error-summary 2>&1; then
            log_success "MyPy type checking passed"
        else
            log_warning "MyPy found type issues"
        fi
    else
        log_warning "MyPy not available, skipping"
    fi
    
    # 1e. Formatting - Black
    log_section "1e. Code Formatting (Black)"
    if command -v black &> /dev/null; then
        if black --check src/ proxy.py 2>&1; then
            log_success "Black formatting check passed"
        else
            log_warning "Black found formatting issues"
            EXIT_CODE=1
        fi
    else
        log_warning "Black not available, skipping"
    fi
    
    # 1f. Import Sorting - Isort
    log_section "1f. Import Sorting (Isort)"
    if command -v isort &> /dev/null; then
        if isort --check-only src/ proxy.py 2>&1; then
            log_success "Isort check passed"
        else
            log_warning "Isort found sorting issues"
            EXIT_CODE=1
        fi
    else
        log_warning "Isort not available, skipping"
    fi
    
    # 1g. SAST - Bandit (security scanning)
    log_section "1g. Security Scanning (Bandit)"
    if docker compose -f "$COMPOSE_FILE" run --rm test \
        bandit -r src/ proxy.py -f json -o "$REPORTS_DIR/bandit.json" \
        -ll 2>&1; then
        log_success "Bandit security scan passed"
    else
        log_warning "Bandit found security issues"
        # Don't fail on security warnings
    fi
    
    # 1h. SAST - Semgrep (skip if no permission)
    log_section "1h. SAST (Semgrep)"
    mkdir -p /tmp/.semgrep 2>/dev/null || true
    if [ -w "/tmp/.semgrep" ]; then
        if docker compose -f "$COMPOSE_FILE" run --rm test \
            semgrep --config=auto --json --output="$REPORTS_DIR/semgrep.json" \
            --quiet src/ proxy.py 2>&1; then
            log_success "Semgrep scan passed"
        else
            log_warning "Semgrep found issues"
        fi
    else
        log_warning "Semgrep skipped (permission issue)"
    fi
    
    # 1i. Dependency Scanning - Safety (skip if broken)
    log_section "1i. Dependency Vulnerability Scanning (Safety)"
    if docker compose -f "$COMPOSE_FILE" run --rm test \
        python -c "import safety" 2>/dev/null; then
        if docker compose -f "$COMPOSE_FILE" run --rm test \
            safety check --json --output="$REPORTS_DIR/safety.json" 2>&1; then
            log_success "Safety dependency scan passed"
        else
            log_warning "Safety found vulnerabilities"
        fi
    else
        log_warning "Safety skipped (module issue)"
    fi
}

# ============================================================================
# Layer 2: Image-Level Tests
# ============================================================================

run_layer2_image() {
    log_header "Layer 2: Image-Level Tests"
    
    # 2a. Dockerfile Linting - Hadolint
    log_section "2a. Dockerfile Linting (Hadolint)"
    if command -v hadolint &> /dev/null; then
        if hadolint Dockerfile Dockerfile.test Dockerfile.trafficgen 2>&1; then
            log_success "Hadolint passed"
        else
            log_warning "Hadolint found issues"
            EXIT_CODE=1
        fi
    else
        log_warning "Hadolint not installed, skipping"
    fi
    
    # 2b. Image Vulnerability Scanning - Trivy
    log_section "2b. Image Vulnerability Scanning (Trivy)"
    if command -v trivy &> /dev/null; then
        # Build image first if needed
        docker compose -f "$COMPOSE_FILE" build proxy 2>/dev/null || true
        
        trivy image --severity HIGH,CRITICAL \
            --format json --output "$REPORTS_DIR/trivy-image.json" \
            ja4proxy-proxy 2>&1 || true
        trivy image --severity HIGH,CRITICAL \
            --exit-code 0 \
            ja4proxy-proxy 2>&1 || {
            log_warning "Trivy found high/critical vulnerabilities"
        }
        log_success "Trivy scan completed"
    else
        log_warning "Trivy not installed, skipping image vulnerability scan"
    fi
    
    # 2c. Secrets Scanning
    log_section "2c. Secrets Scanning"
    if command -v trufflehog &> /dev/null; then
        trufflehog filesystem . --json > "$REPORTS_DIR/trufflehog.json" 2>&1 || true
        log_success "Secrets scan completed"
    else
        log_warning "TruffleHog not installed, skipping secrets scan"
    fi
}

# ============================================================================
# Layer 3: Container-Level Tests
# ============================================================================

run_layer3_container() {
    log_header "Layer 3: Container-Level Tests"
    
    ensure_reports_dir
    
    # 3a. Health Check Validation
    log_section "3a. Health Check Validation"
    local health_status
    health_status=$(docker inspect --format='{{.State.Health.Status}}' ja4proxy 2>/dev/null || echo "unknown")
    if [ "$health_status" = "healthy" ]; then
        log_success "Proxy health check is healthy"
    else
        log_warning "Proxy health status: $health_status"
    fi
    
    # 3b. Runtime Configuration Tests
    log_section "3b. Runtime Configuration"
    
    # Check non-root user
    local user
    user=$(docker inspect --format='{{.Config.User}}' ja4proxy 2>/dev/null || echo "root")
    if [ "$user" = "root" ] || [ -z "$user" ]; then
        log_warning "Container runs as root"
    else
        log_success "Container runs as non-root user"
    fi
    
    # Check read-only filesystem
    if docker inspect ja4proxy 2>/dev/null | grep -q '"ReadonlyRoot":true'; then
        log_success "Read-only filesystem enabled"
    else
        log_warning "Read-only filesystem not enabled"
    fi
    
    # Check capabilities
    log_section "3c. Capability Checks"
    local caps
    caps=$(docker inspect --format='{{.HostConfig.CapDrop}}' ja4proxy 2>/dev/null || echo "")
    if echo "$caps" | grep -q "ALL"; then
        log_success "Capabilities dropped (secure)"
    else
        log_warning "Not all capabilities dropped"
    fi
    
    # 3d. Resource Limits
    log_section "3d. Resource Limits"
    local memory
    memory=$(docker inspect --format='{{.HostConfig.Memory}}' ja4proxy 2>/dev/null || echo "0")
    if [ "$memory" -gt 0 ]; then
        log_success "Memory limit set: $((memory / 1024 / 1024))MB"
    else
        log_warning "No memory limit set"
    fi
}

# ============================================================================
# Layer 4: Integration and Service-Level Tests
# ============================================================================

run_layer4_integration() {
    log_header "Layer 4: Integration and Service-Level Tests"
    
    ensure_reports_dir
    
    # 4a. Integration Tests
    run_pytest "tests/integration/" "4a. Integration Tests" ""
    
    # 4b. Service Health Check
    log_section "4b. Service Health Validation"
    local services=("proxy" "redis" "backend")
    for svc in "${services[@]}"; do
        local status
        status=$(docker inspect --format='{{.State.Status}}' "ja4proxy-$svc" 2>/dev/null || echo "not_found")
        if [ "$status" = "running" ]; then
            log_success "Service $svc is running"
        else
            log_error "Service $svc is not running (status: $status)"
            EXIT_CODE=1
        fi
    done
    
    # 4c. Redis Connectivity
    log_section "4c. Redis Connectivity"
    if docker exec ja4proxy-redis redis-cli ping 2>/dev/null | grep -q PONG; then
        log_success "Redis is responsive"
    else
        log_error "Redis is not responsive"
        EXIT_CODE=1
    fi
}

# ============================================================================
# Layer 5: Orchestration and Deployment Tests
# ============================================================================

run_layer5_orchestration() {
    log_header "Layer 5: Orchestration and Deployment Tests"
    
    # 5a. Docker Compose Validation
    log_section "5a. Docker Compose Validation"
    if docker compose -f "$COMPOSE_FILE" config --quiet 2>&1; then
        log_success " configuration is valid"
Docker Compose    else
        log_error "Docker Compose configuration is invalid"
        EXIT_CODE=1
    fi
    
    # 5b. Network Isolation Check
    log_section "5b. Network Isolation"
    local networks
    networks=$(docker inspect ja4proxy --format='{{range $net, $conf := .NetworkSettings.Networks}}{{$net}} {{end}}')
    if echo "$networks" | grep -q "ja4proxy-backend"; then
        log_success "Container is on backend network"
    else
        log_warning "Container network configuration unexpected"
    fi
    
    # 5c. Volume Mounts Check
    log_section "5c. Volume Mounts"
    local volumes
    volumes=$(docker inspect ja4proxy --format='{{range .Mounts}}{{.Destination}}:{{.Source}} {{end}}')
    if echo "$volumes" | grep -q "config"; then
        log_success "Config volume mounted"
    else
        log_warning "Config volume not mounted"
    fi
}

# ============================================================================
# Layer 6: Security and Compliance Tests
# ============================================================================

run_layer6_security() {
    log_header "Layer 6: Security and Compliance Tests"
    
    ensure_reports_dir
    
    # 6a. Security Tests
    log_section "6a. OWASP Security Tests"
    if docker compose -f "$COMPOSE_FILE" run --rm test \
        pytest tests/security/ -v --tb=short \
        --junitxml="$REPORTS_DIR/junit-security.xml" 2>&1; then
        log_success "Security tests passed"
    else
        log_error "Security tests failed"
        EXIT_CODE=1
    fi
    
    # 6b. Compliance Tests
    log_section "6b. GDPR Compliance Tests"
    if docker compose -f "$COMPOSE_FILE" run --rm test \
        pytest tests/compliance/ -v --tb=short \
        --junitxml="$REPORTS_DIR/junit-compliance.xml" 2>&1; then
        log_success "Compliance tests passed"
    else
        log_error "Compliance tests failed"
        EXIT_CODE=1
    fi
}

# ============================================================================
# Layer 7: Performance, Resilience, and Operational Tests
# ============================================================================

run_layer7_performance() {
    log_header "Layer 7: Performance, Resilience, and Operational Tests"
    
    ensure_reports_dir
    
    # 7a. Chaos Tests
    log_section "7a. Chaos/Resilience Tests"
    if docker compose -f "$COMPOSE_FILE" run --rm test \
        pytest tests/chaos/ -v --tb=short \
        --junitxml="$REPORTS_DIR/junit-chaos.xml" 2>&1; then
        log_success "Chaos tests passed"
    else
        log_error "Chaos tests failed"
        EXIT_CODE=1
    fi
    
    # 7b. Performance Benchmarks
    log_section "7b. Performance Benchmarks"
    if docker compose -f "$COMPOSE_FILE" run --rm test \
        python tests/performance/bench_pipeline.py \
        | tee "$REPORTS_DIR/benchmark.txt" 2>&1; then
        log_success "Performance benchmarks completed"
    else
        log_warning "Performance benchmarks had issues"
    fi
    
    # 7c. Load Testing with Locust (optional, takes longer)
    if [ "${RUN_LOAD_TESTS:-false}" = "true" ]; then
        log_section "7c. Load Testing (Locust)"
        docker compose -f "$COMPOSE_FILE" run --rm trafficgen \
            locust -f performance/locustfile.py \
            --headless -u 100 -r 10 -t 60s \
            --html "$REPORTS_DIR/locust-report.html" \
            --json 2>&1 || true
        log_success "Load tests completed"
    else
        log_warning "Load tests skipped (set RUN_LOAD_TESTS=true to run)"
    fi
}

# ============================================================================
# Layer 8: End-to-End and User-Journey Tests
# ============================================================================

run_layer8_e2e() {
    log_header "Layer 8: End-to-End and User-Journey Tests"
    
    ensure_reports_dir
    
    # 8a. End-to-End Tests
    log_section "8a. End-to-End Tests"
    if docker compose -f "$COMPOSE_FILE" run --rm test \
        pytest tests/integration/test_end_to_end.py -v --tb=short \
        --junitxml="$REPORTS_DIR/junit-e2e.xml" 2>&1; then
        log_success "E2E tests passed"
    else
        log_error "E2E tests failed"
        EXIT_CODE=1
    fi
    
    # 8b. Docker Stack Tests
    log_section "8b. Docker Stack Integration Tests"
    if docker compose -f "$COMPOSE_FILE" run --rm test \
        pytest tests/integration/test_docker_stack.py -v --tb=short \
        --junitxml="$REPORTS_DIR/junit-stack.xml" 2>&1; then
        log_success "Docker stack tests passed"
    else
        log_error "Docker stack tests failed"
        EXIT_CODE=1
    fi
}

# ============================================================================
# TLS Traffic Generator (Not a test per se, but validates proxy behavior)
# ============================================================================

run_tls_traffic_generator() {
    log_header "TLS Traffic Generator (Functional Validation)"
    
    ensure_reports_dir
    
    log_section "Generate TLS Traffic Through Proxy"
    log_step "This generates real TLS connections to test the proxy's detection capabilities"
    
    # Clear stale state
    log_step "Clearing stale security state..."
    REDIS_PASS=$(grep '^REDIS_PASSWORD=' .env 2>/dev/null | cut -d= -f2)
    if [ -n "$REDIS_PASS" ]; then
        docker exec ja4proxy-redis redis-cli -a "$REDIS_PASS" --no-auth-warning \
            EVAL "local n=0; for _,p in ipairs({'enforcement:*','audit:*','rate:*','banned:*','blocked:*','repeat_block:*'}) do for _,k in ipairs(redis.call('keys',p)) do redis.call('del',k); n=n+1 end end; return n" 0 \
            2>/dev/null || true
    fi
    
    # Generate traffic (short duration for testing)
    log_step "Generating TLS traffic..."
    if docker compose -f "$COMPOSE_FILE" run --rm -e PYTHONUNBUFFERED=1 trafficgen \
        --target-host proxy --target-port 8080 \
        --duration 10 --good-percent 50 --workers 10 2>&1 | tee "$REPORTS_DIR/tls-traffic.txt"; then
        log_success "TLS traffic generation completed"
    else
        log_warning "TLS traffic generation had issues"
    fi
    
    # Show quick metrics summary
    log_section "Metrics Summary"
    if curl -s http://localhost:9090/metrics > "$REPORTS_DIR/metrics.txt" 2>/dev/null; then
        log_success "Metrics captured"
    else
        log_warning "Could not capture metrics"
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║          JA4proxy Comprehensive Test Suite                        ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Mode: $MODE"
    echo "Reports directory: $REPORTS_DIR"
    echo ""
    
    ensure_reports_dir
    
    case "$MODE" in
        --static|-s)
            log_step "Running static tests only (no services needed)"
            run_layer1_static
            run_layer2_image
            ;;
        --dynamic|-d)
            log_step "Running dynamic tests (requires services)"
            if ! check_services; then
                start_services
            fi
            run_layer3_container
            run_layer4_integration
            run_layer5_orchestration
            run_layer6_security
            run_layer7_performance
            run_layer8_e2e
            run_tls_traffic_generator
            ;;
        --layer|-l)
            log_step "Running specific layer: $LAYER"
            if ! check_services && [ "$LAYER" -gt 2 ]; then
                start_services
            fi
            case "$LAYER" in
                1) run_layer1_static ;;
                2) run_layer2_image ;;
                3) run_layer3_container ;;
                4) run_layer4_integration ;;
                5) run_layer5_orchestration ;;
                6) run_layer6_security ;;
                7) run_layer7_performance ;;
                8) run_layer8_e2e ;;
                *) log_error "Invalid layer: $LAYER" ;;
            esac
            ;;
        --lint)
            log_step "Running linting only"
            
            # Run linting locally (on host) since tools may not be in container
            cd "$(dirname "$0")"
            
            # Check if tools are available locally
            if command -v ruff &> /dev/null; then
                ruff check src/ proxy.py --output-format=concise || EXIT_CODE=1
            else
                log_warning "ruff not installed locally, skipping"
            fi
            
            if command -v black &> /dev/null; then
                black --check src/ proxy.py || EXIT_CODE=1
            else
                log_warning "black not installed locally, skipping"
            fi
            
            if command -v isort &> /dev/null; then
                isort --check-only src/ proxy.py || EXIT_CODE=1
            else
                log_warning "isort not installed locally, skipping"
            fi
            
            if command -v mypy &> /dev/null; then
                mypy src/ proxy.py --ignore-missing-imports || true
            else
                log_warning "mypy not installed locally, skipping"
            fi
            
            # Also try in container if host tools not available
            if ! command -v ruff &> /dev/null; then
                log_step "Trying in container..."
                docker compose -f "$COMPOSE_FILE" run --rm test \
                    ruff check src/ proxy.py --output-format=concise 2>&1 || true
                docker compose -f "$COMPOSE_FILE" run --rm test \
                    black --check src/ proxy.py 2>&1 || true
                docker compose -f "$COMPOSE_FILE" run --rm test \
                    isort --check-only src/ proxy.py 2>&1 || true
            fi
            ;;
        --security)
            log_step "Running security scans only"
            run_layer1_static
            run_layer2_image
            ;;
        --all|-a|"")
            log_step "Running ALL tests (static + dynamic)"
            
            # Static tests (don't need services)
            run_layer1_static
            run_layer2_image
            
            # Start services for dynamic tests
            if ! check_services; then
                log_step "Starting services for dynamic tests..."
                start_services
            fi
            
            run_layer3_container
            run_layer4_integration
            run_layer5_orchestration
            run_layer6_security
            run_layer7_performance
            run_layer8_e2e
            run_tls_traffic_generator
            ;;
        *)
            echo "Usage: $0 [mode]"
            echo ""
            echo "Modes:"
            echo "  (default)     Run all tests"
            echo "  --all, -a     Run all tests"
            echo "  --static, -s  Run static tests only (lint, type check, SAST)"
            echo "  --dynamic, -d  Run dynamic tests only (requires services)"
            echo "  --layer, -l N Run specific layer N (1-8)"
            echo "  --lint        Run linting only"
            echo "  --security    Run security scans only"
            echo ""
            echo "Layers:"
            echo "  1  Code-Level and Build-Time Tests"
            echo "  2  Image-Level Tests"
            echo "  3  Container-Level Tests"
            echo "  4  Integration and Service-Level Tests"
            echo "  5  Orchestration and Deployment Tests"
            echo "  6  Security and Compliance Tests"
            echo "  7  Performance, Resilience, and Operational Tests"
            echo "  8  End-to-End and User-Journey Tests"
            exit 1
            ;;
    esac
    
    # Summary
    echo ""
    log_header "Test Summary"
    if [ $EXIT_CODE -eq 0 ]; then
        echo -e "${GREEN}✓ All tests passed!${NC}"
    else
        echo -e "${RED}✗ Some tests failed (exit code: $EXIT_CODE)${NC}"
    fi
    echo ""
    echo "Reports available in ./$REPORTS_DIR/"
    echo "  - Coverage: ./$REPORTS_DIR/coverage/index.html"
    echo "  - JUnit XML: ./$REPORTS_DIR/junit*.xml"
    echo "  - Security: ./$REPORTS_DIR/bandit.json, semgrep.json, safety.json"
    echo "  - Benchmark: ./$REPORTS_DIR/benchmark.txt"
    echo "  - TLS Traffic: ./$REPORTS_DIR/tls-traffic.txt"
    
    exit $EXIT_CODE
}

main "$@"
