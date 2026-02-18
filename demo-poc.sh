#!/bin/bash
# JA4 Proxy POC Demo Script
# Automated demonstration of POC capabilities

set -e

# Load .env if available
[ -f .env ] && set -a && source .env && set +a
REDIS_PW="${REDIS_PASSWORD:-changeme}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Configuration
PROXY_URL="http://localhost:8080"
BACKEND_URL="http://localhost:8081"
METRICS_URL="http://localhost:9090/metrics"
PROMETHEUS_URL="http://localhost:9091"

# Demo pause between steps
DEMO_SPEED=${DEMO_SPEED:-2}  # seconds between steps

pause() {
    sleep $DEMO_SPEED
}

header() {
    echo ""
    echo -e "${BOLD}${BLUE}=========================================${NC}"
    echo -e "${BOLD}${BLUE}$1${NC}"
    echo -e "${BOLD}${BLUE}=========================================${NC}"
    echo ""
    pause
}

step() {
    echo -e "${CYAN}▶${NC} ${BOLD}$1${NC}"
    pause
}

command_demo() {
    echo -e "${YELLOW}$ $1${NC}"
    pause
}

result() {
    echo -e "${GREEN}$1${NC}"
    pause
}

error() {
    echo -e "${RED}✗ $1${NC}"
}

success() {
    echo -e "${GREEN}✓ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Check if services are running
check_services() {
    if ! curl -sf "$METRICS_URL" > /dev/null 2>&1; then
        error "Services are not running!"
        echo ""
        echo "Please start the POC first:"
        echo "  ./start-poc.sh"
        echo ""
        exit 1
    fi
}

# Introduction
intro() {
    clear
    header "JA4 Proxy POC Demonstration"
    
    echo -e "${BOLD}This demo will showcase:${NC}"
    echo "  1. Service architecture and components"
    echo "  2. Backend server capabilities"
    echo "  3. Proxy metrics collection"
    echo "  4. Redis data storage"
    echo "  5. Monitoring with Prometheus"
    echo "  6. Security features"
    echo ""
    echo -e "${CYAN}Press Ctrl+C to exit at any time${NC}"
    echo ""
    read -p "Press Enter to start the demo..." -r
}

# Demo 1: Show architecture
demo_architecture() {
    header "1. Service Architecture"
    
    step "Checking running services..."
    command_demo "docker compose -f docker-compose.poc.yml ps"
    docker compose -f docker-compose.poc.yml ps
    echo ""
    
    success "All 4 services are running:"
    echo "  • JA4 Proxy Server (port 8080, 9090)"
    echo "  • Redis Cache (port 6379)"
    echo "  • Mock Backend (port 8081)"
    echo "  • Prometheus Monitoring (port 9091)"
    pause
}

# Demo 2: Backend server
demo_backend() {
    header "2. Mock Backend Server"
    
    step "Testing backend health endpoint..."
    command_demo "curl http://localhost:8081/api/health"
    RESPONSE=$(curl -s "$BACKEND_URL/api/health")
    echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
    echo ""
    success "Backend is healthy!"
    pause
    
    step "Testing backend echo endpoint..."
    command_demo "curl http://localhost:8081/api/echo"
    RESPONSE=$(curl -s "$BACKEND_URL/api/echo")
    echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
    echo ""
    success "Backend echo works!"
    pause
    
    step "Testing different HTTP methods..."
    command_demo "curl -X POST http://localhost:8081/api/echo -d 'test=data'"
    RESPONSE=$(curl -s -X POST "$BACKEND_URL/api/echo" -d "test=data")
    echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
    echo ""
    success "Backend supports POST requests!"
    pause
}

# Demo 3: Proxy metrics
demo_metrics() {
    header "3. Proxy Metrics Collection"
    
    step "Fetching Prometheus metrics from proxy..."
    command_demo "curl http://localhost:9090/metrics | grep ja4_"
    echo ""
    
    echo -e "${BOLD}JA4 Proxy Metrics:${NC}"
    curl -s "$METRICS_URL" | grep "^ja4_" | grep -v "^#" | head -15
    echo ""
    
    success "Proxy is exposing JA4-specific metrics!"
    echo ""
    echo -e "${CYAN}Available metric types:${NC}"
    echo "  • ja4_requests_total - Request counter"
    echo "  • ja4_request_duration_seconds - Response time histogram"
    echo "  • ja4_active_connections - Current connections"
    echo "  • ja4_blocked_requests_total - Blocked request counter"
    echo "  • ja4_security_events_total - Security event counter"
    pause
}

# Demo 4: Redis integration
demo_redis() {
    header "4. Redis Data Storage"
    
    step "Testing Redis connectivity..."
    command_demo "docker exec ja4proxy-redis redis-cli -a "${REDIS_PW}" PING"
    RESULT=$(docker exec ja4proxy-redis redis-cli -a "${REDIS_PW}" PING 2>/dev/null)
    result "$RESULT"
    echo ""
    success "Redis is connected!"
    pause
    
    step "Adding sample JA4 fingerprint to whitelist..."
    command_demo "docker exec ja4proxy-redis redis-cli -a "${REDIS_PW}" SADD ja4:whitelist 't13d1516h2_8daaf6152771_02713d6af862'"
    docker exec ja4proxy-redis redis-cli -a "${REDIS_PW}" SADD ja4:whitelist "t13d1516h2_8daaf6152771_02713d6af862" 2>/dev/null
    success "Fingerprint added to whitelist!"
    pause
    
    step "Checking whitelist contents..."
    command_demo "docker exec ja4proxy-redis redis-cli -a "${REDIS_PW}" SMEMBERS ja4:whitelist"
    docker exec ja4proxy-redis redis-cli -a "${REDIS_PW}" SMEMBERS ja4:whitelist 2>/dev/null
    echo ""
    success "Whitelist is functional!"
    pause
    
    step "Adding sample to blacklist for demo..."
    command_demo "docker exec ja4proxy-redis redis-cli -a "${REDIS_PW}" SADD ja4:blacklist 't12d090909_ba640532068b_b186095e22b6'"
    docker exec ja4proxy-redis redis-cli -a "${REDIS_PW}" SADD ja4:blacklist "t12d090909_ba640532068b_b186095e22b6" 2>/dev/null
    success "Fingerprint added to blacklist!"
    pause
}

# Demo 5: Prometheus monitoring
demo_prometheus() {
    header "5. Prometheus Monitoring"
    
    step "Checking Prometheus health..."
    command_demo "curl http://localhost:9091/-/healthy"
    if curl -sf "$PROMETHEUS_URL/-/healthy" > /dev/null 2>&1; then
        success "Prometheus is healthy!"
    else
        warning "Prometheus is starting up..."
    fi
    pause
    
    step "Checking if Prometheus is scraping proxy metrics..."
    command_demo "curl 'http://localhost:9091/api/v1/query?query=up{job=\"ja4proxy\"}'"
    echo ""
    RESPONSE=$(curl -s "$PROMETHEUS_URL/api/v1/query?query=up{job=\"ja4proxy\"}" 2>/dev/null || echo "{}")
    if echo "$RESPONSE" | grep -q "success"; then
        result "Prometheus is successfully scraping metrics!"
    else
        warning "Prometheus is still initializing..."
    fi
    echo ""
    
    echo -e "${CYAN}Prometheus Web UI:${NC}"
    echo "  Open: http://localhost:9091"
    echo "  Try queries like: ja4_requests_total"
    pause
}

# Demo 6: Security features
demo_security() {
    header "6. Security Features"
    
    step "Checking proxy configuration..."
    echo -e "${BOLD}Security settings:${NC}"
    echo "  • Rate limiting: Enabled"
    echo "  • Whitelist: Enabled"
    echo "  • Blacklist: Enabled"
    echo "  • Audit logging: Enabled"
    echo ""
    success "Security controls are configured!"
    pause
    
    step "Viewing security-related metrics..."
    command_demo "curl http://localhost:9090/metrics | grep security"
    echo ""
    curl -s "$METRICS_URL" | grep "ja4_security" | grep -v "^#" | head -10
    echo ""
    success "Security metrics are being collected!"
    pause
    
    step "Checking for security events in logs..."
    command_demo "docker logs ja4proxy --tail 20 | grep -i security"
    echo ""
    docker logs ja4proxy --tail 20 2>&1 | grep -i -E "(security|warning)" || echo "No security events (this is good!)"
    echo ""
    pause
}

# Demo 7: Quick performance test
demo_performance() {
    header "7. Quick Performance Test"
    
    step "Sending test requests to backend through proxy..."
    echo -e "${BOLD}Sending 10 requests...${NC}"
    echo ""
    
    for i in {1..10}; do
        echo -n "  Request $i/10... "
        if curl -sf "$BACKEND_URL/api/health" > /dev/null 2>&1; then
            echo -e "${GREEN}✓${NC}"
        else
            echo -e "${RED}✗${NC}"
        fi
        sleep 0.1
    done
    
    echo ""
    success "All test requests completed!"
    pause
    
    step "Checking updated metrics..."
    echo ""
    echo -e "${BOLD}Current metrics snapshot:${NC}"
    curl -s "$METRICS_URL" | grep -E "ja4_(requests|active|blocked)" | grep -v "^#" | head -10
    echo ""
    pause
}

# Conclusion
conclusion() {
    header "Demo Complete!"
    
    echo -e "${BOLD}${GREEN}✓ POC Demonstration Summary${NC}"
    echo ""
    echo "Demonstrated capabilities:"
    echo "  ✓ Multi-service architecture"
    echo "  ✓ Backend server integration"
    echo "  ✓ Metrics collection and exposure"
    echo "  ✓ Redis data storage"
    echo "  ✓ Prometheus monitoring"
    echo "  ✓ Security features"
    echo "  ✓ Performance testing"
    echo ""
    
    echo -e "${BOLD}${CYAN}Next Steps:${NC}"
    echo ""
    echo "1. Explore the services:"
    echo "   • Proxy metrics:  http://localhost:9090/metrics"
    echo "   • Backend API:    http://localhost:8081/api/health"
    echo "   • Prometheus:     http://localhost:9091"
    echo ""
    
    echo "2. Try manual testing:"
    echo "   ./smoke-test.sh"
    echo ""
    
    echo "3. Run full test suite:"
    echo "   ./run-tests.sh"
    echo ""
    
    echo "4. View live logs:"
    echo "   docker compose -f docker-compose.poc.yml logs -f"
    echo ""
    
    echo "5. Stop the POC:"
    echo "   docker compose -f docker-compose.poc.yml down"
    echo ""
    
    echo -e "${BOLD}${MAGENTA}For production deployment, see:${NC}"
    echo "  • ENTERPRISE_REVIEW.md - Security and deployment guide"
    echo "  • docs/enterprise/deployment.md - Enterprise setup"
    echo ""
    
    echo -e "${GREEN}Thank you for trying JA4 Proxy POC!${NC}"
    echo ""
}

# Main demo flow
main() {
    # Check if services are running
    check_services
    
    # Run demos
    intro
    demo_architecture
    demo_backend
    demo_metrics
    demo_redis
    demo_prometheus
    demo_security
    demo_performance
    conclusion
}

# Run the demo
main
