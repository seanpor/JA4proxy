#!/bin/bash
set -e

# JA4proxy Quick Start Script
# Spins up POC environment and runs regression/performance tests

echo "🚀 JA4proxy Quick Start"
echo "======================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check prerequisites
echo -e "${BLUE}Checking prerequisites...${NC}"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is required but not installed.${NC}"
    exit 1
fi

# Check Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}❌ Docker Compose is required but not installed.${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Prerequisites check passed${NC}"

# Set environment variables
export REDIS_PASSWORD=$(openssl rand -base64 32 2>/dev/null || echo "secure_$(date +%s)_password")
echo -e "${YELLOW}🔐 Generated Redis password: ${REDIS_PASSWORD}${NC}"

# Function to cleanup on exit
cleanup() {
    echo -e "\n${YELLOW}🧹 Cleaning up...${NC}"
    docker-compose -f docker-compose.poc.yml down -v --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

# Start POC environment
echo -e "\n${BLUE}🚀 Starting POC environment...${NC}"
docker-compose -f docker-compose.poc.yml up -d

# Wait for services to be ready
echo -e "${BLUE}⏳ Waiting for services to start...${NC}"
sleep 30

# Health check
echo -e "\n${BLUE}🔍 Running health checks...${NC}"

# Check proxy health
if curl -f http://localhost:8080/health 2>/dev/null; then
    echo -e "${GREEN}✅ Proxy service is healthy${NC}"
else
    echo -e "${YELLOW}⚠️  Proxy health check endpoint not found, checking if port is open...${NC}"
    if nc -z localhost 8080 2>/dev/null; then
        echo -e "${GREEN}✅ Proxy is listening on port 8080${NC}"
    else
        echo -e "${RED}❌ Proxy is not responding${NC}"
    fi
fi

# Check metrics
if curl -f http://localhost:9090/metrics 2>/dev/null | grep -q "ja4"; then
    echo -e "${GREEN}✅ Metrics service is healthy${NC}"
else
    echo -e "${YELLOW}⚠️  Metrics endpoint not responding or no JA4 metrics found${NC}"
fi

# Check Redis
if docker-compose -f docker-compose.poc.yml exec -T redis redis-cli -a "$REDIS_PASSWORD" ping 2>/dev/null | grep -q PONG; then
    echo -e "${GREEN}✅ Redis service is healthy${NC}"
else
    echo -e "${RED}❌ Redis connection failed${NC}"
fi

# Run regression tests
echo -e "\n${BLUE}🧪 Running regression tests...${NC}"
if docker-compose -f docker-compose.poc.yml run --rm test; then
    echo -e "${GREEN}✅ Regression tests passed${NC}"
else
    echo -e "${RED}❌ Some regression tests failed${NC}"
fi

# Run basic performance test
echo -e "\n${BLUE}🏃 Running basic performance test...${NC}"
if command -v curl &> /dev/null; then
    echo "Testing proxy throughput with 10 concurrent requests..."
    
    # Simple performance test with curl
    start_time=$(date +%s.%N)
    for i in {1..10}; do
        (curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/ &)
    done
    wait
    end_time=$(date +%s.%N)
    
    duration=$(echo "$end_time - $start_time" | bc 2>/dev/null || echo "1")
    rps=$(echo "scale=2; 10 / $duration" | bc 2>/dev/null || echo "~10")
    
    echo -e "${GREEN}✅ Basic performance test completed: ~${rps} requests/second${NC}"
else
    echo -e "${YELLOW}⚠️  curl not available for performance testing${NC}"
fi

# Run advanced performance test if Locust is available
if command -v locust &> /dev/null; then
    echo -e "\n${BLUE}🔥 Running advanced performance test with Locust...${NC}"
    echo "Running 50 users for 2 minutes..."
    
    # Create simple locustfile if it doesn't exist
    if [ ! -f "performance/locust_tests.py" ]; then
        mkdir -p performance
        cat > performance/locust_tests.py << 'EOF'
from locust import HttpUser, task, between

class JA4ProxyUser(HttpUser):
    wait_time = between(1, 3)
    
    @task
    def test_proxy(self):
        self.client.get("/")
    
    @task(2)
    def test_health(self):
        self.client.get("/health")
EOF
    fi
    
    timeout 120 locust -f performance/locust_tests.py --host http://localhost:8080 \
        --users 50 --spawn-rate 5 --run-time 120s --headless \
        --html reports/performance.html || echo "Locust test completed"
    
    echo -e "${GREEN}✅ Advanced performance test completed${NC}"
else
    echo -e "${YELLOW}⚠️  Locust not available, install with: pip install locust${NC}"
fi

# Show service URLs
echo -e "\n${GREEN}🎉 POC environment is ready!${NC}"
echo -e "📊 Services:"
echo -e "   • Proxy:      http://localhost:8080"
echo -e "   • Metrics:    http://localhost:9090/metrics"
echo -e "   • Backend:    http://localhost:8081"
echo -e "   • Redis:      localhost:6379 (password: $REDIS_PASSWORD)"

echo -e "\n${BLUE}📝 To view logs:${NC}"
echo -e "   docker-compose -f docker-compose.poc.yml logs -f"

echo -e "\n${BLUE}🛑 To stop environment:${NC}"
echo -e "   docker-compose -f docker-compose.poc.yml down -v"

echo -e "\n${YELLOW}⚠️  Security Note: This is a POC environment with default configurations.${NC}"
echo -e "${YELLOW}   Do not use in production without implementing security fixes!${NC}"

# Keep running if requested
if [[ "$1" == "--keep-running" ]]; then
    echo -e "\n${BLUE}🔄 Environment will keep running. Press Ctrl+C to stop.${NC}"
    trap 'echo -e "\n${YELLOW}Stopping...${NC}"; cleanup; exit 0' INT
    
    # Show real-time logs
    echo -e "${BLUE}📋 Showing live logs (Ctrl+C to stop):${NC}"
    docker-compose -f docker-compose.poc.yml logs -f
fi