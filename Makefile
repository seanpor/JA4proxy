# Makefile for JA4 Proxy

.PHONY: help build test lint clean deploy-poc deploy-enterprise smoke-test

# Default target
help:
	@echo "Available targets:"
	@echo "  build             - Build Docker images"
	@echo "  test              - Run all tests in Docker"
	@echo "  smoke-test        - Run quick smoke test"
	@echo "  lint              - Run code linting"
	@echo "  clean             - Clean up containers and images"
	@echo "  deploy-poc        - Deploy PoC environment"
	@echo "  deploy-enterprise - Deploy enterprise environment"
	@echo "  health-check      - Run health checks"
	@echo "  logs              - View proxy logs"
	@echo "  stop              - Stop all services"

# Build Docker images
build:
	@echo "Building Docker images..."
	docker-compose -f docker-compose.poc.yml build

# Run tests
test:
	@./run-tests.sh

# Run quick smoke test
smoke-test:
	@./smoke-test.sh

# Run linting
lint:
	docker run --rm -v $(PWD):/app python:3.11-slim sh -c "cd /app && pip install black flake8 mypy && black --check proxy.py && flake8 proxy.py && mypy proxy.py"

# Clean up
clean:
	@echo "Cleaning up containers and volumes..."
	docker-compose -f docker-compose.poc.yml down -v --remove-orphans
	docker-compose -f docker-compose.prod.yml down -v --remove-orphans
	rm -rf reports/ __pycache__/ .pytest_cache/ .mypy_cache/

# Deploy PoC environment
deploy-poc:
	@./start-poc.sh

# Stop services
stop:
	docker-compose -f docker-compose.poc.yml down

# Deploy enterprise environment
deploy-enterprise:
	@echo "Running enterprise deployment script..."
	@sudo ./scripts/deploy.sh production

# Health checks
health-check:
	@echo "Running health checks..."
	@curl -sf http://localhost:9090/metrics > /dev/null && echo "✓ Proxy metrics OK" || echo "✗ Proxy metrics failed"
	@curl -sf http://localhost:8081/api/health > /dev/null && echo "✓ Backend OK" || echo "✗ Backend failed"
	@docker exec ja4proxy-redis redis-cli -a $${REDIS_PASSWORD:-changeme} ping > /dev/null 2>&1 && echo "✓ Redis OK" || echo "✗ Redis failed"

# View logs
logs:
	docker-compose -f docker-compose.poc.yml logs -f proxy

# Run integration tests
test-integration:
	docker-compose -f docker-compose.poc.yml run --rm test pytest tests/integration/ -v

# Run unit tests only
test-unit:
	docker-compose -f docker-compose.poc.yml run --rm test pytest tests/unit/ -v

# Run performance tests
perf-test:
	@echo "Starting performance tests..."
	@echo "Note: This requires services to be running (make deploy-poc)"
	docker-compose -f docker-compose.poc.yml run --rm test locust -f /app/performance/locust_tests.py --host http://proxy:8080 --users 100 --spawn-rate 10 --run-time 5m --headless