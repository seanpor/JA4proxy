# Makefile for JA4 Proxy

.PHONY: help build test lint clean deploy-poc deploy-enterprise quick-start

# Default target
help:
	@echo "Available targets:"
	@echo "  quick-start     - 🚀 Start POC with tests (recommended)"
	@echo "  build           - Build Docker images"
	@echo "  test            - Run all tests"
	@echo "  test-unit       - Run unit tests only"
	@echo "  test-integration- Run integration tests only"
	@echo "  test-performance- Run performance tests only"
	@echo "  test-security   - Run security tests only"
	@echo "  lint            - Run code linting"
	@echo "  clean           - Clean up containers and images"
	@echo "  deploy-poc      - Deploy PoC environment"
	@echo "  deploy-enterprise - Deploy enterprise environment"
	@echo "  health-check    - Run health checks"
	@echo "  security-scan   - Run security vulnerability scan"

# Build Docker images
build:
	docker-compose -f docker-compose.poc.yml build
	docker-compose -f docker-compose.prod.yml build

# Run tests
test:
	docker-compose -f docker-compose.poc.yml run --rm test

# Run linting
lint:
	docker run --rm -v $(PWD):/app python:3.11-slim sh -c "cd /app && pip install black flake8 mypy && black --check proxy.py && flake8 proxy.py && mypy proxy.py"

# Clean up
clean:
	docker-compose -f docker-compose.poc.yml down -v --remove-orphans
	docker-compose -f docker-compose.prod.yml down -v --remove-orphans
	docker system prune -f

# Deploy PoC environment
deploy-poc:
	docker-compose -f docker-compose.poc.yml up -d
	@echo "Waiting for services to start..."
	@sleep 30
	@make health-check

# Deploy enterprise environment
deploy-enterprise:
	@echo "Running enterprise deployment script..."
	@sudo ./scripts/deploy.sh production

# Health checks
health-check:
	@echo "Running health checks..."
	@curl -f http://localhost:8080/health || exit 1
	@curl -f http://localhost:9090/metrics | grep -q ja4_requests_total || exit 1
	@echo "Health checks passed!"

# Start development environment
dev:
	python proxy.py config/proxy.yml

# Install dependencies
install:
	pip install -r requirements.txt
	pip install -r requirements-test.txt

# Quick start - easiest way to get started
quick-start:
	@echo "🚀 Starting JA4proxy POC with tests..."
	@./quick-start.sh

# Enhanced test targets
test-unit:
	docker-compose -f docker-compose.poc.yml run --rm test pytest tests/unit/ -v

test-integration:
	docker-compose -f docker-compose.poc.yml run --rm test pytest tests/integration/ -v

test-performance:
	@echo "🏃 Running performance tests..."
	@if command -v locust >/dev/null 2>&1; then \
		locust -f performance/locust_tests.py --host http://localhost:8080 --users 50 --spawn-rate 5 --run-time 2m --headless --html reports/performance.html; \
	else \
		echo "⚠️  Locust not installed. Install with: pip install locust"; \
		echo "Running basic performance test instead..."; \
		./scripts/basic_perf_test.sh; \
	fi

test-security:
	@echo "🔒 Running security tests..."
	docker-compose -f docker-compose.poc.yml run --rm test pytest tests/security/ -v

# Security scanning
security-scan:
	@echo "🔍 Running security vulnerability scan..."
	@if command -v bandit >/dev/null 2>&1; then \
		bandit -r proxy.py -f json -o reports/bandit-report.json || true; \
		bandit -r proxy.py; \
	else \
		echo "Installing bandit..."; \
		pip install bandit; \
		bandit -r proxy.py; \
	fi

# Run performance tests
perf-test: test-performance