# Makefile for JA4 Proxy

.PHONY: help build test lint clean deploy-poc deploy-enterprise

# Default target
help:
	@echo "Available targets:"
	@echo "  build           - Build Docker images"
	@echo "  test            - Run all tests"
	@echo "  lint            - Run code linting"
	@echo "  clean           - Clean up containers and images"
	@echo "  deploy-poc      - Deploy PoC environment"
	@echo "  deploy-enterprise - Deploy enterprise environment"
	@echo "  health-check    - Run health checks"

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

# Run performance tests
perf-test:
	locust -f performance/locust_tests.py --host http://localhost:8080 --users 100 --spawn-rate 10 --run-time 5m --headless