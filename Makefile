# Makefile for JA4 Proxy

.PHONY: help build test lint clean deploy-poc deploy-enterprise smoke-test flush-redis attack-status top-attackers block-ja4 block-ip unblock-ip fetch-db list-pending approve-all geoip-report geoip-monitor

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
	@echo "  flush-redis       - Clear all security state (bans/blocks/rates) — keep whitelist/blacklist"
	@echo ""
	@echo "Threat intelligence:"
	@echo "  fetch-db          - Fetch new malicious fingerprints from ja4db / FoxIO GitHub"
	@echo "  list-pending      - Show fingerprints awaiting admin approval"
	@echo "  approve-all       - Approve all pending fingerprints"
	@echo "  geoip-report      - Full blocking report (countries, CIDRs, fingerprints)"
	@echo "  geoip-monitor     - Auto-block attacking countries (run once)"
	@echo "  geoip-watch       - Auto-block attacking countries (continuous loop)"
	@echo ""
	@echo "Incident response (no restart needed):"
	@echo "  attack-status     - Quick security snapshot (active bans, block rate)"
	@echo "  top-attackers     - Top 10 fingerprints by traffic right now"
	@echo "  block-ja4 FP=...  - Blacklist a JA4 fingerprint (instant TCP RST)"
	@echo "  block-ip  IP=...  - Hard-block an IP for 1 hour"
	@echo "  unblock-ip IP=... - Remove all blocks for an IP"

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
	@curl -sk https://localhost:8443/api/health > /dev/null && echo "✓ Backend OK" || echo "✗ Backend failed"
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

# Flush all transient security state from Redis (bans, blocks, rate windows, audit logs)
# Preserves ja4:whitelist and ja4:blacklist so config survives the flush.
flush-redis:
	@echo "Flushing Redis security state..."
	@REDIS_PASS=$$(grep '^REDIS_PASSWORD=' .env 2>/dev/null | cut -d= -f2); \
	if [ -z "$$REDIS_PASS" ]; then echo "✗ No REDIS_PASSWORD in .env"; exit 1; fi; \
	COUNT=$$(docker exec ja4proxy-redis redis-cli -a "$$REDIS_PASS" --no-auth-warning \
		EVAL "local n=0; \
		      for _,p in ipairs({'rate:*','banned:*','blocked:*','suspicious:*','enforcement:*','audit:*','repeat_block:*'}) do \
		        for _,k in ipairs(redis.call('keys',p)) do redis.call('del',k); n=n+1 end \
		      end; return n" 0 2>/dev/null); \
	echo "✓ Cleared $$COUNT keys (whitelist/blacklist preserved)"

# ── ja4db feed management ─────────────────────────────────────────────────────

# Fetch new malicious fingerprints from FoxIO GitHub / ja4db.com, queue for review
fetch-db:
	@./scripts/fetch-ja4db.sh

# Show fingerprints awaiting approval
list-pending:
	@./scripts/ja4-admin.sh list-pending

# Approve all pending fingerprints (prompts for confirmation)
approve-all:
	@./scripts/ja4-admin.sh approve-all

# ── GeoIP monitoring ───────────────────────────────────────────────────────────

# Full blocking report (countries, CIDRs, fingerprints, Prometheus summary)
geoip-report:
	@./scripts/ja4-admin.sh report

# Run the GeoIP monitor once — auto-blocks attacking countries, respects safe list
geoip-monitor:
	@./scripts/geoip-monitor.sh

# Run geoip-monitor in watch mode (loops every 60s, Ctrl-C to stop)
geoip-watch:
	@./scripts/geoip-monitor.sh --watch

# ── Incident response shortcuts (wrappers for scripts/ja4-admin.sh) ──────────

# Quick security snapshot: active bans, block totals, top threats
attack-status:
	@./scripts/ja4-admin.sh status

# Top 10 fingerprints by traffic (red = blocked, green = allowed)
top-attackers:
	@./scripts/ja4-admin.sh top 10

# Blacklist a JA4 fingerprint (instant TCP RST, permanent)
# Usage: make block-ja4 FP=t13d190900_9dc949149365_97f8aa674fd9
block-ja4:
	@[ -n "$(FP)" ] || (echo "Usage: make block-ja4 FP=<fingerprint>"; exit 1)
	@./scripts/ja4-admin.sh block-ja4 $(FP)

# Hard-block an IP for 1 hour
# Usage: make block-ip IP=203.0.113.42
block-ip:
	@[ -n "$(IP)" ] || (echo "Usage: make block-ip IP=<address>"; exit 1)
	@./scripts/ja4-admin.sh block-ip $(IP) 3600

# Remove all blocks/bans for an IP
# Usage: make unblock-ip IP=203.0.113.42
unblock-ip:
	@[ -n "$(IP)" ] || (echo "Usage: make unblock-ip IP=<address>"; exit 1)
	@./scripts/ja4-admin.sh unblock-ip $(IP)

# Run performance tests
perf-test:
	@echo "Starting performance tests..."
	@echo "Note: This requires services to be running (make deploy-poc)"
	docker-compose -f docker-compose.poc.yml run --rm test locust -f /app/performance/locust_tests.py --host http://proxy:8080 --users 100 --spawn-rate 10 --run-time 5m --headless