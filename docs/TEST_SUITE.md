<!--
title: Test_Suite
audience: Developers
last_reviewed: 2026-03-27
phase: 21
-->

# JA4proxy Test Suite Documentation

## Overview

JA4proxy uses a comprehensive multi-layer testing approach following the best practices in `docs/docker_container_test_layers_expanded.md`.

## Running Tests

### Quick Start

```bash
# Run all tests (static + dynamic)
./run-all-tests.sh

# Run only static tests (no services needed)
./run-all-tests.sh --static

# Run only dynamic tests (requires services)
./run-all-tests.sh --dynamic

# Run specific layer
./run-all-tests.sh --layer 1

# Run linting only
./run-all-tests.sh --lint
```

## Test Layers

### Layer 1: Code-Level and Build-Time Tests (Static Analysis)

**Purpose:** Validate correctness and security before containerization.

**Tests:**
- **Unit tests** (`tests/unit/`) - Individual function/class/module validation
- **Fuzz/Property tests** (`tests/fuzz/`) - Hypothesis-based property testing
- **Linting (Ruff)** - Code style and syntax checking
- **Type Checking (MyPy)** - Static type analysis
- **Code Formatting (Black)** - Code style enforcement
- **Import Sorting (Isort)** - Import organization
- **SAST (Bandit)** - Security vulnerability scanning
- **SAST (Semgrep)** - Advanced pattern matching
- **Dependency Scanning (Safety)** - Known vulnerability detection

**Run:** `./run-all-tests.sh --static` or `./run-all-tests.sh -s`

---

### Layer 2: Image-Level Tests

**Purpose:** Validate Docker image as a build artifact.

**Tests:**
- **Dockerfile Linting (Hadolint)** - Best practices for Dockerfiles
- **Image Vulnerability Scanning (Trivy)** - CVE detection
- **Secrets Scanning** - Credential detection in images

**Run:** Part of static tests (`./run-all-tests.sh --static`)

---

### Layer 3: Container-Level Tests

**Purpose:** Validate runtime behavior when executed as a container.

**Tests:**
- **Health Check Validation** - Container health status
- **Runtime Configuration** - User, capabilities, read-only filesystem
- **Resource Limits** - Memory and CPU constraints

**Run:** Part of dynamic tests (`./run-all-tests.sh --dynamic`)

---

### Layer 4: Integration and Service-Level Tests

**Purpose:** Validate container interactions with each other and external systems.

**Tests:**
- **Integration Tests** (`tests/integration/`) - Redis, pipeline, caching
- **Service Health Validation** - All services running correctly
- **Redis Connectivity** - Cache and state management

**Run:** `./run-all-tests.sh --layer 4` or `./run-all-tests.sh --dynamic`

---

### Layer 5: Orchestration and Deployment Tests

**Purpose:** Validate behavior under Docker Compose orchestration.

**Tests:**
- **Docker Compose Validation** - Configuration correctness
- **Network Isolation** - Proper network segmentation
- **Volume Mounts** - Config and data persistence

**Run:** `./run-all-tests.sh --layer 5` or `./run-all-tests.sh --dynamic`

---

### Layer 6: Security and Compliance Tests

**Purpose:** Validate security posture.

**Tests:**
- **OWASP Security Tests** (`tests/security/`) - Common vulnerability tests
- **GDPR Compliance Tests** (`tests/compliance/`) - Data retention policies

**Run:** `./run-all-tests.sh --layer 6` or `./run-all-tests.sh --dynamic`

---

### Layer 7: Performance, Resilience, and Operational Tests

**Purpose:** Validate behavior under load and failure conditions.

**Tests:**
- **Chaos Tests** (`tests/chaos/`) - Redis failure, network partition simulation
- **Performance Benchmarks** (`tests/performance/`) - Latency/throughput validation
- **Load Testing (Locust)** - High concurrency simulation (optional)

**Run:** `./run-all-tests.sh --layer 7` or `./run-all-tests.sh --dynamic`

---

### Layer 8: End-to-End and User-Journey Tests

**Purpose:** Validate complete workflows from user perspective.

**Tests:**
- **E2E Tests** (`tests/integration/test_end_to_end.py`) - Full proxy workflows
- **Docker Stack Tests** (`tests/integration/test_docker_stack.py`) - Service integration

**Run:** `./run-all-tests.sh --layer 8` or `./run-all-tests.sh --dynamic`

---

## TLS Traffic Generator

The `../scripts/generate-tls-traffic.sh` script generates real TLS connections through the proxy to validate:

- JA4 fingerprinting accuracy
- Security blocking effectiveness
- Metrics collection
- Rate limiting behavior

**Run:**
```bash
# Short test (10 seconds)
./generate-tls-traffic.sh 10 50 10

# Full test (60 seconds)
./generate-tls-traffic.sh 60 15 50
```

## Test Organization

```
tests/
├── unit/                    # Unit tests (fast, isolated)
│   ├── test_*.py           # Core functionality
│   └── security/           # Security module tests
├── integration/             # Integration tests (require services)
│   ├── test_pipeline.py
│   ├── test_end_to_end.py
│   ├── test_cache_hierarchy.py
│   └── ...
├── chaos/                   # Resilience/failure testing
├── compliance/              # GDPR/compliance tests
├── fuzz/                   # Hypothesis-based property tests
├── performance/            # Benchmarks
└── security/               # OWASP-style security tests
```

## Test Requirements

### Python Dependencies
- pytest==7.4.3
- pytest-asyncio==0.21.1
- pytest-cov==4.1.0
- hypothesis==6.88.1
- bandit==1.7.5
- ruff (linting)
- black (formatting)
- mypy (type checking)

### External Services
- Redis (running on ja4proxy-redis)
- Backend service (for E2E tests)
- HAProxy (for full stack tests)

## CI/CD Integration

The test suite is designed to run in CI pipelines:

```bash
# Full test suite with coverage
docker compose -f docker/docker-compose.poc.yml run --rm test \
    pytest /app/tests -v --cov=proxy \
    --cov-report=xml --cov-report=term

# Quick smoke test
docker compose -f docker/docker-compose.poc.yml run --rm test \
    pytest /app/tests/integration/ -v
```

## Adding New Tests

1. **Unit tests:** Add to `tests/unit/` or `tests/unit/security/`
2. **Integration tests:** Add to `tests/integration/`
3. **Chaos tests:** Add to `tests/chaos/`
4. **Follow existing patterns:** Use fixtures from `../tests/conftest.py`

## Troubleshooting

### Tests fail with import errors
- Ensure PYTHONPATH includes `/app`
- Check that all `src/` modules are properly structured

### Redis connection errors
- Ensure Redis container is running: `docker compose ps`
- Check Redis logs: `docker compose logs redis`

### Flaky tests
- Check for race conditions in async code
- Ensure proper mocking of external services
- Review test isolation

## Reports

Test reports are generated in `reports/`:
- `junit-*.xml` - JUnit format for CI
- `coverage/` - HTML coverage reports
- `benchmark.txt` - Performance benchmarks
- `tls-traffic.txt` - TLS generator output
