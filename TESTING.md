# Testing Guide

This document describes how to run tests for JA4 Proxy in Docker containers.

## Overview

All tests run in isolated Docker containers. No local Python installation is required.

## Test Architecture

```
┌─────────────────────────────────────────┐
│         Test Container                  │
│  - pytest                               │
│  - coverage                             │
│  - All test dependencies                │
└─────────────┬───────────────────────────┘
              │
              ├──► Proxy Container (port 8080, 9090)
              │
              ├──► Backend Container (port 8081)
              │
              └──► Redis Container (port 6379)
```

## Quick Start

### Run All Tests

```bash
./run-tests.sh
```

This script:
1. Starts required services (Redis, Backend, Proxy)
2. Waits for services to be healthy
3. Runs the test suite in a container
4. Generates coverage reports
5. Displays results

### Run Smoke Test

Quick connectivity test without running full test suite:

```bash
./smoke-test.sh
```

## Running Tests Manually

### Full Test Suite

```bash
docker-compose -f docker-compose.poc.yml run --rm test
```

### Specific Test Files

```bash
# Run single test file
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/test_proxy.py -v

# Run specific test class
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/test_proxy.py::TestJA4Fingerprint -v

# Run specific test method
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/test_proxy.py::TestJA4Fingerprint::test_fingerprint_creation -v
```

### Test Categories

```bash
# Unit tests only
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/unit/ -v

# Integration tests only
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/integration/ -v

# Security tests
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/security/ -v

# Performance tests
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/performance/ -v
```

### Test Output Options

```bash
# Verbose output
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/ -v

# Very verbose (show print statements)
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/ -vv -s

# Quiet mode (minimal output)
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/ -q

# Stop on first failure
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/ -x

# Show local variables on failure
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/ -l
```

## Test Reports

### Coverage Reports

After running tests, coverage reports are generated in `./reports/`:

```bash
# HTML coverage report
open reports/coverage/index.html  # macOS
xdg-open reports/coverage/index.html  # Linux
start reports/coverage/index.html  # Windows

# JUnit XML report (for CI/CD)
cat reports/junit.xml
```

### Viewing Coverage in Terminal

```bash
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/ -v --cov=proxy --cov-report=term
```

## Using Makefile

The Makefile provides convenient test commands:

```bash
make test              # Run all tests
make test-unit         # Run unit tests only
make test-integration  # Run integration tests
make smoke-test        # Run quick smoke test
make perf-test         # Run performance tests
```

## Test Environment

### Environment Variables

Tests use these environment variables (automatically set by docker-compose):

- `PROXY_HOST`: Proxy hostname (default: `proxy`)
- `PROXY_PORT`: Proxy port (default: `8080`)
- `BACKEND_HOST`: Backend hostname (default: `backend`)
- `BACKEND_PORT`: Backend port (default: `80`)
- `REDIS_HOST`: Redis hostname (default: `redis`)
- `REDIS_PORT`: Redis port (default: `6379`)
- `REDIS_PASSWORD`: Redis password (default: `changeme`)

### Custom Environment

Override environment variables:

```bash
docker-compose -f docker-compose.poc.yml run --rm \
  -e PROXY_PORT=9999 \
  test pytest tests/ -v
```

## Debugging Tests

### Interactive Debugging

Run tests with pdb debugger:

```bash
# Add breakpoint in test code:
# import pdb; pdb.set_trace()

docker-compose -f docker-compose.poc.yml run --rm test pytest tests/test_proxy.py -s
```

### View Service Logs While Testing

In one terminal:
```bash
docker-compose -f docker-compose.poc.yml logs -f proxy
```

In another terminal:
```bash
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/ -v
```

### Shell Access to Test Container

```bash
docker-compose -f docker-compose.poc.yml run --rm test bash

# Inside container:
pytest tests/ -v
python -m pytest tests/test_proxy.py::specific_test -vv
```

## Writing Tests

### Test Structure

```
tests/
├── __init__.py
├── test_proxy.py          # Main unit tests
├── unit/                  # Unit tests
│   ├── __init__.py
│   └── test_*.py
├── integration/           # Integration tests
│   ├── __init__.py
│   └── test_docker_stack.py
├── security/              # Security tests
│   ├── __init__.py
│   └── test_*.py
└── performance/           # Performance tests
    ├── __init__.py
    └── test_*.py
```

### Example Test

```python
import pytest
import requests

def test_backend_health():
    """Test backend is accessible."""
    response = requests.get('http://backend:80/api/health')
    assert response.status_code == 200
    assert response.json()['status'] == 'ok'

@pytest.fixture
def proxy_url():
    """Fixture providing proxy URL."""
    return 'http://proxy:8080'

def test_with_fixture(proxy_url):
    """Test using fixture."""
    response = requests.get(f'{proxy_url}/metrics')
    assert response.status_code == 200
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run tests
        run: |
          docker-compose -f docker-compose.poc.yml up -d redis backend proxy
          docker-compose -f docker-compose.poc.yml run --rm test
      - name: Upload coverage
        uses: codecov/codecov-action@v2
        with:
          files: ./reports/coverage.xml
```

## Performance Testing

### Load Testing with Locust

```bash
# Start services
./start-poc.sh

# Run load test
docker-compose -f docker-compose.poc.yml run --rm test \
  locust -f /app/performance/locust_tests.py \
  --host http://proxy:8080 \
  --users 100 \
  --spawn-rate 10 \
  --run-time 5m \
  --headless
```

### Benchmark Tests

```bash
docker-compose -f docker-compose.poc.yml run --rm test pytest tests/performance/ -v --benchmark-only
```

## Troubleshooting

### Tests Fail to Connect to Services

1. Ensure services are running:
```bash
./start-poc.sh
```

2. Check service health:
```bash
./smoke-test.sh
```

3. View logs:
```bash
docker-compose -f docker-compose.poc.yml logs proxy
docker-compose -f docker-compose.poc.yml logs backend
```

### Tests Hang or Timeout

Increase timeout in test code:
```python
response = requests.get(url, timeout=30)  # Increase from default
```

### Permission Errors on Reports

```bash
sudo chown -R $USER:$USER reports/
```

### Clean State Between Test Runs

```bash
# Stop all services and remove volumes
docker-compose -f docker-compose.poc.yml down -v

# Restart
./start-poc.sh
```

### Network Issues

Check containers are on same network:
```bash
docker network inspect ja4proxy_ja4proxy
```

### Redis Connection Errors

Test Redis manually:
```bash
docker exec -it ja4proxy-redis redis-cli -a changeme ping
```

## Test Coverage Goals

- **Unit tests**: >90% code coverage
- **Integration tests**: All critical paths
- **Security tests**: All security controls
- **Performance tests**: Baseline metrics

## Best Practices

1. **Isolation**: Each test should be independent
2. **Cleanup**: Use fixtures for setup/teardown
3. **Assertions**: Clear, specific assertions
4. **Documentation**: Docstrings for all tests
5. **Performance**: Keep tests fast (<1s per test)
6. **Reliability**: No flaky tests

## Additional Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [Coverage.py Documentation](https://coverage.readthedocs.io/)
- [Docker Compose Testing](https://docs.docker.com/compose/)
- [POC Guide](POC_GUIDE.md)
