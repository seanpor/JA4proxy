<!--
title: Testing Guidelines
audience: Developers
last_reviewed: 2026-04-03
phase: 0
-->

# Testing Guidelines

## Overview
This document describes the test types, coverage goals, and guidelines for writing genuine tests in the JA4proxy project.

## Test Types

### Unit Tests
- **Location**: `tests/unit/`
- **Purpose**: Validate individual components in isolation.
- **Examples**:
  - `test_action_decider.py`: Tests the `ActionDecider` class.
  - `test_blocklists.py`: Tests blocklist functionality.
- **Guidelines**:
  - Mock external dependencies (e.g., Redis, APIs).
  - Focus on one component per test.
  - Use `pytest` fixtures for setup and teardown.

### Integration Tests
- **Location**: `tests/integration/`
- **Purpose**: Validate interactions between components.
- **Examples**:
  - `test_pipeline.py`: Tests the full security pipeline.
  - `test_end_to_end.py`: Tests end-to-end scenarios.
- **Guidelines**:
  - Use real dependencies (e.g., Redis) where possible.
  - Simulate real-world scenarios (e.g., TLS handshakes).
  - Validate end-to-end behavior.

### Chaos Tests
- **Location**: `tests/chaos/`
- **Purpose**: Validate resilience and fail-open behavior under failure conditions.
- **Examples**:
  - `test_redis_failure.py`: Tests behavior when Redis is unavailable.
  - `test_external_api_failure.py`: Tests behavior when external APIs fail.
- **Guidelines**:
  - Simulate failures (e.g., Redis downtime, API outages).
  - Ensure the proxy fails open (allows connections).
  - Log errors but do not crash.

### Adversarial Tests
- **Location**: `tests/adversarial/`
- **Purpose**: Simulate real-world attacks and edge cases.
- **Examples**:
  - `test_ja4_adversarial.py`: Tests JA4 generation with degenerate inputs.
  - `test_rdap_fp.py`: Tests RDAP enrichment with false positives.
  - `test_sql_injection.py`: Tests SQL injection detection and blocking.
  - `test_xss.py`: Tests XSS (Cross-Site Scripting) detection and blocking.
  - `test_path_traversal.py`: Tests path traversal detection and blocking.
  - `test_command_injection.py`: Tests command injection detection and blocking.
- **Guidelines**:
  - Handle degenerate inputs (e.g., empty lists, max-length fields).
  - Simulate attacks (e.g., SQL injection, XSS, path traversal).
  - Ensure the proxy does not crash or leak sensitive data.

## Coverage Goals

### Overall Coverage
- **Target**: 80% minimum for all modules.
- **Current**: 84% overall (11570 statements, 1870 missed) — 3124 tests collected.

### Module-Specific Goals
- **High Coverage (90%+)**: Core security modules (e.g., `src/security/`).
- **Moderate Coverage (80-90%)**: Utility modules (e.g., `src/utils/`).
- **Low Coverage (<80%)**: TAP and export modules (e.g., `src/tap/tap_pipeline.py` at 44%, `src/tap/export/export_manager.py` at 44%); `src/utils/logging_config.py` currently at 0%.

### Coverage Reporting
- **Tool**: `pytest-cov`.
- **Command**:
  ```bash
  python3 -m pytest tests/ --cov=src --cov-report=term-missing
  ```
- **Output**: HTML report in `reports/coverage/html`.

## Writing Genuine Tests

### Do's
- **Do** write meaningful assertions:
  ```python
  def test_dial_zero_score_0_allows(self, decider):
      assert decider.decide(score=0, dial=0) == "allow"
  ```
- **Do** cover edge cases:
  ```python
  @pytest.mark.parametrize("cipher_list,ext_list,sni", [
      ([], [], None),  # All empty
      ([0x0A0A], [], "example.com"),  # Single GREASE cipher
  ])
  def test_ja4_does_not_crash(cipher_list, ext_list, sni):
      result = generator.generate_ja4(client_hello_fields)
      assert isinstance(result, str)
  ```

- **Do** test adversarial inputs:
  ```python
  @pytest.mark.parametrize("malicious_input", [
      "<script>alert('XSS')</script>",
      "'; DROP TABLE users--",
  ])
  def test_adversarial_input_blocked(self, evaluator, malicious_input):
      result = evaluator.evaluate_input(malicious_input)
      assert result.is_malicious
  ```
- **Do** use fixtures for setup:
  ```python
  @pytest.fixture
  def decider():
      return ActionDecider(thresholds=THRESHOLDS, ban_duration_seconds=300)
  ```

### Don'ts
- **Don't** write placeholder tests:
  ```python
  def test_placeholder():
      pass  # No assertions
  ```
- **Don't** ignore edge cases:
  ```python
  def test_ja4_normal_input():
      # Missing tests for empty lists, max-length fields, etc.
      result = generator.generate_ja4(normal_fields)
      assert isinstance(result, str)
  ```
- **Don't** rely on external state:
  ```python
  def test_redis_dependent():
      # Fails if Redis is not running
      result = pipeline.execute(ctx)
      assert result.action == "allow"
  ```

## Test Maintenance

### Regular Audits
- **Frequency**: Quarterly.
- **Goal**: Ensure tests remain genuine and relevant.
- **Steps**:
  1. Run `make test` and review coverage.
  2. Audit test files for meaningful assertions.
  3. Update documentation (e.g., `docs/TESTING.md`).

### Automated Checks
- **Tool**: `pytest-cov`.
- **Integration**: CI/CD pipelines.
- **Command**:
  ```bash
  make test  # Runs all tests with coverage
  ```

## Resources
- **Phase Documentation**: `docs/phases/PHASE_44.md`.
- **Test Examples**: `tests/unit/`, `tests/integration/`, `tests/chaos/`, `tests/adversarial/`.
- **Coverage Reports**: `reports/coverage/html`.

## Conclusion
Follow these guidelines to write genuine tests that provide meaningful coverage. Regular audits and automated checks ensure tests remain relevant and effective.