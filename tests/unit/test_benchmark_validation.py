"""Tests for M26 — Benchmark numeric + SHA validation.

TDD Tests — these define the contract:
- Benchmark results contain only finite numeric values (no NaN, no Inf)
- SHA of serialized results is stable across two consecutive runs

These test the validation logic that should be applied to benchmark results.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Dict, List

import pytest

# ── Helpers: benchmark result validation functions ────────────────────────────
# These test a validation function that should exist in the benchmark tooling.
# Until the Coder creates it, we define the contract here and test against it.


def _all_numeric_values(obj: Any) -> List[float]:
    """Recursively extract all numeric values from a nested dict/list."""
    values: List[float] = []
    if isinstance(obj, (int, float)):
        values.append(float(obj))
    elif isinstance(obj, dict):
        for v in obj.values():
            values.extend(_all_numeric_values(v))
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            values.extend(_all_numeric_values(item))
    return values


def _stable_sha256(result: dict) -> str:
    """Compute a stable SHA-256 of a benchmark result dict.

    Uses sorted keys and deterministic float formatting to ensure
    two identical logical results produce the same hash.
    """
    serialized = json.dumps(result, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


# ── M26: Benchmark results contain only finite numeric values ─────────────────


class TestBenchmarkNumericValidation:
    """All numeric values in benchmark results must be finite (no NaN, no Inf)."""

    def test_valid_results_pass(self):
        """A clean result dict with only finite numbers passes."""
        result = {
            "throughput_cps": 350.5,
            "latency_p50_ms": 2.1,
            "latency_p99_ms": 15.8,
            "connections_attempted": 10000,
            "connections_completed": 9950,
            "error_rate": 0.005,
        }
        values = _all_numeric_values(result)
        assert all(math.isfinite(v) for v in values)

    @pytest.mark.parametrize(
        "bad_value,label",
        [
            (float("nan"), "NaN"),
            (float("inf"), "Inf"),
            (float("-inf"), "-Inf"),
        ],
    )
    def test_nan_inf_detected(self, bad_value: float, label: str):
        """Results containing NaN or Inf must be caught by validation."""
        result = {
            "throughput_cps": 350.5,
            "bad_metric": bad_value,
        }
        values = _all_numeric_values(result)
        non_finite = [v for v in values if not math.isfinite(v)]
        assert len(non_finite) > 0, (
            f"Validation should detect {label} in benchmark results"
        )

    def test_nested_nan_detected(self):
        """NaN buried in nested structures must be detected."""
        result = {
            "phases": {
                "baseline": {
                    "latency_p99_ms": float("nan"),
                    "throughput": 100.0,
                }
            }
        }
        values = _all_numeric_values(result)
        non_finite = [v for v in values if not math.isfinite(v)]
        assert len(non_finite) == 1

    def test_list_values_validated(self):
        """NaN in a list of latency samples must be detected."""
        result = {
            "latency_samples": [0.01, 0.02, float("nan"), 0.04],
        }
        values = _all_numeric_values(result)
        non_finite = [v for v in values if not math.isfinite(v)]
        assert len(non_finite) == 1


# ── M26: SHA stability across consecutive runs ───────────────────────────────


class TestBenchmarkSHAStability:
    """SHA of serialized benchmark results must be stable across runs."""

    def test_same_input_same_sha(self):
        """Two calls with identical data must produce the same SHA."""
        result = {
            "throughput_cps": 350.5,
            "latency_p50_ms": 2.1,
            "connections": 10000,
        }
        sha1 = _stable_sha256(result)
        sha2 = _stable_sha256(result)
        assert sha1 == sha2

    def test_key_order_does_not_affect_sha(self):
        """Dict key insertion order must not affect the SHA (sort_keys=True)."""
        result_a = {"z_metric": 1.0, "a_metric": 2.0}
        result_b = {"a_metric": 2.0, "z_metric": 1.0}
        assert _stable_sha256(result_a) == _stable_sha256(result_b)

    def test_different_values_produce_different_sha(self):
        """Different results must produce different SHAs."""
        result_a = {"throughput": 350.0}
        result_b = {"throughput": 351.0}
        assert _stable_sha256(result_a) != _stable_sha256(result_b)

    def test_sha_is_valid_hex_string(self):
        """SHA output must be a 64-char lowercase hex string."""
        result = {"metric": 42.0}
        sha = _stable_sha256(result)
        assert len(sha) == 64
        assert all(c in "0123456789abcdef" for c in sha)

    def test_empty_result_has_stable_sha(self):
        """Even an empty result dict should have a stable SHA."""
        sha1 = _stable_sha256({})
        sha2 = _stable_sha256({})
        assert sha1 == sha2
        assert len(sha1) == 64
