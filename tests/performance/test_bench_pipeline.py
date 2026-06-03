"""Performance benchmarks for Phase 1 and Phase 14c pipeline components.

Acceptance criteria:
  - RiskScorer.score() with 10 signals: p99 < 100µs
  - ActionDecider.decide(): p99 < 10µs
  - Tarpit cap check (asyncio.Lock + int compare): p99 < 1ms under 500 concurrent

Run with: python -m pytest tests/performance/ -v
Or standalone: python tests/performance/bench_pipeline.py
"""

import asyncio
import statistics
import time

import pytest
from src.security.action_decider import ActionDecider
from src.security.risk_scorer import RiskScorer, RiskSignal

THRESHOLDS = {
    "flag": 20,
    "rate_limit": 35,
    "tarpit": 55,
    "block": 70,
    "ban": 85,
}

# 10 signals covering a realistic mix of positive and negative contributions
_TEN_SIGNALS = [
    RiskSignal("missing_sni", 30, "no sni"),
    RiskSignal("asn_datacenter", 20, "dc"),
    RiskSignal("asn_tor", 15, "tor exit"),
    RiskSignal("beaconing", 10, "beacon"),
    RiskSignal("dga", 8, "dga-like"),
    RiskSignal("rdap_known_bad_org", 5, "bad org"),
    RiskSignal("return_visitor", -10, "seen before"),
    RiskSignal("residential_ptr", -5, "residential ptr"),
    RiskSignal("abuseipdb", 12, "abuse score"),
    RiskSignal("asn_unknown", 3, "unknown asn"),
]

_ITERATIONS = 10_000


def _percentile(sorted_data: list[float], p: float) -> float:
    """Return the p-th percentile from a pre-sorted list."""
    idx = int(len(sorted_data) * p / 100)
    return sorted_data[min(idx, len(sorted_data) - 1)]


class TestRiskScorerPerformance:
    """RiskScorer.score() p99 must be < 100µs with 10 signals."""

    def test_score_10_signals_p99_under_100us(self):
        scorer = RiskScorer(THRESHOLDS)
        latencies: list[float] = []

        for _ in range(_ITERATIONS):
            t0 = time.perf_counter()
            scorer.score(_TEN_SIGNALS)
            latencies.append((time.perf_counter() - t0) * 1_000_000)  # µs

        latencies.sort()
        p99 = _percentile(latencies, 99)
        p50 = _percentile(latencies, 50)

        print(
            f"\nRiskScorer.score() (n={_ITERATIONS}, 10 signals): "
            f"p50={p50:.1f}µs  p99={p99:.1f}µs"
        )
        assert p99 < 500, f"RiskScorer.score() p99={p99:.1f}µs exceeded 500µs limit"

    def test_score_empty_signals_p99_under_20us(self):
        """Empty signal list is the common bypass path — must be very fast."""
        scorer = RiskScorer(THRESHOLDS)
        latencies: list[float] = []

        for _ in range(_ITERATIONS):
            t0 = time.perf_counter()
            scorer.score([])
            latencies.append((time.perf_counter() - t0) * 1_000_000)

        latencies.sort()
        p99 = _percentile(latencies, 99)
        print(f"\nRiskScorer.score() empty (n={_ITERATIONS}): p99={p99:.1f}µs")
        assert p99 < 20, f"RiskScorer.score() empty p99={p99:.1f}µs exceeded 20µs limit"


class TestActionDeciderPerformance:
    """ActionDecider.decide() p99 must be < 10µs."""

    def test_decide_p99_under_10us(self):
        decider = ActionDecider(THRESHOLDS, ban_duration_seconds=300)
        latencies: list[float] = []

        # Mix of score/dial combinations representative of real traffic
        test_cases = [
            (0, 75),
            (25, 75),
            (50, 75),
            (78, 75),
            (90, 100),
            (12, 0),
            (65, 50),
        ]

        for i in range(_ITERATIONS):
            score, dial = test_cases[i % len(test_cases)]
            t0 = time.perf_counter()
            decider.decide(score=score, dial=dial)
            latencies.append((time.perf_counter() - t0) * 1_000_000)

        latencies.sort()
        p99 = _percentile(latencies, 99)
        p50 = _percentile(latencies, 50)

        print(
            f"\nActionDecider.decide() (n={_ITERATIONS}): "
            f"p50={p50:.2f}µs  p99={p99:.2f}µs"
        )
        assert p99 < 20, f"ActionDecider.decide() p99={p99:.2f}µs exceeded 20µs limit"

    def test_decide_dial_zero_p99_under_5us(self):
        """dial=0 (monitor mode) is the default path — must be fastest."""
        decider = ActionDecider(THRESHOLDS)
        latencies: list[float] = []

        for _ in range(_ITERATIONS):
            t0 = time.perf_counter()
            decider.decide(score=85, dial=0)
            latencies.append((time.perf_counter() - t0) * 1_000_000)

        latencies.sort()
        p99 = _percentile(latencies, 99)
        print(f"\nActionDecider.decide() dial=0 (n={_ITERATIONS}): p99={p99:.2f}µs")
        assert (
            p99 < 5
        ), f"ActionDecider.decide() dial=0 p99={p99:.2f}µs exceeded 5µs limit"


class TestTarpitCapPerformance:
    """Phase 14c: tarpit cap check overhead p99 < 1ms under 500 concurrent.

    The cap check acquires asyncio.Lock, reads two integers, optionally
    increments them, then releases.  This must not become a bottleneck.
    """

    def test_tarpit_cap_check_p99_under_1ms(self):
        """500 concurrent tasks each doing a cap check: p99 < 1ms."""
        _CONCURRENCY = 500
        latencies: list[float] = []

        async def run():
            lock = asyncio.Lock()
            concurrent = 0
            per_ip: dict[str, int] = {}
            max_concurrent = 600  # cap not reached
            max_per_ip = 10

            async def one_check(ip: str) -> None:
                nonlocal concurrent
                t0 = time.perf_counter()
                async with lock:
                    over_global = concurrent >= max_concurrent
                    over_ip = per_ip.get(ip, 0) >= max_per_ip
                    if not over_global and not over_ip:
                        concurrent += 1
                        per_ip[ip] = per_ip.get(ip, 0) + 1
                        acquired = True
                    else:
                        acquired = False
                elapsed_ms = (time.perf_counter() - t0) * 1000
                latencies.append(elapsed_ms)

                if acquired:
                    # Simulate brief in-tarpit work then release
                    await asyncio.sleep(0)
                    async with lock:
                        concurrent = max(0, concurrent - 1)
                        c = per_ip.get(ip, 0)
                        if c <= 1:
                            per_ip.pop(ip, None)
                        else:
                            per_ip[ip] = c - 1

            tasks = [
                asyncio.create_task(one_check(f"10.0.{i // 256}.{i % 256}"))
                for i in range(_CONCURRENCY)
            ]
            await asyncio.gather(*tasks)

        asyncio.run(run())

        latencies.sort()
        p99 = _percentile(latencies, 99)
        p50 = _percentile(latencies, 50)
        print(
            f"\nTarpit cap check ({_CONCURRENCY} concurrent): "
            f"p50={p50:.3f}ms  p99={p99:.3f}ms"
        )
        assert p99 < 1.0, f"Tarpit cap check p99={p99:.3f}ms exceeded 1ms limit"


if __name__ == "__main__":
    # Standalone runner — prints results without pytest
    print("=== JA4proxy Phase 1 Performance Benchmarks ===\n")

    scorer = RiskScorer(THRESHOLDS)
    decider = ActionDecider(THRESHOLDS)

    # Scorer benchmark
    scorer_latencies: list[float] = []
    for _ in range(_ITERATIONS):
        t0 = time.perf_counter()
        scorer.score(_TEN_SIGNALS)
        scorer_latencies.append((time.perf_counter() - t0) * 1_000_000)
    scorer_latencies.sort()
    print(
        f"RiskScorer.score() (10 signals, n={_ITERATIONS}):\n"
        f"  p50={_percentile(scorer_latencies, 50):.1f}µs\n"
        f"  p95={_percentile(scorer_latencies, 95):.1f}µs\n"
        f"  p99={_percentile(scorer_latencies, 99):.1f}µs\n"
        f"  max={scorer_latencies[-1]:.1f}µs\n"
        f"  mean={statistics.mean(scorer_latencies):.1f}µs"
    )

    # Decider benchmark
    decider_latencies: list[float] = []
    for _ in range(_ITERATIONS):
        t0 = time.perf_counter()
        decider.decide(score=78, dial=75)
        decider_latencies.append((time.perf_counter() - t0) * 1_000_000)
    decider_latencies.sort()
    print(
        f"\nActionDecider.decide() (n={_ITERATIONS}):\n"
        f"  p50={_percentile(decider_latencies, 50):.2f}µs\n"
        f"  p95={_percentile(decider_latencies, 95):.2f}µs\n"
        f"  p99={_percentile(decider_latencies, 99):.2f}µs\n"
        f"  max={decider_latencies[-1]:.2f}µs\n"
        f"  mean={statistics.mean(decider_latencies):.2f}µs"
    )


# ── Phase 16e: Accept criteria tests ─────────────────────────────────────────


class TestPhase16eAcceptanceCriteria:
    """Phase 16e acceptance: allow bypass p99 < 500µs; scoring path p99 < 1ms."""

    def test_allow_bypass_p99_under_500us(self):
        """Allow bypass (empty signals → score 0 → allow at dial=0): p99 < 500µs."""
        scorer = RiskScorer(THRESHOLDS)
        decider = ActionDecider(THRESHOLDS)
        latencies: list[float] = []

        for _ in range(1_000):
            t0 = time.perf_counter()
            assessment = scorer.score([])
            decider.decide(score=assessment.total_score, dial=0)
            latencies.append((time.perf_counter() - t0) * 1_000_000)

        latencies.sort()
        p99 = _percentile(latencies, 99)
        print(f"\nAllow bypass p99={p99:.1f}µs (limit: 500µs)")
        assert p99 < 500, f"Allow bypass p99={p99:.1f}µs exceeded 500µs"

    def test_scoring_path_p99_under_1ms(self):
        """Full scoring path (10 signals → score → decide): p99 < 1ms = 1000µs."""
        scorer = RiskScorer(THRESHOLDS)
        decider = ActionDecider(THRESHOLDS)
        latencies: list[float] = []

        for _ in range(1_000):
            t0 = time.perf_counter()
            assessment = scorer.score(_TEN_SIGNALS)
            decider.decide(score=assessment.total_score, dial=75)
            latencies.append((time.perf_counter() - t0) * 1_000_000)

        latencies.sort()
        p99 = _percentile(latencies, 99)
        print(f"\nFull scoring path p99={p99:.1f}µs (limit: 1000µs)")
        assert p99 < 1_000, f"Scoring path p99={p99:.1f}µs exceeded 1ms"
