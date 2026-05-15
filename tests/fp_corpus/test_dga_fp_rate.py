"""
tests/fp_corpus/test_dga_fp_rate.py
Purpose: Verify DGA false-positive rate stays below 1% threshold
Coverage: Tranco top 10,000 domains
Owner: Phase 16
"""

from pathlib import Path

from src.security.sni_analyzer import SNIAnalyzer

FP_DATA_DIR = Path(__file__).parent / "data"
MAX_DGA_FP_RATE = 0.01  # 1% false positive rate threshold


def test_sni_dga_fp_rate_below_threshold():
    """Tranco top 10k must not be flagged as DGA above 1% FP rate."""
    domains = (FP_DATA_DIR / "tranco_top_10k.txt").read_text().splitlines()

    # Create SNI analyzer with DGA detection enabled
    config = {"sni_analysis": {"enabled": True, "score": 40}}
    analyzer = SNIAnalyzer(config)

    # Count how many domains are flagged as DGA
    flagged = sum(
        1
        for domain in domains
        if any(signal.name == "dga_sni" for signal in analyzer.analyze(domain))
    )

    fp_rate = flagged / len(domains)

    assert fp_rate <= MAX_DGA_FP_RATE, (
        f"DGA FP rate {fp_rate:.2%} exceeds {MAX_DGA_FP_RATE:.0%} threshold "
        f"({flagged}/{len(domains)} Tranco top-10k domains flagged as DGA)"
    )

    print(
        f"✓ DGA false-positive rate: {fp_rate:.3%} ({flagged}/{len(domains)} domains)"
    )
