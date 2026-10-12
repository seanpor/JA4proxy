"""Adversarial regression test for JA4PROXY-2026-0118.

Verifies that management/api/prometheus_metrics.py:normalise_path does not pass
arbitrary unauthenticated URL paths through verbatim, preventing Prometheus
metric cardinality explosion DoS.
"""

from management.api.prometheus_metrics import normalise_path


def test_normalise_path_collapses_arbitrary_unregistered_paths():
    """Prove that random attacker-supplied paths are collapsed to bounded labels."""
    # Arbitrary random strings and probing paths
    malicious_paths = [
        "/api/v1/fuzz_target_alpha",
        "/api/v1/fuzz_target_beta",
        "/users/alice",
        "/random_probe_12345",
        "/admin/secret_token_lookup",
        "/wp-admin/setup-config.php",
        "/.env",
    ]

    labels = {normalise_path(p) for p in malicious_paths}
    # Pre-fix: every path returned as its own unique label, len(labels) == 7.
    # Post-fix: unmatched arbitrary paths collapse to "{unmatched}" (bounded).
    assert "{unmatched}" in labels or len(labels) <= 2, (
        f"vulnerability confirmed: arbitrary paths created unbounded labels: {labels}"
    )


def test_normalise_path_preserves_legitimate_routes():
    """Legitimate canonical routes still produce standard metrics."""
    assert normalise_path("/api/v1/health") == "/api/v1/health"
    assert normalise_path("/api/v1/dial") == "/api/v1/dial"
    assert normalise_path("/api/v1/bans/192.0.2.1") == "/api/v1/bans/{id}"
    assert normalise_path("/") == "/"
